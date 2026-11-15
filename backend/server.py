from __future__ import annotations
import asyncio, glob, os, random, threading, sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import socket
import struct
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ------------------------------------------------------------------ model
_ARTIFACT_CANDIDATES = [
    Path("out/rf_ddos.joblib"),
    Path("rf_ddos.joblib"),
    Path("backend/rf_ddos.joblib"),
    Path(__file__).resolve().parent.parent / "out" / "rf_ddos.joblib",
]
ARTIFACT = next((p for p in _ARTIFACT_CANDIDATES if p.exists()), None)
if ARTIFACT is None:
    raise SystemExit("rf_ddos.joblib not found. Run your training pipeline first.")
art = joblib.load(ARTIFACT)
MODEL, FEATURES = art["model"], art["features"]
print(f"[model] loaded {ARTIFACT} with {len(FEATURES)} features")

# ------------------------------------------------------- multi-attack pools
def _load_all_pools(cap_per_attack: int = 3_000, seed: int = 42):
    attack_pools: dict[str, pd.DataFrame] = {}
    benign_chunks: list[pd.DataFrame] = []
    
    files = sorted(glob.glob("data/**/*.parquet", recursive=True) + glob.glob("data/**/*.csv", recursive=True))
    if not files:
        base_dir = Path(__file__).resolve().parent.parent
        files = sorted(glob.glob(str(base_dir / "data/**/*.parquet"), recursive=True))

    for f in files:
        try:
            if f.endswith(".parquet"):
                df = pd.read_parquet(f)
            else:
                df = pd.read_csv(f, low_memory=False)
            df.columns = [str(c).strip().lower() for c in df.columns]
            if "label" not in df.columns:
                continue

            keep = [c for c in df.columns if c in set(FEATURES) | {"label", "source ip", "destination ip", "src_ip", "dst_ip"}]
            df = df[keep].reset_index(drop=True)

            is_benign = df["label"].astype(str).str.lower() == "benign"
            ben = df[is_benign]
            if not ben.empty:
                benign_chunks.append(ben.sample(min(len(ben), 1000), random_state=seed))

            for lbl, grp in df[~is_benign].groupby(df["label"].astype(str).str.lower()):
                norm_lbl = lbl.replace("-", "_").strip()
                if norm_lbl not in attack_pools:
                    attack_pools[norm_lbl] = []
                attack_pools[norm_lbl].append(grp.sample(min(len(grp), cap_per_attack), random_state=seed))
        except Exception as e:
            print(f"[pool] warning reading {f}: {e}")

    benign_pool = pd.concat(benign_chunks, ignore_index=True).drop_duplicates().reset_index(drop=True) if benign_chunks else pd.DataFrame()
    consolidated_attacks: dict[str, pd.DataFrame] = {}
    for k, v in attack_pools.items():
        consolidated_attacks[k] = pd.concat(v, ignore_index=True).drop_duplicates().reset_index(drop=True)

    print(f"[pool] Initialized {len(consolidated_attacks)} attack classes & {len(benign_pool)} benign flows")
    return consolidated_attacks, benign_pool

ATTACK_POOLS, BENIGN_POOL = _load_all_pools()

# ---------------------------------------------------------------- state
class Stats:
    def __init__(self): self.reset()
    def reset(self):
        self.total = 0
        self.pred_attacks = 0
        self.true_attacks = 0
        self.correct = 0
        self.has_truth = False

class ProducerState:
    def __init__(self):
        self.mode: Literal["idle", "synthetic", "live"] = "idle"
        self.task: Optional[asyncio.Task] = None
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self.live_stop: Optional[threading.Event] = None
        self.live_error: Optional[str] = None
        self.attack_type: str = "drdos_dns"

STATS = Stats()
PROD  = ProducerState()
BUFFER: deque = deque(maxlen=200)
CLIENTS: set[WebSocket] = set()

app = FastAPI(title="DDoS Live Monitor")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --------------------------------------------------------- classification
def _to_features(flow: dict) -> pd.DataFrame:
    df = pd.DataFrame([flow])
    df.columns = [str(c).strip().lower() for c in df.columns]
    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    return df.reindex(columns=FEATURES, fill_value=0).astype("float32")

def _classify(flow: dict) -> dict:
    X = _to_features(flow)
    prob = float(MODEL.predict_proba(X)[0, 1])
    
       # --- HYBRID DETECTION RULE ENGINE ---
    try:
        total_pkts = float(X["total fwd packets"].iloc[0]) if "total fwd packets" in X.columns else 0
        duration = float(X["flow duration"].iloc[0]) if "flow duration" in X.columns else 1
        pkt_rate = float(X["flow packets/s"].iloc[0]) if "flow packets/s" in X.columns else 0
    except Exception:
        total_pkts = 0
        duration = 1
        pkt_rate = 0
        
    # Trigger if we see >50 packets in a short flow OR a crazy packet rate
    if (total_pkts > 50 and duration < 1000000) or pkt_rate > 500:
        prob = 0.99
        print(f"🚨 [RULE ENGINE] Flood detected! pkts={total_pkts}, rate={pkt_rate:.0f}/s. Overriding ML to ATTACK.")
    # ------------------------------------

    pred = "ATTACK" if prob >= 0.5 else "SAFE"

    true_label = flow.get("label")
    STATS.total += 1
    if pred == "ATTACK": STATS.pred_attacks += 1
    
    if true_label is not None:
        STATS.has_truth = True
        is_atk = str(true_label).lower() != "benign"
        if is_atk: STATS.true_attacks += 1
        if (pred == "ATTACK") == is_atk: STATS.correct += 1

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "prediction": pred,
        "confidence": round(prob, 4),
        "src": str(flow.get("source ip") or flow.get("src_ip") or "192.168.1.105")[:40],
        "dst": str(flow.get("destination ip") or flow.get("dst_ip") or "192.168.1.1")[:40],
        "true_label": str(true_label) if true_label else None,
    }


async def _broadcast(msg: dict) -> None:
    for ws in list(CLIENTS):
        try: await ws.send_json(msg)
        except Exception: CLIENTS.discard(ws)

async def ingest_worker():
    print("--- [ingest] worker started and listening for flows ---")
    while True:
        flow = await PROD.queue.get()
        try:
            rec = _classify(flow)
            # ADD THIS LINE:
            print(f"--- [ingest] Processed a flow: {rec['prediction']} ({rec['confidence']}) ---")
            
            BUFFER.append(rec)
            await _broadcast({"type": "flow", "flow": rec})
        except Exception as e:
            print("!!! [ingest] classify error:", e)
        finally:
            PROD.queue.task_done()

@app.on_event("startup")
async def _startup():
    asyncio.create_task(ingest_worker())

# ------------------------------------------------------------- producers
async def _synthetic_producer(total: int, ratio: float, rate: float, seed: int, attack_type: str = "drdos_dns"):
    norm_atk = attack_type.strip().lower().replace("-", "_")
    if norm_atk == "mixed":
        chosen_pool = pd.concat(list(ATTACK_POOLS.values()), ignore_index=True)
    elif norm_atk in ATTACK_POOLS:
        chosen_pool = ATTACK_POOLS[norm_atk]
    elif "dns" in norm_atk and "drdos_dns" in ATTACK_POOLS:
        chosen_pool = ATTACK_POOLS["drdos_dns"]
    else:
        chosen_pool = ATTACK_POOLS.get("drdos_dns", next(iter(ATTACK_POOLS.values())))

    print(f"--- [producer] starting synthetic: {total} flows, {ratio*100:.0f}% attacks, class: {norm_atk} ({len(chosen_pool)} pool rows) ---")
    rng = random.Random(seed)
    try:
        for _ in range(total):
            is_atk = rng.random() < ratio
            pool = chosen_pool if is_atk else BENIGN_POOL
            row = pool.iloc[rng.randrange(len(pool))].to_dict()

            # Realistic simulated IPs for dashboard view if not present in dataset
            if not row.get("src_ip") and not row.get("source ip"):
                if is_atk:
                    row["src_ip"] = f"172.16.0.{rng.randint(2, 254)}"
                    row["dst_ip"] = "192.168.50.1"
                else:
                    row["src_ip"] = f"192.168.1.{rng.randint(10, 200)}"
                    row["dst_ip"] = f"142.250.{rng.randint(1, 254)}.{rng.randint(1, 254)}"

            await PROD.queue.put(row)
            await asyncio.sleep(1.0 / rate)
    except asyncio.CancelledError:
        raise
    finally:
        if PROD.mode == "synthetic":
            PROD.mode = "idle"
            await _broadcast({"type": "producer", "mode": "idle"})

# --------------------------------------------------- interface resolution
def resolve_interface(iface: str) -> str:
    if sys.platform != "win32":
        return iface or "eth0"
    iface_clean = (iface or "").strip()
    if iface_clean.startswith("\\Device\\NPF_"):
        return iface_clean
    if iface_clean.lower() in ("eth0", "loopback", "127.0.0.1", "localhost", "lo", "auto", ""):
        return "\\Device\\NPF_Loopback"
    try:
        from scapy.arch.windows import get_windows_if_list
        for w_if in get_windows_if_list():
            name = (w_if.get("name") or "").lower()
            desc = (w_if.get("description") or "").lower()
            ips = [str(ip) for ip in (w_if.get("ips") or [])]
            pcap = w_if.get("pcap_name")
            if pcap and (iface_clean.lower() in name or iface_clean.lower() in desc or iface_clean in ips):
                return pcap
    except Exception:
        pass
    return "\\Device\\NPF_Loopback"

def get_available_interfaces():
    ifaces = []
    if sys.platform == "win32":
        ifaces.append({"id": "\\Device\\NPF_Loopback", "name": "Loopback (127.0.0.1 - Local Test Traffic)"})
        try:
            from scapy.arch.windows import get_windows_if_list
            for w_if in get_windows_if_list():
                pcap = w_if.get("pcap_name")
                name = w_if.get("name") or "Network Adapter"
                desc = w_if.get("description") or ""
                ips = [ip for ip in (w_if.get("ips") or []) if ":" not in str(ip)]
                ip_str = f" ({ips[0]})" if ips else ""
                if pcap and pcap != "\\Device\\NPF_Loopback":
                    ifaces.append({"id": pcap, "name": f"{name}{ip_str} - {desc}"})
                elif not pcap and ("wi-fi" in name.lower() or "ethernet" in name.lower()):
                    ifaces.append({"id": name, "name": f"{name}{ip_str} (Admin elevation required for Npcap)"})
        except Exception:
            pass
    else:
        ifaces.append({"id": "eth0", "name": "eth0 (Primary Ethernet)"})
        ifaces.append({"id": "lo", "name": "lo (Loopback 127.0.0.1)"})
    return ifaces

# --------------------------------------------------------------- control
class SyntheticStart(BaseModel):
    total_flows:  int   = Field(500, ge=1)
    attack_ratio: float = Field(0.3, ge=0.0, le=1.0)
    rate:         float = Field(10.0, gt=0.0)
    seed:         int   = 42
    attack_type:  str   = Field("drdos_dns")

class LiveStart(BaseModel):
    interface: str = "auto"

async def _stop_internal(broadcast: bool = True):
    if PROD.task:
        PROD.task.cancel()
        try: 
            await PROD.task
        except asyncio.CancelledError:
            pass
        except Exception: 
            pass
        PROD.task = None
    if PROD.live_stop:
        PROD.live_stop.set()
        PROD.live_stop = None
    PROD.mode = "idle"
    if broadcast:
        await _broadcast({"type": "producer", "mode": "idle"})

@app.get("/control/attack_types")
def control_attack_types():
    friendly_names = {
        "drdos_dns": "DRDoS DNS (Amplification Flood)",
        "drdos_ntp": "DRDoS NTP (Monlist Amplification)",
        "drdos_mssql": "DRDoS MSSQL (Database Reflection)",
        "drdos_udp": "DRDoS UDP (Volumetric UDP Flood)",
        "tftp": "TFTP (Amplification Attack)",
        "syn": "TCP SYN Flood (State Exhaustion)",
        "drdos_ldap": "DRDoS LDAP (Reflection Flood)",
        "ldap": "LDAP Flood",
        "netbios": "NetBIOS Flood",
        "portmap": "Portmap Reflection",
        "udp_lag": "UDP Lag (Low-Rate Pulsed UDP)",
        "webddos": "WebDDoS (HTTP Application-Layer Flood)",
    }
    items = []
    # prioritize DRDoS DNS first
    ordered_keys = ["drdos_dns"] + [k for k in ATTACK_POOLS if k != "drdos_dns"]
    for k in ordered_keys:
        items.append({
            "id": k,
            "name": friendly_names.get(k, k.replace("_", " ").upper()),
            "count": len(ATTACK_POOLS[k])
        })
    items.append({"id": "mixed", "name": "Mixed Traffic (All Attack Types Combined)", "count": sum(len(v) for v in ATTACK_POOLS.values())})
    return {"attack_types": items}



@app.get("/control/interfaces")
def control_interfaces():
    return {"interfaces": get_available_interfaces()}

@app.post("/control/start_synthetic")
async def control_start_synthetic(cfg: SyntheticStart):
    await _stop_internal(broadcast=False)
    STATS.reset(); BUFFER.clear()
    PROD.mode = "synthetic"
    PROD.attack_type = cfg.attack_type
    await _broadcast({"type": "producer", "mode": "synthetic", "attack_type": cfg.attack_type})
    PROD.task = asyncio.create_task(
        _synthetic_producer(cfg.total_flows, cfg.attack_ratio, cfg.rate, cfg.seed, cfg.attack_type)
    )
    return {"ok": True, "mode": "synthetic", "attack_type": cfg.attack_type}

# --- NATIVE RAW SOCKET CAPTURE (Bypasses Npcap) ---
def _start_live_thread(iface_ip: str, loop: asyncio.AbstractEventLoop):
    def _run():
        try:
            print(f"--- [live] attempting native raw socket capture on IP: {iface_ip} ---")
            
            # Create a raw socket
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((iface_ip, 0))
            
            # Include IP headers
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode (Windows only)
            import os
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            # Simple flow tracking dictionary
            flows = {}
            
            while not PROD.live_stop.is_set():
                sniffer.settimeout(0.5)
                try:
                    raw_packet, addr = sniffer.recvfrom(65535)
                except socket.timeout:
                    # Expire old flows and push them to the model
                    now = time.time()
                    for k in list(flows.keys()):
                        v = flows[k]
                        if now - v["last"] > 2.0: # 2-second timeout
                            flow_data = {
                                "source ip": k[0],
                                "destination ip": k[1],
                                "flow duration": int((v["last"] - v["start"]) * 1000000),
                                "total fwd packets": v["fwd_pkts"],
                                "total backward packets": v["bwd_pkts"],
                                "total length of fwd packets": v["fwd_bytes"],
                                "total length of bwd packets": v["bwd_bytes"],
                            }
                            loop.call_soon_threadsafe(PROD.queue.put_nowait, flow_data)
                            del flows[k]
                    continue

                # Parse IP header
                ip_header = raw_packet[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                ihl = (iph[0] & 0xF) * 4
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                proto = iph[6]
                length = iph[2]
                
                src_port, dst_port = 0, 0
                if proto == 6: # TCP
                    tcp_header = raw_packet[ihl:ihl+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    src_port, dst_port = tcph[0], tcph[1]
                elif proto == 17: # UDP
                    udp_header = raw_packet[ihl:ihl+8]
                    udph = struct.unpack('!HHHH', udp_header)
                    src_port, dst_port = udph[0], udph[1]
                else:
                    continue # Skip non-TCP/UDP
                
                # Group into bidirectional flows
                if src_ip == iface_ip:
                    key = (src_ip, dst_ip, src_port, dst_port, proto)
                    if key not in flows:
                        flows[key] = {"start": time.time(), "last": time.time(), "fwd_pkts": 0, "bwd_pkts": 0, "fwd_bytes": 0, "bwd_bytes": 0}
                    flows[key]["fwd_pkts"] += 1
                    flows[key]["fwd_bytes"] += length
                    flows[key]["last"] = time.time()
                else:
                    key = (dst_ip, src_ip, dst_port, src_port, proto)
                    if key not in flows:
                        flows[key] = {"start": time.time(), "last": time.time(), "fwd_pkts": 0, "bwd_pkts": 0, "fwd_bytes": 0, "bwd_bytes": 0}
                    flows[key]["bwd_pkts"] += 1
                    flows[key]["bwd_bytes"] += length
                    flows[key]["last"] = time.time()

        except Exception as e:
            PROD.live_error = str(e)
            PROD.mode = "idle"
            print(f"!!! [live] RAW SOCKET CRASHED: {e} !!!")
            asyncio.run_coroutine_threadsafe(
                _broadcast({"type": "producer", "mode": "idle", "error": str(e)}), 
                loop
            )
    threading.Thread(target=_run, daemon=True).start()


@app.post("/control/start_live")
async def control_start_live(cfg: LiveStart):
    await _stop_internal(broadcast=False)
    STATS.reset(); BUFFER.clear()
    PROD.mode = "live"
    
    # We no longer start raw sockets here. 
    # The Streamlit producer will POST directly to /ingest.
    await _broadcast({"type": "producer", "mode": "live"})
    return {"ok": True, "mode": "live"}

@app.post("/control/stop")
async def control_stop():
    await _stop_internal(broadcast=True)
    return {"ok": True}

@app.get("/control/status")
def control_status():
    return {
        "mode": PROD.mode,
        "live_error": PROD.live_error,
        "attack_type": PROD.attack_type,
        "stats": STATS.__dict__
    }

# ---------------------------------------------------------------- ingest
@app.post("/ingest")
async def ingest(flow: dict):
    """External producers (like Streamlit) POST flows here."""
    await PROD.queue.put(flow)
    return {"ok": True}

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    CLIENTS.add(ws)
    await ws.send_json({"type": "producer", "mode": PROD.mode, "attack_type": PROD.attack_type})
    await ws.send_json({"type": "history",  "flows": list(BUFFER)})
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: CLIENTS.discard(ws)

# Mount frontend regardless of working directory
_frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if not _frontend_dir.exists():
    _frontend_dir = Path("frontend")


app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")
