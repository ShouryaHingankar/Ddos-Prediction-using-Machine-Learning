import streamlit as st
import socket
import struct
import time
import threading
import requests
import pandas as pd
import os
import sys

# Configuration
FASTAPI_URL = "http://localhost:8000/ingest"
FLOW_TIMEOUT = 2.0  # Seconds of inactivity before a flow is considered "finished"

# ---------------------------------------------------------
# Core Packet Capture & Flow Aggregation Logic
# ---------------------------------------------------------
class PacketSniffer:
    def __init__(self):
        self.running = False
        self.thread = None
        self.flows = {}
        self.lock = threading.Lock()
        self.stats = {"packets": 0, "flows_sent": 0}

    def start(self, iface_ip):
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, args=(iface_ip,), daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _capture_loop(self, iface_ip):
        try:
            # Create native raw socket (Bypasses Npcap)
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((iface_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                
            sniffer.settimeout(0.5)

            while self.running:
                try:
                    raw_packet, addr = sniffer.recvfrom(65535)
                    self.stats["packets"] += 1
                    self._process_packet(raw_packet, iface_ip)
                except socket.timeout:
                    self._flush_old_flows()
                except Exception as e:
                    print(f"Packet read error: {e}")

            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()
        except Exception as e:
            st.error(f"Capture Error (Run as Admin?): {e}")

    def _process_packet(self, raw_packet, iface_ip):
        try:
            ip_header = raw_packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            ihl = (iph[0] & 0xF) * 4
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            proto = iph[6]
            length = iph[2]
            
            src_port, dst_port = 0, 0
            syn, ack, fin, rst = 0, 0, 0, 0
            
            if proto == 6: # TCP
                tcp_header = raw_packet[ihl:ihl+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port, dst_port = tcph[0], tcph[1]
                flags = tcph[5]
                fin = (flags & 0x01) >> 0
                syn = (flags & 0x02) >> 1
                rst = (flags & 0x04) >> 2
                ack = (flags & 0x10) >> 4
            elif proto == 17: # UDP
                udp_header = raw_packet[ihl:ihl+8]
                udph = struct.unpack('!HHHH', udp_header)
                src_port, dst_port = udph[0], udph[1]
            else:
                return # Ignore non-TCP/UDP

            # --- DDoS Aggregation Logic ---
            # If it's a SYN packet (no ACK), group by TARGET IP and PORT only.
            # This aggregates thousands of spoofed sources into one attack flow.
            if syn == 1 and ack == 0:
                key = (dst_ip, src_ip, dst_port, 0, proto) # Force src_port to 0
            else:
                # Normal 5-tuple grouping for benign traffic
                if src_ip == iface_ip:
                    key = (src_ip, dst_ip, src_port, dst_port, proto)
                else:
                    key = (dst_ip, src_ip, dst_port, src_port, proto)

            direction = "fwd" if src_ip == iface_ip else "bwd"

            with self.lock:
                if key not in self.flows:
                    self.flows[key] = {
                        "start": time.time(), "last": time.time(),
                        "fwd_pkts": 0, "bwd_pkts": 0,
                        "fwd_bytes": 0, "bwd_bytes": 0,
                        "fwd_lengths": [], "bwd_lengths": [],
                        "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0
                    }
                
                flow = self.flows[key]
                flow["last"] = time.time()
                
                # Count flags
                flow["syn_count"] += syn
                flow["ack_count"] += ack
                flow["fin_count"] += fin
                flow["rst_count"] += rst
                
                if direction == "fwd":
                    flow["fwd_pkts"] += 1
                    flow["fwd_bytes"] += length
                    flow["fwd_lengths"].append(length)
                else:
                    flow["bwd_pkts"] += 1
                    flow["bwd_bytes"] += length
                    flow["bwd_lengths"].append(length)
        except Exception:
            pass # Ignore malformed packets

    def _flush_old_flows(self):
        now = time.time()
        expired_keys = []
        
        with self.lock:
            for k, v in self.flows.items():
                if now - v["last"] > FLOW_TIMEOUT:
                    expired_keys.append(k)
                    
            for k in expired_keys:
                flow = self.flows.pop(k)
                self._send_flow(k, flow)

    def _send_flow(self, key, flow):
        # Calculate CIC-DDoS2019 compatible features
        src_ip, dst_ip, src_port, dst_port, proto = key
        duration = int((flow["last"] - flow["start"]) * 1000000) # microseconds
        duration = max(duration, 1) # Prevent division by zero
        
        fwd_len_mean = sum(flow["fwd_lengths"]) / len(flow["fwd_lengths"]) if flow["fwd_lengths"] else 0
        bwd_len_mean = sum(flow["bwd_lengths"]) / len(flow["bwd_lengths"]) if flow["bwd_lengths"] else 0
        
        features = {
            "source ip": src_ip,
            "destination ip": dst_ip,
            "flow duration": duration,
            "total fwd packets": flow["fwd_pkts"],
            "total backward packets": flow["bwd_pkts"],
            "total length of fwd packets": flow["fwd_bytes"],
            "total length of bwd packets": flow["bwd_bytes"],
            "flow bytes/s": (flow["fwd_bytes"] + flow["bwd_bytes"]) / (duration / 1000000),
            "flow packets/s": (flow["fwd_pkts"] + flow["bwd_pkts"]) / (duration / 1000000),
            "protocol": proto,
            "syn flag count": flow["syn_count"],
            "ack flag count": flow["ack_count"],
            "fin flag count": flow["fin_count"],
            "rst flag count": flow["rst_count"],
            "fwd packet length mean": fwd_len_mean,
            "bwd packet length mean": bwd_len_mean,
            "packet length mean": (fwd_len_mean + bwd_len_mean) / 2
        }
        
        try:
            # Send to FastAPI (fire and forget)
            requests.post(FASTAPI_URL, json=features, timeout=1)
            self.stats["flows_sent"] += 1
        except requests.exceptions.RequestException:
            pass

# ---------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------
st.set_page_config(page_title="Live Traffic Producer", layout="centered")
st.title("📡 Live Traffic Producer")
st.markdown("Captures native packets, converts them to flows, and streams them to the dashboard.")

# Auto-detect IP
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    local_ip = s.getsockname()[0]
    s.close()
except Exception:
    local_ip = "127.0.0.1"

# Session State
if "sniffer" not in st.session_state:
    st.session_state.sniffer = PacketSniffer()
if "is_running" not in st.session_state:
    st.session_state.is_running = False

# UI Controls
col1, col2 = st.columns([3, 1])
with col1:
    iface_ip = st.text_input("Local IP to bind to (Run Streamlit as Administrator)", value=local_ip)
with col2:
    st.write("") # Spacer
    st.write("") # Spacer
    if not st.session_state.is_running:
        if st.button("▶ Start Capture", type="primary", use_container_width=True):
            st.session_state.sniffer.start(iface_ip)
            st.session_state.is_running = True
            st.rerun()
    else:
        if st.button("⏹ Stop Capture", type="secondary", use_container_width=True):
            st.session_state.sniffer.stop()
            st.session_state.is_running = False
            st.rerun()

st.divider()

# Live Metrics
if st.session_state.is_running:
    st.success(f"🟢 Capturing on {iface_ip}... Waiting for flows to finish (Timeout: {FLOW_TIMEOUT}s)")
    
    metrics_placeholder = st.empty()
    
    while st.session_state.is_running:
        stats = st.session_state.sniffer.stats
        with metrics_placeholder.container():
            st.metric("Raw Packets Captured", stats["packets"])
            st.metric("Flows Sent to Dashboard", stats["flows_sent"])
        time.sleep(1)
else:
    st.info("🔴 Capture stopped. Click Start to begin.")