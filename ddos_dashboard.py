"""
DDoS detection dashboard (REPLAY mode).

Run from your project folder:
    pip install -U streamlit
    streamlit run ddos_dashboard.py

Needs out/rf_ddos.joblib (made by ddos_pipeline.py) and the *-testing.parquet files in data/test.
Flows are replayed from the dataset; this is not live packet capture.
"""
import glob
import os

import joblib
import numpy as np
import pandas as pd
import streamlit as st

DROP = {"flow id", "source ip", "destination ip", "source port", "destination port",
        "timestamp", "unnamed: 0", "simillarhttp", "inbound"}
PROTO = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}
SCENARIOS = ["Mixed (normal + all attacks)", "Normal traffic only", "Attack wave"]


@st.cache_resource
def load_model(path):
    bundle = joblib.load(path)
    model = bundle["model"]
    model.set_params(n_jobs=1)  # tiny batches: threading overhead is slower than 1 core
    return model, bundle["features"]


@st.cache_data(show_spinner="Loading flows...")
def load_flows(folder, cap, seed):
    files = sorted(glob.glob(os.path.join(folder, "**", "*.parquet"), recursive=True))
    if not files:
        return None
    frames = []
    for f in files:
        df = pd.read_parquet(f)
        df.columns = df.columns.astype(str).str.strip().str.lower()
        df = df.drop(columns=[c for c in df.columns if c in DROP])
        label = df.pop("label").astype(str).str.strip().str.lower()
        X = df.apply(pd.to_numeric, errors="coerce").astype("float32")
        X = X.replace([np.inf, -np.inf], np.nan)
        X["label"] = label.values
        frames.append(X)
    data = pd.concat(frames, ignore_index=True).dropna().drop_duplicates().reset_index(drop=True)
    # demo mix: cap each label so rare attacks show up too (NOT the real class ratio)
    return pd.concat([g.sample(min(len(g), cap), random_state=seed)
                      for _, g in data.groupby("label")], ignore_index=True)


def build_queue(data, scenario, attack, n_block, seed=7):
    rng = np.random.default_rng(seed)
    ben = rng.permutation(data.index[data.label == "benign"].to_numpy())
    if scenario == "Normal traffic only":
        return ben
    if scenario.startswith("Mixed"):
        return rng.permutation(data.index.to_numpy())
    pool = rng.permutation(data.index[data.label == attack].to_numpy())[:n_block]
    extra = max(1, len(pool) // 8)  # a little normal traffic inside the wave
    wave = rng.permutation(np.concatenate([pool, ben[2 * n_block:2 * n_block + extra]]))
    return np.concatenate([ben[:n_block], wave, ben[n_block:2 * n_block]])


def reset_state():
    s = st.session_state
    s.running, s.pos, s.tick, s.log = False, 0, 0, pd.DataFrame()


def main():
    st.set_page_config(page_title="DDoS detection demo", page_icon="🛡️", layout="wide")
    s = st.session_state
    for k, v in {"running": False, "pos": 0, "tick": 0, "log": pd.DataFrame(), "sig": None}.items():
        s.setdefault(k, v)

    st.title("🛡️ DDoS detection – replay dashboard")
    st.warning("**Replay mode:** flows come from the CIC-DDoS2019 test files and are fed to the model "
               "batch by batch. This is not live network capture, and the numbers here come from a demo "
               "mix, so they are not the evaluation results in the report.")

    with st.sidebar:
        st.header("Setup")
        model_path = st.text_input("Model file", "out/rf_ddos.joblib")
        data_dir = st.text_input("Flow files folder", "data/test")
        cap = st.number_input("Max flows per label (demo mix)", 50, 5000, 300, step=50)

    if not os.path.exists(model_path):
        st.error(f"Model file not found: {model_path}. Run ddos_pipeline.py first.")
        st.stop()
    data = load_flows(data_dir, int(cap), 42)
    if data is None:
        st.error(f"No .parquet files found in {data_dir}")
        st.stop()
    model, feats = load_model(model_path)
    missing = [f for f in feats if f not in data.columns]
    if missing:
        st.error(f"Model needs features missing from the data: {missing[:5]}")
        st.stop()
    attack_labels = sorted(l for l in data.label.unique() if l != "benign")

    with st.sidebar:
        st.header("Scenario")
        scenario = st.selectbox("Traffic", SCENARIOS)
        attack = st.selectbox("Attack type (for 'Attack wave')", attack_labels)
        block = st.slider("Wave block size (flows)", 50, 500, 150, 10)
        st.header("Replay")
        batch = st.slider("Flows per tick", 1, 50, 10)
        tick_s = st.slider("Seconds per tick", 0.2, 3.0, 1.0, 0.1)
        st.header("Alerting")
        threshold = st.slider("Flag a flow if attack probability ≥", 0.05, 0.95, 0.5, 0.05)
        window = st.slider("Alert window (last N flows)", 20, 300, 100, 10)
        alert_share = st.slider("Raise alert if flagged share ≥", 0.1, 0.9, 0.5, 0.05)
        c1, c2, c3 = st.columns(3)
        start, pause, reset = c1.button("▶ Start"), c2.button("⏸ Pause"), c3.button("↺ Reset")

    queue = build_queue(data, scenario, attack, int(block))
    sig = (model_path, data_dir, int(cap), scenario, attack, int(block))
    if s.sig != sig:
        reset_state()
        s.sig = sig
    if reset:
        reset_state()
    if pause:
        s.running = False
    if start:
        if s.pos >= len(queue):
            reset_state()
        s.running = True

    @st.fragment(run_every=(tick_s if s.running else None))
    def live():
        if s.running and s.pos < len(queue):
            take = queue[s.pos:s.pos + batch]
            rows = data.loc[take]
            proba = model.predict_proba(rows[feats])[:, 1]
            first = s.pos
            s.pos += len(take)
            s.tick += 1
            new = pd.DataFrame({
                "flow": np.arange(first + 1, first + len(take) + 1),
                "tick": s.tick,
                "proto": rows["protocol"].astype(int).map(PROTO).fillna("other").values,
                "duration_ms": (rows["flow duration"] / 1000).round(1).values,
                "fwd_pkts": rows["total fwd packets"].astype(int).values,
                "bwd_pkts": rows["total backward packets"].astype(int).values,
                "pkts_per_s": rows["flow packets/s"].round(0).values,
                "truth": rows["label"].values,
                "attack_prob": np.round(proba, 3),
            })
            s.log = pd.concat([s.log, new], ignore_index=True)
        if s.running and s.pos >= len(queue):
            s.running = False
            st.rerun()

        log = s.log
        st.progress(min(1.0, s.pos / max(1, len(queue))),
                    text=f"{s.pos} / {len(queue)} flows replayed" + ("  (running)" if s.running else ""))
        if log.empty:
            st.info("Press ▶ Start in the sidebar to begin the replay.")
            return

        pred = log.attack_prob >= threshold
        truth_att = log.truth != "benign"
        recent_share = float(pred.tail(int(window)).mean())
        if recent_share >= alert_share:
            st.error(f"🚨 **DDoS ALERT** – {recent_share:.0%} of the last {min(len(log), int(window))} "
                     f"flows were flagged as attack. (Prevention layer not implemented: nothing is blocked.)")
        else:
            st.success(f"✅ Traffic looks normal – {recent_share:.0%} of the last "
                       f"{min(len(log), int(window))} flows flagged.")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Flows processed", len(log))
        m2.metric("Flagged as attack", int(pred.sum()))
        m3.metric("Allowed", int((~pred).sum()))
        m4.metric("Flagged share (window)", f"{recent_share:.0%}")

        left, right = st.columns([3, 2])
        with left:
            st.subheader("Share of flows per tick")
            chart = pd.DataFrame({
                "model flagged": pred.groupby(log.tick).mean(),
                "actually attack": truth_att.groupby(log.tick).mean(),
            })
            st.line_chart(chart, height=240)
            st.subheader("Latest flows")
            view = log.tail(15).iloc[::-1].copy()
            p = view.attack_prob >= threshold
            a = view.truth != "benign"
            view["model says"] = np.where(p, "🚨 ALERT", "✅ allow")
            view["correct?"] = np.select([p == a, ~a], ["✓", "✗ false alarm"], "✗ missed attack")
            st.dataframe(view.drop(columns="tick"), hide_index=True, width="stretch")
        with right:
            st.subheader("Running confusion matrix")
            cm = pd.DataFrame(
                [[int((~truth_att & ~pred).sum()), int((~truth_att & pred).sum())],
                 [int((truth_att & ~pred).sum()), int((truth_att & pred).sum())]],
                index=["actually normal", "actually attack"],
                columns=["model: allow", "model: alert"])
            st.dataframe(cm, width="stretch")
            st.subheader("By true label")
            t = pd.DataFrame({"flows": log.groupby("truth").size(),
                              "flagged": pred.groupby(log.truth).sum().astype(int)})
            t["flagged %"] = (100 * t.flagged / t.flows).round(1)
            st.dataframe(t, width="stretch")
            st.caption("For 'benign', flagged % is the false-alarm rate. For attacks it is the detection "
                       "rate. 'truth' comes from the dataset labels; the model never sees it.")

    live()

    with st.expander("How this works"):
        st.markdown(
            "1. Each row is one **network flow** already summarised into CICFlowMeter features "
            "(durations, packet counts, packet sizes, flags…).\n"
            "2. The saved Random Forest sees only its selected features and outputs an **attack probability**.\n"
            "3. A flow is flagged if the probability ≥ the threshold; an **alert** fires when enough of the "
            "recent flows are flagged.\n"
            "4. The 'truth' column is used only to show whether the model was right.\n\n"
            "**Limits:** features are computed after a flow ends, so this design cannot block traffic "
            "mid-flow; live use would need a flow extractor that matches CICFlowMeter exactly.")


if __name__ == "__main__":
    main()