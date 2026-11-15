const MAX_POINTS = 60;
const MAX_ROWS   = 50;

const state = {
  labels: [], probs: [],
  rows: [],
  total: 0,
  attacks: 0,
  correct: 0,
  labeled: 0,
  paused: false,
  filter: "all",
  mode: "synthetic",
  running: false,
};

// ---------------------------------------------------------------- chart
const chart = new Chart(document.getElementById("chart").getContext("2d"), {
  type: "line",
  data: {
    labels: state.labels,
    datasets: [{
      data: state.probs,
      borderColor: "#60a5fa",
      backgroundColor: "rgba(96,165,250,0.12)",
      fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2,
    }],
  },
  options: {
    animation: false, responsive: true, maintainAspectRatio: false,
    scales: {
      y: { min: 0, max: 1, grid: { color: "#232a38" }, ticks: { color: "#8b94a6" } },
      x: { grid: { display: false }, ticks: { color: "#8b94a6", maxTicksLimit: 8 } },
    },
    plugins: { legend: { display: false } },
  },
});

// ---------------------------------------------------------------- helpers
const $ = (id) => document.getElementById(id);
const els = {
  dot: $("dot"), status: $("status-text"),
  latest: $("kpi-latest"), conf: $("kpi-conf"),
  share: $("kpi-share"), acc: $("kpi-acc"),
  accBadge: $("acc-badge"),
  log: $("log"), pauseBtn: $("pause-btn"), filter: $("filter"),
  tabs: $("mode-tabs"), formSyn: $("form-synthetic"), formLive: $("form-live"),
  btnStart: $("btn-start"), btnStop: $("btn-stop"), msg: $("control-msg"),
  inAttackType: $("in-attack-type"),
  inTotal: $("in-total"), inRatio: $("in-ratio"), inRate: $("in-rate"),
  inIface: $("in-iface"), ratioOut: $("ratio-out"), ratioCount: $("ratio-count"),
  rateOut: $("rate-out"),
};

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function updateRatioLabel() {
  const total = parseInt(els.inTotal.value, 10) || 0;
  const ratio = parseInt(els.inRatio.value, 10) / 100;
  const a = Math.round(total * ratio);
  const b = total - a;
  els.ratioOut.textContent = `${els.inRatio.value}%`;
  els.ratioCount.textContent = `(≈${a} attacks, ${b} benign)`;
}

function renderKpis(latest) {
  if (!latest) return;
  els.latest.textContent = latest.prediction;
  els.latest.className = "value " + (latest.prediction === "ATTACK" ? "attack" : "safe");
  els.conf.textContent = (latest.confidence * 100).toFixed(1) + "%";
  els.share.textContent = state.total
    ? ((state.attacks / state.total) * 100).toFixed(1) + "%" : "—";
  if (state.labeled > 0) {
    els.acc.textContent = ((state.correct / state.labeled) * 100).toFixed(1) + "%";
    els.accBadge.classList.remove("hidden");
  } else {
    els.acc.textContent = "—";
    els.accBadge.classList.add("hidden");
  }
}

function renderRow(rec) {
  if (state.filter !== "all" && rec.prediction !== state.filter) return;
  const tr = document.createElement("tr");
  if (rec.prediction === "ATTACK") tr.className = "row-attack";
  const t = rec.ts.split("T")[1].slice(0, 8);
  const trueCell = rec.true_label
    ? `<td class="${rec.true_label.toLowerCase() === "benign" ? "safe" : "attack"}">${escapeHtml(rec.true_label)}</td>`
    : `<td class="muted">—</td>`;
  tr.innerHTML = `
    <td>${t}</td>
    <td><span class="pill ${rec.prediction}">${rec.prediction}</span></td>
    <td>${(rec.confidence * 100).toFixed(1)}%</td>
    ${trueCell}
    <td>${escapeHtml(rec.src || "")}</td>
    <td>${escapeHtml(rec.dst || "")}</td>`;
  els.log.prepend(tr);
  while (els.log.children.length > MAX_ROWS) els.log.removeChild(els.log.lastChild);
}

// ---------------------------------------------------------------- flow
function onFlow(rec) {
  state.total += 1;
  if (rec.prediction === "ATTACK") state.attacks += 1;
  if (rec.true_label) {
    state.labeled += 1;
    const isAtk = rec.true_label.toLowerCase() !== "benign";
    if ((rec.prediction === "ATTACK") === isAtk) state.correct += 1;
  }
  state.rows.push(rec);
  if (state.rows.length > MAX_ROWS * 2) state.rows.shift();

  if (state.paused) return;

  renderKpis(rec);
  renderRow(rec);
  state.labels.push(rec.ts.split("T")[1].slice(0, 8));
  state.probs.push(rec.confidence);
  if (state.labels.length > MAX_POINTS) { state.labels.shift(); state.probs.shift(); }
  chart.update("none");
}

function resetView() {
  state.labels.length = 0;
  state.probs.length = 0;
  state.rows = [];
  state.total = 0;
  state.attacks = 0;
  state.correct = 0;
  state.labeled = 0;
  els.log.innerHTML = "";
  els.latest.textContent = "—"; els.latest.className = "value";
  els.conf.textContent = "—";
  els.share.textContent = "—";
  els.acc.textContent = "—";
  chart.update("none");
}

// ---------------------------------------------------------------- controls
function setMode(mode) {
  state.mode = mode;
  els.tabs.querySelectorAll(".tab").forEach(t =>
    t.classList.toggle("active", t.dataset.mode === mode));
  els.formSyn.classList.toggle("hidden", mode !== "synthetic");
  els.formLive.classList.toggle("hidden", mode !== "live");
}

function setRunning(running) {
  state.running = running;
  els.btnStart.disabled = running;
  els.btnStop.disabled = !running;
  els.tabs.querySelectorAll(".tab").forEach(t => t.disabled = running);
}

async function startProducer() {
  els.msg.textContent = "starting…";
  els.msg.style.color = "var(--muted)";
  try {
    let url, body;
    if (state.mode === "synthetic") {
      url  = "/control/start_synthetic";
      body = {
        total_flows:  parseInt(els.inTotal.value, 10) || 500,
        attack_ratio: parseInt(els.inRatio.value, 10) / 100,
        rate:         parseFloat(els.inRate.value) || 10,
        attack_type:  els.inAttackType ? els.inAttackType.value : "drdos_dns",
      };
    } else {
      url  = "/control/start_live";
      body = { interface: els.inIface ? els.inIface.value : "auto" };
    }
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail || "start failed");
    els.msg.textContent = `running · ${state.mode}` + (state.mode === "synthetic" ? ` (${body.attack_type})` : "");
  } catch (e) {
    els.msg.textContent = "error: " + e.message;
    els.msg.style.color = "var(--attack)";
  }
}

async function loadControlOptions() {
  try {
    const resTypes = await fetch("/control/attack_types");
    if (resTypes.ok) {
      const data = await resTypes.json();
      if (els.inAttackType && data.attack_types) {
        els.inAttackType.innerHTML = "";
        data.attack_types.forEach(atk => {
          const opt = document.createElement("option");
          opt.value = atk.id;
          opt.textContent = `${atk.name} (${atk.count.toLocaleString()} flows)`;
          if (atk.id === "drdos_dns") opt.selected = true;
          els.inAttackType.appendChild(opt);
        });
      }
    }
  } catch (e) {
    console.warn("Could not load attack types:", e);
  }

  try {
    const resIfaces = await fetch("/control/interfaces");
    if (resIfaces.ok) {
      const data = await resIfaces.json();
      if (els.inIface && data.interfaces && data.interfaces.length > 0) {
        els.inIface.innerHTML = "";
        data.interfaces.forEach(iface => {
          const opt = document.createElement("option");
          opt.value = iface.id;
          opt.textContent = iface.name;
          if (iface.id === "\\Device\\NPF_Loopback") opt.selected = true;
          els.inIface.appendChild(opt);
        });
      }
    }
  } catch (e) {
    console.warn("Could not load interfaces:", e);
  }
}

async function stopProducer() {
  try {
    await fetch("/control/stop", { method: "POST" });
    els.msg.textContent = "stopped";
  } catch (e) {
    els.msg.textContent = "stop failed: " + e.message;
  }
}

els.tabs.addEventListener("click", (e) => {
  const b = e.target.closest(".tab");
  if (!b || b.disabled) return;
  setMode(b.dataset.mode);
});

els.inTotal.addEventListener("input", updateRatioLabel);
els.inRatio.addEventListener("input", () => {
  updateRatioLabel();
  els.ratioOut.textContent = els.inRatio.value + "%";
});
els.inRate.addEventListener("input", () =>
  els.rateOut.textContent = els.inRate.value);

els.btnStart.addEventListener("click", startProducer);
els.btnStop .addEventListener("click", stopProducer);

els.pauseBtn.addEventListener("click", () => {
  state.paused = !state.paused;
  els.pauseBtn.textContent = state.paused ? "Resume" : "Pause";
});

els.filter.addEventListener("change", (e) => {
  state.filter = e.target.value;
  els.log.innerHTML = "";
  state.rows.slice().reverse().forEach(renderRow);
});

// ---------------------------------------------------------------- socket
let ws, backoff = 500;

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    backoff = 500;
    els.dot.className = "dot live";
    els.status.textContent = "live";
  };
  ws.onclose = () => {
    els.dot.className = "dot dead";
    els.status.textContent = `reconnecting in ${(backoff/1000).toFixed(1)}s`;
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 5000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "history") {
      resetView();
      msg.flows.forEach(onFlow);
    } else if (msg.type === "producer") {
      resetView();
      setRunning(msg.mode !== "idle");
      if (msg.error) {
        els.msg.textContent = msg.error;
        els.msg.style.color = "var(--attack)";
      } else {
        els.msg.textContent = msg.mode === "idle" ? "idle" : `running · ${msg.mode}` + (msg.attack_type ? ` (${msg.attack_type})` : "");
        els.msg.style.color = "var(--muted)";
      }
    } else if (msg.type === "flow") {
      onFlow(msg.flow);
    }
  };
}

// init
updateRatioLabel();
setMode("synthetic");
setRunning(false);
loadControlOptions();
connect();