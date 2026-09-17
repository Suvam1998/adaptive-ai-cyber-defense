/* Adaptive AI Cyber Defense System — build-free SPA.
 * Vanilla JS, no build step. Talks to the FastAPI backend under /api.
 */
"use strict";

const state = { dataset: "real", route: "dashboard", config: {}, charts: {},
                es: null, dashTimer: null, dashLastData: null };
const DASHBOARD_POLL_MS = 2000;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

// ---------- helpers ----------
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" }, ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = j.detail || JSON.stringify(j); } catch (e) {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}
function h(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; }
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function toast(msg, kind = "ok") {
  const t = $("#toast"); t.className = "toast " + kind; t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), 3800);
}
function sevPill(s) { const k = (s || "medium").toLowerCase(); return `<span class="pill sev-${k}">${esc(s)}</span>`; }
function pct(x) { return Math.round((x || 0) * 100); }
function ds() { return state.dataset; }
function modal(html) { $("#modalCard").innerHTML = html; $("#modal").classList.remove("hidden"); }
function closeModal() { $("#modal").classList.add("hidden"); }
$("#modal").addEventListener("click", e => { if (e.target.id === "modal") closeModal(); });

// ---------- router ----------
const routes = {
  dashboard: renderDashboard, incidents: renderIncidents, responses: renderResponses,
  realdata: renderRealData, demo: renderDemo, analytics: renderAnalytics,
  memory: renderMemory, audit: renderAudit, incident: renderInvestigation,
  assessment: renderAssessment, evaluation: renderEvaluation,
};
function parseHash() {
  const raw = (location.hash || "#/dashboard").slice(2).split("/");
  return { route: raw[0] || "dashboard", param: raw[1] || null };
}
async function route() {
  const { route: r, param } = parseHash();
  // Leaving any page tears down the dashboard poller so it never stacks up.
  // The dashboard re-arms its own poller inside renderDashboard().
  stopDashboardUpdates();
  state.route = r;
  $$(".sidebar a").forEach(a => a.classList.toggle("active", a.dataset.route === r));
  const view = $("#view");
  view.innerHTML = `<div class="loading">Loading…</div>`;
  try { await (routes[r] || renderDashboard)(view, param); }
  catch (e) { view.innerHTML = `<div class="panel"><h2>Error</h2><p class="muted">${esc(e.message)}</p></div>`; }
}
window.addEventListener("hashchange", route);

// ---------- dataset toggle ----------
$("#datasetToggle").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  state.dataset = b.dataset.ds;
  $$("#datasetToggle button").forEach(x => x.classList.toggle("active", x === b));
  $("#dsIndicator").innerHTML = `Dataset: <b>${ds().toUpperCase()}</b>`;
  $("#demoBanner").classList.toggle("hidden", ds() !== "demo");
  startStream();
  route();
});

// ---------- global search ----------
const searchBox = $("#globalSearch"), searchRes = $("#searchResults");
let searchTimer;
searchBox.addEventListener("input", () => {
  clearTimeout(searchTimer);
  const q = searchBox.value.trim();
  if (!q) { searchRes.classList.add("hidden"); return; }
  searchTimer = setTimeout(async () => {
    try {
      const { results } = await api(`/api/search?q=${encodeURIComponent(q)}&dataset=${ds()}`);
      if (!results.length) { searchRes.innerHTML = `<div class="muted">No results</div>`; }
      else searchRes.innerHTML = results.map(r =>
        `<div data-inc="${esc(r.incident_id || "")}">${esc(r.label)}</div>`).join("");
      searchRes.classList.remove("hidden");
    } catch (e) {}
  }, 250);
});
searchRes.addEventListener("click", e => {
  const d = e.target.closest("div[data-inc]"); if (!d) return;
  const inc = d.dataset.inc; searchRes.classList.add("hidden"); searchBox.value = "";
  if (inc) location.hash = `#/incident/${inc}`;
});
document.addEventListener("click", e => {
  if (!e.target.closest(".topbar-mid")) searchRes.classList.add("hidden");
});

// ---------- live stream (SSE) ----------
function setConnState(kind) {
  // kind: connecting | connected | reconnecting | disconnected
  state.streamConnected = kind === "connected";
  const boot = $("#bootConn");
  const labels = { connecting: "CONNECTING", connected: "CONNECTED",
                   reconnecting: "RECONNECTING", disconnected: "DISCONNECTED" };
  if (boot) { boot.className = "boot-conn-state " + kind;
    boot.innerHTML = `<span class="dot"></span>${labels[kind]}`; }
  const live = $("#liveDot"), lt = $("#liveText");
  if (live) {
    live.classList.toggle("stale", kind !== "connected");
    live.classList.toggle("reconnect", kind === "reconnecting");
    live.classList.toggle("down", kind === "disconnected");
    if (lt) lt.textContent = kind === "connected" ? "LIVE"
      : kind === "reconnecting" ? "RECONNECTING" : kind === "disconnected" ? "OFFLINE" : "…";
  }
}

function startStream() {
  if (state.es) { state.es.close(); state.es = null; }
  setConnState("connecting");
  const es = new EventSource(`/api/stream?dataset=${ds()}`);
  state.es = es;
  es.onopen = () => setConnState("connected");
  es.onmessage = ev => {
    try {
      const data = JSON.parse(ev.data);
      setConnState("connected");
      window._liveDash = data.dashboard; window._liveDemo = data.demo;
      // NOTE: the Dashboard is refreshed by its own dedicated poller
      // (startDashboardUpdates) so it also updates charts + timestamp and has a
      // single, lifecycle-managed loop. SSE handles the other live pages.
      if (["demo", "incidents", "responses", "analytics"].includes(state.route)) {
        if (!window._lastLive || Date.now() - window._lastLive > 2000) {
          window._lastLive = Date.now();
          if (state.route === "demo") updateDemoLive(data.demo);
          if (state.route === "incidents" || state.route === "responses" || state.route === "analytics")
            route();
        }
      }
    } catch (e) {}
  };
  es.onerror = () => setConnState("reconnecting");  // browser auto-retries SSE
}

// ---------- KPI card ----------
function kpi(val, label, sub = "") {
  return `<div class="card kpi"><div class="k-val">${val}</div><div class="k-lbl">${esc(label)}</div>${sub ? `<div class="k-sub muted">${sub}</div>` : ""}</div>`;
}

// ==================================================================
// DASHBOARD
// ==================================================================
async function renderDashboard(view) {
  const d = await api(`/api/dashboard?dataset=${ds()}`);
  const c = await api(`/api/analytics?dataset=${ds()}`);
  view.innerHTML = `
    <div class="page-head"><div><h1>SOC Dashboard</h1>
      <div class="muted">${ds() === "demo" ? "DEMO DATA — synthetic scenarios" : "Real uploaded security data"}</div></div>
      <div class="dash-status" id="dashStatus">
        <span class="dot"></span><span id="dashStatusText">● LIVE</span>
        <span class="muted" id="dashUpdated">Last updated: --:--:--</span>
      </div></div>
    <div class="cards" id="kpis">
      ${kpi(d.active_incidents, "Active Incidents", `${d.by_severity.Critical} crit · ${d.by_severity.High} high`)}
      ${kpi(d.threats_detected, "Threats Detected")}
      ${kpi(d.investigations_running, "Investigations Running")}
      ${kpi(d.responses_executed, "Responses Executed", `${d.automated_responses} automated`)}
      ${kpi(d.human_escalations, "Human Escalations")}
      ${kpi(d.response_success_rate == null ? "—" : d.response_success_rate + "%", "Response Success Rate")}
      ${kpi(d.avg_investigation_time_s == null ? "—" : d.avg_investigation_time_s + "s", "Avg Investigation Time")}
      ${kpi(d.false_positive_rate == null ? "—" : d.false_positive_rate + "%", "Est. False Positive Rate")}
    </div>
    <div class="chart-grid" style="margin-top:16px">
      <div class="panel"><h2>Threats over time</h2><div class="chart-box"><canvas id="ch_time"></canvas></div></div>
      <div class="panel"><h2>Incidents by severity</h2><div class="chart-box"><canvas id="ch_sev"></canvas></div></div>
      <div class="panel"><h2>Attack techniques (MITRE)</h2><div class="chart-box"><canvas id="ch_tech"></canvas></div></div>
      <div class="panel"><h2>Response outcomes</h2><div class="chart-box"><canvas id="ch_out"></canvas></div></div>
      <div class="panel"><h2>Risk distribution</h2><div class="chart-box"><canvas id="ch_risk"></canvas></div></div>
      <div class="panel"><h2>Detection method</h2><div class="chart-box"><canvas id="ch_method"></canvas></div></div>
    </div>`;
  drawDashboardCharts(c.charts);
  state.dashLastData = { summary: d, charts: c.charts };
  setDashStatus("live");
  startDashboardUpdates();   // begin auto-refresh while this page is mounted
}

// ---------- dashboard auto-refresh (single lifecycle-managed poller) ----------
function startDashboardUpdates() {
  stopDashboardUpdates();    // idempotent: never stack timers
  state.dashTimer = setInterval(refreshDashboard, DASHBOARD_POLL_MS);
}
function stopDashboardUpdates() {
  if (state.dashTimer) { clearInterval(state.dashTimer); state.dashTimer = null; }
}
async function refreshDashboard() {
  if (state.route !== "dashboard") { stopDashboardUpdates(); return; }
  try {
    // ONE analytics request returns KPIs + all charts; demo state for the pill.
    const c = await api(`/api/analytics?dataset=${ds()}`);
    let demoStatus = null;
    if (ds() === "demo") {
      try { demoStatus = (await api("/api/demo/state")).status; } catch (e) {}
    }
    if (state.route !== "dashboard") return;   // navigated away mid-request
    updateDashboardLive(c.summary);
    drawDashboardCharts(c.charts);
    state.dashLastData = { summary: c.summary, charts: c.charts };
    setDashStatus(ds() === "demo" ? (demoStatus || "stopped") : "live");
  } catch (e) {
    // Retain last valid data; surface the failure; keep retrying on the timer.
    setDashStatus("lost");
  }
}
function setDashStatus(kind) {
  const el = $("#dashStatusText"), up = $("#dashUpdated"), box = $("#dashStatus");
  if (!el || !box) return;
  const map = {
    live: ["LIVE", "ok"], running: ["LIVE", "ok"],
    paused: ["PAUSED", "warn"], stopped: ["STOPPED", "muted-dot"],
    lost: ["CONNECTION LOST — retrying…", "err"],
  };
  const [text, cls] = map[kind] || map.live;
  el.textContent = text;
  box.className = "dash-status " + cls;
  if (kind !== "lost") up.textContent = "Last updated: " + new Date().toLocaleTimeString();
}
function updateDashboardLive(d) {
  const box = $("#kpis"); if (!box || !d) return;
  box.innerHTML =
    kpi(d.active_incidents, "Active Incidents", `${d.by_severity.Critical} crit · ${d.by_severity.High} high`) +
    kpi(d.threats_detected, "Threats Detected") +
    kpi(d.investigations_running, "Investigations Running") +
    kpi(d.responses_executed, "Responses Executed", `${d.automated_responses} automated`) +
    kpi(d.human_escalations, "Human Escalations") +
    kpi(d.response_success_rate == null ? "—" : d.response_success_rate + "%", "Response Success Rate") +
    kpi(d.avg_investigation_time_s == null ? "—" : d.avg_investigation_time_s + "s", "Avg Investigation Time") +
    kpi(d.false_positive_rate == null ? "—" : d.false_positive_rate + "%", "Est. False Positive Rate");
}

const SEV_COLORS = { Critical: "#ff4d5e", High: "#ff8a3d", Medium: "#ffd24d", Low: "#56c0ff" };
function hasChart() { return typeof Chart !== "undefined"; }
function mkChart(id, cfg) {
  if (!hasChart()) { const c = $("#" + id); if (c) c.parentElement.innerHTML = "<p class='muted'>Chart library unavailable (offline). Data via API.</p>"; return; }
  const ctx = $("#" + id); if (!ctx) return;
  Chart.defaults.color = "#93a1c0"; Chart.defaults.borderColor = "#263355";
  const existing = state.charts[id];
  // Update in place when the same canvas is still on screen (polling refresh):
  // mutate data and call update() — no new DOM, no memory leak, no flicker.
  if (existing && existing.canvas && existing.canvas.isConnected
      && existing.config.type === cfg.type) {
    existing.data.labels = cfg.data.labels;
    existing.data.datasets = cfg.data.datasets;
    existing.update("none");   // 'none' = no re-animation
    return;
  }
  if (existing) existing.destroy();   // canvas was replaced (navigation) -> rebuild
  state.charts[id] = new Chart(ctx, cfg);
}
function drawDashboardCharts(ch) {
  mkChart("ch_time", { type: "line", data: { labels: ch.threats_over_time.map(x => x.t.replace("T", " ")), datasets: [{ label: "Incidents", data: ch.threats_over_time.map(x => x.count), borderColor: "#4f8cff", backgroundColor: "rgba(79,140,255,.2)", fill: true, tension: .3 }] }, options: chOpts() });
  const sev = ch.by_severity;
  mkChart("ch_sev", { type: "doughnut", data: { labels: Object.keys(sev), datasets: [{ data: Object.values(sev), backgroundColor: Object.keys(sev).map(k => SEV_COLORS[k] || "#888") }] }, options: chOpts(true) });
  mkChart("ch_tech", { type: "bar", data: { labels: Object.keys(ch.attack_techniques), datasets: [{ label: "Count", data: Object.values(ch.attack_techniques), backgroundColor: "#7b61ff" }] }, options: { ...chOpts(), indexAxis: "y" } });
  mkChart("ch_out", { type: "pie", data: { labels: Object.keys(ch.response_outcomes), datasets: [{ data: Object.values(ch.response_outcomes), backgroundColor: ["#2ecc71", "#ff8a3d", "#ff4d5e", "#56c0ff"] }] }, options: chOpts(true) });
  mkChart("ch_risk", { type: "bar", data: { labels: Object.keys(ch.risk_distribution), datasets: [{ label: "Incidents", data: Object.values(ch.risk_distribution), backgroundColor: "#4f8cff" }] }, options: chOpts() });
  const dm = ch.detection_methods || {};
  mkChart("ch_method", { type: "doughnut", data: { labels: Object.keys(dm), datasets: [{ data: Object.values(dm), backgroundColor: ["#4f8cff", "#ff8a3d", "#2ecc71"] }] }, options: chOpts(true) });
}
function chOpts(legend = false) { return { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: legend, position: "bottom" } }, scales: legend ? {} : { x: { grid: { color: "#1c2748" } }, y: { grid: { color: "#1c2748" }, beginAtZero: true } } }; }

// ==================================================================
// INCIDENT CENTER
// ==================================================================
async function renderIncidents(view) {
  const { incidents } = await api(`/api/incidents?dataset=${ds()}`);
  const attackTypes = [...new Set(incidents.map(i => i.attack_type))];
  view.innerHTML = `
    <div class="page-head"><h1>Incident Center</h1>
      <a class="btn secondary" href="/api/export/incidents.csv?dataset=${ds()}">⬇ Export CSV</a></div>
    <div class="filters">
      <select id="f_sev"><option value="">All severity</option>${["Critical", "High", "Medium", "Low"].map(s => `<option>${s}</option>`).join("")}</select>
      <select id="f_status"><option value="">All status</option>${["New", "Investigating", "Awaiting Approval", "Contained", "Closed"].map(s => `<option>${s}</option>`).join("")}</select>
      <select id="f_attack"><option value="">All threats</option>${attackTypes.map(s => `<option>${s}</option>`).join("")}</select>
      <input id="f_host" placeholder="host…"><input id="f_user" placeholder="user…">
      <input id="f_risk" type="number" min="0" max="100" placeholder="min risk">
      <button class="btn" id="applyF">Filter</button>
    </div>
    <div class="table-wrap"><table><thead><tr>
      <th>Incident</th><th>Time</th><th>Threat</th><th>Source</th><th>Target</th>
      <th>Sev</th><th>Risk</th><th>Conf</th><th>Status</th><th>Recommended</th>
    </tr></thead><tbody id="incBody"></tbody></table></div>`;
  const rows = () => {
    const sev = $("#f_sev").value, st = $("#f_status").value, at = $("#f_attack").value;
    const host = $("#f_host").value.toLowerCase(), user = $("#f_user").value.toLowerCase();
    const minr = parseFloat($("#f_risk").value || "0") / 100;
    const filtered = incidents.filter(i =>
      (!sev || i.severity === sev) && (!st || i.status === st) && (!at || i.attack_type === at) &&
      (!host || (i.affected_hosts || []).join(",").toLowerCase().includes(host)) &&
      (!user || (i.affected_users || []).join(",").toLowerCase().includes(user)) &&
      ((i.risk_score || 0) >= minr));
    $("#incBody").innerHTML = filtered.length ? filtered.map(i => `
      <tr class="clickable" onclick="location.hash='#/incident/${i.incident_id}'">
        <td class="mono">${esc(i.incident_id)}</td>
        <td class="muted">${esc((i.created_at || "").replace("T", " ").slice(0, 19))}</td>
        <td>${esc(i.attack_type)}</td>
        <td class="mono">${esc((i.source_ips || []).join(", ") || "—")}</td>
        <td class="mono">${esc((i.affected_hosts || []).join(", ") || (i.affected_users || []).join(", ") || "—")}</td>
        <td>${sevPill(i.severity)}</td>
        <td><b>${pct(i.risk_score)}</b></td>
        <td>${pct(i.confidence)}%</td>
        <td><span class="pill status-pill">${esc(i.status)}</span></td>
        <td class="muted">${esc(i.recommended_action || "—")}</td>
      </tr>`).join("") : `<tr><td colspan="10" class="muted" style="padding:24px;text-align:center">No incidents. Upload data & run detection, or start Demo Mode.</td></tr>`;
  };
  $("#applyF").addEventListener("click", rows);
  rows();
}

// ==================================================================
// INVESTIGATION (per incident)
// ==================================================================
async function renderInvestigation(view, incId) {
  if (!incId) { view.innerHTML = `<div class="panel">No incident selected.</div>`; return; }
  let inc = await api(`/api/incidents/${incId}`);
  let analysis = null;
  try { analysis = await api(`/api/incidents/${incId}/analysis`); } catch (e) {}
  const timeline = (await api(`/api/incidents/${incId}/timeline`)).timeline;

  const riskTotal = analysis ? analysis.risk.total : pct(inc.risk_score);
  view.innerHTML = `
    <div class="page-head">
      <div><a class="muted" href="#/incidents">← Incident Center</a>
        <h1>${esc(inc.incident_id)} · ${esc(inc.attack_type)}</h1></div>
      <div class="btnrow">
        <button class="btn" id="btnInvestigate">${analysis ? "Re-run" : "Run"} Investigation</button>
        <a class="btn secondary" href="/api/export/incident/${incId}.md">⬇ Report (MD)</a>
        <a class="btn ghost" href="/api/export/incident/${incId}.json">⬇ JSON</a>
      </div>
    </div>
    <div class="inv-grid">
      <div>
        <div class="panel">
          <h2>Incident Summary</h2>
          <div>Risk <b>${riskTotal}/100</b> · Confidence <b>${pct(inc.confidence)}%</b></div>
          <div class="risk-bar"><span style="width:${riskTotal}%"></span></div>
          <div>Severity ${sevPill(inc.severity)} · Status <span class="pill status-pill">${esc(inc.status)}</span></div>
          <div class="muted" style="margin:8px 0">Stage: ${esc(inc.stage)}</div>
          <div><b>Consensus:</b> ${pct(inc.consensus)}%</div>
          <div style="margin-top:8px"><b>Autonomy:</b> ${esc(inc.autonomy_decision || "—")}</div>
          <hr style="border-color:var(--border)">
          <div class="muted">Detection reason</div>
          <div style="font-size:12px">${esc((inc.detection_reason || "").replace(/\[[^\]]+\]$/, ""))}</div>
          <div style="margin-top:10px"><b>Source IPs</b><br>${(inc.source_ips || []).map(x => `<span class="tag mono">${esc(x)}</span>`).join("") || "—"}</div>
          <div style="margin-top:6px"><b>Hosts</b><br>${(inc.affected_hosts || []).map(x => `<span class="tag">${esc(x)}</span>`).join("") || "—"}</div>
          <div style="margin-top:6px"><b>Users</b><br>${(inc.affected_users || []).map(x => `<span class="tag">${esc(x)}</span>`).join("") || "—"}</div>
          <div style="margin-top:10px"><b>MITRE ATT&CK</b><br>${(inc.mitre || []).map(t => `<span class="tag" title="${esc(t.evidence || "")}">${esc(t.id)} ${esc(t.name)}</span>`).join("") || "—"}</div>
        </div>
        <div class="panel" style="margin-top:16px"><h2>Evidence Graph</h2>
          <div class="graph-wrap"><svg id="graph" width="100%" height="280"></svg></div>
          <div class="muted" style="font-size:11px;margin-top:6px">Click a node to inspect its events.</div>
        </div>
      </div>
      <div>
        <div class="panel"><h2>Attack Chain</h2>
          ${analysis && analysis.attack_chain && analysis.attack_chain.length
        ? `<div class="chain">${analysis.attack_chain.map((c, i) => `
              <div class="chain-node" data-refs='${JSON.stringify(c.event_ids || [])}'>
                <span class="chain-label">${esc(c.label)}</span>
                <span class="tag">${c.count} event(s)</span></div>
              ${i < analysis.attack_chain.length - 1 ? '<div class="chain-arrow">↓</div>' : ""}`).join("")}</div>
            <div class="muted" style="font-size:11px;margin-top:6px">Only stages supported by the evidence are shown. Click a stage to inspect events.</div>`
        : "<div class='muted'>Run investigation to build the attack chain.</div>"}
        </div>
        <div class="panel" style="margin-top:16px"><h2>Evidence Timeline</h2>
          <div class="timeline">${timeline.length ? timeline.map(t => `
            <div class="tl-item">
              <div class="tl-time">${esc((t.timestamp || "").replace("T", " ").slice(0, 19))}</div>
              <div><div class="tl-label">${esc(t.label)}</div>
                <div class="tl-detail">user=${esc(t.user || "—")} host=${esc(t.host || "—")} src=${esc(t.source_ip || "—")} ${t.port ? "port=" + esc(t.port) : ""} ${t.command ? "· " + esc(t.command) : ""}</div></div>
            </div>`).join("") : "<div class='muted'>No timeline events.</div>"}</div>
        </div>
      </div>
      <div>
        <div class="panel" id="aiPanel"><h2>AI Assessment</h2>${analysis ? renderAI(analysis) : "<div class='muted'>Run investigation to see multi-agent analysis, risk breakdown & consensus.</div>"}</div>
      </div>
    </div>
    ${analysis && analysis.decision_explanation ? renderWhyPanel(analysis.decision_explanation) : ""}
    <div class="inv-bottom panel" id="respPanel"><h2>Recommended Response</h2>
      ${analysis ? renderResponsePlan(analysis, incId) : "<div class='muted'>Run investigation first.</div>"}</div>`;

  drawGraph(incId);
  bindChainNodes(incId);
  $("#btnInvestigate").addEventListener("click", async () => {
    $("#btnInvestigate").disabled = true; $("#btnInvestigate").textContent = "Investigating…";
    try { await api(`/api/incidents/${incId}/investigate`, { method: "POST" }); toast("Investigation complete"); renderInvestigation(view, incId); }
    catch (e) { toast(e.message, "err"); $("#btnInvestigate").disabled = false; }
  });
}

function renderAI(a) {
  const agents = a.agents.map(ag => `
    <div class="agent"><div class="a-name">${esc(ag.agent)}</div>
      <div class="a-verdict">${esc(ag.verdict)} · conf ${pct(ag.confidence)}%</div>
      <div class="a-rat">${esc(ag.rationale)}</div></div>`).join("");
  const rb = a.risk.breakdown;
  const risk = Object.keys(rb).map(k => `<div class="riskcomp"><span>${esc(k.replace(/_/g, " "))}</span><b>${rb[k].score}/${rb[k].max}</b></div>`).join("");
  return `
    <div style="margin-bottom:10px"><b>Agent consensus:</b> ${pct(a.consensus.score)}%
      (agreement ${pct(a.consensus.agreement)}%) ${a.consensus.disagreement ? "<span class='pill sev-high'>DISAGREEMENT</span>" : ""}</div>
    ${agents}
    <h2 style="margin-top:14px">Risk Breakdown</h2>${risk}
    <div class="riskcomp" style="border:0"><span><b>Total</b></span><b>${a.risk.total}/100</b></div>
    ${a.memory && a.memory.recommendation ? `<div class="agent" style="border-color:var(--accent2)"><div class="a-name">Historical Memory</div><div class="a-rat">Previously '${esc(a.memory.recommendation.strategy)}' was ${Math.round(a.memory.recommendation.effectiveness * 100)}% effective (learned confidence ${a.memory.recommendation.confidence}).</div></div>` : ""}`;
}

function renderWhyPanel(d) {
  const f = d.factors;
  const item = (lbl, val, cls = "") => `<div class="why-item"><div class="muted">${lbl}</div><div class="why-val ${cls}">${esc(val)}</div></div>`;
  return `<div class="inv-bottom panel" style="border-color:var(--accent2)">
    <h2>🧭 Why this decision?</h2>
    <div class="why-grid">
      ${item("Risk", f.risk)}
      ${item("Evidence confidence", f.evidence_confidence)}
      ${item("Agent agreement", f.agent_agreement)}
      ${item("Historical success", f.historical_success)}
      ${item("Memory trust", f.memory_trust)}
      ${item("Response risk", f.response_risk)}
      ${item("Rollback", f.rollback)}
      ${item("Autonomy level", f.autonomy_level)}
      ${item("Human approval", f.human_approval_required ? "REQUIRED" : "not required", f.human_approval_required ? "fail" : "pass")}
      ${item("Validation", f.validation_decision, f.validation_decision === "APPROVED" ? "pass" : f.validation_decision === "REJECTED" ? "fail" : "")}
    </div>
    <div style="margin-top:12px"><b>Decision:</b> Recommend <b>${esc(d.recommended_action)}</b> → <span class="mono">${esc(d.target)}</span>
      ${d.recommendation_confidence != null ? `<span class="tag">recommendation confidence ${Math.round(d.recommendation_confidence * 100)}%</span>` : ""}</div>
    <div class="muted" style="margin-top:6px">${esc(d.reason)}</div>
  </div>`;
}

function bindChainNodes(incId) {
  $$(".chain-node").forEach(node => node.addEventListener("click", () => {
    const refs = JSON.parse(node.dataset.refs || "[]");
    showEventsModal(node.querySelector(".chain-label").textContent, refs);
  }));
}

function renderResponsePlan(a, incId) {
  const v = a.validation, auto = a.autonomy;
  const decCls = v.decision === "APPROVED" ? "d-approved" : v.decision === "REJECTED" ? "d-rejected" : "d-needs";
  const checks = Object.keys(v.checks).map(k =>
    `<div><span>${esc(k.replace(/_/g, " "))}</span><span class="${v.checks[k] ? "pass" : "fail"}">${v.checks[k] ? "PASS" : "FAIL"}</span></div>`).join("");
  const scoreBar = (sc) => {
    if (!sc) return "";
    const c = sc.components;
    const row = (lbl, v) => `<div class="riskcomp" style="padding:2px 0"><span>${lbl}</span><b>${Math.round(v * 100)}%</b></div>`;
    return `<div style="margin-top:8px;font-size:11px">
      ${row("Historical success", c.historical_success)}
      ${row("Memory trust", c.memory_trust)}
      ${row("Current confidence", c.current_confidence)}
      ${row("Agent agreement", c.agent_agreement)}
      ${row("Response-risk score", c.response_risk)}
      ${row("Rollback", c.rollback)}
      <div class="riskcomp" style="border:0;padding:3px 0"><span><b>Recommendation confidence</b></span><b>${Math.round(sc.recommendation_confidence * 100)}%</b></div>
    </div>`;
  };
  const plans = a.plans.map(p => `
    <div class="card" style="margin-bottom:10px;${p.recommended ? "border-color:var(--accent)" : ""}">
      <div style="display:flex;justify-content:space-between">
        <b>${esc(p.action)} → <span class="mono">${esc(p.target)}</span></b>
        ${p.recommended ? "<span class='pill sev-low'>RECOMMENDED</span>" : ""}</div>
      <div class="muted" style="font-size:12px;margin-top:4px">${esc(p.reason)}</div>
      <div style="font-size:12px;margin-top:6px">Response risk: <b>${esc(p.response_risk)}</b> · Expected: ${esc(p.expected_outcome)}</div>
      <div class="muted" style="font-size:12px">Rollback: ${esc(p.rollback)} · Evidence: ${esc(p.evidence_summary)}</div>
      ${scoreBar(p.score)}
    </div>`).join("");
  return `
    <div class="row" style="align-items:stretch">
      <div style="flex:2;min-width:320px">${plans}</div>
      <div style="flex:1;min-width:260px">
        <div class="decision-box ${decCls}">${esc(v.decision)}</div>
        <div class="checklist" style="margin-top:10px">${checks}</div>
        <div style="margin-top:10px" class="panel">
          <b>Autonomy:</b> ${esc(auto.outcome)}<br>
          <span class="muted" style="font-size:12px">Level ${auto.level}: ${esc(auto.level_name)}<br>${auto.reasons.map(esc).join("; ")}</span>
        </div>
        <div class="btnrow" style="margin-top:12px" id="respActions" data-rid="${esc(a.recommended_response_id || "")}">
          <button class="btn secondary" id="btnValidate">Validate Response</button>
          <button class="btn warn" id="btnApprove" ${v.decision === "REJECTED" ? "disabled" : ""}>Request Human Approval</button>
          <button class="btn" id="btnSimulate" ${v.decision === "REJECTED" ? "disabled" : ""}>Simulate Response</button>
        </div>
        <div class="muted" style="font-size:11px;margin-top:6px">Responses run in SIMULATION only — no real systems are touched.</div>
        <div id="verifyOut" style="margin-top:10px"></div>
      </div>
    </div>`;
}

// response action buttons (delegated after render)
document.addEventListener("click", async e => {
  const rid = () => { const box = $("#respActions"); return box ? box.dataset.rid : null; };
  if (e.target.id === "btnValidate") {
    try { const v = await api(`/api/responses/${rid()}/validate`, { method: "POST" }); toast("Validation: " + v.decision); }
    catch (err) { toast(err.message, "err"); }
  }
  if (e.target.id === "btnApprove") {
    try { await api(`/api/responses/${rid()}/approve`, { method: "POST", body: JSON.stringify({ analyst: "analyst" }) }); toast("Human approval recorded"); }
    catch (err) { toast(err.message, "err"); }
  }
  if (e.target.id === "btnSimulate") {
    try {
      const r = await api(`/api/responses/${rid()}/simulate`, { method: "POST", body: JSON.stringify({}) });
      const v = r.verification;
      const ok = v.verification_status === "VERIFIED_RESOLVED";
      const indRows = Object.keys(v.indicators_before || {}).map(k =>
        `<div class="riskcomp" style="padding:2px 0"><span>${esc(k.replace(/_/g, " "))}</span><b>${v.indicators_before[k]} → ${(v.indicators_after || {})[k] ?? 0}</b></div>`).join("");
      $("#verifyOut").innerHTML = `<div class="panel">
        <span class="pill badge-ok" style="background:rgba(46,204,113,.15)">${esc(r.simulation.message)}</span>
        <div style="margin-top:8px">Verification: <b class="${ok ? "pass" : "fail"}">${esc(v.verification_status)}</b>
          ${v.persistence_detected ? "<span class='pill sev-high'>THREAT PERSISTS</span>" : ""}</div>
        <div class="muted" style="font-size:12px;margin-top:4px">Method: ${esc(v.verification_method)}</div>
        <div style="margin-top:8px"><b>Indicators (before → after)</b>${indRows}</div>
        <div class="muted" style="font-size:12px;margin-top:6px">Verification confidence ${Math.round(v.verification_confidence * 100)}% · effectiveness ${Math.round(v.effectiveness * 100)}% · original evidence unchanged.</div>
      </div>`;
      toast("Simulated response: " + v.verification_status);
    } catch (err) {
      if (err.message.toLowerCase().includes("approval")) toast("Human approval required first — click Request Human Approval.", "err");
      else toast(err.message, "err");
    }
  }
});

// ---------- evidence graph (lightweight SVG) ----------
async function drawGraph(incId) {
  const svg = $("#graph"); if (!svg) return;
  let g; try { g = await api(`/api/incidents/${incId}/graph`); } catch (e) { return; }
  const W = svg.clientWidth || 300, H = 280, cx = W / 2, cy = H / 2;
  const nodes = g.nodes; const R = Math.min(W, H) / 2 - 40;
  const typeColor = { ip: "#ff8a3d", user: "#4f8cff", host: "#7b61ff", dest: "#ff4d5e", process: "#2ecc71", event: "#93a1c0" };
  const pos = {};
  nodes.forEach((n, i) => { const ang = (2 * Math.PI * i) / Math.max(nodes.length, 1); pos[n.id] = { x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang) }; });
  let svgHtml = "";
  g.edges.forEach(ed => { const a = pos[ed.source], b = pos[ed.target]; if (a && b) svgHtml += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#263355" stroke-width="1.5"/>`; });
  nodes.forEach(n => { const p = pos[n.id]; svgHtml += `<g class="graph-node" data-refs='${JSON.stringify(n.event_refs || [])}' data-label="${esc(n.label)}">
      <circle cx="${p.x}" cy="${p.y}" r="10" fill="${typeColor[n.type] || "#888"}"/>
      <text class="node-label" x="${p.x + 12}" y="${p.y + 4}">${esc(n.label)}</text></g>`; });
  svg.innerHTML = svgHtml;
  $$(".graph-node", svg).forEach(node => node.addEventListener("click", () =>
    showEventsModal(node.dataset.label, JSON.parse(node.dataset.refs || "[]"))));
}

async function showEventsModal(label, refs) {
  if (!refs || !refs.length) {
    modal(`<h2>${esc(label)}</h2><p class="muted">No underlying events.</p><button class="btn" onclick="closeModal()">Close</button>`);
    return;
  }
  const { events } = await api(`/api/events?dataset=${ds()}&limit=1000`);
  const matched = events.filter(ev => refs.includes(ev.id));
  modal(`<h2>${esc(label)} — ${matched.length} event(s)</h2>
    <div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>User</th><th>Host</th><th>Src IP</th><th>Detail</th></tr></thead>
    <tbody>${matched.map(ev => `<tr><td class="muted">${esc((ev.timestamp || "").slice(0, 19))}</td><td>${esc(ev.event_type)}</td><td>${esc(ev.user || "")}</td><td>${esc(ev.host || "")}</td><td class="mono">${esc(ev.source_ip || "")}</td><td class="mono" style="max-width:260px">${esc((ev.raw_event || "").slice(0, 120))}</td></tr>`).join("")}</tbody></table></div>
    <button class="btn" style="margin-top:12px" onclick="closeModal()">Close</button>`);
}
window.closeModal = closeModal;

// ==================================================================
// RESPONSE CENTER
// ==================================================================
async function renderResponses(view) {
  const { buckets } = await api(`/api/responses?dataset=${ds()}`);
  const section = (title, arr, cls = "") => `
    <div class="panel" style="margin-bottom:16px"><h2>${title} <span class="muted">(${arr.length})</span></h2>
    ${arr.length ? `<div class="table-wrap"><table><thead><tr><th>Action</th><th>Target</th><th>Incident</th><th>Threat</th><th>Reason</th><th>Risk</th><th>Rollback</th><th></th></tr></thead>
      <tbody>${arr.map(r => `<tr><td><b>${esc(r.action)}</b></td><td class="mono">${esc(r.target)}</td>
        <td class="mono clickable" onclick="location.hash='#/incident/${r.incident_id}'">${esc(r.incident_id)}</td>
        <td>${esc(r.attack_type)}</td><td class="muted" style="max-width:220px">${esc(r.reason)}</td>
        <td>${esc(r.response_risk)}</td><td class="muted">${esc(r.rollback)}</td>
        <td><button class="btn ghost" onclick="location.hash='#/incident/${r.incident_id}'">Open</button></td></tr>`).join("")}</tbody></table></div>` : "<div class='muted'>None.</div>"}</div>`;
  view.innerHTML = `<div class="page-head"><h1>Response Center</h1></div>
    ${section("⏳ Human Approval Required", buckets.awaiting_approval || [])}
    ${section("📋 Pending / Validated", buckets.pending || [])}
    ${section("✅ Approved", buckets.approved || [])}
    ${section("⚡ Executed (Simulated)", buckets.executed || [])}
    ${section("🚫 Rejected by Validation", buckets.rejected || [])}
    ${section("❌ Failed", buckets.failed || [])}`;
}

// ==================================================================
// REAL DATA
// ==================================================================
async function renderRealData(view) {
  const { total, events } = await api(`/api/events?dataset=real&limit=500`);
  view.innerHTML = `
    <div class="page-head"><h1>Analyze Real Data</h1>
      <div class="muted">Upload a security-event CSV / JSON / syslog. Data stays in the REAL dataset (never mixed with demo).</div></div>
    <div class="row">
      <div class="panel" style="flex:2;min-width:340px">
        <div class="dropzone" id="drop">📥 Drag & drop a file here, or click to choose<br>
          <span class="muted">.csv · .json / .ndjson · .log/.syslog (max 500 MB)</span>
          <input type="file" id="fileInput" class="hidden" accept=".csv,.json,.ndjson,.log,.syslog,.txt">
        </div>
        <div class="btnrow" style="margin-top:12px">
          <button class="btn secondary" id="loadSample">Load bundled sample CSV</button>
          <button class="btn" id="runDetect" ${total ? "" : "disabled"}>Run Detection (${total} events)</button>
        </div>
        <div id="uploadSummary" style="margin-top:14px"></div>
      </div>
      <div class="panel" style="flex:1;min-width:280px"><h2>Workflow</h2>
        <ol class="muted" style="line-height:1.9">
          <li>Upload security log</li><li>Preview & normalize</li><li>Run detection</li>
          <li>Incidents created</li><li>Investigate (multi-agent)</li>
          <li>Risk · consensus · response</li><li>Validate · approve · simulate</li>
          <li>Verify · learn · analytics</li></ol>
      </div>
    </div>
    <div class="panel" style="margin-top:16px"><h2>Event Preview <span class="muted">(latest ${events.length} of ${total})</span></h2>
      <div class="table-wrap" style="max-height:340px">${eventsTable(events)}</div></div>`;

  const fileInput = $("#fileInput"), drop = $("#drop");
  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", e => { e.preventDefault(); drop.classList.remove("drag"); if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]); });
  fileInput.addEventListener("change", () => { if (fileInput.files[0]) uploadFile(fileInput.files[0]); });
  $("#loadSample").addEventListener("click", loadSample);
  $("#runDetect").addEventListener("click", runDetection);
}
function eventsTable(events) {
  if (!events.length) return "<div class='muted' style='padding:16px'>No events yet.</div>";
  return `<table><thead><tr><th>Time</th><th>Type</th><th>User</th><th>Host</th><th>Src IP</th><th>Dst IP</th><th>Port</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>${events.map(e => `<tr><td class="muted">${esc((e.timestamp || "").replace("T", " ").slice(0, 19))}</td>
      <td>${esc(e.event_type || "")}</td><td>${esc(e.user || "")}</td><td>${esc(e.host || "")}</td>
      <td class="mono">${esc(e.source_ip || "")}</td><td class="mono">${esc(e.destination_ip || "")}</td>
      <td>${esc(e.port ?? "")}</td><td>${esc(e.status || e.authentication_result || "")}</td>
      <td class="mono" style="max-width:240px;overflow:hidden">${esc((e.raw_event || "").slice(0, 100))}</td></tr>`).join("")}</tbody>`;
}
async function uploadFile(file) {
  const fd = new FormData(); fd.append("file", file); fd.append("dataset", "real");
  try {
    const res = await fetch("/api/events/upload", { method: "POST", body: fd });
    if (!res.ok) { const j = await res.json(); throw new Error(j.detail || "upload failed"); }
    const s = await res.json(); showUploadSummary(s); toast(`Ingested ${s.stored} events`); renderRealData($("#view"));
  } catch (e) { toast(e.message, "err"); }
}
function showUploadSummary(s) {
  const el = $("#uploadSummary"); if (!el) return;
  const tr = s.time_range ? `${s.time_range.start} → ${s.time_range.end}` : "—";
  el.innerHTML = `<div class="stat-inline">
    <div class="s"><b>${s.count}</b><div class="muted">events</div></div>
    <div class="s"><b>${s.unique_users}</b><div class="muted">users</div></div>
    <div class="s"><b>${s.unique_hosts}</b><div class="muted">hosts</div></div>
    <div class="s"><b>${s.source_ips}</b><div class="muted">src IPs</div></div>
    <div class="s"><b>${s.destination_ips}</b><div class="muted">dst IPs</div></div>
    <div class="s"><b>${s.failed_logins}</b><div class="muted">failed logins</div></div>
    <div class="s"><b>${s.suspicious_events}</b><div class="muted">suspicious</div></div>
    <div class="s"><b>${s.injection_flags}</b><div class="muted">injection flags</div></div>
  </div><div class="muted" style="margin-top:8px">Format: ${esc(s.format)} · time range: ${esc(tr)} · types: ${esc(Object.keys(s.event_types || {}).join(", "))}</div>
  ${dataQualityHtml(s.data_quality)}`;
}
function dataQualityHtml(q) {
  if (!q) return "";
  const fieldMap = Object.entries(q.normalized_fields || {})
    .map(([raw, canon]) => `<span class="tag mono">${esc(raw)} → ${esc(canon)}</span>`).join(" ");
  const unmapped = (q.unmapped_fields || []).map(f => `<span class="tag">${esc(f)}</span>`).join(" ");
  return `<div class="panel" style="margin-top:14px">
    <h2>Data-Quality Report</h2>
    <div class="stat-inline">
      <div class="s"><b>${q.total_records}</b><div class="muted">records</div></div>
      <div class="s"><b class="pass">${q.valid_records}</b><div class="muted">valid</div></div>
      <div class="s"><b class="${q.rejected_records ? "fail" : ""}">${q.rejected_records}</b><div class="muted">rejected</div></div>
      <div class="s"><b>${q.duplicate_records}</b><div class="muted">duplicates</div></div>
      <div class="s"><b>${q.missing_timestamps}</b><div class="muted">missing ts</div></div>
      <div class="s"><b>${q.missing_ip_addresses}</b><div class="muted">missing IP</div></div>
      <div class="s"><b>${q.missing_users}</b><div class="muted">missing user</div></div>
    </div>
    <div style="margin-top:10px"><b>Field normalization</b><br>${fieldMap || "<span class='muted'>none</span>"}</div>
    ${unmapped ? `<div style="margin-top:6px"><b>Unmapped (kept in raw_event)</b><br>${unmapped}</div>` : ""}
  </div>`;
}
async function loadSample() {
  try {
    const s = await api("/api/samples/load", { method: "POST", body: JSON.stringify({ name: "sample_events.csv" }) });
    showUploadSummary(s); toast(`Loaded bundled sample: ${s.stored} events`); renderRealData($("#view"));
  } catch (e) { toast("Could not load sample: " + e.message, "err"); }
}
async function runDetection() {
  try {
    const r = await api("/api/detection/run", { method: "POST", body: JSON.stringify({ dataset: "real" }) });
    toast(`Detection: ${r.detections} findings, ${r.incidents_created.length} new incidents`);
    if (r.incidents_created.length) location.hash = "#/incidents";
    else renderRealData($("#view"));
  } catch (e) { toast(e.message, "err"); }
}

// ==================================================================
// DEMO MODE
// ==================================================================
async function renderDemo(view) {
  const st = await api("/api/demo/state");
  view.innerHTML = `
    <div class="page-head"><div><h1>Demo Mode</h1>
      <div class="muted">Continuous synthetic scenarios. Clearly labelled DEMO DATA — never real.</div></div></div>
    <div class="panel">
      <div class="demo-controls">
        <button class="btn" id="dStart">▶ Start</button>
        <button class="btn secondary" id="dPause">⏸ Pause</button>
        <button class="btn secondary" id="dResume">⏵ Resume</button>
        <button class="btn warn" id="dStop">⏹ Stop</button>
        <button class="btn crit" id="dReset">↺ Reset</button>
        <span style="margin-left:auto" class="pill status-pill" id="dStatus">status: ${esc(st.status)}</span>
      </div>
      <div class="stat-inline" style="margin-top:14px" id="dStats">
        <div class="s"><b id="dEv">${st.events_generated || 0}</b><div class="muted">events generated</div></div>
        <div class="s"><b id="dInc">${st.incidents_generated || 0}</b><div class="muted">incidents generated</div></div>
      </div>
    </div>
    <div class="panel" style="margin-top:16px"><h2>Scenarios generated</h2>
      <div>${["Brute Force", "Credential Compromise", "Port Scan", "Malware Execution", "Data Exfiltration", "Lateral Movement"].map(s => `<span class="scenario-chip">${s}</span>`).join(" ")}</div>
      <div class="muted" style="margin-top:10px">Switch the top toggle to <b>Demo Data</b> to watch the Dashboard, Incident Center, Analytics, Response Center and Audit Log populate live.</div>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn ghost" onclick="location.hash='#/dashboard'">Open Demo Dashboard →</button>
        <button class="btn ghost" onclick="location.hash='#/incidents'">Open Demo Incidents →</button>
      </div>
    </div>`;
  const call = async (p, msg) => { try { const s = await api(`/api/demo/${p}`, { method: "POST" }); toast(msg); updateDemoLive(s); if (ds() !== "demo" && p === "start") { toast("Tip: switch to Demo Data toggle to view.", "ok"); } } catch (e) { toast(e.message, "err"); } };
  $("#dStart").onclick = () => { if (ds() !== "demo") { state.dataset = "demo"; $$("#datasetToggle button").forEach(x => x.classList.toggle("active", x.dataset.ds === "demo")); $("#dsIndicator").innerHTML = "Dataset: <b>DEMO</b>"; $("#demoBanner").classList.remove("hidden"); startStream(); } call("start", "Demo started"); };
  $("#dPause").onclick = () => call("pause", "Demo paused");
  $("#dResume").onclick = () => call("resume", "Demo resumed");
  $("#dStop").onclick = () => call("stop", "Demo stopped");
  $("#dReset").onclick = () => call("reset", "Demo data reset");
}
function updateDemoLive(st) {
  if (!st) return;
  const s = $("#dStatus"); if (s) s.textContent = "status: " + st.status;
  const ev = $("#dEv"), inc = $("#dInc");
  if (ev) ev.textContent = st.events_generated || 0;
  if (inc) inc.textContent = st.incidents_generated || 0;
}

// ==================================================================
// ANALYTICS
// ==================================================================
async function renderAnalytics(view) {
  const { summary, charts } = await api(`/api/analytics?dataset=${ds()}`);
  view.innerHTML = `
    <div class="page-head"><h1>Analytics</h1><div class="muted">${ds().toUpperCase()} dataset</div></div>
    <div class="cards">
      ${kpi(summary.threats_detected, "Total Incidents")}
      ${kpi(summary.responses_executed, "Responses (Simulated)")}
      ${kpi(summary.response_success_rate == null ? "—" : summary.response_success_rate + "%", "Response Success Rate")}
      ${kpi(summary.total_events, "Events Ingested")}
      ${kpi(summary.avg_risk == null ? "—" : summary.avg_risk, "Avg Risk", "estimated")}
      ${kpi(summary.avg_confidence == null ? "—" : summary.avg_confidence + "%", "Avg Confidence", "estimated")}
      ${kpi(summary.autonomous_decision_rate == null ? "—" : summary.autonomous_decision_rate + "%", "Autonomous Decision Rate")}
      ${kpi(summary.human_escalation_rate == null ? "—" : summary.human_escalation_rate + "%", "Human Escalation Rate")}
      ${kpi(summary.memory_reuse_rate == null ? "—" : summary.memory_reuse_rate + "%", "Memory Reuse Rate", "estimated")}
    </div>
    <div class="muted" style="margin:10px 0;font-size:12px">
      <span class="pill sev-low">Measured</span> from actual records ·
      <span class="pill sev-medium">Estimated</span> heuristic proxy ·
      <span class="pill sev-high">Simulated</span> responses run in simulation only (no real systems touched).
    </div>
    <div class="chart-grid" style="margin-bottom:16px">
      <div class="panel"><h2>Detection method distribution</h2><div class="chart-box"><canvas id="a_method"></canvas></div></div>
    </div>
    <div class="chart-grid" style="margin-top:16px">
      <div class="panel"><h2>Detection trend</h2><div class="chart-box"><canvas id="a_time"></canvas></div></div>
      <div class="panel"><h2>Attack type distribution</h2><div class="chart-box"><canvas id="a_attack"></canvas></div></div>
      <div class="panel"><h2>MITRE techniques</h2><div class="chart-box"><canvas id="a_tech"></canvas></div></div>
      <div class="panel"><h2>Risk distribution</h2><div class="chart-box"><canvas id="a_risk"></canvas></div></div>
      <div class="panel"><h2>Response outcomes</h2><div class="chart-box"><canvas id="a_out"></canvas></div></div>
      <div class="panel"><h2>Top source IPs</h2><div class="chart-box"><canvas id="a_ip"></canvas></div></div>
      <div class="panel"><h2>Top targeted hosts</h2><div class="chart-box"><canvas id="a_host"></canvas></div></div>
      <div class="panel"><h2>User risk</h2><div class="chart-box"><canvas id="a_user"></canvas></div></div>
    </div>`;
  mkChart("a_time", { type: "line", data: { labels: charts.threats_over_time.map(x => x.t.replace("T", " ")), datasets: [{ label: "Incidents", data: charts.threats_over_time.map(x => x.count), borderColor: "#4f8cff", backgroundColor: "rgba(79,140,255,.2)", fill: true, tension: .3 }] }, options: chOpts() });
  mkChart("a_attack", { type: "bar", data: { labels: Object.keys(charts.by_attack_type), datasets: [{ label: "Count", data: Object.values(charts.by_attack_type), backgroundColor: "#7b61ff" }] }, options: { ...chOpts(), indexAxis: "y" } });
  mkChart("a_tech", { type: "bar", data: { labels: Object.keys(charts.attack_techniques), datasets: [{ label: "Count", data: Object.values(charts.attack_techniques), backgroundColor: "#4f8cff" }] }, options: { ...chOpts(), indexAxis: "y" } });
  mkChart("a_risk", { type: "bar", data: { labels: Object.keys(charts.risk_distribution), datasets: [{ label: "Incidents", data: Object.values(charts.risk_distribution), backgroundColor: "#ff8a3d" }] }, options: chOpts() });
  mkChart("a_out", { type: "doughnut", data: { labels: Object.keys(charts.response_outcomes), datasets: [{ data: Object.values(charts.response_outcomes), backgroundColor: ["#2ecc71", "#ff8a3d", "#ff4d5e", "#56c0ff"] }] }, options: chOpts(true) });
  mkChart("a_ip", { type: "bar", data: { labels: charts.top_source_ips.map(x => x[0]), datasets: [{ label: "Incidents", data: charts.top_source_ips.map(x => x[1]), backgroundColor: "#ff4d5e" }] }, options: { ...chOpts(), indexAxis: "y" } });
  mkChart("a_host", { type: "bar", data: { labels: charts.top_hosts.map(x => x[0]), datasets: [{ label: "Incidents", data: charts.top_hosts.map(x => x[1]), backgroundColor: "#7b61ff" }] }, options: { ...chOpts(), indexAxis: "y" } });
  mkChart("a_user", { type: "bar", data: { labels: charts.user_risk.map(x => x[0]), datasets: [{ label: "Max risk", data: charts.user_risk.map(x => Math.round(x[1])), backgroundColor: "#4f8cff" }] }, options: { ...chOpts(), indexAxis: "y" } });
  const dm = charts.detection_methods || {};
  mkChart("a_method", { type: "doughnut", data: { labels: Object.keys(dm), datasets: [{ data: Object.values(dm), backgroundColor: ["#4f8cff", "#ff8a3d", "#2ecc71"] }] }, options: chOpts(true) });
}

// ==================================================================
// MEMORY
// ==================================================================
async function renderMemory(view) {
  const { experiences } = await api("/api/memory");
  let strategies = [];
  try { strategies = (await api("/api/memory/strategies")).strategies; } catch (e) {}
  const stratRows = strategies.length ? strategies.map(s => `<tr>
      <td>${esc(s.attack_type)}</td><td><b>${esc(s.strategy)}</b></td>
      <td>${s.successes}/${s.attempts}</td>
      <td>${Math.round(s.success_rate * 100)}%</td>
      <td>${s.learned_confidence.toFixed(2)}</td>
      <td><span class="pill status-pill">${esc(s.validation_status)}</span></td></tr>`).join("")
    : `<tr><td colspan="6" class="muted" style="text-align:center;padding:16px">No verified outcomes yet — simulate a response to build strategy statistics.</td></tr>`;
  view.innerHTML = `<div class="page-head"><div><h1>Incident Memory & Adaptive Learning</h1>
    <div class="muted">Adaptive learning from VALIDATED outcomes. Revoked experiences never influence recommendations.</div></div></div>
    <div class="panel" style="margin-bottom:16px"><h2>Strategy Learning <span class="muted">(measured success rate → ranks future recommendations)</span></h2>
      <div class="table-wrap"><table><thead><tr><th>Attack Type</th><th>Strategy</th><th>Success</th><th>Success Rate</th><th>Learned Confidence</th><th>Status</th></tr></thead>
      <tbody>${stratRows}</tbody></table></div></div>
    <h2>Learned Experiences</h2>
    <div class="table-wrap"><table><thead><tr><th>Experience</th><th>Attack</th><th>Strategy</th><th>Outcome</th>
      <th>Effectiveness</th><th>Confidence</th><th>Trust</th><th>Status</th><th>Source</th><th>Actions</th></tr></thead>
    <tbody>${experiences.length ? experiences.map(m => `<tr>
      <td class="mono">${esc(m.experience_id)}</td><td>${esc(m.attack_type)}</td><td>${esc(m.strategy)}</td>
      <td>${esc(m.outcome)}</td><td>${Math.round((m.effectiveness || 0) * 100)}%</td>
      <td>${(m.confidence || 0).toFixed(2)}</td><td>${(m.trust_score || 0).toFixed(2)}</td>
      <td><span class="pill status-pill">${esc(m.validation_status)}</span></td><td>${esc(m.source)}</td>
      <td class="btnrow">
        <button class="btn ghost" data-exp="${esc(m.experience_id)}" data-st="trusted">Trust</button>
        <button class="btn ghost" data-exp="${esc(m.experience_id)}" data-st="under_review">Review</button>
        <button class="btn ghost" data-exp="${esc(m.experience_id)}" data-st="revoked">Revoke</button>
      </td></tr>`).join("") : `<tr><td colspan="10" class="muted" style="text-align:center;padding:24px">No learned experiences yet. Simulate a response to teach the system.</td></tr>`}</tbody></table></div>`;
  $$("button[data-exp]").forEach(b => b.onclick = async () => {
    try { await api(`/api/memory/${b.dataset.exp}/trust`, { method: "POST", body: JSON.stringify({ status: b.dataset.st }) }); toast("Trust set to " + b.dataset.st); renderMemory(view); }
    catch (e) { toast(e.message, "err"); }
  });
}

// ==================================================================
// AUDIT LOG
// ==================================================================
async function renderAudit(view) {
  const { audit } = await api(`/api/audit?dataset=${ds()}&limit=300`);
  view.innerHTML = `<div class="page-head"><h1>Audit Log</h1>
    <a class="btn secondary" href="/api/export/audit.csv?dataset=${ds()}">⬇ Export CSV</a></div>
    <div class="muted" style="margin-bottom:8px">Append-only. ${audit.length} most recent entries (${ds().toUpperCase()}).</div>
    <div class="table-wrap" style="max-height:70vh"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Incident</th><th>Detail</th></tr></thead>
    <tbody>${audit.map(a => `<tr><td class="muted mono">${esc((a.ts || "").replace("T", " ").slice(0, 19))}</td>
      <td>${esc(a.actor)}</td><td><b>${esc(a.action)}</b></td>
      <td class="mono clickable" ${a.incident_id ? `onclick="location.hash='#/incident/${a.incident_id}'"` : ""}>${esc(a.incident_id || "")}</td>
      <td class="muted">${esc(a.detail || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

// ==================================================================
// SECURITY POSTURE ASSESSMENT
// ==================================================================
const STATUS_PILL = {
  ASSESSED: "sev-low", PARTIALLY_ASSESSED: "sev-medium", NOT_ASSESSED: "status-pill",
};
async function renderAssessment(view) {
  const data = await api(`/api/security-assessment?dataset=${ds()}`);
  const demoWarn = ds() === "demo"
    ? `<div class="demo-banner" style="margin:0 0 12px">Assessing DEMO data — this is NOT a real security posture. Switch to Real Data for a real assessment.</div>` : "";
  const runBtn = `<button class="btn" id="runAssess">Run Assessment${data.assessment ? " Again" : ""}</button>`;
  if (!data.assessment) {
    view.innerHTML = `<div class="page-head"><h1>Security Posture Assessment</h1>${runBtn}</div>
      ${demoWarn}<div class="panel"><p class="muted">${esc(data.message || "No assessment yet.")}</p>
      <p class="muted">The assessment analyses only the evidence available in the <b>${ds().toUpperCase()}</b> dataset. Missing information is reported as <b>Not Assessed</b>, never assumed secure.</p></div>`;
    $("#runAssess").onclick = () => runAssessment(view);
    return;
  }
  const a = data.assessment, cats = a.category_scores;
  const covPct = Math.round(100 * a.coverage_assessed / a.coverage_total);
  const score = a.overall_score;
  const scoreColor = score == null ? "var(--muted)" : score >= 80 ? "var(--ok)" : score >= 60 ? "var(--warn)" : "var(--crit)";
  const sevOrder = ["Critical", "High", "Medium", "Low", "Informational"];
  const bySev = {}; sevOrder.forEach(s => bySev[s] = []);
  data.findings.forEach(f => (bySev[f.severity] || (bySev[f.severity] = [])).push(f));

  view.innerHTML = `
    <div class="page-head"><div><h1>Security Posture Assessment</h1>
      <div class="muted">Data source: <b>${esc(a.data_source)}</b> · ${a.events_analyzed} events, ${a.incidents_analyzed} incidents · ${esc((a.created_at||"").replace("T"," ").slice(0,19))}</div></div>
      ${runBtn}</div>
    ${demoWarn}
    <div class="row">
      <div class="card kpi" style="min-width:220px;text-align:center">
        <div class="k-val" style="color:${scoreColor}">${score == null ? "—" : score}</div>
        <div class="k-lbl">Security Posture Score /100</div>
        <div class="k-sub">${esc(a.posture_label)}</div></div>
      <div class="card kpi" style="min-width:200px">
        <div class="k-val">${a.coverage_assessed}/${a.coverage_total}</div>
        <div class="k-lbl">Assessment Coverage (${covPct}%)</div>
        <div class="k-sub muted">Categories with evidence</div></div>
      <div class="card kpi" style="min-width:160px">
        <div class="k-val">${data.findings.length}</div><div class="k-lbl">Findings</div>
        <div class="k-sub muted">${bySev.Critical.length} crit · ${bySev.High.length} high</div></div>
    </div>
    <div class="panel" style="margin-top:16px"><h2>Category Breakdown <span class="muted">(click a category for the scoring detail)</span></h2>
      <div class="table-wrap"><table><thead><tr><th>Category</th><th>Status</th><th>Score</th><th>Checks</th><th>Findings</th><th>Confidence</th></tr></thead>
      <tbody id="catRows">${Object.values(cats).map(c => `
        <tr class="clickable" data-cat='${esc(JSON.stringify(c).replace(/'/g,"&#39;"))}'>
          <td><b>${esc(c.title)}</b></td>
          <td><span class="pill ${STATUS_PILL[c.status] || "status-pill"}">${esc(c.status.replace(/_/g," "))}</span></td>
          <td>${c.score == null ? "<span class='muted'>—</span>" : "<b>"+c.score+"</b>"}</td>
          <td class="muted">${(c.checks_performed||[]).join(", ")}</td>
          <td>${(c.findings||[]).length}</td>
          <td>${c.evidence_available ? Math.round(c.confidence*100)+"%" : "<span class='muted'>n/a</span>"}</td>
        </tr>`).join("")}</tbody></table></div></div>
    ${data.diff && data.diff.deltas ? renderAssessDiff(data.diff) : ""}
    <div class="panel" style="margin-top:16px"><h2>Findings</h2>
      ${data.findings.length ? sevOrder.filter(s => bySev[s].length).map(s => `
        <div style="margin-bottom:10px"><span class="pill sev-${s.toLowerCase()==="informational"?"low":s.toLowerCase()}">${s}</span>
        ${bySev[s].map(f => `<div class="card" style="margin-top:8px">
          <b>${esc(f.title)}</b> <span class="muted">— ${esc(f.category.replace(/_/g," "))} · conf ${Math.round(f.confidence*100)}% · asset ${esc(f.affected_asset)}</span>
          <div class="muted" style="font-size:12px;margin-top:4px">${esc(f.explanation)}</div>
          <div style="font-size:12px;margin-top:4px"><b>Evidence:</b> ${(f.evidence||[]).map(e=>`<span class="tag mono">${esc(e)}</span>`).join("") || "—"}</div>
          <div style="font-size:12px;margin-top:4px"><b>Recommendation:</b> ${esc(f.recommendation)}</div></div>`).join("")}</div>`).join("")
      : "<p class='muted'>No findings from the available evidence.</p>"}</div>
    <div class="panel" style="margin-top:16px"><h2>Recommendations</h2>
      ${data.recommendations.length ? `<div class="table-wrap"><table><thead><tr><th>Priority</th><th>Recommendation</th><th>Reason</th><th>Category</th><th>Impl. Risk</th></tr></thead>
      <tbody>${data.recommendations.map(r => `<tr><td><span class="pill sev-${r.priority.toLowerCase()}">${esc(r.priority)}</span></td>
        <td>${esc(r.recommendation)}</td><td class="muted">${esc(r.reason)}</td><td>${esc(r.category.replace(/_/g," "))}</td><td class="muted">${esc(r.implementation_risk)}</td></tr>`).join("")}</tbody></table></div>`
      : "<p class='muted'>No recommendations.</p>"}</div>
    <div class="panel" style="margin-top:16px"><h2>Unassessed Areas <span class="muted">(insufficient evidence — NOT assumed secure)</span></h2>
      ${data.unassessed.length ? data.unassessed.map(u => `<div style="padding:6px 0;border-bottom:1px solid var(--border)"><b>${esc(u.title)}</b> <span class="muted">— ${esc(u.notes)}</span></div>`).join("") : "<p class='muted'>All categories had sufficient evidence.</p>"}</div>
    <div class="panel" style="margin-top:16px" id="assessHist"><h2>Assessment History</h2><div class="muted">Loading…</div></div>`;

  $("#runAssess").onclick = () => runAssessment(view);
  $$("#catRows tr").forEach(tr => tr.onclick = () => {
    const c = JSON.parse(tr.dataset.cat);
    modal(`<h2>${esc(c.title)} — why this score?</h2>
      <p><b>Status:</b> ${esc(c.status)} · <b>Score:</b> ${c.score == null ? "Not Assessed" : c.score + "/100"}</p>
      <p class="muted">${esc(c.notes || "")}</p>
      <h3>Checks performed</h3><ul>${(c.checks_performed||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul>
      <h3>Deductions (transparent scoring)</h3>
      ${(c.deductions||[]).length ? `<div class="table-wrap"><table><thead><tr><th>Reason</th><th>Points</th></tr></thead><tbody>${c.deductions.map(d=>`<tr><td>${esc(d.reason)}</td><td>-${d.points}</td></tr>`).join("")}</tbody></table></div>` : "<p class='muted'>No deductions.</p>"}
      <button class="btn" style="margin-top:12px" onclick="closeModal()">Close</button>`);
  });
  loadAssessHistory();
}
function renderAssessDiff(diff) {
  const rows = Object.values(diff.deltas).filter(d => d.previous != null || d.current != null);
  if (!rows.length) return "";
  return `<div class="panel" style="margin-top:16px"><h2>Change vs Previous Assessment</h2>
    <div class="table-wrap"><table><thead><tr><th>Category</th><th>Previous</th><th>Current</th><th>Δ</th></tr></thead>
    <tbody>${rows.map(d => {
      const prev = d.previous == null ? "—" : d.previous, cur = d.current == null ? "—" : d.current;
      const delta = (d.previous != null && d.current != null) ? (d.current - d.previous) : null;
      const dcls = delta == null ? "muted" : delta >= 0 ? "pass" : "fail";
      return `<tr><td>${esc(d.title)}</td><td>${prev}</td><td>${cur}</td><td class="${dcls}">${delta == null ? "—" : (delta >= 0 ? "+" : "") + delta.toFixed(1)}</td></tr>`;
    }).join("")}</tbody></table></div></div>`;
}
async function loadAssessHistory() {
  try {
    const { history } = await api(`/api/security-assessment/history?dataset=${ds()}`);
    const el = $("#assessHist"); if (!el) return;
    el.innerHTML = `<h2>Assessment History</h2>${history.length ? `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Score</th><th>Coverage</th><th>Events</th><th>Incidents</th></tr></thead>
      <tbody>${history.map(h => `<tr><td class="muted mono">${esc((h.created_at||"").replace("T"," ").slice(0,19))}</td><td>${esc(h.data_source)}</td>
        <td><b>${h.overall_score == null ? "—" : h.overall_score}</b></td><td>${h.coverage_assessed}/${h.coverage_total}</td>
        <td>${h.events_analyzed}</td><td>${h.incidents_analyzed}</td></tr>`).join("")}</tbody></table></div>` : "<p class='muted'>No previous assessments.</p>"}`;
  } catch (e) {}
}
async function runAssessment(view) {
  const btn = $("#runAssess"); if (btn) { btn.disabled = true; btn.textContent = "Assessing…"; }
  try {
    await api("/api/security-assessment/run", { method: "POST", body: JSON.stringify({ dataset: ds() }) });
    toast("Assessment complete"); renderAssessment(view);
  } catch (e) { toast(e.message, "err"); if (btn) { btn.disabled = false; btn.textContent = "Run Assessment"; } }
}

// ==================================================================
// EVALUATION (controlled, reproducible metrics vs labelled ground truth)
// ==================================================================
async function renderEvaluation(view) {
  const r = await api(`/api/evaluation?dataset=${ds()}`);
  const metricRow = (label, base, prop) => `<tr><td>${label}</td><td>${base}</td><td><b>${prop}</b></td></tr>`;
  const b = r.baseline || {}, p = r.proposed || {};
  const attackRows = Object.entries(r.attack_types || {}).map(([k, v]) => `<span class="tag">${esc(k)}: ${v}</span>`).join(" ");
  view.innerHTML = `
    <div class="page-head"><div><h1>Evaluation</h1>
      <div class="muted">Detection quality vs the dataset's ground-truth <b>Label</b> column · ${ds().toUpperCase()} dataset</div></div></div>
    ${!r.labelled_available ? `<div class="panel" style="border-color:var(--warn)"><h2>No labelled dataset loaded</h2>
      <p class="muted">${esc((r.notes||[]).join(" "))}</p>
      <p class="muted">Place a CIC-IDS2017 / CSE-CIC-IDS2018 CSV (with a <code>Label</code> column) via the Real Data page, run detection, then reload this page. Until then all metrics show <b>Not available</b>.</p></div>` : ""}
    <div class="cards">
      ${kpi(r.records_total, "Records (total)")}
      ${kpi(r.records_labelled, "Records (labelled)")}
      ${kpi(Object.keys(r.attack_types||{}).length || "—", "Label classes")}
    </div>
    ${attackRows ? `<div class="panel" style="margin-top:14px"><h2>Attack-type distribution (ground truth)</h2><div>${attackRows}</div></div>` : ""}
    <div class="panel" style="margin-top:16px"><h2>Detection Metrics <span class="muted">(Baseline: rules-only · Proposed: rules + anomaly + multi-agent)</span></h2>
      <div class="table-wrap"><table><thead><tr><th>Metric</th><th>Baseline</th><th>Proposed</th></tr></thead>
      <tbody>
        ${metricRow("Precision", b.precision ?? "—", p.precision ?? "—")}
        ${metricRow("Recall", b.recall ?? "—", p.recall ?? "—")}
        ${metricRow("F1 score", b.f1 ?? "—", p.f1 ?? "—")}
        ${metricRow("False-positive rate", b.false_positive_rate ?? "—", p.false_positive_rate ?? "—")}
        ${metricRow("Accuracy", b.accuracy ?? "—", p.accuracy ?? "—")}
        ${metricRow("True / False positives", `${b.true_positives ?? "—"} / ${b.false_positives ?? "—"}`, `${p.true_positives ?? "—"} / ${p.false_positives ?? "—"}`)}
        ${metricRow("True / False negatives", `${b.true_negatives ?? "—"} / ${b.false_negatives ?? "—"}`, `${p.true_negatives ?? "—"} / ${p.false_negatives ?? "—"}`)}
      </tbody></table></div>
      <div class="muted" style="font-size:12px;margin-top:8px">Ground truth = dataset labels; predictions = events actually incorporated into incidents. No numbers are invented; unavailable metrics show "Not available".</div></div>
    <div class="panel" style="margin-top:16px"><h2>Measured Timings</h2>
      <div class="table-wrap"><table><tbody>
      ${Object.entries(r.timings||{}).map(([k,v]) => `<tr><td>${esc(k.replace(/_/g," "))}</td><td><b>${esc(String(v))}</b></td></tr>`).join("") || "<tr><td class='muted'>Not available</td></tr>"}
      </tbody></table></div></div>
    ${(r.notes||[]).length ? `<div class="panel" style="margin-top:16px"><h2>Methodology notes</h2>${r.notes.map(n=>`<p class="muted">${esc(n)}</p>`).join("")}</div>` : ""}`;
}

// ---------- boot ----------
// ==================================================================
// STARTUP / INITIALIZATION SCREEN
// ==================================================================
// A single controlled initialization lifecycle. Stages marked (real) perform an
// actual backend check; (ui) stages are clearly frontend/application init.
// The single SSE (startStream) and single dashboard poller (via route) are each
// created exactly once here — no duplicates.
const SOC_AGENTS = [
  "Detection Engine", "Investigation Agent", "Threat Intelligence",
  "Evidence Correlation", "Risk Assessment", "Response Planner",
  "Response Validator", "Incident Memory", "SOC Orchestrator",
];

function bootLog(msg, cls = "") {
  const el = $("#bootLog"); if (!el) return;
  const t = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.innerHTML = `<span class="t">${t}</span>  <span class="${cls}">${esc(msg)}</span>`;
  el.appendChild(line); el.scrollTop = el.scrollHeight;
}
function setBootProgress(pct, msg) {
  const fill = $("#bootBarFill"), bar = $("#bootBar");
  if (fill) fill.style.width = pct + "%";
  if (bar) bar.setAttribute("aria-valuenow", String(pct));
  if ($("#bootPct")) $("#bootPct").textContent = pct + "%";
  if (msg && $("#bootMsg")) $("#bootMsg").textContent = msg;
}
function setAgent(name, status) {
  const el = document.querySelector(`.boot-agent[data-agent="${CSS.escape(name)}"]`);
  if (!el) return;
  el.className = "boot-agent " + status;
  el.querySelector(".a-s").textContent = status.toUpperCase();
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function renderBootScaffold() {
  const stagesEl = $("#bootStages");
  BOOT_STAGES.forEach((s, i) => {
    const li = document.createElement("li");
    li.id = "stage-" + i;
    li.innerHTML = `<span class="ico">○</span><span>${esc(s.label)}</span>`;
    stagesEl.appendChild(li);
  });
  const agEl = $("#bootAgents");
  SOC_AGENTS.forEach(a => {
    const d = document.createElement("div");
    d.className = "boot-agent waiting"; d.dataset.agent = a;
    d.innerHTML = `<div class="a-n">${esc(a)}</div><div class="a-s">WAITING</div>`;
    agEl.appendChild(d);
  });
}
function markStage(i, cls, ico) {
  const li = $("#stage-" + i); if (!li) return;
  li.className = cls;
  li.querySelector(".ico").textContent = ico;
}

// Stage definitions. `run` returns {ok:true} | {ok:false, critical, reason}.
const BOOT_STAGES = [
  { label: "Loading security configuration", pct: 15, kind: "real",
    run: async () => {
      const cfg = await api("/api/config");
      state.config = cfg;
      applyConfigBadges();
      bootLog("Security configuration loaded", "ok");
      return { ok: true };
    } },
  { label: "Verifying backend / threat detection engine", pct: 30, kind: "real",
    run: async () => {
      const h = await api("/health");
      if (!h || h.status !== "ok") return { ok: false, critical: true, reason: "Health check failed." };
      bootLog("Backend reachable — SOC services available", "ok");
      ["Detection Engine", "Investigation Agent", "SOC Orchestrator"].forEach(a => setAgent(a, "online"));
      return { ok: true };
    } },
  { label: "Loading threat intelligence", pct: 45, kind: "real",
    run: async () => {
      await api("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip");
      bootLog("Threat intelligence subsystem responded (local CTI)", "ok");
      setAgent("Threat Intelligence", "online");
      return { ok: true };
    } },
  { label: "Initializing multi-agent SOC", pct: 60, kind: "ui",
    run: async () => {
      ["Evidence Correlation", "Risk Assessment", "Response Planner",
       "Response Validator", "Incident Memory"].forEach(a => setAgent(a, "online"));
      bootLog("Multi-agent SOC services registered", "ok");
      return { ok: true };
    } },
  { label: "Loading incident database", pct: 75, kind: "real",
    run: async () => {
      const d = await api(`/api/dashboard?dataset=${ds()}`);
      bootLog(`Incident database connected (${d.total_events} events, ${ds().toUpperCase()} mode)`, "ok");
      return { ok: true };
    } },
  { label: "Establishing real-time event stream", pct: 90, kind: "real",
    run: async () => {
      startStream();                    // the single SSE the app uses
      const connected = await waitFor(() => state.streamConnected, 4000);
      if (connected) { bootLog("Real-time event stream connected", "ok"); return { ok: true }; }
      bootLog("Real-time stream not confirmed yet — will keep retrying", "warn");
      return { ok: false, critical: false, reason: "Event stream connection could not be confirmed (optional; auto-retrying)." };
    } },
  { label: "Preparing SOC dashboard", pct: 100, kind: "ui",
    run: async () => {
      route();                          // renders dashboard + arms single poller
      bootLog("SOC dashboard ready", "ok");
      return { ok: true };
    } },
];

function applyConfigBadges() {
  const cfg = state.config || {};
  if ($("#badgeSim")) {
    $("#badgeSim").textContent = cfg.response_simulation ? "SIMULATION" : "LIVE-EXEC";
    $("#badgeSim").className = "badge " + (cfg.response_simulation ? "badge-ok" : "badge-warn");
  }
  if ($("#badgeAuto")) $("#badgeAuto").textContent = cfg.auto_response_enabled ? "AUTO-RESP ON" : "AUTO-RESP OFF";
}

function waitFor(pred, timeout = 4000, step = 150) {
  return new Promise(resolve => {
    const t0 = Date.now();
    (function check() {
      if (pred()) return resolve(true);
      if (Date.now() - t0 >= timeout) return resolve(false);
      setTimeout(check, step);
    })();
  });
}

async function runStartup() {
  renderBootScaffold();
  if (!location.hash) location.hash = "#/dashboard";
  const failures = [];
  for (let i = 0; i < BOOT_STAGES.length; i++) {
    const s = BOOT_STAGES[i];
    markStage(i, "active", "●");
    setBootProgress(BOOT_STAGES[i - 1] ? BOOT_STAGES[i - 1].pct : 0, s.label);
    SOC_AGENTS.forEach(a => { const el = document.querySelector(`.boot-agent[data-agent="${CSS.escape(a)}"]`);
      if (el && el.classList.contains("waiting") && i >= 1) setAgent(a, "initializing"); });
    let res;
    try { res = await s.run(); }
    catch (e) { res = { ok: false, critical: s.kind === "real" && i <= 4, reason: e.message || "check failed" }; }
    await sleep(260);  // brief, visible pacing (not fake work)
    if (res.ok) {
      markStage(i, "done", "✓");
    } else if (res.critical) {
      markStage(i, "failed", "✕");
      bootLog(s.label + " — FAILED: " + (res.reason || ""), "err");
      failures.push({ stage: s, reason: res.reason, critical: true });
      // mark backend agents failed if the backend is unreachable
      if (i <= 1) SOC_AGENTS.forEach(a => setAgent(a, "failed"));
      break;  // stop on a critical failure
    } else {
      markStage(i, "warn", "!");
      failures.push({ stage: s, reason: res.reason, critical: false });
    }
    setBootProgress(s.pct, s.label);
  }
  finishStartup(failures);
}

function finishStartup(failures) {
  const critical = failures.find(f => f.critical);
  const status = $("#bootStatus"), final = $("#bootFinal");
  $("#bootScreen").setAttribute("aria-busy", "false");
  if (critical) {
    status.className = "boot-status degraded";
    status.innerHTML = "SYSTEM STATUS: <b>DEGRADED</b>";
    if ($("#sysStat")) { $("#sysStat").className = "sysstat degraded"; $("#sysStat").innerHTML = `<span class="dot"></span>SYSTEM DEGRADED`; }
    final.innerHTML = `
      <div class="boot-ready-title" style="color:var(--crit)">SYSTEM INITIALIZATION DEGRADED</div>
      <div class="boot-ready-sub">Component: <b>${esc(critical.stage.label)}</b></div>
      <div class="boot-ready-sub">Status: <b>FAILED</b> · ${esc(critical.reason || "Initialization failed.")}</div>
      <div style="margin-top:14px">
        <button class="boot-retry" id="bootRetry">RETRY</button>
      </div>`;
    $("#bootRetry").onclick = retryStartup;
    $("#bootRetry").focus();
    return;
  }
  const warned = failures.filter(f => !f.critical);
  status.className = "boot-status ready";
  status.innerHTML = warned.length
    ? "SYSTEM STATUS: <b>READY</b> (with warnings)"
    : "SYSTEM STATUS: <b>READY</b>";
  if ($("#sysStat")) { $("#sysStat").className = "sysstat online"; $("#sysStat").innerHTML = `<span class="dot"></span>SYSTEM ONLINE`; }
  final.innerHTML = `
    <div class="boot-ready-title">SYSTEM READY</div>
    <div class="boot-ready-sub">${warned.length ? "Core security services online — "
        + esc(warned[0].stage.label) + " will keep retrying." : "ALL SECURITY SERVICES ONLINE"}</div>
    <div class="boot-protected">● ${ds().toUpperCase()} MODE · ${state.config && state.config.response_simulation ? "RESPONSE SIMULATION" : "LIVE"}</div>
    <button class="boot-enter" id="bootEnter" aria-label="Enter the Security Operations Center dashboard">ENTER SOC</button>`;
  const enter = $("#bootEnter");
  enter.onclick = enterDashboard;
  enter.focus();
  document.addEventListener("keydown", bootEnterKey);
}
function bootEnterKey(e) {
  if ((e.key === "Enter" || e.key === " ") && $("#bootEnter")) { e.preventDefault(); enterDashboard(); }
}
function enterDashboard() {
  document.removeEventListener("keydown", bootEnterKey);
  const boot = $("#bootScreen");
  boot.classList.add("boot-hidden");
  setTimeout(() => boot.classList.add("boot-gone"), 550);
  const q = $("#globalSearch"); if (q) q.blur();
}
function retryStartup() {
  // reset the scaffold and re-run the same single lifecycle
  $("#bootStages").innerHTML = "";
  $("#bootAgents").innerHTML = "";
  $("#bootLog").innerHTML = "";
  $("#bootFinal").innerHTML = "";
  $("#bootStatus").className = "boot-status";
  $("#bootStatus").innerHTML = "SYSTEM STATUS: <b>INITIALIZING</b>";
  $("#bootScreen").setAttribute("aria-busy", "true");
  setBootProgress(0, "Retrying initialization…");
  runStartup();
}

(async function init() {
  runStartup();   // single controlled initialization lifecycle
})();
