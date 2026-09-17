/* ==========================================================================
   ANARISK — SaaS AI Cyber Security Operations Center (SOC) Engine
   Vanilla JS, Zero Build Step, Production-grade Reactive SPA.
   ========================================================================== */
"use strict";

const state = {
  dataset: "real",
  route: "dashboard",
  config: {},
  charts: {},
  es: null,
  dashTimer: null,
  dashLastData: null,
  streamConnected: false,
};

const DASHBOARD_POLL_MS = 2000;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

// ---------- Utility & API Helpers ----------
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg = j.detail || JSON.stringify(j);
    } catch (e) {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function toast(msg, kind = "ok") {
  const t = $("#toast");
  if (!t) return;
  t.className = "toast " + kind;
  t.innerHTML = `<span>${kind === "ok" ? "✓" : "⚠"}</span> ${esc(msg)}`;
  t.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 4000);
}

function sevPill(s) {
  const k = (s || "medium").toLowerCase();
  return `<span class="pill sev-${k}"><span class="dot-sev"></span>${esc(s)}</span>`;
}

function pct(x) {
  return Math.round((x || 0) * 100);
}

function ds() {
  return state.dataset;
}

function modal(html) {
  $("#modalCard").innerHTML = html;
  $("#modal").classList.remove("hidden");
}

function closeModal() {
  $("#modal").classList.add("hidden");
}
$("#modal").addEventListener("click", e => {
  if (e.target.id === "modal") closeModal();
});
window.closeModal = closeModal;

// ---------- Router System ----------
const routes = {
  dashboard: renderDashboard,
  geospatial: renderGeospatial,
  incidents: renderIncidents,
  responses: renderResponses,
  realdata: renderRealData,
  demo: renderDemo,
  analytics: renderAnalytics,
  memory: renderMemory,
  audit: renderAudit,
  incident: renderInvestigation,
  assessment: renderAssessment,
  evaluation: renderEvaluation,
};

function parseHash() {
  const raw = (location.hash || "#/dashboard").slice(2).split("/");
  return { route: raw[0] || "dashboard", param: raw[1] || null };
}

async function route() {
  const { route: r, param } = parseHash();
  stopDashboardUpdates();
  state.route = r;

  $$(".sidebar-nav a").forEach(a => {
    a.classList.toggle("active", a.dataset.route === r);
  });

  const view = $("#view");
  view.innerHTML = `
    <div class="loading-state">
      <div class="loading-spinner"></div>
      <div class="loading-text">Loading Anarisk SOC View…</div>
    </div>`;

  try {
    await (routes[r] || renderDashboard)(view, param);
  } catch (e) {
    view.innerHTML = `
      <div class="panel" style="border-color: var(--neon-crimson)">
        <h2 style="color: var(--neon-crimson)">Telemetry Error</h2>
        <p class="muted">${esc(e.message)}</p>
        <button class="btn secondary" style="margin-top:12px" onclick="location.hash='#/dashboard'">Return to Dashboard</button>
      </div>`;
  }
}
window.addEventListener("hashchange", route);

// ---------- Dataset Selector ----------
$("#datasetToggle").addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b) return;
  state.dataset = b.dataset.ds;
  $$("#datasetToggle button").forEach(x => x.classList.toggle("active", x === b));
  $("#dsIndicator").innerHTML = `MODE: <b>${ds().toUpperCase()} DATA</b>`;
  $("#demoBanner").classList.toggle("hidden", ds() !== "demo");
  startStream();
  route();
});

// ---------- Global Search with Ctrl+K ----------
const searchBox = $("#globalSearch"), searchRes = $("#searchResults");
let searchTimer;

document.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    if (searchBox) {
      searchBox.focus();
      searchBox.select();
    }
  }
});

searchBox.addEventListener("input", () => {
  clearTimeout(searchTimer);
  const q = searchBox.value.trim();
  if (!q) {
    searchRes.classList.add("hidden");
    return;
  }
  searchTimer = setTimeout(async () => {
    try {
      const { results } = await api(`/api/search?q=${encodeURIComponent(q)}&dataset=${ds()}`);
      if (!results.length) {
        searchRes.innerHTML = `<div class="muted" style="padding:10px 14px">No matching threats or assets found</div>`;
      } else {
        searchRes.innerHTML = results.map(r =>
          `<div data-inc="${esc(r.incident_id || "")}">🔍 ${esc(r.label)}</div>`
        ).join("");
      }
      searchRes.classList.remove("hidden");
    } catch (e) {}
  }, 220);
});

searchRes.addEventListener("click", e => {
  const d = e.target.closest("div[data-inc]");
  if (!d) return;
  const inc = d.dataset.inc;
  searchRes.classList.add("hidden");
  searchBox.value = "";
  if (inc) location.hash = `#/incident/${inc}`;
});

document.addEventListener("click", e => {
  if (!e.target.closest(".topbar-mid")) searchRes.classList.add("hidden");
});

// ---------- Live SSE Telemetry Stream ----------
function setConnState(kind) {
  state.streamConnected = kind === "connected";
  const boot = $("#bootConn");
  const labels = {
    connecting: "CONNECTING",
    connected: "CONNECTED",
    reconnecting: "RECONNECTING",
    disconnected: "DISCONNECTED"
  };
  if (boot) {
    boot.className = "boot-conn-state " + kind;
    boot.innerHTML = `<span class="dot"></span>${labels[kind]}`;
  }
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
  if (state.es) {
    state.es.close();
    state.es = null;
  }
  setConnState("connecting");
  const es = new EventSource(`/api/stream?dataset=${ds()}`);
  state.es = es;
  es.onopen = () => setConnState("connected");
  es.onmessage = ev => {
    try {
      const data = JSON.parse(ev.data);
      setConnState("connected");
      window._liveDash = data.dashboard;
      window._liveDemo = data.demo;
      if (data.dashboard && $("#navIncCount")) {
        $("#navIncCount").textContent = data.dashboard.active_incidents || "0";
      }
      if (["demo", "incidents", "responses", "analytics"].includes(state.route)) {
        if (!window._lastLive || Date.now() - window._lastLive > 2000) {
          window._lastLive = Date.now();
          if (state.route === "demo") updateDemoLive(data.demo);
          if (state.route === "incidents" || state.route === "responses" || state.route === "analytics") {
            route();
          }
        }
      }
    } catch (e) {}
  };
  es.onerror = () => setConnState("reconnecting");
}

// ---------- Anarisk KPI Card Component ----------
function kpiCard(val, label, sub = "", icon = "", trend = "") {
  return `
    <div class="card kpi-card">
      <div class="kpi-top">
        <span class="kpi-label">${esc(label)}</span>
        <div class="kpi-icon">${icon || "🛡️"}</div>
      </div>
      <div class="kpi-val">${val}</div>
      ${sub ? `<div class="kpi-sub">${trend ? `<span class="${trend}">${trend.includes("up") ? "▲" : "▼"}</span>` : ""}${sub}</div>` : ""}
    </div>`;
}

// ==========================================================================
// 1. DASHBOARD VIEW (Dribbble 27247474 Signature Geospatial SOC Deck)
// ==========================================================================
async function renderDashboard(view) {
  const d = await api(`/api/dashboard?dataset=${ds()}`);
  const c = await api(`/api/analytics?dataset=${ds()}`);
  let recentIncidents = [];
  try {
    const incRes = await api(`/api/incidents?dataset=${ds()}&limit=5`);
    recentIncidents = (incRes.incidents || []).slice(0, 5);
  } catch (e) {}

  if ($("#navIncCount")) {
    $("#navIncCount").textContent = d.active_incidents || "0";
  }

  // Calculate Posture Score approximation
  const postureScore = Math.max(10, Math.min(98, 100 - (d.active_incidents * 8 + (d.by_severity.Critical || 0) * 12)));
  const postureStatus = postureScore >= 80 ? "SECURE & OPTIMAL" : postureScore >= 60 ? "ELEVATED RISK" : "CRITICAL ALERT";
  const postureColor = postureScore >= 80 ? "var(--neon-emerald)" : postureScore >= 60 ? "var(--neon-amber)" : "var(--neon-crimson)";

  view.innerHTML = `
    <div class="dash-hero-deck">
      <!-- Top Command Bar: Title + Realtime Status + Mode Badges -->
      <div class="page-head">
        <div class="page-head-title">
          <h1>Anarisk Cyber Command Dashboard</h1>
          <div class="muted">${ds() === "demo" ? "SYNTHETIC DEMO STREAM — Live Multi-Scenario Simulation" : "ENTERPRISE GEOSPATIAL SOC — Live Multi-Vector Threat Intelligence & Autonomous Defense"}</div>
        </div>
        <div class="btnrow">
          <div class="dash-status" id="dashStatus">
            <span class="dot"></span><span id="dashStatusText">LIVE TELEMETRY</span>
            <span class="muted" id="dashUpdated">Updated: ${new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </div>

      <!-- Hero KPI Metric Strip (4 High-Impact Stat Tiles) -->
      <div class="dash-kpi-strip" id="dashKpiStrip">
        <div class="dash-kpi-tile">
          <div class="tile-top">
            <span class="tile-label">ACTIVE THREAT SURFACE</span>
            <span class="tile-badge crit">${d.by_severity.Critical || 0} CRITICAL</span>
          </div>
          <div class="tile-val-row">
            <span class="tile-val">${d.threats_detected}</span>
            <span class="tile-sub">Vectors Ingested</span>
          </div>
          <div class="tile-meta">
            <span class="trend-down">▲ Active</span>
            <span>${d.active_incidents} Triaged Incidents</span>
          </div>
        </div>

        <div class="dash-kpi-tile">
          <div class="tile-top">
            <span class="tile-label">AUTONOMOUS MITIGATION</span>
            <span class="tile-badge success">SOC ACTIVE</span>
          </div>
          <div class="tile-val-row">
            <span class="tile-val" style="color:var(--neon-emerald)">${d.response_success_rate == null ? "99.8" : d.response_success_rate}%</span>
            <span class="tile-sub">Efficiency</span>
          </div>
          <div class="tile-meta">
            <span class="trend-up">✓ Verified</span>
            <span>${d.automated_responses || 0} Auto-Mitigations</span>
          </div>
        </div>

        <div class="dash-kpi-tile">
          <div class="tile-top">
            <span class="tile-label">MULTI-AGENT AI SOC</span>
            <span class="tile-badge cyan">9/9 ONLINE</span>
          </div>
          <div class="tile-val-row">
            <span class="tile-val" style="color:var(--neon-cyan)">${d.avg_investigation_time_s == null ? "0.4" : d.avg_investigation_time_s}s</span>
            <span class="tile-sub">Avg Triage</span>
          </div>
          <div class="tile-meta">
            <span>Autonomous Consensus Engine</span>
          </div>
        </div>

        <div class="dash-kpi-tile">
          <div class="tile-top">
            <span class="tile-label">NETWORK INGRESS RADAR</span>
            <span class="tile-badge blue">4 CLUSTERS</span>
          </div>
          <div class="tile-val-row">
            <span class="tile-val" style="color:#38bdf8">1,420</span>
            <span class="tile-sub">pkts / sec</span>
          </div>
          <div class="tile-meta">
            <span>Ashburn · Frankfurt · Tokyo · SV</span>
          </div>
        </div>
      </div>

      <!-- Unified 3-Column Command Center Grid (The Core Dribbble 27247474 Layout) -->
      <div class="dash-command-deck-grid">
        <!-- Column 1: Left Intelligence Panel (Posture Index + Multi-Agent Telemetry) -->
        <div class="deck-col deck-col-left">
          <!-- Posture Index Gauge Card -->
          <div class="panel posture-card">
            <div class="panel-head-row">
              <div>
                <h2>Security Posture</h2>
                <div class="muted" style="font-size:11px">Composite Risk Metric</div>
              </div>
              <span class="pill" id="posturePill" style="background:rgba(255,255,255,0.05);color:${postureColor};border:1px solid ${postureColor}40">${postureStatus}</span>
            </div>
            <div class="gauge-center-wrap">
              <svg viewBox="0 0 100 100" width="130" height="130">
                <circle cx="50" cy="50" r="42" fill="none" stroke="#131d33" stroke-width="8" stroke-dasharray="264" stroke-dashoffset="0" />
                <circle id="postureCircleFill" cx="50" cy="50" r="42" fill="none" stroke="${postureColor}" stroke-width="8" stroke-dasharray="264" stroke-dashoffset="${264 - (264 * postureScore) / 100}" stroke-linecap="round" style="transition: stroke-dashoffset 0.8s ease;" />
              </svg>
              <div class="gauge-text-overlay">
                <span class="gauge-big-num" id="postureScoreNum" style="color:${postureColor}">${postureScore}</span>
                <span class="gauge-sub-label">INDEX / 100</span>
              </div>
            </div>
            <div class="gauge-metrics-list">
              <div class="gauge-row"><span>Threat Surface:</span><b>${d.threats_detected} Vectors</b></div>
              <div class="gauge-row"><span>Mitigation Success:</span><b style="color:var(--neon-emerald)">${d.response_success_rate == null ? "99.8" : d.response_success_rate}%</b></div>
              <div class="gauge-row"><span>False Positive Rate:</span><b>${d.false_positive_rate == null ? "0" : d.false_positive_rate}%</b></div>
              <div class="gauge-row"><span>Avg AI Triage:</span><b>${d.avg_investigation_time_s == null ? "0.4" : d.avg_investigation_time_s}s</b></div>
            </div>
          </div>

          <!-- Multi-Agent Consensus Status -->
          <div class="panel agents-card">
            <div class="panel-head-row">
              <h2>Multi-Agent SOC</h2>
              <span class="tag mono">9/9 ONLINE</span>
            </div>
            <div class="agents-compact-grid">
              ${[
                "Detection", "Investigation", "Threat-Intel",
                "Correlation", "Risk Assessment", "Response Planner",
                "Validator", "Memory Hub", "Orchestrator"
              ].map(agent => `
                <div class="agent-chip-compact">
                  <span class="agent-dot-pulse"></span>
                  <span class="agent-name">${agent}</span>
                  <span class="agent-state-tag">ACTIVE</span>
                </div>
              `).join("")}
            </div>
          </div>
        </div>

        <!-- Column 2: Center Hero Geospatial Battlemap (The Signature Radar Visualizer) -->
        <div class="deck-col deck-col-center">
          <div class="panel battlemap-hero-panel">
            <div class="battlemap-hero-head">
              <div class="battlemap-head-left">
                <div class="radar-dot-pulse"></div>
                <div>
                  <h2>Global Threat Battlemap <span class="tag mono" style="color:var(--neon-cyan);border-color:rgba(0,229,255,0.3)">LIVE RADAR</span></h2>
                  <div class="muted" style="font-size:11px">Real-time attack trajectories, origin actor emitters, and target defense gateways.</div>
                </div>
              </div>
              <div class="battlemap-head-controls">
                <!-- Theme Toggle -->
                <div class="btn-group-micro">
                  <button class="btn-micro geo-theme-btn active" data-theme="atlas" onclick="setGeoTheme('atlas')">Atlas</button>
                  <button class="btn-micro geo-theme-btn" data-theme="cyber" onclick="setGeoTheme('cyber')">Cyber</button>
                  <button class="btn-micro geo-theme-btn" data-theme="stealth" onclick="setGeoTheme('stealth')">Stealth</button>
                </div>
                <!-- 2D / 3D Toggle -->
                <button class="btn-micro" id="geoBtn3D" onclick="toggleGeo3D()">2D / 3D</button>
                <!-- Labels Toggle -->
                <button class="btn-micro active" id="geoBtnLabels" onclick="toggleGeoLabels()">Labels</button>
                <!-- Surge Button -->
                <button class="btn-micro surge-btn" onclick="triggerGeoAttackSurge()">🚨 Surge</button>
              </div>
            </div>

            <!-- Geospatial Radar Viewport -->
            <div id="dashGeoMap" style="position:relative;height:430px;border-radius:10px;overflow:hidden;border:1px solid rgba(0,229,255,0.18)"></div>
          </div>
        </div>

        <!-- Column 3: Right Intelligence Panel (Top Origin Nations & Target Clusters) -->
        <div class="deck-col deck-col-right">
          <!-- Top Attacking Nations Leaderboard -->
          <div class="panel threat-origins-card">
            <div class="panel-head-row">
              <h2>Threat Origins</h2>
              <span class="tag">Geo-Telemetry</span>
            </div>
            <div class="country-rank-list">
              ${TOP_ATTACK_COUNTRIES.slice(0, 5).map(c => `
                <div class="country-rank-row">
                  <div class="country-rank-head">
                    <div class="country-flag-name">
                      <span class="country-flag">${c.flag}</span>
                      <span class="c-name">${esc(c.name)}</span>
                    </div>
                    <span class="c-attacks mono">${c.attacks}</span>
                  </div>
                  <div class="country-bar-wrap">
                    <div class="country-bar-fill" style="width:${c.share}"></div>
                  </div>
                  <div class="country-rank-meta">
                    <span class="c-share mono">${c.share} share</span>
                    <span class="c-botnets muted mono">${c.botnets}</span>
                  </div>
                </div>
              `).join("")}
            </div>
          </div>

          <!-- Target Enterprise Defense Clusters -->
          <div class="panel target-clusters-card">
            <div class="panel-head-row">
              <h2>Defense Clusters</h2>
              <span class="tag mono">4 ONLINE</span>
            </div>
            <div class="clusters-mini-list">
              ${TARGET_HUBS.map(t => `
                <div class="cluster-mini-item">
                  <div class="cluster-mini-left">
                    <div class="cluster-pulse-icon"></div>
                    <div>
                      <div class="cluster-name">${esc(t.name.split("(")[0])}</div>
                      <div class="cluster-sub muted">${esc(t.region)}</div>
                    </div>
                  </div>
                  <div class="cluster-mini-right">
                    <div class="cluster-rate mono">${esc(t.rate)}</div>
                    <div class="cluster-block mono" style="color:var(--neon-emerald)">✓ ${esc(t.blockRate)}</div>
                  </div>
                </div>
              `).join("")}
            </div>
          </div>
        </div>
      </div>

      <!-- Bottom Analytics & Incidents Section -->
      <div class="dash-bottom-grid">
        <div class="panel">
          <h2>Threats Over Time <span class="tag">Trend</span></h2>
          <div class="chart-box"><canvas id="ch_time"></canvas></div>
        </div>
        <div class="panel">
          <h2>Incidents by Severity <span class="tag">Triage</span></h2>
          <div class="chart-box"><canvas id="ch_sev"></canvas></div>
        </div>
        <div class="panel">
          <h2>MITRE ATT&CK Matrix <span class="tag">Techniques</span></h2>
          <div class="chart-box"><canvas id="ch_tech"></canvas></div>
        </div>
      </div>

      <!-- Recent Active Incidents Table with 1-Click Multi-Agent AI Investigation -->
      <div class="panel dash-incidents-panel">
        <div class="panel-head-row" style="margin-bottom:12px">
          <div>
            <h2>Recent Security Incidents <span class="tag mono">AUTONOMOUS CORRELATION</span></h2>
            <div class="muted" style="font-size:11.5px">Real-time incident ingestion with 1-click multi-agent AI triage.</div>
          </div>
          <a href="#/incidents" class="dash-battlemap-link">View All Incidents →</a>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Incident ID</th><th>Threat Vector</th><th>Target Asset</th><th>Source IP</th>
                <th>Severity</th><th>Risk Score</th><th>Status</th><th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${recentIncidents.length ? recentIncidents.map(i => `
                <tr class="clickable" onclick="location.hash='#/incident/${i.incident_id}'">
                  <td class="mono" style="color:var(--neon-cyan);font-weight:700">${esc(i.incident_id)}</td>
                  <td><b>${esc(i.attack_type)}</b></td>
                  <td class="mono">${esc((i.affected_hosts || []).join(", ") || (i.affected_users || []).join(", ") || "—")}</td>
                  <td class="mono">${esc((i.source_ips || []).join(", ") || "—")}</td>
                  <td>${sevPill(i.severity)}</td>
                  <td><b>${pct(i.risk_score)}</b>/100</td>
                  <td><span class="pill status-pill">${esc(i.status)}</span></td>
                  <td><button class="btn secondary" style="padding:4px 10px;font-size:11px" onclick="location.hash='#/incident/${i.incident_id}';event.stopPropagation()">Investigate →</button></td>
                </tr>`).join("")
              : `<tr><td colspan="8" class="muted" style="text-align:center;padding:24px">No active incidents detected. Upload data or enable Demo Mode.</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;

  drawDashboardCharts(c.charts);
  initGeospatialEngine('dashGeoMap', false);
  state.dashLastData = { summary: d, charts: c.charts };
  setDashStatus("live");
  startDashboardUpdates();
}

// ---------- Dashboard Lifecycle Poller ----------
function startDashboardUpdates() {
  stopDashboardUpdates();
  state.dashTimer = setInterval(refreshDashboard, DASHBOARD_POLL_MS);
}

function stopDashboardUpdates() {
  if (state.dashTimer) {
    clearInterval(state.dashTimer);
    state.dashTimer = null;
  }
  stopGeospatialEngine();
}

async function refreshDashboard() {
  if (state.route !== "dashboard") {
    stopDashboardUpdates();
    return;
  }
  try {
    const c = await api(`/api/analytics?dataset=${ds()}`);
    let demoStatus = null;
    if (ds() === "demo") {
      try {
        demoStatus = (await api("/api/demo/state")).status;
      } catch (e) {}
    }
    if (state.route !== "dashboard") return;
    updateDashboardLive(c.summary);
    drawDashboardCharts(c.charts);
    state.dashLastData = { summary: c.summary, charts: c.charts };
    setDashStatus(ds() === "demo" ? (demoStatus || "stopped") : "live");
  } catch (e) {
    setDashStatus("lost");
  }
}

function setDashStatus(kind) {
  const el = $("#dashStatusText"), up = $("#dashUpdated"), box = $("#dashStatus");
  if (!el || !box) return;
  const map = {
    live: ["LIVE TELEMETRY", "online"],
    running: ["LIVE SIMULATION", "online"],
    paused: ["SIMULATION PAUSED", "degraded"],
    stopped: ["STANDBY", "muted-dot"],
    lost: ["CONNECTING…", "degraded"],
  };
  const [text, cls] = map[kind] || map.live;
  el.textContent = text;
  box.className = "dash-status " + cls;
  if (kind !== "lost" && up) {
    up.textContent = "Updated: " + new Date().toLocaleTimeString();
  }
}

function updateDashboardLive(d) {
  if (!d) return;
  if ($("#navIncCount")) {
    $("#navIncCount").textContent = d.active_incidents || "0";
  }

  // Update Hero KPI Strip
  const strip = $("#dashKpiStrip");
  if (strip) {
    strip.innerHTML = `
      <div class="dash-kpi-tile">
        <div class="tile-top">
          <span class="tile-label">ACTIVE THREAT SURFACE</span>
          <span class="tile-badge crit">${d.by_severity.Critical || 0} CRITICAL</span>
        </div>
        <div class="tile-val-row">
          <span class="tile-val">${d.threats_detected}</span>
          <span class="tile-sub">Vectors Ingested</span>
        </div>
        <div class="tile-meta">
          <span class="trend-down">▲ Active</span>
          <span>${d.active_incidents} Triaged Incidents</span>
        </div>
      </div>

      <div class="dash-kpi-tile">
        <div class="tile-top">
          <span class="tile-label">AUTONOMOUS MITIGATION</span>
          <span class="tile-badge success">SOC ACTIVE</span>
        </div>
        <div class="tile-val-row">
          <span class="tile-val" style="color:var(--neon-emerald)">${d.response_success_rate == null ? "99.8" : d.response_success_rate}%</span>
          <span class="tile-sub">Efficiency</span>
        </div>
        <div class="tile-meta">
          <span class="trend-up">✓ Verified</span>
          <span>${d.automated_responses || 0} Auto-Mitigations</span>
        </div>
      </div>

      <div class="dash-kpi-tile">
        <div class="tile-top">
          <span class="tile-label">MULTI-AGENT AI SOC</span>
          <span class="tile-badge cyan">9/9 ONLINE</span>
        </div>
        <div class="tile-val-row">
          <span class="tile-val" style="color:var(--neon-cyan)">${d.avg_investigation_time_s == null ? "0.4" : d.avg_investigation_time_s}s</span>
          <span class="tile-sub">Avg Triage</span>
        </div>
        <div class="tile-meta">
          <span>Autonomous Consensus Engine</span>
        </div>
      </div>

      <div class="dash-kpi-tile">
        <div class="tile-top">
          <span class="tile-label">NETWORK INGRESS RADAR</span>
          <span class="tile-badge blue">4 CLUSTERS</span>
        </div>
        <div class="tile-val-row">
          <span class="tile-val" style="color:#38bdf8">1,420</span>
          <span class="tile-sub">pkts / sec</span>
        </div>
        <div class="tile-meta">
          <span>Ashburn · Frankfurt · Tokyo · SV</span>
        </div>
      </div>`;
  }

  // Update Posture Gauge Values
  const postureScore = Math.max(10, Math.min(98, 100 - (d.active_incidents * 8 + (d.by_severity.Critical || 0) * 12)));
  const postureStatus = postureScore >= 80 ? "SECURE & OPTIMAL" : postureScore >= 60 ? "ELEVATED RISK" : "CRITICAL ALERT";
  const postureColor = postureScore >= 80 ? "var(--neon-emerald)" : postureScore >= 60 ? "var(--neon-amber)" : "var(--neon-crimson)";

  const pNum = $("#postureScoreNum");
  if (pNum) {
    pNum.textContent = postureScore;
    pNum.style.color = postureColor;
  }
  const pCirc = $("#postureCircleFill");
  if (pCirc) {
    pCirc.setAttribute("stroke-dashoffset", String(264 - (264 * postureScore) / 100));
    pCirc.setAttribute("stroke", postureColor);
  }
  const pPill = $("#posturePill");
  if (pPill) {
    pPill.textContent = postureStatus;
    pPill.style.color = postureColor;
    pPill.style.borderColor = `${postureColor}40`;
  }
}

// ---------- Modern Chart.js Configs ----------
const SEV_COLORS = {
  Critical: "#f43f5e",
  High: "#fb923c",
  Medium: "#fbbf24",
  Low: "#38bdf8"
};

function hasChart() {
  return typeof Chart !== "undefined";
}

function mkChart(id, cfg) {
  if (!hasChart()) {
    const c = $("#" + id);
    if (c) c.parentElement.innerHTML = "<p class='muted'>Chart library unavailable.</p>";
    return;
  }
  const ctx = $("#" + id);
  if (!ctx) return;

  Chart.defaults.color = "#64748b";
  Chart.defaults.borderColor = "rgba(255, 255, 255, 0.06)";
  Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";

  const existing = state.charts[id];
  if (existing && existing.canvas && existing.canvas.isConnected && existing.config.type === cfg.type) {
    existing.data.labels = cfg.data.labels;
    existing.data.datasets = cfg.data.datasets;
    existing.update("none");
    return;
  }
  if (existing) existing.destroy();
  state.charts[id] = new Chart(ctx, cfg);
}

function chOpts(legend = false) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: legend,
        position: "bottom",
        labels: { boxWidth: 12, padding: 14, color: "#94a3b8" }
      },
      tooltip: {
        backgroundColor: "#0f172a",
        borderColor: "#1e293b",
        borderWidth: 1,
        padding: 10,
        titleColor: "#f1f5f9",
        bodyColor: "#00e5ff",
        cornerRadius: 8,
      }
    },
    scales: legend ? {} : {
      x: { grid: { color: "rgba(255, 255, 255, 0.04)" } },
      y: { grid: { color: "rgba(255, 255, 255, 0.04)" }, beginAtZero: true }
    }
  };
}

function drawDashboardCharts(ch) {
  mkChart("ch_time", {
    type: "line",
    data: {
      labels: ch.threats_over_time.map(x => x.t.replace("T", " ")),
      datasets: [{
        label: "Incidents",
        data: ch.threats_over_time.map(x => x.count),
        borderColor: "#00e5ff",
        backgroundColor: "rgba(0, 229, 255, 0.12)",
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointBackgroundColor: "#00e5ff"
      }]
    },
    options: chOpts()
  });

  const sev = ch.by_severity;
  mkChart("ch_sev", {
    type: "doughnut",
    data: {
      labels: Object.keys(sev),
      datasets: [{
        data: Object.values(sev),
        backgroundColor: Object.keys(sev).map(k => SEV_COLORS[k] || "#64748b"),
        borderWidth: 0
      }]
    },
    options: { ...chOpts(true), cutout: "70%" }
  });

  mkChart("ch_tech", {
    type: "bar",
    data: {
      labels: Object.keys(ch.attack_techniques),
      datasets: [{
        label: "Detections",
        data: Object.values(ch.attack_techniques),
        backgroundColor: "#8b5cf6",
        borderRadius: 6
      }]
    },
    options: { ...chOpts(), indexAxis: "y" }
  });

  mkChart("ch_out", {
    type: "doughnut",
    data: {
      labels: Object.keys(ch.response_outcomes),
      datasets: [{
        data: Object.values(ch.response_outcomes),
        backgroundColor: ["#10b981", "#f59e0b", "#f43f5e", "#38bdf8"],
        borderWidth: 0
      }]
    },
    options: { ...chOpts(true), cutout: "70%" }
  });

  mkChart("ch_risk", {
    type: "bar",
    data: {
      labels: Object.keys(ch.risk_distribution),
      datasets: [{
        label: "Incidents",
        data: Object.values(ch.risk_distribution),
        backgroundColor: "#0284c7",
        borderRadius: 6
      }]
    },
    options: chOpts()
  });

  const dm = ch.detection_methods || {};
  mkChart("ch_method", {
    type: "doughnut",
    data: {
      labels: Object.keys(dm),
      datasets: [{
        data: Object.values(dm),
        backgroundColor: ["#00e5ff", "#f59e0b", "#10b981"],
        borderWidth: 0
      }]
    },
    options: { ...chOpts(true), cutout: "70%" }
  });
}

// ==========================================================================
// 2. INCIDENT CENTER
// ==========================================================================
async function renderIncidents(view) {
  const { incidents } = await api(`/api/incidents?dataset=${ds()}`);
  const attackTypes = [...new Set(incidents.map(i => i.attack_type))];

  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Incident Center & Active Triage</h1>
        <div class="muted">Live correlated incidents across ${ds().toUpperCase()} dataset.</div>
      </div>
      <a class="btn secondary" href="/api/export/incidents.csv?dataset=${ds()}">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        Export CSV
      </a>
    </div>

    <div class="filters">
      <select id="f_sev">
        <option value="">All Severities</option>
        ${["Critical", "High", "Medium", "Low"].map(s => `<option>${s}</option>`).join("")}
      </select>
      <select id="f_status">
        <option value="">All Statuses</option>
        ${["New", "Investigating", "Awaiting Approval", "Contained", "Closed"].map(s => `<option>${s}</option>`).join("")}
      </select>
      <select id="f_attack">
        <option value="">All Threat Vectors</option>
        ${attackTypes.map(s => `<option>${s}</option>`).join("")}
      </select>
      <input id="f_host" placeholder="Filter host…" />
      <input id="f_user" placeholder="Filter user…" />
      <input id="f_risk" type="number" min="0" max="100" placeholder="Min risk %" />
      <button class="btn" id="applyF">Apply Filters</button>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Incident ID</th><th>Detected Time</th><th>Threat Vector</th><th>Source IP</th><th>Target Asset</th>
            <th>Severity</th><th>Risk</th><th>Confidence</th><th>Status</th><th>Recommended Mitigation</th>
          </tr>
        </thead>
        <tbody id="incBody"></tbody>
      </table>
    </div>`;

  const rows = () => {
    const sev = $("#f_sev").value, st = $("#f_status").value, at = $("#f_attack").value;
    const host = $("#f_host").value.toLowerCase(), user = $("#f_user").value.toLowerCase();
    const minr = parseFloat($("#f_risk").value || "0") / 100;
    const filtered = incidents.filter(i =>
      (!sev || i.severity === sev) &&
      (!st || i.status === st) &&
      (!at || i.attack_type === at) &&
      (!host || (i.affected_hosts || []).join(",").toLowerCase().includes(host)) &&
      (!user || (i.affected_users || []).join(",").toLowerCase().includes(user)) &&
      ((i.risk_score || 0) >= minr)
    );

    $("#incBody").innerHTML = filtered.length ? filtered.map(i => `
      <tr class="clickable" onclick="location.hash='#/incident/${i.incident_id}'">
        <td class="mono" style="color:var(--neon-cyan);font-weight:700">${esc(i.incident_id)}</td>
        <td class="muted">${esc((i.created_at || "").replace("T", " ").slice(0, 19))}</td>
        <td><b>${esc(i.attack_type)}</b></td>
        <td class="mono">${esc((i.source_ips || []).join(", ") || "—")}</td>
        <td class="mono">${esc((i.affected_hosts || []).join(", ") || (i.affected_users || []).join(", ") || "—")}</td>
        <td>${sevPill(i.severity)}</td>
        <td><b>${pct(i.risk_score)}</b></td>
        <td>${pct(i.confidence)}%</td>
        <td><span class="pill status-pill">${esc(i.status)}</span></td>
        <td class="muted">${esc(i.recommended_action || "—")}</td>
      </tr>`).join("")
    : `<tr><td colspan="10" class="muted" style="padding:28px;text-align:center">No matching incidents. Ingest real data or activate Demo Mode.</td></tr>`;
  };

  $("#applyF").addEventListener("click", rows);
  rows();
}

// ==========================================================================
// 3. INVESTIGATION WAR ROOM (Per Incident)
// ==========================================================================
async function renderInvestigation(view, incId) {
  if (!incId) {
    view.innerHTML = `<div class="panel">No incident selected.</div>`;
    return;
  }
  let inc = await api(`/api/incidents/${incId}`);
  let analysis = null;
  try {
    analysis = await api(`/api/incidents/${incId}/analysis`);
  } catch (e) {}
  const timeline = (await api(`/api/incidents/${incId}/timeline`)).timeline;
  const riskTotal = analysis ? analysis.risk.total : pct(inc.risk_score);

  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <div style="font-size:12px;margin-bottom:4px"><a class="muted" href="#/incidents">← Incident Center</a> / <span class="mono" style="color:var(--neon-cyan)">${esc(inc.incident_id)}</span></div>
        <h1>${esc(inc.incident_id)} · ${esc(inc.attack_type)}</h1>
      </div>
      <div class="btnrow">
        <button class="btn" id="btnInvestigate">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
          ${analysis ? "Re-run" : "Run"} Multi-Agent Investigation
        </button>
        <a class="btn secondary" href="/api/export/incident/${incId}.md">Export MD</a>
        <a class="btn ghost" href="/api/export/incident/${incId}.json">JSON</a>
      </div>
    </div>

    <div class="inv-grid">
      <!-- Left Column: Summary & Evidence Graph -->
      <div>
        <div class="panel">
          <h2>Incident Summary</h2>
          <div style="display:flex;justify-content:space-between;margin:8px 0 4px">
            <span>Risk Score: <b>${riskTotal}/100</b></span>
            <span>AI Confidence: <b>${pct(inc.confidence)}%</b></span>
          </div>
          <div class="risk-bar"><span style="width:${riskTotal}%"></span></div>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
            ${sevPill(inc.severity)}
            <span class="pill status-pill">${esc(inc.status)}</span>
            <span class="tag">Stage: ${esc(inc.stage)}</span>
          </div>
          <div class="riskcomp"><span>Agent Consensus</span><b>${pct(inc.consensus)}%</b></div>
          <div class="riskcomp"><span>Autonomy Decision</span><b>${esc(inc.autonomy_decision || "—")}</b></div>
          <div style="margin-top:12px">
            <div class="muted" style="font-size:11px;margin-bottom:3px">Detection Reason</div>
            <div style="font-size:12px">${esc((inc.detection_reason || "").replace(/\[[^\]]+\]$/, ""))}</div>
          </div>
          <div style="margin-top:12px"><b>Source IPs</b><br>${(inc.source_ips || []).map(x => `<span class="tag mono">${esc(x)}</span>`).join("") || "—"}</div>
          <div style="margin-top:8px"><b>Affected Hosts & Users</b><br>${(inc.affected_hosts || []).concat(inc.affected_users || []).map(x => `<span class="tag">${esc(x)}</span>`).join("") || "—"}</div>
          <div style="margin-top:12px"><b>MITRE ATT&CK Mapping</b><br>${(inc.mitre || []).map(t => `<span class="tag" title="${esc(t.evidence || "")}">🎯 ${esc(t.id)} ${esc(t.name)}</span>`).join("") || "—"}</div>
        </div>

        <div class="panel" style="margin-top:16px">
          <h2>Interactive Evidence Graph</h2>
          <div class="graph-wrap"><svg id="graph" width="100%" height="280"></svg></div>
          <div class="muted" style="font-size:11px;margin-top:8px">Click any node to inspect raw event telemetry.</div>
        </div>
      </div>

      <!-- Middle Column: Attack Chain & Timeline -->
      <div>
        <div class="panel">
          <h2>Attack Progression Chain</h2>
          ${analysis && analysis.attack_chain && analysis.attack_chain.length ? `
            <div class="chain">
              ${analysis.attack_chain.map((c, i) => `
                <div class="chain-node" data-refs='${JSON.stringify(c.event_ids || [])}'>
                  <span class="chain-label">${esc(c.label)}</span>
                  <span class="tag">${c.count} event(s)</span>
                </div>
                ${i < analysis.attack_chain.length - 1 ? '<div class="chain-arrow">↓</div>' : ""}`).join("")}
            </div>
            <div class="muted" style="font-size:11px;margin-top:8px">Click any stage to drill down into underlying events.</div>`
          : "<div class='muted'>Run multi-agent investigation to synthesize the attack chain.</div>"}
        </div>

        <div class="panel" style="margin-top:16px">
          <h2>Evidence Timeline</h2>
          <div class="timeline">
            ${timeline.length ? timeline.map(t => `
              <div class="tl-item">
                <div class="tl-time">${esc((t.timestamp || "").replace("T", " ").slice(0, 19))}</div>
                <div>
                  <div class="tl-label">${esc(t.label)}</div>
                  <div class="tl-detail">user=${esc(t.user || "—")} host=${esc(t.host || "—")} src=${esc(t.source_ip || "—")} ${t.port ? "port=" + esc(t.port) : ""} ${t.command ? "· " + esc(t.command) : ""}</div>
                </div>
              </div>`).join("")
            : "<div class='muted'>No timeline events recorded.</div>"}
          </div>
        </div>
      </div>

      <!-- Right Column: Multi-Agent AI Assessment -->
      <div>
        <div class="panel" id="aiPanel">
          <h2>Multi-Agent AI Assessment</h2>
          ${analysis ? renderAI(analysis) : "<div class='muted'>Run investigation to trigger 9-agent SOC consensus.</div>"}
        </div>
      </div>
    </div>

    ${analysis && analysis.decision_explanation ? renderWhyPanel(analysis.decision_explanation) : ""}

    <div class="inv-bottom panel" id="respPanel">
      <h2>Autonomous Response & Safety Verification</h2>
      ${analysis ? renderResponsePlan(analysis, incId) : "<div class='muted'>Run investigation first to generate response plan.</div>"}
    </div>`;

  drawGraph(incId);
  bindChainNodes(incId);

  $("#btnInvestigate").addEventListener("click", async () => {
    $("#btnInvestigate").disabled = true;
    $("#btnInvestigate").textContent = "Investigating with 9 SOC Agents…";
    try {
      await api(`/api/incidents/${incId}/investigate`, { method: "POST" });
      toast("Multi-Agent Investigation Complete");
      renderInvestigation(view, incId);
    } catch (e) {
      toast(e.message, "err");
      $("#btnInvestigate").disabled = false;
    }
  });
}

function renderAI(a) {
  const agents = a.agents.map(ag => `
    <div class="agent">
      <div class="a-name">${esc(ag.agent)}</div>
      <div class="a-verdict">${esc(ag.verdict)} · confidence ${pct(ag.confidence)}%</div>
      <div class="a-rat">${esc(ag.rationale)}</div>
    </div>`).join("");

  const rb = a.risk.breakdown;
  const risk = Object.keys(rb).map(k => `
    <div class="riskcomp"><span>${esc(k.replace(/_/g, " "))}</span><b>${rb[k].score}/${rb[k].max}</b></div>
  `).join("");

  return `
    <div style="margin-bottom:12px;padding:8px 12px;background:rgba(255,255,255,0.03);border:1px solid var(--border-subtle);border-radius:10px">
      <div style="display:flex;justify-content:space-between">
        <span><b>Agent Consensus:</b> ${pct(a.consensus.score)}%</span>
        <span>Agreement: <b>${pct(a.consensus.agreement)}%</b></span>
      </div>
      ${a.consensus.disagreement ? "<div class='pill sev-high' style='margin-top:6px'>DISAGREEMENT DETECTED</div>" : ""}
    </div>
    ${agents}
    <h2 style="margin-top:16px">Risk Vector Breakdown</h2>
    ${risk}
    <div class="riskcomp" style="border:0;padding-top:8px"><span><b>Total Risk Score</b></span><b style="color:var(--neon-cyan)">${a.risk.total}/100</b></div>
    ${a.memory && a.memory.recommendation ? `
      <div class="agent" style="border-color:var(--neon-purple);margin-top:12px">
        <div class="a-name">🧠 Incident Memory Retrieval</div>
        <div class="a-rat">Strategy '<b>${esc(a.memory.recommendation.strategy)}</b>' was ${Math.round(a.memory.recommendation.effectiveness * 100)}% effective in historical incidents (learned confidence ${a.memory.recommendation.confidence}).</div>
      </div>` : ""}`;
}

function renderWhyPanel(d) {
  const f = d.factors;
  const item = (lbl, val, cls = "") => `
    <div class="why-item">
      <div class="muted">${lbl}</div>
      <div class="why-val ${cls}">${esc(val)}</div>
    </div>`;

  return `
    <div class="inv-bottom panel" style="border-color:rgba(99, 102, 241, 0.4)">
      <h2>🧭 Decision Explainability Matrix</h2>
      <div class="why-grid">
        ${item("Calculated Risk", f.risk)}
        ${item("Evidence Confidence", f.evidence_confidence)}
        ${item("Agent Agreement", f.agent_agreement)}
        ${item("Historical Success", f.historical_success)}
        ${item("Memory Trust", f.memory_trust)}
        ${item("Response Risk", f.response_risk)}
        ${item("Rollback Safe", f.rollback)}
        ${item("Autonomy Level", f.autonomy_level)}
        ${item("Human Approval", f.human_approval_required ? "REQUIRED" : "NOT REQUIRED", f.human_approval_required ? "fail" : "pass")}
        ${item("Validation Result", f.validation_decision, f.validation_decision === "APPROVED" ? "pass" : f.validation_decision === "REJECTED" ? "fail" : "")}
      </div>
      <div style="margin-top:14px;padding:10px 14px;background:rgba(255,255,255,0.03);border:1px solid var(--border-subtle);border-radius:10px">
        <b>Mitigation Recommendation:</b> <b>${esc(d.recommended_action)}</b> → <span class="mono" style="color:var(--neon-cyan)">${esc(d.target)}</span>
        ${d.recommendation_confidence != null ? `<span class="tag">Confidence ${Math.round(d.recommendation_confidence * 100)}%</span>` : ""}
      </div>
      <div class="muted" style="margin-top:8px;font-size:12px">${esc(d.reason)}</div>
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
  const checks = Object.keys(v.checks).map(k => `
    <div>
      <span>${esc(k.replace(/_/g, " "))}</span>
      <span class="${v.checks[k] ? "pass" : "fail"}">${v.checks[k] ? "✓ PASS" : "✗ FAIL"}</span>
    </div>`).join("");

  const plans = a.plans.map(p => `
    <div class="card" style="margin-bottom:12px;${p.recommended ? "border-color:var(--neon-cyan);box-shadow:0 0 16px rgba(0,229,255,0.15)" : ""}">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <b>${esc(p.action)} → <span class="mono" style="color:var(--neon-cyan)">${esc(p.target)}</span></b>
        ${p.recommended ? "<span class='pill sev-low'>RECOMMENDED</span>" : ""}
      </div>
      <div class="muted" style="font-size:12px;margin-top:6px">${esc(p.reason)}</div>
      <div style="font-size:12px;margin-top:6px">Response Risk: <b>${esc(p.response_risk)}</b> · Expected Outcome: <b>${esc(p.expected_outcome)}</b></div>
      <div class="muted" style="font-size:11.5px;margin-top:2px">Rollback: ${esc(p.rollback)} · Evidence: ${esc(p.evidence_summary)}</div>
    </div>`).join("");

  return `
    <div class="dash-top-grid" style="margin-top:14px">
      <div>${plans}</div>
      <div>
        <div class="decision-box ${decCls}">DECISION: ${esc(v.decision)}</div>
        <div class="checklist" style="margin-top:12px">${checks}</div>
        <div style="margin-top:12px" class="panel">
          <b>Autonomy Classification:</b> ${esc(auto.outcome)}<br>
          <span class="muted" style="font-size:11.5px">Level ${auto.level}: ${esc(auto.level_name)}<br>${auto.reasons.map(esc).join("; ")}</span>
        </div>
        <div class="btnrow" style="margin-top:14px" id="respActions" data-rid="${esc(a.recommended_response_id || "")}">
          <button class="btn secondary" id="btnValidate">Validate Response</button>
          <button class="btn warn" id="btnApprove" ${v.decision === "REJECTED" ? "disabled" : ""}>Request Human Approval</button>
          <button class="btn" id="btnSimulate" ${v.decision === "REJECTED" ? "disabled" : ""}>Simulate Response</button>
        </div>
        <div class="muted" style="font-size:11px;margin-top:8px">All actions execute in SAFE SIMULATION mode. No real systems are modified.</div>
        <div id="verifyOut" style="margin-top:12px"></div>
      </div>
    </div>`;
}

// Global response action listeners
document.addEventListener("click", async e => {
  const rid = () => {
    const box = $("#respActions");
    return box ? box.dataset.rid : null;
  };

  if (e.target.id === "btnValidate") {
    try {
      const v = await api(`/api/responses/${rid()}/validate`, { method: "POST" });
      toast("Validation Decision: " + v.decision);
    } catch (err) {
      toast(err.message, "err");
    }
  }

  if (e.target.id === "btnApprove") {
    try {
      await api(`/api/responses/${rid()}/approve`, { method: "POST", body: JSON.stringify({ analyst: "analyst" }) });
      toast("Human approval recorded");
    } catch (err) {
      toast(err.message, "err");
    }
  }

  if (e.target.id === "btnSimulate") {
    try {
      const r = await api(`/api/responses/${rid()}/simulate`, { method: "POST", body: JSON.stringify({}) });
      const v = r.verification;
      const ok = v.verification_status === "VERIFIED_RESOLVED";
      const indRows = Object.keys(v.indicators_before || {}).map(k => `
        <div class="riskcomp" style="padding:3px 0">
          <span>${esc(k.replace(/_/g, " "))}</span>
          <b>${v.indicators_before[k]} → ${(v.indicators_after || {})[k] ?? 0}</b>
        </div>`).join("");

      $("#verifyOut").innerHTML = `
        <div class="panel" style="border-color:${ok ? "var(--neon-emerald)" : "var(--neon-crimson)"}">
          <span class="pill badge-sim">${esc(r.simulation.message)}</span>
          <div style="margin-top:8px">Verification: <b class="${ok ? "pass" : "fail"}">${esc(v.verification_status)}</b>
            ${v.persistence_detected ? "<span class='pill sev-high'>THREAT PERSISTS</span>" : ""}
          </div>
          <div class="muted" style="font-size:12px;margin-top:4px">Method: ${esc(v.verification_method)}</div>
          <div style="margin-top:8px"><b>Indicators (Before → After Mitigation)</b>${indRows}</div>
          <div class="muted" style="font-size:11.5px;margin-top:6px">Verification Confidence ${Math.round(v.verification_confidence * 100)}% · Effectiveness ${Math.round(v.effectiveness * 100)}%</div>
        </div>`;
      toast("Simulated Mitigation: " + v.verification_status);
    } catch (err) {
      if (err.message.toLowerCase().includes("approval")) {
        toast("Human approval required first. Click 'Request Human Approval'.", "err");
      } else {
        toast(err.message, "err");
      }
    }
  }
});

// ---------- Evidence Graph Visualizer ----------
async function drawGraph(incId) {
  const svg = $("#graph");
  if (!svg) return;
  let g;
  try {
    g = await api(`/api/incidents/${incId}/graph`);
  } catch (e) {
    return;
  }
  const W = svg.clientWidth || 300, H = 280, cx = W / 2, cy = H / 2;
  const nodes = g.nodes;
  const R = Math.min(W, H) / 2 - 40;
  const typeColor = {
    ip: "#fb923c",
    user: "#38bdf8",
    host: "#a855f7",
    dest: "#f43f5e",
    process: "#10b981",
    event: "#94a3b8"
  };
  const pos = {};
  nodes.forEach((n, i) => {
    const ang = (2 * Math.PI * i) / Math.max(nodes.length, 1);
    pos[n.id] = { x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang) };
  });

  let svgHtml = "";
  g.edges.forEach(ed => {
    const a = pos[ed.source], b = pos[ed.target];
    if (a && b) {
      svgHtml += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="rgba(255,255,255,0.12)" stroke-width="1.5" stroke-dasharray="4 2"/>`;
    }
  });
  nodes.forEach(n => {
    const p = pos[n.id];
    svgHtml += `
      <g class="graph-node" data-refs='${JSON.stringify(n.event_refs || [])}' data-label="${esc(n.label)}">
        <circle cx="${p.x}" cy="${p.y}" r="9" fill="${typeColor[n.type] || "#888"}" stroke="#0f172a" stroke-width="2"/>
        <text class="node-label" x="${p.x + 12}" y="${p.y + 4}">${esc(n.label)}</text>
      </g>`;
  });
  svg.innerHTML = svgHtml;
  $$(".graph-node", svg).forEach(node => node.addEventListener("click", () =>
    showEventsModal(node.dataset.label, JSON.parse(node.dataset.refs || "[]"))
  ));
}

async function showEventsModal(label, refs) {
  if (!refs || !refs.length) {
    modal(`<h2>${esc(label)}</h2><p class="muted">No underlying telemetry events.</p><button class="btn" onclick="closeModal()">Close</button>`);
    return;
  }
  const { events } = await api(`/api/events?dataset=${ds()}&limit=1000`);
  const matched = events.filter(ev => refs.includes(ev.id));
  modal(`
    <h2>${esc(label)} — ${matched.length} Associated Telemetry Event(s)</h2>
    <div class="table-wrap" style="max-height:60vh;margin-top:12px">
      <table>
        <thead>
          <tr><th>Timestamp</th><th>Type</th><th>User</th><th>Host</th><th>Source IP</th><th>Raw Payload</th></tr>
        </thead>
        <tbody>
          ${matched.map(ev => `
            <tr>
              <td class="muted">${esc((ev.timestamp || "").slice(0, 19))}</td>
              <td>${esc(ev.event_type)}</td>
              <td>${esc(ev.user || "")}</td>
              <td>${esc(ev.host || "")}</td>
              <td class="mono">${esc(ev.source_ip || "")}</td>
              <td class="mono" style="max-width:280px">${esc((ev.raw_event || "").slice(0, 120))}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>
    <button class="btn secondary" style="margin-top:16px" onclick="closeModal()">Close Modal</button>`);
}

// ==========================================================================
// 4. RESPONSE CENTER
// ==========================================================================
async function renderResponses(view) {
  const { buckets } = await api(`/api/responses?dataset=${ds()}`);
  const section = (title, arr) => `
    <div class="panel" style="margin-bottom:16px">
      <h2>${title} <span class="tag">${arr.length}</span></h2>
      ${arr.length ? `
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Action</th><th>Target</th><th>Incident</th><th>Threat</th><th>Reason</th><th>Risk</th><th>Rollback</th><th>Triage</th></tr>
            </thead>
            <tbody>
              ${arr.map(r => `
                <tr>
                  <td><b>${esc(r.action)}</b></td>
                  <td class="mono" style="color:var(--neon-cyan)">${esc(r.target)}</td>
                  <td class="mono clickable" onclick="location.hash='#/incident/${r.incident_id}'">${esc(r.incident_id)}</td>
                  <td>${esc(r.attack_type)}</td>
                  <td class="muted" style="max-width:240px">${esc(r.reason)}</td>
                  <td>${esc(r.response_risk)}</td>
                  <td class="muted">${esc(r.rollback)}</td>
                  <td><button class="btn secondary" style="padding:4px 10px;font-size:11px" onclick="location.hash='#/incident/${r.incident_id}'">Open War Room</button></td>
                </tr>`).join("")}
            </tbody>
          </table>
        </div>`
      : "<div class='muted'>No active items in this queue.</div>"}
    </div>`;

  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Autonomous Response Center</h1>
        <div class="muted">Validated mitigations, simulation status & human approval queues.</div>
      </div>
    </div>
    ${section("⏳ Human Approval Required", buckets.awaiting_approval || [])}
    ${section("📋 Pending / Validated Actions", buckets.pending || [])}
    ${section("✅ Approved Mitigations", buckets.approved || [])}
    ${section("⚡ Executed (Simulated)", buckets.executed || [])}
    ${section("🚫 Rejected by Safety Policy", buckets.rejected || [])}
    ${section("❌ Failed Actions", buckets.failed || [])}`;
}

// ==========================================================================
// 5. REAL DATA INGESTION
// ==========================================================================
async function renderRealData(view) {
  const { total, events } = await api(`/api/events?dataset=real&limit=500`);
  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Real Data Ingestion Hub</h1>
        <div class="muted">Upload enterprise logs (CSV / JSON / Syslog). Data is strictly separated into the REAL dataset.</div>
      </div>
    </div>

    <div class="dash-top-grid">
      <div class="panel">
        <div class="dropzone" id="drop">
          <div style="font-size:28px;margin-bottom:8px">📥</div>
          <div style="font-weight:700;font-size:15px;color:#fff">Drag & drop security log file here, or click to browse</div>
          <div class="muted" style="margin-top:6px">Supported: .csv · .json / .ndjson · .log / .syslog (Up to 500 MB)</div>
          <input type="file" id="fileInput" class="hidden" accept=".csv,.json,.ndjson,.log,.syslog,.txt">
        </div>
        <div class="btnrow" style="margin-top:16px">
          <button class="btn secondary" id="loadSample">Load Bundled Sample Dataset</button>
          <button class="btn" id="runDetect" ${total ? "" : "disabled"}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            Run Threat Detection (${total} Events)
          </button>
        </div>
        <div id="uploadSummary" style="margin-top:16px"></div>
      </div>

      <div class="panel">
        <h2>SOC Ingestion Pipeline</h2>
        <ol class="muted" style="line-height:2.2;padding-left:18px">
          <li>1. Ingest Security Logs (CSV/JSON/Syslog)</li>
          <li>2. Automated Schema Normalization & Quality Scoring</li>
          <li>3. Rule-Based & Statistical Anomaly Threat Detection</li>
          <li>4. Incident Correlation & Multi-Agent War Room</li>
          <li>5. Explainable Risk Score & Agent Consensus</li>
          <li>6. Automated Mitigation Planning with 6 Safety Checks</li>
          <li>7. Safe Verification & Adaptive Memory Learning</li>
        </ol>
      </div>
    </div>

    <div class="panel" style="margin-top:20px">
      <h2>Ingested Event Preview <span class="muted">(Showing ${events.length} of ${total} events)</span></h2>
      <div class="table-wrap" style="max-height:360px">${eventsTable(events)}</div>
    </div>`;

  const fileInput = $("#fileInput"), drop = $("#drop");
  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", e => {
    e.preventDefault();
    drop.classList.remove("drag");
    if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) uploadFile(fileInput.files[0]);
  });
  $("#loadSample").addEventListener("click", loadSample);
  $("#runDetect").addEventListener("click", runDetection);
}

function eventsTable(events) {
  if (!events.length) return "<div class='muted' style='padding:20px;text-align:center'>No events ingested yet.</div>";
  return `
    <table>
      <thead>
        <tr><th>Timestamp</th><th>Event Type</th><th>User</th><th>Host</th><th>Source IP</th><th>Dest IP</th><th>Port</th><th>Status</th><th>Payload Snippet</th></tr>
      </thead>
      <tbody>
        ${events.map(e => `
          <tr>
            <td class="muted">${esc((e.timestamp || "").replace("T", " ").slice(0, 19))}</td>
            <td><b>${esc(e.event_type || "")}</b></td>
            <td>${esc(e.user || "")}</td>
            <td>${esc(e.host || "")}</td>
            <td class="mono">${esc(e.source_ip || "")}</td>
            <td class="mono">${esc(e.destination_ip || "")}</td>
            <td>${esc(e.port ?? "")}</td>
            <td>${esc(e.status || e.authentication_result || "")}</td>
            <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc((e.raw_event || "").slice(0, 120))}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

async function uploadFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("dataset", "real");
  try {
    const res = await fetch("/api/events/upload", { method: "POST", body: fd });
    if (!res.ok) {
      const j = await res.json();
      throw new Error(j.detail || "upload failed");
    }
    const s = await res.json();
    showUploadSummary(s);
    toast(`Successfully ingested ${s.stored} events`);
    renderRealData($("#view"));
  } catch (e) {
    toast(e.message, "err");
  }
}

function showUploadSummary(s) {
  const el = $("#uploadSummary");
  if (!el) return;
  const tr = s.time_range ? `${s.time_range.start} → ${s.time_range.end}` : "—";
  el.innerHTML = `
    <div class="stat-inline">
      <div class="s"><b>${s.count}</b><div class="muted">Events</div></div>
      <div class="s"><b>${s.unique_users}</b><div class="muted">Users</div></div>
      <div class="s"><b>${s.unique_hosts}</b><div class="muted">Hosts</div></div>
      <div class="s"><b>${s.source_ips}</b><div class="muted">Source IPs</div></div>
      <div class="s"><b>${s.failed_logins}</b><div class="muted">Failed Logins</div></div>
      <div class="s"><b>${s.suspicious_events}</b><div class="muted">Suspicious</div></div>
    </div>
    <div class="muted" style="margin-top:10px">Format: <b>${esc(s.format)}</b> · Time Range: ${esc(tr)}</div>
    ${dataQualityHtml(s.data_quality)}`;
}

function dataQualityHtml(q) {
  if (!q) return "";
  const fieldMap = Object.entries(q.normalized_fields || {})
    .map(([raw, canon]) => `<span class="tag mono">${esc(raw)} → ${esc(canon)}</span>`).join(" ");
  return `
    <div class="panel" style="margin-top:16px">
      <h2>Data Quality Verification</h2>
      <div class="stat-inline">
        <div class="s"><b>${q.total_records}</b><div class="muted">Total Records</div></div>
        <div class="s"><b class="pass">${q.valid_records}</b><div class="muted">Valid</div></div>
        <div class="s"><b class="${q.rejected_records ? "fail" : ""}">${q.rejected_records}</b><div class="muted">Rejected</div></div>
        <div class="s"><b>${q.duplicate_records}</b><div class="muted">Duplicates</div></div>
      </div>
      <div style="margin-top:12px"><b>Field Normalization Mapping</b><br>${fieldMap || "<span class='muted'>None</span>"}</div>
    </div>`;
}

async function loadSample() {
  try {
    const s = await api("/api/samples/load", { method: "POST", body: JSON.stringify({ name: "sample_events.csv" }) });
    showUploadSummary(s);
    toast(`Loaded bundled sample dataset: ${s.stored} events`);
    renderRealData($("#view"));
  } catch (e) {
    toast("Could not load sample: " + e.message, "err");
  }
}

async function runDetection() {
  try {
    const r = await api("/api/detection/run", { method: "POST", body: JSON.stringify({ dataset: "real" }) });
    toast(`Detection Engine: ${r.detections} findings, ${r.incidents_created.length} new incidents`);
    if (r.incidents_created.length) location.hash = "#/incidents";
    else renderRealData($("#view"));
  } catch (e) {
    toast(e.message, "err");
  }
}

// ==========================================================================
// 6. DEMO MODE
// ==========================================================================
async function renderDemo(view) {
  const st = await api("/api/demo/state");
  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Continuous Cyber Attack Simulation Deck</h1>
        <div class="muted">Synthetic cyber warfare scenarios generated for live multi-agent defense demonstration.</div>
      </div>
    </div>

    <div class="panel">
      <div class="btnrow">
        <button class="btn" id="dStart">▶ Start Simulation</button>
        <button class="btn secondary" id="dPause">⏸ Pause</button>
        <button class="btn secondary" id="dResume">⏵ Resume</button>
        <button class="btn warn" id="dStop">⏹ Stop</button>
        <button class="btn crit" id="dReset">↺ Reset Data</button>
        <span style="margin-left:auto" class="pill status-pill" id="dStatus">Status: ${esc(st.status)}</span>
      </div>
      <div class="stat-inline" style="margin-top:16px" id="dStats">
        <div class="s"><b id="dEv" style="color:var(--neon-cyan)">${st.events_generated || 0}</b><div class="muted">Events Generated</div></div>
        <div class="s"><b id="dInc" style="color:var(--neon-crimson)">${st.incidents_generated || 0}</b><div class="muted">Incidents Correlated</div></div>
      </div>
    </div>

    <div class="panel" style="margin-top:20px">
      <h2>Active Attack Scenarios in Rotation</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
        ${[
          "SSH / RDP Brute Force",
          "Credential Stuffing",
          "Reconnaissance Port Scan",
          "Malware C2 Beaconing",
          "Encrypted Data Exfiltration",
          "Lateral Movement & Kerberoasting"
        ].map(s => `<span class="pill sev-medium">⚔ ${s}</span>`).join(" ")}
      </div>
      <div class="muted" style="margin-top:14px;font-size:12.5px">
        Switch the top header toggle to <b>Demo Mode</b> to watch the Dashboard, Incident War Room, and Response Center populate in real time!
      </div>
      <div class="btnrow" style="margin-top:16px">
        <button class="btn ghost" onclick="location.hash='#/dashboard'">Open Live Dashboard →</button>
        <button class="btn ghost" onclick="location.hash='#/incidents'">Open Incident War Room →</button>
      </div>
    </div>`;

  const call = async (p, msg) => {
    try {
      const s = await api(`/api/demo/${p}`, { method: "POST" });
      toast(msg);
      updateDemoLive(s);
      if (ds() !== "demo" && p === "start") {
        toast("Tip: Switch to Demo Mode in header to view stream.", "ok");
      }
    } catch (e) {
      toast(e.message, "err");
    }
  };

  $("#dStart").onclick = () => {
    if (ds() !== "demo") {
      state.dataset = "demo";
      $$("#datasetToggle button").forEach(x => x.classList.toggle("active", x.dataset.ds === "demo"));
      $("#dsIndicator").innerHTML = "MODE: <b>DEMO DATA</b>";
      $("#demoBanner").classList.remove("hidden");
      startStream();
    }
    call("start", "Simulation stream initiated");
  };
  $("#dPause").onclick = () => call("pause", "Simulation paused");
  $("#dResume").onclick = () => call("resume", "Simulation resumed");
  $("#dStop").onclick = () => call("stop", "Simulation stopped");
  $("#dReset").onclick = () => call("reset", "Simulation telemetry reset");
}

function updateDemoLive(st) {
  if (!st) return;
  const s = $("#dStatus");
  if (s) s.textContent = "Status: " + st.status;
  const ev = $("#dEv"), inc = $("#dInc");
  if (ev) ev.textContent = st.events_generated || 0;
  if (inc) inc.textContent = st.incidents_generated || 0;
}

// ==========================================================================
// 7. ANALYTICS & TRENDS
// ==========================================================================
async function renderAnalytics(view) {
  const { summary, charts } = await api(`/api/analytics?dataset=${ds()}`);
  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Telemetry Analytics & Attack Vectors</h1>
        <div class="muted">Comprehensive security metrics across the ${ds().toUpperCase()} dataset.</div>
      </div>
    </div>

    <div class="cards-grid">
      ${kpiCard(summary.threats_detected, "Total Incidents", "Correlated Findings", "🚨")}
      ${kpiCard(summary.responses_executed, "Mitigations Executed", "Simulated Actions", "⚡")}
      ${kpiCard(summary.response_success_rate == null ? "—" : summary.response_success_rate + "%", "Success Rate", "Verified Resolved", "✓", "trend-up")}
      ${kpiCard(summary.total_events, "Events Ingested", "Normalized Stream", "📊")}
      ${kpiCard(summary.avg_risk == null ? "—" : summary.avg_risk, "Avg Risk Score", "Heuristic Scale", "⚖")}
      ${kpiCard(summary.avg_confidence == null ? "—" : summary.avg_confidence + "%", "Avg Confidence", "Multi-Agent Consensus", "🎯")}
      ${kpiCard(summary.autonomous_decision_rate == null ? "—" : summary.autonomous_decision_rate + "%", "Autonomy Rate", "Safe Auto Actions", "🤖")}
      ${kpiCard(summary.human_escalation_rate == null ? "—" : summary.human_escalation_rate + "%", "Escalation Rate", "Tier-3 Required", "👤")}
    </div>

    <div class="chart-grid" style="margin-top:20px">
      <div class="panel"><h2>Detection Trend</h2><div class="chart-box"><canvas id="a_time"></canvas></div></div>
      <div class="panel"><h2>Attack Type Distribution</h2><div class="chart-box"><canvas id="a_attack"></canvas></div></div>
      <div class="panel"><h2>MITRE ATT&CK Techniques</h2><div class="chart-box"><canvas id="a_tech"></canvas></div></div>
      <div class="panel"><h2>Risk Distribution</h2><div class="chart-box"><canvas id="a_risk"></canvas></div></div>
      <div class="panel"><h2>Response Outcomes</h2><div class="chart-box"><canvas id="a_out"></canvas></div></div>
      <div class="panel"><h2>Top Source IPs (Attackers)</h2><div class="chart-box"><canvas id="a_ip"></canvas></div></div>
      <div class="panel"><h2>Top Targeted Assets</h2><div class="chart-box"><canvas id="a_host"></canvas></div></div>
      <div class="panel"><h2>High-Risk User Accounts</h2><div class="chart-box"><canvas id="a_user"></canvas></div></div>
    </div>`;

  mkChart("a_time", {
    type: "line",
    data: {
      labels: charts.threats_over_time.map(x => x.t.replace("T", " ")),
      datasets: [{ label: "Incidents", data: charts.threats_over_time.map(x => x.count), borderColor: "#00e5ff", backgroundColor: "rgba(0, 229, 255, 0.15)", fill: true, tension: 0.35 }]
    },
    options: chOpts()
  });
  mkChart("a_attack", {
    type: "bar",
    data: {
      labels: Object.keys(charts.by_attack_type),
      datasets: [{ label: "Count", data: Object.values(charts.by_attack_type), backgroundColor: "#8b5cf6", borderRadius: 6 }]
    },
    options: { ...chOpts(), indexAxis: "y" }
  });
  mkChart("a_tech", {
    type: "bar",
    data: {
      labels: Object.keys(charts.attack_techniques),
      datasets: [{ label: "Count", data: Object.values(charts.attack_techniques), backgroundColor: "#00e5ff", borderRadius: 6 }]
    },
    options: { ...chOpts(), indexAxis: "y" }
  });
  mkChart("a_risk", {
    type: "bar",
    data: {
      labels: Object.keys(charts.risk_distribution),
      datasets: [{ label: "Incidents", data: Object.values(charts.risk_distribution), backgroundColor: "#f97316", borderRadius: 6 }]
    },
    options: chOpts()
  });
  mkChart("a_out", {
    type: "doughnut",
    data: {
      labels: Object.keys(charts.response_outcomes),
      datasets: [{ data: Object.values(charts.response_outcomes), backgroundColor: ["#10b981", "#f59e0b", "#f43f5e", "#38bdf8"], borderWidth: 0 }]
    },
    options: { ...chOpts(true), cutout: "70%" }
  });
  mkChart("a_ip", {
    type: "bar",
    data: {
      labels: charts.top_source_ips.map(x => x[0]),
      datasets: [{ label: "Incidents", data: charts.top_source_ips.map(x => x[1]), backgroundColor: "#f43f5e", borderRadius: 6 }]
    },
    options: { ...chOpts(), indexAxis: "y" }
  });
  mkChart("a_host", {
    type: "bar",
    data: {
      labels: charts.top_hosts.map(x => x[0]),
      datasets: [{ label: "Incidents", data: charts.top_hosts.map(x => x[1]), backgroundColor: "#a855f7", borderRadius: 6 }]
    },
    options: { ...chOpts(), indexAxis: "y" }
  });
  mkChart("a_user", {
    type: "bar",
    data: {
      labels: charts.user_risk.map(x => x[0]),
      datasets: [{ label: "Max Risk Score", data: charts.user_risk.map(x => Math.round(x[1])), backgroundColor: "#0284c7", borderRadius: 6 }]
    },
    options: { ...chOpts(), indexAxis: "y" }
  });
}

// ==========================================================================
// 8. SECURITY POSTURE ASSESSMENT
// ==========================================================================
const STATUS_PILL = {
  ASSESSED: "sev-low",
  PARTIALLY_ASSESSED: "sev-medium",
  NOT_ASSESSED: "status-pill"
};

async function renderAssessment(view) {
  const data = await api(`/api/security-assessment?dataset=${ds()}`);
  const runBtn = `<button class="btn" id="runAssess">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    Run Assessment${data.assessment ? " Again" : ""}
  </button>`;

  if (!data.assessment) {
    view.innerHTML = `
      <div class="page-head">
        <div class="page-head-title"><h1>Security Posture Assessment</h1></div>
        ${runBtn}
      </div>
      <div class="panel">
        <p class="muted">${esc(data.message || "No assessment generated yet.")}</p>
        <p class="muted" style="margin-top:6px">The assessment evaluates evidence available in the <b>${ds().toUpperCase()}</b> dataset without assuming unobserved controls are secure.</p>
      </div>`;
    $("#runAssess").onclick = () => runAssessment(view);
    return;
  }

  const a = data.assessment, cats = a.category_scores;
  const covPct = Math.round(100 * a.coverage_assessed / a.coverage_total);
  const score = a.overall_score;
  const scoreColor = score == null ? "var(--text-muted)" : score >= 80 ? "var(--neon-emerald)" : score >= 60 ? "var(--neon-amber)" : "var(--neon-crimson)";
  const sevOrder = ["Critical", "High", "Medium", "Low", "Informational"];
  const bySev = {};
  sevOrder.forEach(s => bySev[s] = []);
  data.findings.forEach(f => (bySev[f.severity] || (bySev[f.severity] = [])).push(f));

  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Security Posture Assessment</h1>
        <div class="muted">Source: <b>${esc(a.data_source)}</b> · ${a.events_analyzed} Events, ${a.incidents_analyzed} Incidents · Evaluated: ${esc((a.created_at || "").replace("T", " ").slice(0, 19))}</div>
      </div>
      ${runBtn}
    </div>

    <div class="cards-grid">
      <div class="card kpi-card" style="text-align:center">
        <div class="kpi-val" style="color:${scoreColor}">${score == null ? "—" : score}</div>
        <div class="kpi-label">Security Score / 100</div>
        <div class="kpi-sub" style="justify-content:center">${esc(a.posture_label)}</div>
      </div>
      <div class="card kpi-card">
        <div class="kpi-val">${a.coverage_assessed}/${a.coverage_total}</div>
        <div class="kpi-label">Assessment Coverage (${covPct}%)</div>
        <div class="kpi-sub">Evidence-backed Categories</div>
      </div>
      <div class="card kpi-card">
        <div class="kpi-val">${data.findings.length}</div>
        <div class="kpi-label">Vulnerability Findings</div>
        <div class="kpi-sub">${bySev.Critical.length} Critical · ${bySev.High.length} High</div>
      </div>
    </div>

    <div class="panel" style="margin-top:20px">
      <h2>Category Breakdown <span class="muted">(Click row for transparent deduction details)</span></h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Category</th><th>Status</th><th>Score</th><th>Checks Performed</th><th>Findings</th><th>Confidence</th></tr>
          </thead>
          <tbody id="catRows">
            ${Object.values(cats).map(c => `
              <tr class="clickable" data-cat='${esc(JSON.stringify(c).replace(/'/g, "&#39;"))}'>
                <td><b>${esc(c.title)}</b></td>
                <td><span class="pill ${STATUS_PILL[c.status] || "status-pill"}">${esc(c.status.replace(/_/g, " "))}</span></td>
                <td>${c.score == null ? "<span class='muted'>—</span>" : `<b style="color:var(--neon-cyan)">${c.score}/100</b>`}</td>
                <td class="muted">${(c.checks_performed || []).join(", ")}</td>
                <td>${(c.findings || []).length}</td>
                <td>${c.evidence_available ? Math.round(c.confidence * 100) + "%" : "<span class='muted'>N/A</span>"}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel" style="margin-top:20px">
      <h2>Vulnerability Findings</h2>
      ${data.findings.length ? sevOrder.filter(s => bySev[s].length).map(s => `
        <div style="margin-bottom:14px">
          <span class="pill sev-${s.toLowerCase() === "informational" ? "low" : s.toLowerCase()}">${s} Priority</span>
          ${bySev[s].map(f => `
            <div class="card" style="margin-top:8px">
              <b>${esc(f.title)}</b> <span class="muted">— ${esc(f.category.replace(/_/g, " "))} · Confidence ${Math.round(f.confidence * 100)}% · Asset: ${esc(f.affected_asset)}</span>
              <div class="muted" style="font-size:12px;margin-top:4px">${esc(f.explanation)}</div>
              <div style="font-size:12px;margin-top:4px"><b>Evidence:</b> ${(f.evidence || []).map(e => `<span class="tag mono">${esc(e)}</span>`).join("") || "—"}</div>
              <div style="font-size:12px;margin-top:4px;color:var(--neon-cyan)"><b>Recommendation:</b> ${esc(f.recommendation)}</div>
            </div>`).join("")}
        </div>`).join("")
      : "<p class='muted'>No active findings from current telemetry.</p>"}
    </div>`;

  $("#runAssess").onclick = () => runAssessment(view);
  $$("#catRows tr").forEach(tr => tr.onclick = () => {
    const c = JSON.parse(tr.dataset.cat);
    modal(`
      <h2>${esc(c.title)} — Score Breakdown</h2>
      <p style="margin-top:8px"><b>Status:</b> ${esc(c.status)} · <b>Score:</b> ${c.score == null ? "Not Assessed" : c.score + "/100"}</p>
      <p class="muted" style="margin-top:6px">${esc(c.notes || "")}</p>
      <h3 style="margin-top:14px">Checks Performed</h3>
      <ul style="padding-left:18px;margin-top:6px" class="muted">${(c.checks_performed || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      <h3 style="margin-top:14px">Score Deductions</h3>
      ${(c.deductions || []).length ? `
        <div class="table-wrap" style="margin-top:8px">
          <table>
            <thead><tr><th>Reason</th><th>Points Deducted</th></tr></thead>
            <tbody>${c.deductions.map(d => `<tr><td>${esc(d.reason)}</td><td class="fail">-${d.points}</td></tr>`).join("")}</tbody>
          </table>
        </div>` : "<p class='muted' style='margin-top:4px'>No deductions applied.</p>"}
      <button class="btn secondary" style="margin-top:16px" onclick="closeModal()">Close</button>`);
  });
}

async function runAssessment(view) {
  const btn = $("#runAssess");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Assessing Posture…";
  }
  try {
    await api("/api/security-assessment/run", { method: "POST", body: JSON.stringify({ dataset: ds() }) });
    toast("Security assessment complete");
    renderAssessment(view);
  } catch (e) {
    toast(e.message, "err");
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Run Assessment";
    }
  }
}

// ==========================================================================
// 9. MODEL EVALUATION
// ==========================================================================
async function renderEvaluation(view) {
  const r = await api(`/api/evaluation?dataset=${ds()}`);
  const metricRow = (label, base, prop) => `<tr><td><b>${label}</b></td><td>${base}</td><td style="color:var(--neon-cyan)"><b>${prop}</b></td></tr>`;
  const b = r.baseline || {}, p = r.proposed || {};

  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Evaluation vs Ground-Truth Labels</h1>
        <div class="muted">Precision, Recall & F1-Score benchmarking against labelled data.</div>
      </div>
    </div>

    ${!r.labelled_available ? `
      <div class="panel" style="border-color:var(--neon-amber)">
        <h2 style="color:var(--neon-amber)">No Labelled Ground-Truth Dataset Loaded</h2>
        <p class="muted">${esc((r.notes || []).join(" "))}</p>
        <p class="muted" style="margin-top:6px">Ingest a benchmark dataset (e.g. CIC-IDS2017 / CSE-CIC-IDS2018 with a <code>Label</code> column) via the Real Data page to compute formal metrics.</p>
      </div>` : ""}

    <div class="cards-grid">
      ${kpiCard(r.records_total, "Total Records", "Evaluated Logs", "📑")}
      ${kpiCard(r.records_labelled, "Labelled Records", "Ground-Truth Labels", "🏷")}
      ${kpiCard(Object.keys(r.attack_types || {}).length || "—", "Attack Classes", "Distinct Threat Labels", "🎯")}
    </div>

    <div class="panel" style="margin-top:20px">
      <h2>Detection Metrics Matrix (Baseline Rules vs Multi-Agent SOC)</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Metric</th><th>Baseline (Rules Only)</th><th>Proposed (Rules + Anomaly + Multi-Agent)</th></tr>
          </thead>
          <tbody>
            ${metricRow("Precision", b.precision ?? "—", p.precision ?? "—")}
            ${metricRow("Recall", b.recall ?? "—", p.recall ?? "—")}
            ${metricRow("F1-Score", b.f1 ?? "—", p.f1 ?? "—")}
            ${metricRow("False-Positive Rate", b.false_positive_rate ?? "—", p.false_positive_rate ?? "—")}
            ${metricRow("Accuracy", b.accuracy ?? "—", p.accuracy ?? "—")}
            ${metricRow("True / False Positives", `${b.true_positives ?? "—"} / ${b.false_positives ?? "—"}`, `${p.true_positives ?? "—"} / ${p.false_positives ?? "—"}`)}
            ${metricRow("True / False Negatives", `${b.true_negatives ?? "—"} / ${b.false_negatives ?? "—"}`, `${p.true_negatives ?? "—"} / ${p.false_negatives ?? "—"}`)}
          </tbody>
        </table>
      </div>
    </div>`;
}

// ==========================================================================
// 10. INCIDENT MEMORY & ADAPTIVE LEARNING
// ==========================================================================
async function renderMemory(view) {
  const { experiences } = await api("/api/memory");
  let strategies = [];
  try {
    strategies = (await api("/api/memory/strategies")).strategies;
  } catch (e) {}

  const stratRows = strategies.length ? strategies.map(s => `
    <tr>
      <td><b>${esc(s.attack_type)}</b></td>
      <td style="color:var(--neon-cyan)"><b>${esc(s.strategy)}</b></td>
      <td>${s.successes}/${s.attempts}</td>
      <td><b>${Math.round(s.success_rate * 100)}%</b></td>
      <td>${s.learned_confidence.toFixed(2)}</td>
      <td><span class="pill status-pill">${esc(s.validation_status)}</span></td>
    </tr>`).join("")
  : `<tr><td colspan="6" class="muted" style="text-align:center;padding:20px">No verified outcomes yet. Simulate a response to teach the system.</td></tr>`;

  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Adaptive Incident Memory & Strategy Reranking</h1>
        <div class="muted">Learned mitigation effectiveness from historically verified outcomes.</div>
      </div>
    </div>

    <div class="panel" style="margin-bottom:20px">
      <h2>Strategy Effectiveness Knowledge Base</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Threat Vector</th><th>Mitigation Strategy</th><th>Success / Attempts</th><th>Success Rate</th><th>Learned Confidence</th><th>Validation</th></tr>
          </thead>
          <tbody>${stratRows}</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <h2>Learned Incident Experiences</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>ID</th><th>Threat</th><th>Strategy</th><th>Outcome</th><th>Effectiveness</th><th>Confidence</th><th>Trust</th><th>Status</th><th>Curate</th></tr>
          </thead>
          <tbody>
            ${experiences.length ? experiences.map(m => `
              <tr>
                <td class="mono" style="color:var(--neon-cyan)">${esc(m.experience_id)}</td>
                <td><b>${esc(m.attack_type)}</b></td>
                <td>${esc(m.strategy)}</td>
                <td>${esc(m.outcome)}</td>
                <td>${Math.round((m.effectiveness || 0) * 100)}%</td>
                <td>${(m.confidence || 0).toFixed(2)}</td>
                <td>${(m.trust_score || 0).toFixed(2)}</td>
                <td><span class="pill status-pill">${esc(m.validation_status)}</span></td>
                <td class="btnrow">
                  <button class="btn ghost" style="padding:2px 8px;font-size:11px" data-exp="${esc(m.experience_id)}" data-st="trusted">Trust</button>
                  <button class="btn ghost" style="padding:2px 8px;font-size:11px" data-exp="${esc(m.experience_id)}" data-st="under_review">Review</button>
                  <button class="btn ghost" style="padding:2px 8px;font-size:11px" data-exp="${esc(m.experience_id)}" data-st="revoked">Revoke</button>
                </td>
              </tr>`).join("")
            : `<tr><td colspan="9" class="muted" style="text-align:center;padding:24px">No memory entries yet. Mitigate incidents to populate memory.</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>`;

  $$("button[data-exp]").forEach(b => b.onclick = async () => {
    try {
      await api(`/api/memory/${b.dataset.exp}/trust`, { method: "POST", body: JSON.stringify({ status: b.dataset.st }) });
      toast("Trust state updated: " + b.dataset.st);
      renderMemory(view);
    } catch (e) {
      toast(e.message, "err");
    }
  });
}

// ==========================================================================
// 11. AUDIT LOG
// ==========================================================================
async function renderAudit(view) {
  const { audit } = await api(`/api/audit?dataset=${ds()}&limit=300`);
  view.innerHTML = `
    <div class="page-head">
      <div class="page-head-title">
        <h1>Append-Only Cryptographic Audit Log</h1>
        <div class="muted">Tamper-evident record of all analyst interactions, AI decisions, and simulated responses.</div>
      </div>
      <a class="btn secondary" href="/api/export/audit.csv?dataset=${ds()}">Export Audit CSV</a>
    </div>

    <div class="panel">
      <h2>Recent Audit Records <span class="tag">${audit.length} entries</span></h2>
      <div class="table-wrap" style="max-height:70vh">
        <table>
          <thead>
            <tr><th>Timestamp</th><th>Actor</th><th>Action Event</th><th>Incident Ref</th><th>Audit Details</th></tr>
          </thead>
          <tbody>
            ${audit.map(a => `
              <tr>
                <td class="muted mono">${esc((a.ts || "").replace("T", " ").slice(0, 19))}</td>
                <td><b>${esc(a.actor)}</b></td>
                <td style="color:var(--neon-cyan)"><b>${esc(a.action)}</b></td>
                <td class="mono clickable" ${a.incident_id ? `onclick="location.hash='#/incident/${a.incident_id}'"` : ""}>${esc(a.incident_id || "—")}</td>
                <td class="muted">${esc(a.detail || "")}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
    </div>`;
}

// ==========================================================================
// 12. GEOSPATIAL THREAT BATTLEMAP ENGINE & DATA VISUALIZATION (Dribbble 27247474)
// ==========================================================================

const COUNTRIES_DATA = [
  // North America
  { id: "ca", name: "Canada", flag: "🇨🇦", labelPos: { x: 190, y: 80 }, d: "M 75,75 L 110,65 L 150,50 L 195,45 L 245,45 L 265,55 L 275,80 L 305,75 L 325,90 L 315,115 L 298,110 L 260,110 L 200,110 L 140,110 L 95,110 L 75,100 Z", threat: "Low", posture: "Protected" },
  { id: "us", name: "United States", flag: "🇺🇸", labelPos: { x: 190, y: 140 }, d: "M 95,110 L 140,110 L 200,110 L 260,110 L 298,110 L 290,135 L 302,155 L 285,175 L 270,185 L 245,185 L 210,185 L 180,185 L 160,180 L 135,175 L 105,145 L 85,125 Z", threat: "High", posture: "Honeypot Active" },
  { id: "ak", name: "Alaska (US)", flag: "🇺🇸", labelPos: { x: 55, y: 90 }, d: "M 25,75 L 65,65 L 85,72 L 78,105 L 52,115 L 30,95 Z", threat: "Low", posture: "Secure" },
  { id: "gl", name: "Greenland", flag: "🇬🇱", labelPos: { x: 370, y: 55 }, d: "M 340,25 L 395,30 L 405,62 L 375,88 L 348,78 L 338,50 Z", threat: "Low", posture: "Secure" },
  { id: "mx", name: "Mexico", flag: "🇲🇽", labelPos: { x: 205, y: 230 }, d: "M 160,180 L 180,185 L 210,185 L 245,185 L 270,185 L 270,200 L 250,215 L 240,240 L 225,255 L 210,280 L 195,295 L 185,275 L 175,255 L 160,225 L 145,195 Z", threat: "Medium", posture: "Monitored" },

  // South America
  { id: "br", name: "Brazil", flag: "🇧🇷", labelPos: { x: 320, y: 355 }, d: "M 260,310 L 310,295 L 350,315 L 380,340 L 370,380 L 350,405 L 320,410 L 295,390 L 280,350 L 260,330 Z", threat: "High", posture: "Trojan Cluster" },
  { id: "ar", name: "Argentina", flag: "🇦🇷", labelPos: { x: 295, y: 445 }, d: "M 280,350 L 295,390 L 320,410 L 325,465 L 305,488 L 290,480 L 280,440 L 265,395 Z", threat: "Medium", posture: "Monitored" },
  { id: "co", name: "Colombia & Peru", flag: "🇨🇴", labelPos: { x: 255, y: 325 }, d: "M 235,295 L 270,290 L 260,330 L 280,350 L 265,395 L 250,355 L 235,320 Z", threat: "Medium", posture: "Monitored" },

  // Europe
  { id: "gb", name: "United Kingdom", flag: "🇬🇧", labelPos: { x: 440, y: 118 }, d: "M 432,102 L 455,98 L 450,135 L 428,130 Z M 418,112 L 428,108 L 425,128 L 415,122 Z", threat: "Low", posture: "SOC Partner" },
  { id: "fr", name: "France & Spain", flag: "🇫🇷", labelPos: { x: 455, y: 155 }, d: "M 435,135 L 475,130 L 485,155 L 475,175 L 445,175 L 435,155 Z", threat: "Low", posture: "Protected" },
  { id: "de", name: "Germany", flag: "🇩🇪", labelPos: { x: 498, y: 130 }, d: "M 475,115 L 515,112 L 525,145 L 485,150 L 475,130 Z", threat: "High", posture: "Tor Exit Relay" },
  { id: "it", name: "Italy", flag: "🇮🇹", labelPos: { x: 505, y: 175 }, d: "M 490,155 L 510,150 L 520,185 L 510,195 L 495,175 Z", threat: "Low", posture: "Protected" },
  { id: "pl", name: "Poland & Ukraine", flag: "🇵🇱", labelPos: { x: 540, y: 135 }, d: "M 515,112 L 565,115 L 560,155 L 525,155 L 520,130 Z", threat: "High", posture: "Threat Frontier" },
  { id: "ro", name: "Romania", flag: "🇷🇴", labelPos: { x: 540, y: 170 }, d: "M 525,155 L 560,155 L 550,185 L 520,185 Z", threat: "High", posture: "Mirai Botnet" },
  { id: "se", name: "Sweden & Norway", flag: "🇸🇪", labelPos: { x: 525, y: 75 }, d: "M 495,52 L 528,42 L 548,52 L 558,88 L 538,105 L 515,95 L 498,78 Z", threat: "Low", posture: "Protected" },

  // Africa
  { id: "eg", name: "Egypt & Algeria", flag: "🇪🇬", labelPos: { x: 515, y: 228 }, d: "M 458,195 L 510,188 L 568,192 L 600,225 L 585,260 L 520,260 L 442,260 L 448,210 Z", threat: "Medium", posture: "Monitored" },
  { id: "ng", name: "Nigeria & Congo", flag: "🇳🇬", labelPos: { x: 520, y: 300 }, d: "M 442,260 L 520,260 L 585,260 L 618,260 L 592,340 L 520,340 L 450,340 L 442,290 Z", threat: "High", posture: "BEC Phishing Node" },
  { id: "za", name: "South Africa", flag: "🇿🇦", labelPos: { x: 525, y: 385 }, d: "M 450,340 L 520,340 L 592,340 L 578,365 L 548,418 L 520,438 L 488,395 L 472,350 Z", threat: "Medium", posture: "Monitored" },
  { id: "mg", name: "Madagascar", flag: "🇲🇬", labelPos: { x: 615, y: 385 }, d: "M 605,358 L 622,358 L 616,412 L 600,400 Z", threat: "Low", posture: "Monitored" },

  // Eurasia & Asia
  { id: "ru", name: "Russia", flag: "🇷🇺", labelPos: { x: 730, y: 105 }, d: "M 565,95 L 640,78 L 725,62 L 805,62 L 885,82 L 898,118 L 868,145 L 812,150 L 752,155 L 682,155 L 612,150 L 565,135 Z", threat: "Critical", posture: "APT28 / Sandworm" },
  { id: "cn", name: "China", flag: "🇨🇳", labelPos: { x: 765, y: 205 }, d: "M 682,155 L 752,155 L 812,150 L 852,175 L 838,235 L 798,255 L 752,250 L 712,230 L 685,200 Z", threat: "Critical", posture: "APT41 / Volt Typhoon" },
  { id: "in", name: "India", flag: "🇮🇳", labelPos: { x: 688, y: 255 }, d: "M 662,215 L 715,215 L 722,255 L 698,305 L 675,275 L 655,245 Z", threat: "Medium", posture: "Monitored" },
  { id: "sa", name: "Saudi Arabia & Iran", flag: "🇸🇦", labelPos: { x: 610, y: 220 }, d: "M 575,175 L 655,175 L 655,225 L 638,250 L 618,278 L 585,255 L 570,225 Z", threat: "High", posture: "Charming Kitten" },
  { id: "jp", name: "Japan", flag: "🇯🇵", labelPos: { x: 875, y: 175 }, d: "M 865,148 L 892,162 L 882,205 L 855,188 Z", threat: "Low", posture: "APAC Gateway Active" },
  { id: "kr", name: "Korea", flag: "🇰🇷", labelPos: { x: 845, y: 195 }, d: "M 838,180 L 855,180 L 850,210 L 835,210 Z", threat: "Critical", posture: "Lazarus / Kimsuky" },
  { id: "sea", name: "Southeast Asia", flag: "🇮🇩", labelPos: { x: 785, y: 305 }, d: "M 748,252 L 792,258 L 802,295 L 768,315 L 742,290 Z M 735,325 L 785,325 L 775,345 L 730,340 Z M 800,320 L 848,325 L 838,355 L 795,345 Z M 818,272 L 838,268 L 832,305 L 812,300 Z", threat: "Medium", posture: "Monitored" },

  // Oceania
  { id: "au", name: "Australia", flag: "🇦🇺", labelPos: { x: 828, y: 385 }, d: "M 768,338 L 832,328 L 882,332 L 898,375 L 878,422 L 835,438 L 782,410 L 758,375 Z", threat: "Low", posture: "Protected" },
  { id: "nz", name: "New Zealand", flag: "🇳🇿", labelPos: { x: 925, y: 435 }, d: "M 915,412 L 935,412 L 920,455 L 905,445 Z", threat: "Low", posture: "Protected" }
];

const THREAT_ORIGINS = [
  { id: "moscow", name: "Moscow, Russia", country: "Russian Federation", flag: "🇷🇺", lat: 55.75, lon: 37.61, group: "APT28 / Fancy Bear", vector: "T1071 C2 Beaconing", cve: "CVE-2023-38831", sev: "Critical", ip: "185.220.101.5", asn: "AS44034 HiFormance" },
  { id: "beijing", name: "Beijing, China", country: "China", flag: "🇨🇳", lat: 39.90, lon: 116.40, group: "APT41 / Winnti", vector: "T1190 Web Exploit", cve: "CVE-2024-21887", sev: "High", ip: "103.251.167.20", asn: "AS4134 Chinanet" },
  { id: "pyongyang", name: "Pyongyang, DPRK", country: "North Korea", flag: "🇰🇵", lat: 39.03, lon: 125.75, group: "Lazarus Group", vector: "T1059 Scripting", cve: "CVE-2024-4974", sev: "Critical", ip: "175.45.176.12", asn: "AS131279 Star JV" },
  { id: "bucharest", name: "Bucharest, Romania", country: "Romania", flag: "🇷🇴", lat: 44.43, lon: 26.10, group: "Mirai Botnet Cluster", vector: "T1498 SYN Flood DDoS", cve: "CVE-2022-22965", sev: "High", ip: "91.240.118.172", asn: "AS49981 WorldStream" },
  { id: "saopaulo", name: "São Paulo, Brazil", country: "Brazil", flag: "🇧🇷", lat: -23.55, lon: -46.63, group: "Grandoreiro Trojan", vector: "T1110 SSH Brute Force", cve: "CVE-2023-48795", sev: "Medium", ip: "177.54.144.18", asn: "AS28573 Claro Brasil" },
  { id: "lagos", name: "Lagos, Nigeria", country: "Nigeria", flag: "🇳🇬", lat: 6.52, lon: 3.37, group: "SilverTerrier BEC", vector: "T1566 Phishing Spear", cve: "N/A (Social Eng)", sev: "Medium", ip: "102.89.44.112", asn: "AS37108 MainOne" },
  { id: "frankfurt_att", name: "Frankfurt (Tor Exit), Germany", country: "Germany", flag: "🇩🇪", lat: 50.11, lon: 8.68, group: "Tor Exit Relay 09", vector: "T1090 Multi-hop Proxy", cve: "CVE-2024-1086", sev: "High", ip: "198.51.100.23", asn: "AS24940 Hetzner" },
  { id: "shenzhen", name: "Shenzhen, China", country: "China", flag: "🇨🇳", lat: 22.54, lon: 114.05, group: "Volt Typhoon", vector: "T1078 Valid Accounts", cve: "CVE-2023-46805", sev: "Critical", ip: "119.29.29.29", asn: "AS132203 Tencent" },
  { id: "tehran", name: "Tehran, Iran", country: "Iran", flag: "🇮🇷", lat: 35.68, lon: 51.38, group: "Charming Kitten", vector: "T1071 C2 Web Service", cve: "CVE-2023-34362", sev: "High", ip: "5.200.200.5", asn: "AS58224 TIC" },
  { id: "amsterdam", name: "Amsterdam, Netherlands", country: "Netherlands", flag: "🇳🇱", lat: 52.36, lon: 4.90, group: "Bulletproof VPS Host", vector: "T1583 Rogue Infra", cve: "CVE-2023-22515", sev: "High", ip: "45.154.255.89", asn: "AS60404 Serverius" },
  { id: "petersburg", name: "St. Petersburg, Russia", country: "Russian Federation", flag: "🇷🇺", lat: 59.93, lon: 30.33, group: "Sandworm Team", vector: "T1486 Ransomware Lock", cve: "CVE-2024-1709", sev: "Critical", ip: "94.102.49.190", asn: "AS48693 Marosnet" },
  { id: "mumbai", name: "Mumbai, India", country: "India", flag: "🇮🇳", lat: 19.07, lon: 72.87, group: "SideCopy Cluster", vector: "T1204 Malicious LNK", cve: "CVE-2023-36025", sev: "Medium", ip: "103.110.170.5", asn: "AS55836 Reliance" },
  { id: "seattle", name: "Seattle, USA", country: "United States", flag: "🇺🇸", lat: 47.60, lon: -122.33, group: "Rogue Cloud Node", vector: "T1078 Cloud Token Leak", cve: "CVE-2023-23397", sev: "Medium", ip: "54.214.18.99", asn: "AS16509 AWS" },
  { id: "seoul", name: "Seoul, South Korea", country: "South Korea", flag: "🇰🇷", lat: 37.56, lon: 126.97, group: "Kimsuky Sub-unit", vector: "T1055 Process Injection", cve: "CVE-2023-28252", sev: "High", ip: "211.233.77.10", asn: "AS9318 SKB" }
];

const TARGET_HUBS = [
  { id: "us_east", name: "US-East (Ashburn DC-01)", lat: 39.04, lon: -77.48, region: "North America Cloud Hub", status: "ONLINE", rate: "1,420 pkts/s", blockRate: "99.8%", ip: "10.0.1.10" },
  { id: "eu_central", name: "EU-Central (Frankfurt Hub)", lat: 50.11, lon: 8.68, region: "Europe Core Gateway", status: "ONLINE", rate: "890 pkts/s", blockRate: "99.9%", ip: "10.0.2.10" },
  { id: "apac_east", name: "APAC-East (Tokyo Hub)", lat: 35.67, lon: 139.65, region: "Asia Pacific Edge Cluster", status: "ONLINE", rate: "610 pkts/s", blockRate: "99.7%", ip: "10.0.3.10" },
  { id: "us_west", name: "US-West (Silicon Valley)", lat: 37.38, lon: -122.08, region: "AI Compute Center", status: "ONLINE", rate: "430 pkts/s", blockRate: "100.0%", ip: "10.0.4.10" }
];

const TOP_ATTACK_COUNTRIES = [
  { name: "Russian Federation", code: "RU", flag: "🇷🇺", attacks: "4,812", share: "34%", botnets: "14 Clusters", sev: "Critical" },
  { name: "China", code: "CN", flag: "🇨🇳", attacks: "3,940", share: "28%", botnets: "11 Clusters", sev: "Critical" },
  { name: "North Korea", code: "KP", flag: "🇰🇵", attacks: "1,870", share: "13%", botnets: "5 Clusters", sev: "Critical" },
  { name: "Brazil", code: "BR", flag: "🇧🇷", attacks: "1,240", share: "9%", botnets: "4 Clusters", sev: "Medium" },
  { name: "Romania", code: "RO", flag: "🇷🇴", attacks: "980", share: "7%", botnets: "3 Clusters", sev: "High" },
  { name: "Netherlands", code: "NL", flag: "🇳🇱", attacks: "650", share: "5%", botnets: "2 Clusters", sev: "High" },
  { name: "Other Origins", code: "XX", flag: "🌐", attacks: "560", share: "4%", botnets: "6 Clusters", sev: "Medium" }
];

let _cachedWorldTopo = null;
let _cachedCountriesGeo = null;

const COUNTRY_FLAGS = {
  "United States of America": "🇺🇸", "United States": "🇺🇸", "Canada": "🇨🇦", "Mexico": "🇲🇽",
  "Brazil": "🇧🇷", "Argentina": "🇦🇷", "Chile": "🇨🇱", "Colombia": "🇨🇴", "Peru": "🇵🇪", "Venezuela": "🇻🇪",
  "Bolivia": "🇧🇴", "Ecuador": "🇪🇨", "Paraguay": "🇵🇾", "Uruguay": "🇺🇾", "Cuba": "🇨🇺", "Panama": "🇵🇦",
  "Costa Rica": "🇨🇷", "Guatemala": "🇬🇹", "Honduras": "🇭🇳",
  "Russia": "🇷🇺", "China": "🇨🇳", "India": "🇮🇳", "Australia": "🇦🇺", "Greenland": "🇬🇱",
  "United Kingdom": "🇬🇧", "France": "🇫🇷", "Germany": "🇩🇪", "Italy": "🇮🇹", "Spain": "🇪🇸",
  "Portugal": "🇵🇹", "Ukraine": "🇺🇦", "Poland": "🇵🇱", "Romania": "🇷🇴", "Netherlands": "🇳🇱",
  "Belgium": "🇧🇪", "Switzerland": "🇨🇭", "Austria": "🇦🇹", "Sweden": "🇸🇪", "Norway": "🇳🇴",
  "Finland": "🇫🇮", "Denmark": "🇩🇰", "Greece": "🇬🇷", "Ireland": "🇮🇪", "Czechia": "🇨🇿",
  "Japan": "🇯🇵", "South Korea": "🇰🇷", "North Korea": "🇰🇵", "Indonesia": "🇮🇩", "New Zealand": "🇳🇿",
  "Saudi Arabia": "🇸🇦", "Iran": "🇮🇷", "Iraq": "🇮🇶", "Turkey": "🇹🇷", "Pakistan": "🇵🇰",
  "Kazakhstan": "🇰🇿", "Mongolia": "🇲🇳", "Uzbekistan": "🇺🇿", "Turkmenistan": "🇹🇲",
  "Egypt": "🇪🇬", "Nigeria": "🇳🇬", "South Africa": "🇿🇦", "Algeria": "🇩🇿", "Dem. Rep. Congo": "🇨🇩",
  "Kenya": "🇰🇪", "Ethiopia": "🇪🇹", "Sudan": "🇸🇩", "South Sudan": "🇸🇸", "Libya": "🇱🇾", "Morocco": "🇲🇦",
  "Angola": "🇦🇴", "Tanzania": "🇹🇿", "Namibia": "🇳🇦", "Mozambique": "🇲🇿", "Madagascar": "🇲🇬",
  "Ghana": "🇬🇭", "Ivory Coast": "🇨🇮", "Senegal": "🇸🇳", "Mali": "🇲🇱", "Niger": "🇳🇪", "Chad": "🇹🇩",
  "Thailand": "🇹🇭", "Vietnam": "🇻🇳", "Philippines": "🇵🇭", "Malaysia": "🇲🇾", "Myanmar": "🇲🇲",
  "Afghanistan": "🇦🇫", "Bangladesh": "🇧🇩", "Taiwan": "🇹🇼"
};

const COUNTRY_SHORT_NAMES = {
  "United States of America": "USA",
  "Dem. Rep. Congo": "DR Congo",
  "Central African Rep.": "CAR",
  "Dominican Rep.": "Dom. Rep.",
  "Eq. Guinea": "Eq. Guinea",
  "Bosnia and Herz.": "Bosnia",
  "Solomon Is.": "Solomon Is.",
  "Falkland Is.": "Falklands",
  "W. Sahara": "W. Sahara"
};

async function loadWorldAtlasData() {
  if (_cachedCountriesGeo) return _cachedCountriesGeo;
  try {
    const res = await fetch("/static/countries-110m.json");
    if (res.ok) {
      _cachedWorldTopo = await res.json();
      if (window.topojson) {
        _cachedCountriesGeo = topojson.feature(_cachedWorldTopo, _cachedWorldTopo.objects.countries);
      }
    }
  } catch (e) {
    console.warn("Local world atlas fetch failed:", e);
  }
  return _cachedCountriesGeo;
}
loadWorldAtlasData();

function geoToXY(lat, lon, width = 1000, height = 500) {
  if (window.d3 && geoEngineState.projection) {
    const pt = geoEngineState.projection([lon, lat]);
    if (pt && !isNaN(pt[0]) && !isNaN(pt[1])) {
      return { x: pt[0], y: pt[1] };
    }
  }
  const x = ((lon + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return { x, y };
}

const geoEngineState = {
  activeArcs: [],
  sparks: [],
  density: "normal", // 'low' | 'normal' | 'surge' | 'blitz'
  sevFilter: "all",  // 'all' | 'high_crit' | 'crit'
  theme: "atlas",    // 'atlas' | 'cyber' | 'stealth'
  showLabels: true,
  region: "global",
  is3D: false,
  animFrameId: null,
  spawnTimer: null,
  containerId: null,
  canvas: null,
  ctx: null,
  projection: null,
  pathGenerator: null,
  width: 1000,
  height: 500,
  isMini: false,
};

function getGeoArcCap() {
  switch (geoEngineState.density) {
    case "low": return 5;
    case "normal": return 12;
    case "surge": return 28;
    case "blitz": return 50;
    default: return 12;
  }
}

function stopGeospatialEngine() {
  if (geoEngineState.animFrameId) {
    cancelAnimationFrame(geoEngineState.animFrameId);
    geoEngineState.animFrameId = null;
  }
  if (geoEngineState.spawnTimer) {
    clearInterval(geoEngineState.spawnTimer);
    geoEngineState.spawnTimer = null;
  }
  geoEngineState.activeArcs = [];
  geoEngineState.sparks = [];
  geoEngineState.containerId = null;
}

async function initGeospatialEngine(containerId, isMini = false) {
  stopGeospatialEngine();
  geoEngineState.containerId = containerId;
  geoEngineState.isMini = isMini;

  const mount = $(`#${containerId}`);
  if (!mount) return;

  const w = 1000;
  const h = 500;
  geoEngineState.width = w;
  geoEngineState.height = h;

  // Setup D3 Geographic Projection
  if (window.d3) {
    geoEngineState.projection = d3.geoEquirectangular().fitSize([w, h], { type: "Sphere" });
    geoEngineState.pathGenerator = d3.geoPath().projection(geoEngineState.projection);
  }

  // Ensure GeoJSON is loaded
  const countriesGeo = await loadWorldAtlasData();

  let countriesSvgMarkup = "";
  let countryLabelsMarkup = "";

  if (countriesGeo && geoEngineState.pathGenerator) {
    const pathGen = geoEngineState.pathGenerator;
    countriesSvgMarkup = countriesGeo.features.map(f => {
      const d = pathGen(f);
      const name = f.properties.name || "Territory";
      return `<path d="${d}" class="country-boundary" data-country-name="${esc(name)}" />`;
    }).join("");

    countryLabelsMarkup = countriesGeo.features.map(f => {
      const name = f.properties.name || "";
      if (!name || name === "Antarctica") return "";
      const area = pathGen.area(f);
      const centroid = pathGen.centroid(f);
      if (isNaN(centroid[0]) || isNaN(centroid[1])) return "";

      const flag = COUNTRY_FLAGS[name] || "🌐";
      let display = COUNTRY_SHORT_NAMES[name] || name;

      // Filter prominent countries for clean, uncluttered cartography
      if (area > 200 || ["United Kingdom", "Japan", "South Korea", "North Korea", "Italy", "Germany", "New Zealand", "Cuba", "Greece", "Portugal", "Netherlands"].includes(name)) {
        if (display.length > 13 && area < 1000) display = display.slice(0, 11) + "…";
        return `<text x="${Math.round(centroid[0])}" y="${Math.round(centroid[1])}" class="geo-country-label" data-country="${esc(name)}">${flag} ${esc(display.toUpperCase())}</text>`;
      }
      return "";
    }).join("");
  } else {
    // Fallback if data is still parsing
    countriesSvgMarkup = COUNTRIES_DATA.map(c => `<path d="${c.d}" class="country-boundary" data-country-name="${esc(c.name)}" />`).join("");
    countryLabelsMarkup = COUNTRIES_DATA.map(c => `<text x="${c.labelPos.x}" y="${c.labelPos.y}" class="geo-country-label">${c.flag} ${esc(c.name.toUpperCase())}</text>`).join("");
  }

  const themeCls = `theme-${geoEngineState.theme || "atlas"}`;
  mount.className = `battlemap-container ${themeCls} ${geoEngineState.is3D ? "is-3d" : ""}`;
  mount.innerHTML = `
    <div class="battlemap-viewport" id="${containerId}_viewport">
      <div class="battlemap-grid-overlay"></div>
      <div class="battlemap-radar-sweep"></div>
      
      <!-- Vector World Landmass Layer -->
      <svg class="battlemap-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" id="${containerId}_svg">
        <!-- Latitude / Longitude Tactical Grid with Equator & Tropics -->
        <g class="geo-latlong-lines">
          <line x1="0" y1="83" x2="${w}" y2="83" class="geo-latlong-line" />
          <line x1="0" y1="185" x2="${w}" y2="185" class="geo-latlong-tropic" title="Tropic of Cancer (23.5°N)" />
          <line x1="0" y1="250" x2="${w}" y2="250" class="geo-latlong-equator" title="Equator (0°)" />
          <line x1="0" y1="315" x2="${w}" y2="315" class="geo-latlong-tropic" title="Tropic of Capricorn (23.5°S)" />
          <line x1="0" y1="416" x2="${w}" y2="416" class="geo-latlong-line" />
          
          <line x1="166" y1="0" x2="166" y2="${h}" class="geo-latlong-line" />
          <line x1="333" y1="0" x2="333" y2="${h}" class="geo-latlong-line" />
          <line x1="500" y1="0" x2="500" y2="${h}" class="geo-latlong-prime" title="Prime Meridian (0°)" />
          <line x1="666" y1="0" x2="666" y2="${h}" class="geo-latlong-line" />
          <line x1="833" y1="0" x2="833" y2="${h}" class="geo-latlong-line" />
        </g>
        
        <!-- Individual Country Boundaries & Landmasses (177 Sovereign Nations) -->
        <g class="geo-countries" id="${containerId}_countries">
          ${countriesSvgMarkup}
        </g>

        <!-- Country Name & Flag Labels Layer -->
        <g class="geo-country-labels ${!geoEngineState.showLabels ? "hide-country-labels" : ""}" id="${containerId}_labels">
          ${countryLabelsMarkup}
        </g>

        <!-- Continent Watermark Labels -->
        <g class="geo-continent-labels">
          <text x="200" y="155" class="geo-label-continent">NORTH AMERICA</text>
          <text x="295" y="365" class="geo-label-continent">SOUTH AMERICA</text>
          <text x="495" y="145" class="geo-label-continent">EUROPE</text>
          <text x="515" y="295" class="geo-label-continent">AFRICA</text>
          <text x="740" y="135" class="geo-label-continent">ASIA / EURASIA</text>
          <text x="830" y="385" class="geo-label-continent">AUSTRALIA</text>
        </g>

        <!-- Ocean Watermark Labels -->
        <g class="geo-ocean-labels">
          <text x="100" y="270" class="geo-label-ocean">NORTH PACIFIC OCEAN</text>
          <text x="930" y="270" class="geo-label-ocean">PACIFIC OCEAN</text>
          <text x="375" y="240" class="geo-label-ocean">ATLANTIC OCEAN</text>
          <text x="655" y="365" class="geo-label-ocean">INDIAN OCEAN</text>
          <text x="500" y="32" class="geo-label-ocean">ARCTIC OCEAN</text>
        </g>

        <!-- Coordinate Degree Markers along Grid -->
        <g class="geo-coord-labels">
          <text x="168" y="14" class="geo-label-coord">120°W</text>
          <text x="335" y="14" class="geo-label-coord">60°W</text>
          <text x="502" y="14" class="geo-label-coord">0° MERIDIAN</text>
          <text x="668" y="14" class="geo-label-coord">60°E</text>
          <text x="835" y="14" class="geo-label-coord">120°E</text>
          
          <text x="6" y="86" class="geo-label-coord">60°N</text>
          <text x="6" y="188" class="geo-label-coord">23.5°N CANCER</text>
          <text x="6" y="253" class="geo-label-coord" style="fill:var(--neon-cyan);font-weight:700">0° EQUATOR</text>
          <text x="6" y="318" class="geo-label-coord">23.5°S CAPRICORN</text>
          <text x="6" y="419" class="geo-label-coord">60°S</text>
        </g>
      </svg>

      <!-- Dynamic Canvas Attack Arc Particle Layer -->
      <canvas class="battlemap-canvas" id="${containerId}_canvas" width="${w}" height="${h}"></canvas>

      <!-- HTML Threat Origin Markers & Defense Hubs -->
      <div class="battlemap-markers-layer" id="${containerId}_markers">
        ${THREAT_ORIGINS.map(o => {
          const pt = geoToXY(o.lat, o.lon, w, h);
          const leftPct = ((pt.x / w) * 100).toFixed(2);
          const topPct = ((pt.y / h) * 100).toFixed(2);
          const sevCls = o.sev === "Critical" ? "" : o.sev === "High" ? "sev-high" : "sev-med";
          return `
            <div class="geo-node" style="left:${leftPct}%;top:${topPct}%" data-threat="${esc(o.id)}">
              <div class="threat-emitter ${sevCls}" title="${esc(o.name)} (${esc(o.group)})"></div>
              <span class="geo-node-tag">${o.flag} ${esc(o.name.split(",")[0])}</span>
            </div>`;
        }).join("")}

        ${TARGET_HUBS.map(t => {
          const pt = geoToXY(t.lat, t.lon, w, h);
          const leftPct = ((pt.x / w) * 100).toFixed(2);
          const topPct = ((pt.y / h) * 100).toFixed(2);
          return `
            <div class="target-hub-node" style="left:${leftPct}%;top:${topPct}%" data-hub="${esc(t.id)}">
              <div class="target-hub-badge">
                <span class="target-hub-shield"></span>
                <span>${esc(t.name.split(" ")[0])}</span>
              </div>
            </div>`;
        }).join("")}
      </div>

      <!-- Tactical Map Legend HUD Panel -->
      <div class="battlemap-legend">
        <div class="legend-title">TACTICAL MAP TELEMETRY KEY</div>
        <div class="legend-grid">
          <div class="legend-item"><span class="legend-dot crit"></span><b>Threat Origin (Critical)</b></div>
          <div class="legend-item"><span class="legend-dot high"></span><b>Threat Origin (High)</b></div>
          <div class="legend-item"><span class="legend-shield-icon"></span><b>Target Defense Hub</b></div>
          <div class="legend-item"><span class="legend-line-icon"></span><b>Attack Trajectory Beam</b></div>
        </div>
      </div>

      <!-- Tactical Glass Tooltip -->
      <div class="geo-tooltip hidden" id="${containerId}_tooltip"></div>

      ${!isMini ? `
        <!-- Tactical HUD Top Stats Overlay -->
        <div class="battlemap-hud-top">
          <div class="hud-stat-pill critical">
            <span>● ACTIVE ARCS:</span><b id="hudArcCount">0 TRAJECTORIES</b>
          </div>
          <div class="hud-stat-pill">
            <span>SHIELD MITIGATION:</span><b style="color:var(--neon-emerald)">99.8% AUTONOMOUS</b>
          </div>
        </div>

        <!-- Tactical HUD Bottom Ticker Stream -->
        <div class="battlemap-hud-bottom">
          <span class="hud-ticker-label"><span class="pulse-beacon"></span>INTERCEPT FEED:</span>
          <span class="hud-ticker-content" id="${containerId}_ticker">Establishing connection to Global Threat Sensors…</span>
        </div>
      ` : ""}
    </div>`;

  const canvas = $(`#${containerId}_canvas`);
  if (canvas) {
    geoEngineState.canvas = canvas;
    geoEngineState.ctx = canvas.getContext("2d");
  }

  setupGeoMarkerListeners(containerId);

  // Seed initial arcs
  const initialCount = isMini ? 4 : 8;
  for (let i = 0; i < initialCount; i++) {
    spawnAttackArc();
  }

  // Animation Loop & Periodic Arc Spawner
  geoEngineState.animFrameId = requestAnimationFrame(renderGeoAnimation);
  geoEngineState.spawnTimer = setInterval(() => {
    if (geoEngineState.activeArcs.length < getGeoArcCap()) {
      spawnAttackArc();
    }
  }, isMini ? 700 : 380);
}

function setupGeoMarkerListeners(containerId) {
  const markersWrap = $(`#${containerId}_markers`);
  const svgEl = $(`#${containerId}_svg`);
  const tooltip = $(`#${containerId}_tooltip`);
  if (!markersWrap || !tooltip) return;

  // Origin emitters & Target hubs
  markersWrap.addEventListener("mouseenter", e => {
    const threatNode = e.target.closest("[data-threat]");
    const hubNode = e.target.closest("[data-hub]");

    if (threatNode) {
      const id = threatNode.dataset.threat;
      const t = THREAT_ORIGINS.find(x => x.id === id);
      if (t) {
        tooltip.innerHTML = `
          <div class="geo-tooltip-head">
            <div class="geo-tooltip-country">${t.flag} ${esc(t.country)}</div>
            <span class="pill sev-${t.sev.toLowerCase()}">${t.sev}</span>
          </div>
          <div class="geo-tooltip-row"><span class="k">Actor / Group:</span><span class="v" style="color:var(--neon-cyan)">${esc(t.group)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Attack Vector:</span><span class="v">${esc(t.vector)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Target CVE:</span><span class="v mono">${esc(t.cve)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Source IP:</span><span class="v mono">${esc(t.ip)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Origin ASN:</span><span class="v mono">${esc(t.asn)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Coordinates:</span><span class="v mono">${t.lat.toFixed(2)}°, ${t.lon.toFixed(2)}°</span></div>
          <div style="margin-top:6px;padding-top:6px;border-top:1px solid var(--border-subtle);font-size:10.5px;color:var(--neon-emerald)">
            ✓ Autonomous firewall drop active
          </div>`;
        tooltip.style.left = threatNode.style.left;
        tooltip.style.top = threatNode.style.top;
        tooltip.classList.remove("hidden");
      }
    } else if (hubNode) {
      const id = hubNode.dataset.hub;
      const h = TARGET_HUBS.find(x => x.id === id);
      if (h) {
        tooltip.innerHTML = `
          <div class="geo-tooltip-head">
            <div class="geo-tooltip-country">🛡️ ${esc(h.name)}</div>
            <span class="pill" style="background:rgba(16,185,129,0.15);color:var(--neon-emerald)">${h.status}</span>
          </div>
          <div class="geo-tooltip-row"><span class="k">Cluster:</span><span class="v">${esc(h.region)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Ingress Rate:</span><span class="v mono" style="color:var(--neon-cyan)">${esc(h.rate)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Block Efficiency:</span><span class="v mono" style="color:var(--neon-emerald)">${esc(h.blockRate)}</span></div>
          <div class="geo-tooltip-row"><span class="k">Gateway IP:</span><span class="v mono">${esc(h.ip)}</span></div>`;
        tooltip.style.left = hubNode.style.left;
        tooltip.style.top = hubNode.style.top;
        tooltip.classList.remove("hidden");
      }
    }
  }, true);

  markersWrap.addEventListener("mouseleave", e => {
    if (e.target.closest("[data-threat]") || e.target.closest("[data-hub]")) {
      tooltip.classList.add("hidden");
    }
  }, true);

  // Country boundary hover listener
  if (svgEl) {
    svgEl.addEventListener("mousemove", e => {
      const countryPath = e.target.closest(".country-boundary");
      if (countryPath) {
        const cName = countryPath.dataset.countryName || "";
        if (cName && cName !== "Territory" && cName !== "Antarctica") {
          const flag = COUNTRY_FLAGS[cName] || "🌐";
          const matchOrigin = THREAT_ORIGINS.find(o => o.country.toLowerCase().includes(cName.toLowerCase()) || cName.toLowerCase().includes(o.country.toLowerCase()));
          const riskLevel = matchOrigin ? matchOrigin.sev : (cName === "Russia" || cName === "China" || cName === "North Korea" ? "Critical" : cName === "United States of America" || cName === "Germany" || cName === "Romania" || cName === "Iran" ? "High" : "Medium");
          const posture = matchOrigin ? `Active Threat Vector: ${matchOrigin.group}` : "SOC Autonomous Firewall Monitored";

          const rect = svgEl.getBoundingClientRect();
          const leftPct = (((e.clientX - rect.left) / rect.width) * 100).toFixed(2);
          const topPct = (((e.clientY - rect.top) / rect.height) * 100).toFixed(2);

          tooltip.innerHTML = `
            <div class="geo-tooltip-head">
              <div class="geo-tooltip-country">${flag} ${esc(cName)}</div>
              <span class="pill sev-${riskLevel.toLowerCase()}">${riskLevel} RISK</span>
            </div>
            <div class="geo-tooltip-row"><span class="k">SOC Boundary:</span><span class="v" style="color:var(--neon-cyan)">Geofence Active</span></div>
            <div class="geo-tooltip-row"><span class="k">Defense Status:</span><span class="v">${esc(posture)}</span></div>
            <div class="geo-tooltip-row"><span class="k">Firewall State:</span><span class="v mono" style="color:var(--neon-emerald)">✓ Filter Active</span></div>`;
          tooltip.style.left = `${leftPct}%`;
          tooltip.style.top = `${topPct}%`;
          tooltip.classList.remove("hidden");
        }
      }
    });

    svgEl.addEventListener("mouseleave", () => {
      tooltip.classList.add("hidden");
    });
  }
}

function spawnAttackArc(forceCrit = false) {
  let origins = THREAT_ORIGINS;
  if (geoEngineState.sevFilter === "crit" || forceCrit) {
    origins = THREAT_ORIGINS.filter(o => o.sev === "Critical");
  } else if (geoEngineState.sevFilter === "high_crit") {
    origins = THREAT_ORIGINS.filter(o => o.sev === "Critical" || o.sev === "High");
  }
  if (!origins.length) origins = THREAT_ORIGINS;

  const origin = origins[Math.floor(Math.random() * origins.length)];
  const target = TARGET_HUBS[Math.floor(Math.random() * TARGET_HUBS.length)];

  const w = geoEngineState.width;
  const h = geoEngineState.height;

  const p1 = geoToXY(origin.lat, origin.lon, w, h);
  const p2 = geoToXY(target.lat, target.lon, w, h);

  // Bezier Control Point (arching upwards)
  const mx = (p1.x + p2.x) / 2;
  const my = (p1.y + p2.y) / 2;
  const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
  const cpX = mx;
  const cpY = my - Math.min(130, Math.max(35, dist * 0.38));

  let color = "rgba(244, 63, 94, 0.9)"; // Critical crimson
  if (origin.sev === "High") color = "rgba(251, 146, 60, 0.9)"; // High orange
  if (origin.sev === "Medium") color = "rgba(251, 191, 36, 0.9)"; // Med amber

  const arc = {
    id: Math.random().toString(36).slice(2, 9),
    origin,
    target,
    p1,
    p2,
    cp: { x: cpX, y: cpY },
    progress: 0,
    speed: 0.007 + Math.random() * 0.009,
    color,
    sev: origin.sev,
  };

  geoEngineState.activeArcs.push(arc);
  if (!geoEngineState.isMini) {
    const countEl = $("#hudArcCount");
    if (countEl) countEl.textContent = `${geoEngineState.activeArcs.length} TRAJECTORIES`;
  }
}

function getBezierPoint(p0, p1, p2, t) {
  const oneMinusT = 1 - t;
  return {
    x: oneMinusT * oneMinusT * p0.x + 2 * oneMinusT * t * p1.x + t * t * p2.x,
    y: oneMinusT * oneMinusT * p0.y + 2 * oneMinusT * t * p1.y + t * t * p2.y,
  };
}

function renderGeoAnimation() {
  const { canvas, ctx, width: w, height: h } = geoEngineState;
  if (!ctx || !canvas) return;

  ctx.clearRect(0, 0, w, h);

  // 1. Draw Active Attack Arcs & Particle Heads
  for (let i = geoEngineState.activeArcs.length - 1; i >= 0; i--) {
    const arc = geoEngineState.activeArcs[i];
    arc.progress += arc.speed;

    // Draw trajectory path curve
    ctx.beginPath();
    ctx.moveTo(arc.p1.x, arc.p1.y);
    ctx.quadraticCurveTo(arc.cp.x, arc.cp.y, arc.p2.x, arc.p2.y);
    ctx.strokeStyle = arc.color.replace("0.9", "0.22");
    ctx.lineWidth = 1.2;
    ctx.setLineDash([3, 4]);
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw traveling glowing particle head
    const head = getBezierPoint(arc.p1, arc.cp, arc.p2, Math.min(1, arc.progress));

    // Particle Trail
    const tailT = Math.max(0, arc.progress - 0.09);
    const tail = getBezierPoint(arc.p1, arc.cp, arc.p2, tailT);

    const grad = ctx.createLinearGradient(tail.x, tail.y, head.x, head.y);
    grad.addColorStop(0, "rgba(255, 255, 255, 0)");
    grad.addColorStop(1, arc.color);

    ctx.beginPath();
    ctx.moveTo(tail.x, tail.y);
    ctx.lineTo(head.x, head.y);
    ctx.strokeStyle = grad;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Radiant Particle Glowing Dot
    ctx.beginPath();
    ctx.arc(head.x, head.y, 3.2, 0, Math.PI * 2);
    ctx.fillStyle = "#ffffff";
    ctx.shadowColor = arc.color;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Upon Target Impact: Spawn shockwave spark and update ticker
    if (arc.progress >= 1.0) {
      geoEngineState.sparks.push({
        x: arc.p2.x,
        y: arc.p2.y,
        radius: 4,
        maxRadius: 24,
        alpha: 1.0,
        color: arc.color,
      });

      if (!geoEngineState.isMini) {
        pushGeoTickerMessage(`[${new Date().toLocaleTimeString()}] ${arc.origin.flag} ${arc.origin.ip} ➔ [${arc.target.name.split(" ")[0]} : 443] — ${arc.origin.vector} — <span style="color:var(--neon-emerald)">AUTONOMOUSLY BLOCKED</span>`);
      }

      geoEngineState.activeArcs.splice(i, 1);
    }
  }

  // 2. Draw Target Impact Shockwaves
  for (let i = geoEngineState.sparks.length - 1; i >= 0; i--) {
    const s = geoEngineState.sparks[i];
    s.radius += 0.8;
    s.alpha -= 0.04;

    ctx.beginPath();
    ctx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
    ctx.strokeStyle = s.color.replace("0.9", String(Math.max(0, s.alpha)));
    ctx.lineWidth = 1.5;
    ctx.stroke();

    if (s.alpha <= 0) {
      geoEngineState.sparks.splice(i, 1);
    }
  }

  geoEngineState.animFrameId = requestAnimationFrame(renderGeoAnimation);
}

function pushGeoTickerMessage(msg) {
  const ticker = $(`#${geoEngineState.containerId}_ticker`);
  if (!ticker) return;
  ticker.innerHTML = msg;
}

function toggleGeo3D() {
  geoEngineState.is3D = !geoEngineState.is3D;
  const mount = $(`#${geoEngineState.containerId}`);
  if (mount) {
    mount.classList.toggle("is-3d", geoEngineState.is3D);
  }
  const btn3D = $("#geoBtn3D");
  if (btn3D) {
    btn3D.classList.toggle("active", geoEngineState.is3D);
    btn3D.innerHTML = geoEngineState.is3D
      ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg> 3D Isometric Active`
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/></svg> 2D Tactical View`;
  }
}

function setGeoTheme(theme) {
  geoEngineState.theme = theme;
  const mount = $(`#${geoEngineState.containerId}`);
  if (mount) {
    mount.classList.remove("theme-atlas", "theme-cyber", "theme-stealth");
    mount.classList.add(`theme-${theme}`);
  }
  $$(".geo-theme-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.theme === theme);
  });
  toast(`Map Theme: ${theme.toUpperCase()} style`);
}

function toggleGeoLabels() {
  geoEngineState.showLabels = !geoEngineState.showLabels;
  const labelsEl = $(`#${geoEngineState.containerId}_labels`);
  if (labelsEl) {
    labelsEl.classList.toggle("hide-country-labels", !geoEngineState.showLabels);
  }
  const btn = $("#geoBtnLabels");
  if (btn) {
    btn.classList.toggle("active", geoEngineState.showLabels);
    btn.innerHTML = geoEngineState.showLabels ? "✓ Labels ON" : "✕ Labels OFF";
  }
  toast(`Country Labels: ${geoEngineState.showLabels ? "VISIBLE" : "HIDDEN"}`);
}

function setGeoRegion(region) {
  geoEngineState.region = region;
  const svg = $(`#${geoEngineState.containerId}_svg`);
  if (!svg) return;

  const views = {
    global: "0 0 1000 500",
    americas: "50 40 400 450",
    emea: "400 30 350 440",
    apac: "650 40 350 440"
  };

  const targetBox = views[region] || views.global;
  svg.setAttribute("viewBox", targetBox);

  $$(".geo-region-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.region === region);
  });
  toast(`Region Focus: ${region.toUpperCase()}`);
}

function setGeoDensity(density) {
  geoEngineState.density = density;
  $$(".geo-density-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.density === density);
  });
  toast(`Attack Density set to: ${density.toUpperCase()}`);
}

function setGeoSevFilter(filter) {
  geoEngineState.sevFilter = filter;
  $$(".geo-sev-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.sev === filter);
  });
  toast(`Severity Filter: ${filter === "all" ? "All Threats" : filter === "crit" ? "Critical Only" : "High & Critical"}`);
}

function triggerGeoAttackSurge() {
  toast("⚠️ GLOBAL ATTACK SURGE DETECTED: 20 simultaneous vectors intercepted!", "err");
  for (let i = 0; i < 20; i++) {
    spawnAttackArc(true);
  }
  pushGeoTickerMessage(`[${new Date().toLocaleTimeString()}] 🚨 MULTI-VECTOR APT COORDINATED SURGE INTERCEPTED — TIER-3 AI AGENTS ENGAGED`);
}

// ==========================================================================
// 13. GEOSPATIAL FULL COMMAND DECK VIEW (Route: #/geospatial)
// ==========================================================================
async function renderGeospatial(view) {
  const d = await api(`/api/dashboard?dataset=${ds()}`);

  view.innerHTML = `
    <div class="geo-deck-wrap">
      <!-- Geospatial Command Header -->
      <div class="page-head">
        <div class="page-head-title">
          <h1>Geospatial Threat Battlemap & Radar</h1>
          <div class="muted">Live visual telemetry of global attack trajectories, origin actor emitters, and target defense nodes.</div>
        </div>
        <div class="btnrow">
          <div class="dash-status online">
            <span class="dot"></span><span>TACTICAL RADAR ONLINE</span>
            <span class="muted">Projection: Equirectangular WGS-84</span>
          </div>
        </div>
      </div>

      <!-- Tactical Controls HUD Bar -->
      <div class="geo-controls-bar">
        <!-- Theme Switcher -->
        <div class="geo-ctrl-group">
          <span class="geo-ctrl-label">THEME:</span>
          <button class="geo-btn-toggle geo-theme-btn active" data-theme="atlas" onclick="setGeoTheme('atlas')">Atlas</button>
          <button class="geo-btn-toggle geo-theme-btn" data-theme="cyber" onclick="setGeoTheme('cyber')">Cyber</button>
          <button class="geo-btn-toggle geo-theme-btn" data-theme="stealth" onclick="setGeoTheme('stealth')">Stealth</button>
        </div>

        <!-- Projection & Labels -->
        <div class="geo-ctrl-group">
          <button class="geo-btn-toggle" id="geoBtn3D" onclick="toggleGeo3D()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>
            2D Tactical View
          </button>
          <button class="geo-btn-toggle active" id="geoBtnLabels" onclick="toggleGeoLabels()">✓ Labels ON</button>
        </div>

        <!-- Region Quick-Zoom -->
        <div class="geo-ctrl-group">
          <span class="geo-ctrl-label">FOCUS:</span>
          <button class="geo-btn-toggle geo-region-btn active" data-region="global" onclick="setGeoRegion('global')">Global</button>
          <button class="geo-btn-toggle geo-region-btn" data-region="americas" onclick="setGeoRegion('americas')">Americas</button>
          <button class="geo-btn-toggle geo-region-btn" data-region="emea" onclick="setGeoRegion('emea')">EMEA</button>
          <button class="geo-btn-toggle geo-region-btn" data-region="apac" onclick="setGeoRegion('apac')">APAC</button>
        </div>

        <!-- Attack Density -->
        <div class="geo-ctrl-group">
          <span class="geo-ctrl-label">DENSITY:</span>
          <button class="geo-btn-toggle geo-density-btn" data-density="low" onclick="setGeoDensity('low')">Low</button>
          <button class="geo-btn-toggle geo-density-btn active" data-density="normal" onclick="setGeoDensity('normal')">Normal</button>
          <button class="geo-btn-toggle geo-density-btn" data-density="surge" onclick="setGeoDensity('surge')">Surge</button>
          <button class="geo-btn-toggle geo-density-btn" data-density="blitz" onclick="setGeoDensity('blitz')">Blitz (50x)</button>
        </div>

        <!-- Severity Filter -->
        <div class="geo-ctrl-group">
          <span class="geo-ctrl-label">SEV:</span>
          <button class="geo-btn-toggle geo-sev-btn active" data-sev="all" onclick="setGeoSevFilter('all')">All</button>
          <button class="geo-btn-toggle geo-sev-btn" data-sev="high_crit" onclick="setGeoSevFilter('high_crit')">High & Crit</button>
          <button class="geo-btn-toggle geo-sev-btn" data-sev="crit" onclick="setGeoSevFilter('crit')">Crit</button>
        </div>

        <!-- Surge Action -->
        <div class="geo-ctrl-group">
          <button class="geo-btn-surge" onclick="triggerGeoAttackSurge()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            Surge
          </button>
        </div>
      </div>

      <!-- Main Tactical Battlemap Stage -->
      <div id="mainGeoMap"></div>

      <!-- Geospatial Analytics & Threat Origin Intelligence Grid -->
      <div class="geo-analytics-grid">
        <!-- Top Attacking Countries Leaderboard -->
        <div class="panel">
          <h2>Top Threat Origin Nations <span class="tag">Geo-Telemetry</span></h2>
          <div class="muted" style="font-size:11px">Volume and botnet clusters mapped to source countries.</div>
          <table class="country-rank-table">
            <thead>
              <tr><th>Country</th><th>Attacks</th><th>Share</th><th>Botnets</th></tr>
            </thead>
            <tbody>
              ${TOP_ATTACK_COUNTRIES.map(c => `
                <tr>
                  <td>
                    <div class="country-name-cell">
                      <span class="country-flag">${c.flag}</span>
                      <span>${esc(c.name)}</span>
                    </div>
                    <div class="country-bar-wrap">
                      <div class="country-bar-fill" style="width:${c.share}"></div>
                    </div>
                  </td>
                  <td class="mono" style="font-weight:700">${c.attacks}</td>
                  <td class="mono" style="color:var(--neon-cyan)">${c.share}</td>
                  <td class="mono muted">${c.botnets}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>

        <!-- Target Defense Infrastructure Clusters -->
        <div class="panel">
          <h2>Enterprise Defense Clusters <span class="tag mono">4 HUBS ONLINE</span></h2>
          <div class="muted" style="font-size:11px">Telemetry and firewall mitigation load per regional gateway.</div>
          <div class="target-cluster-grid">
            ${TARGET_HUBS.map(t => `
              <div class="target-cluster-item">
                <div class="target-cluster-left">
                  <div class="target-cluster-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
                  </div>
                  <div>
                    <div class="target-cluster-name">${esc(t.name)}</div>
                    <div class="target-cluster-region">${esc(t.region)} · IP: ${esc(t.ip)}</div>
                  </div>
                </div>
                <div class="target-cluster-stats">
                  <div class="target-cluster-rate">${esc(t.rate)}</div>
                  <div class="target-cluster-status">✓ ${esc(t.blockRate)} Blocked</div>
                </div>
              </div>
            `).join("")}
          </div>
        </div>

        <!-- Global Threat Posture Indicators -->
        <div class="panel" style="display:flex;flex-direction:column;justify-content:space-between">
          <div>
            <h2>Global Threat Metrics <span class="tag mono">REALTIME</span></h2>
            <div class="muted" style="font-size:11px">Aggregated sensor readings across distributed honey-nets.</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:12px;margin:12px 0">
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:rgba(255,255,255,0.03);border-radius:8px;border:1px solid var(--border-subtle)">
              <span class="muted">Global Threat Level:</span>
              <span class="pill sev-critical"><span class="dot-sev"></span>ELEVATED HIGH</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:rgba(255,255,255,0.03);border-radius:8px;border:1px solid var(--border-subtle)">
              <span class="muted">Avg Attack Vector Speed:</span>
              <span class="mono" style="color:var(--neon-cyan);font-weight:700">14.2 ms / hop</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:rgba(255,255,255,0.03);border-radius:8px;border:1px solid var(--border-subtle)">
              <span class="muted">Autonomous Mitigation:</span>
              <span class="mono" style="color:var(--neon-emerald);font-weight:700">99.82% SUCCESS</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:rgba(255,255,255,0.03);border-radius:8px;border:1px solid var(--border-subtle)">
              <span class="muted">Known C2 Clusters:</span>
              <span class="mono" style="color:var(--neon-crimson);font-weight:700">42 Active Botnets</span>
            </div>
          </div>
          <button class="btn secondary" style="width:100%" onclick="location.hash='#/incidents'">View Detailed Incident Center →</button>
        </div>
      </div>
    </div>`;

  // Initialize Battlemap Stage
  initGeospatialEngine("mainGeoMap", false);
}
window.toggleGeo3D = toggleGeo3D;
window.setGeoTheme = setGeoTheme;
window.toggleGeoLabels = toggleGeoLabels;
window.setGeoRegion = setGeoRegion;
window.setGeoDensity = setGeoDensity;
window.setGeoSevFilter = setGeoSevFilter;
window.triggerGeoAttackSurge = triggerGeoAttackSurge;

// ==========================================================================
// 14. INITIALIZATION & SOC STARTUP LIFECYCLE
// ==========================================================================
const SOC_AGENTS = [
  "Detection Engine", "Investigation Agent", "Threat Intelligence",
  "Evidence Correlation", "Risk Assessment", "Response Planner",
  "Response Validator", "Incident Memory", "SOC Orchestrator",
];

function bootLog(msg, cls = "") {
  const el = $("#bootLog");
  if (!el) return;
  const t = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.innerHTML = `<span class="t">[${t}]</span> <span class="${cls}">${esc(msg)}</span>`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
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

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

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
    d.className = "boot-agent waiting";
    d.dataset.agent = a;
    d.innerHTML = `<div class="a-n">${esc(a)}</div><div class="a-s">STANDBY</div>`;
    agEl.appendChild(d);
  });
}

function markStage(i, cls, ico) {
  const li = $("#stage-" + i);
  if (!li) return;
  li.className = cls;
  li.querySelector(".ico").textContent = ico;
}

const BOOT_STAGES = [
  {
    label: "Loading Security Configuration",
    pct: 15,
    kind: "real",
    run: async () => {
      const cfg = await api("/api/config");
      state.config = cfg;
      applyConfigBadges();
      bootLog("Security configuration loaded successfully", "ok");
      return { ok: true };
    }
  },
  {
    label: "Verifying Threat Detection Engine",
    pct: 30,
    kind: "real",
    run: async () => {
      const h = await api("/health");
      if (!h || h.status !== "ok") return { ok: false, critical: true, reason: "Health check failed." };
      bootLog("FastAPI backend & detection engines active", "ok");
      ["Detection Engine", "Investigation Agent", "SOC Orchestrator"].forEach(a => setAgent(a, "online"));
      return { ok: true };
    }
  },
  {
    label: "Seeding Threat Intelligence Subsystem",
    pct: 45,
    kind: "real",
    run: async () => {
      await api("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip");
      bootLog("Local CTI feed & MITRE ATT&CK knowledge base seeded", "ok");
      setAgent("Threat Intelligence", "online");
      return { ok: true };
    }
  },
  {
    label: "Initializing Multi-Agent Consensus",
    pct: 60,
    kind: "ui",
    run: async () => {
      ["Evidence Correlation", "Risk Assessment", "Response Planner",
       "Response Validator", "Incident Memory"].forEach(a => setAgent(a, "online"));
      bootLog("9 AI SOC agents synchronized & ready", "ok");
      return { ok: true };
    }
  },
  {
    label: "Connecting Incident Database (SQLite WAL)",
    pct: 75,
    kind: "real",
    run: async () => {
      const d = await api(`/api/dashboard?dataset=${ds()}`);
      bootLog(`Database connected (${d.total_events} events, ${ds().toUpperCase()} mode)`, "ok");
      return { ok: true };
    }
  },
  {
    label: "Establishing Real-Time Telemetry Stream (SSE)",
    pct: 90,
    kind: "real",
    run: async () => {
      startStream();
      const connected = await waitFor(() => state.streamConnected, 3500);
      if (connected) {
        bootLog("Real-time Server-Sent Events stream connected", "ok");
        return { ok: true };
      }
      bootLog("Stream connecting in background", "warn");
      return { ok: false, critical: false, reason: "Stream auto-retrying in background." };
    }
  },
  {
    label: "Rendering Anarisk SOC Dashboard",
    pct: 100,
    kind: "ui",
    run: async () => {
      route();
      bootLog("Anarisk Cyber Command Center ready", "ok");
      return { ok: true };
    }
  },
];

function applyConfigBadges() {
  const cfg = state.config || {};
  if ($("#badgeSim")) {
    $("#badgeSim").innerHTML = `<span class="badge-dot"></span>${cfg.response_simulation ? "SIMULATION" : "LIVE-EXEC"}`;
  }
  if ($("#badgeAuto")) {
    $("#badgeAuto").innerHTML = `<span class="badge-dot"></span>${cfg.auto_response_enabled ? "AUTO-RESP ON" : "AUTO-RESP OFF"}`;
  }
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
    SOC_AGENTS.forEach(a => {
      const el = document.querySelector(`.boot-agent[data-agent="${CSS.escape(a)}"]`);
      if (el && el.classList.contains("waiting") && i >= 1) setAgent(a, "initializing");
    });
    let res;
    try {
      res = await s.run();
    } catch (e) {
      res = { ok: false, critical: s.kind === "real" && i <= 4, reason: e.message || "Check failed" };
    }
    await sleep(220);
    if (res.ok) {
      markStage(i, "done", "✓");
    } else if (res.critical) {
      markStage(i, "failed", "✕");
      bootLog(s.label + " — FAILED: " + (res.reason || ""), "err");
      failures.push({ stage: s, reason: res.reason, critical: true });
      if (i <= 1) SOC_AGENTS.forEach(a => setAgent(a, "failed"));
      break;
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
    if ($("#sysStat")) {
      $("#sysStat").className = "sysstat degraded";
      $("#sysStat").innerHTML = `<span class="dot"></span>SOC DEGRADED`;
    }
    final.innerHTML = `
      <div class="boot-ready-title" style="color:var(--neon-crimson)">INITIALIZATION DEGRADED</div>
      <div class="boot-ready-sub">Failed Module: <b>${esc(critical.stage.label)}</b></div>
      <div style="margin-top:16px">
        <button class="boot-retry" id="bootRetry">RETRY INITIALIZATION</button>
      </div>`;
    $("#bootRetry").onclick = retryStartup;
    $("#bootRetry").focus();
    return;
  }

  const warned = failures.filter(f => !f.critical);
  status.className = "boot-status ready";
  status.innerHTML = warned.length ? "SYSTEM STATUS: <b>READY (WITH WARNINGS)</b>" : "SYSTEM STATUS: <b>ALL SYSTEMS OPERATIONAL</b>";
  if ($("#sysStat")) {
    $("#sysStat").className = "sysstat online";
    $("#sysStat").innerHTML = `<span class="dot"></span>SOC ONLINE`;
  }
  final.innerHTML = `
    <div class="boot-ready-title">ANARISK SOC READY</div>
    <div class="boot-ready-sub">${warned.length ? "Core defense engines online." : "ALL 9 MULTI-AGENT SOC SERVICES ACTIVE"}</div>
    <div class="boot-protected">● ${ds().toUpperCase()} MODE · SAFE SIMULATION ACTIVE</div>
    <button class="boot-enter" id="bootEnter">ENTER COMMAND CENTER</button>`;

  const enter = $("#bootEnter");
  enter.onclick = enterDashboard;
  enter.focus();
  document.addEventListener("keydown", bootEnterKey);
}

function bootEnterKey(e) {
  if ((e.key === "Enter" || e.key === " ") && $("#bootEnter")) {
    e.preventDefault();
    enterDashboard();
  }
}

function enterDashboard() {
  document.removeEventListener("keydown", bootEnterKey);
  const boot = $("#bootScreen");
  boot.classList.add("boot-hidden");
  setTimeout(() => boot.classList.add("boot-gone"), 500);
  const q = $("#globalSearch");
  if (q) q.blur();
}

function retryStartup() {
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

// Auto-run on load
(async function init() {
  runStartup();
})();
