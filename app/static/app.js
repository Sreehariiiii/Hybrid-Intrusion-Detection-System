// Modern IDS Dashboard Client Application (100% Live DB Driven)
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  loadStatus();
  loadDatasetComposition();
  loadAlerts();
  loadMetrics();
  loadConfusionMatrix();
  loadAttribution();
  initSSE();

  document.getElementById("start-replay-btn").addEventListener("click", startReplay);
  document.getElementById("reset-btn").addEventListener("click", resetDatabase);
  document.getElementById("sim-inject-btn").addEventListener("click", injectAttack);
});

// Tab Switching
function initTabs() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      navItems.forEach(n => n.classList.remove("active"));
      item.classList.add("active");

      const targetTab = item.getAttribute("data-tab");
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));
      const activeTabEl = document.getElementById(`tab-${targetTab}`);
      if (activeTabEl) activeTabEl.classList.add("active");

      const titles = {
        telemetry: "Intrusion Telemetry",
        metrics: "Detection Metrics",
        confusion: "Confusion Matrix",
        rules: "Rules & Attribution",
        simulator: "Attack Injection Simulator"
      };
      document.getElementById("page-title").innerText = titles[targetTab] || "Intrusion Telemetry";

      // Refresh data on tab switch
      if (targetTab === "metrics") loadMetrics();
      else if (targetTab === "confusion") loadConfusionMatrix();
      else if (targetTab === "rules") loadAttribution();
      else if (targetTab === "telemetry") { loadAlerts(); loadDatasetComposition(); }
    });
  });
}

// Dynamic Plotly Donut Chart for Dataset Composition
async function loadDatasetComposition() {
  try {
    const res = await fetch("/api/dataset-composition");
    const data = await res.json();
    
    const capEl = document.getElementById("donut-total-caption");
    if (capEl) capEl.innerText = `Total Dataset: ${(data.total_flows || 0).toLocaleString()} flows/packets`;

    const legendList = document.getElementById("donut-legend-list");
    if (!legendList) return;
    legendList.innerHTML = "";

    if (!data.categories || data.categories.length === 0) {
      legendList.innerHTML = `<div style="color:#94a3b8; font-size:12px; padding: 20px 0;">No detections recorded. Run replay to populate.</div>`;
      Plotly.purge('donut-chart-div');
      return;
    }

    const labels = [];
    const values = [];
    const colors = [];

    data.categories.forEach(cat => {
      labels.push(cat.name);
      values.push(cat.count);
      colors.push(cat.color);

      const item = document.createElement("div");
      item.className = "donut-legend-item";
      item.innerHTML = `
        <div class="donut-legend-left">
          <span class="donut-legend-dot" style="background:${cat.color};"></span>
          <span style="font-weight:600; color:#1e293b;">${cat.name}</span>
        </div>
        <div style="font-weight:700; color:#334155;">
          ${cat.count.toLocaleString()} <span style="color:#64748b; font-weight:400;">(${cat.percentage}%)</span>
        </div>
      `;
      legendList.appendChild(item);
    });

    const plotData = [{
      values: values,
      labels: labels,
      type: 'pie',
      hole: 0.65,
      marker: { colors: colors },
      textinfo: 'none',
      hoverinfo: 'label+value+percent'
    }];

    const layout = {
      showlegend: false,
      margin: { t: 5, b: 5, l: 5, r: 5 },
      height: 190,
      width: 220,
      paper_bgcolor: 'transparent',
      plot_bgcolor: 'transparent',
      annotations: [{
        font: { size: 14, weight: 800, color: '#111827' },
        showarrow: false,
        text: `${(data.total_alerts || 0).toLocaleString()}<br><span style="font-size:10px; color:#64748b; font-weight:400;">Alerts</span>`,
        x: 0.5,
        y: 0.5
      }]
    };

    const config = { displayModeBar: false, responsive: true };
    Plotly.newPlot('donut-chart-div', plotData, layout, config);
  } catch (err) {
    console.error("Failed to render donut chart:", err);
  }
}

// Load System Status & Threat Distribution (100% Live DB Driven)
async function loadStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    
    document.getElementById("pcap-subtitle").innerText = `${data.pcap_filename} (${data.pcap_size_gb} GB) · Suricata 8.0.7 Engine`;
    
    const badgeCount = data.total_alerts > 0 ? (data.total_alerts > 999 ? "999+" : data.total_alerts) : "0";
    document.getElementById("live-badge-count").innerText = badgeCount;

    const distList = document.getElementById("threat-distribution-list");
    distList.innerHTML = "";

    if (!data.top_threats || data.top_threats.length === 0) {
      distList.innerHTML = `<div style="color:#9ca3af; font-size:12px; padding:10px;">No threat detections recorded in database.</div>`;
    } else {
      const maxCount = Math.max(...data.top_threats.map(t => t.count), 1);
      data.top_threats.forEach(t => {
        const pct = Math.min(100, Math.max(8, (t.count / maxCount) * 100));
        const div = document.createElement("div");
        div.className = "threat-cat-item";
        div.innerHTML = `
          <div class="threat-cat-header">
            <span>${t.signature}</span>
            <span class="threat-cat-count">${t.count.toLocaleString()}</span>
          </div>
          <div class="threat-progress-track">
            <div class="threat-progress-bar" style="width: ${pct}%;"></div>
          </div>
        `;
        distList.appendChild(div);
      });
    }

    document.getElementById("engine-status-text").innerHTML = `
      Engine Memory RSS: <strong>${data.ram_used_mb} MB</strong> (${data.ram_percent}%)<br>
      Total PCAP Packets: <strong>${data.total_packets.toLocaleString()}</strong><br>
      Total Alerts in DB: <strong>${data.total_alerts.toLocaleString()}</strong>
    `;

    const pill = document.getElementById("engine-status-pill");
    if (pill) {
      if (data.replay_state && data.replay_state.is_running) {
        document.getElementById("progress-card").classList.add("visible");
        pill.style.background = "#fef3c7";
        pill.style.color = "#b45309";
        pill.innerText = "● Ingestion Running";
      } else {
        pill.style.background = "#dcfce7";
        pill.style.color = "#15803d";
        pill.innerText = "● System Ready";
      }
    }
  } catch (err) {
    console.error("Failed to load status:", err);
  }
}

// Load Alerts Feed
async function loadAlerts() {
  try {
    const res = await fetch("/api/alerts?limit=50");
    const data = await res.json();
    const feedList = document.getElementById("alerts-feed-list");
    feedList.innerHTML = "";

    if (!data.alerts || data.alerts.length === 0) {
      feedList.innerHTML = `<div style="text-align:center; padding:30px; color:#9ca3af;">No alerts in database. Click "Run Dataset Replay" to evaluate PCAP.</div>`;
      return;
    }

    data.alerts.forEach(a => {
      const item = document.createElement("div");
      item.className = "alert-item";
      
      let iconClass = "sqli";
      let iconSymbol = "💉";
      const sigLower = a.signature.toLowerCase();
      if (sigLower.includes("xss")) { iconClass = "xss"; iconSymbol = "⚡"; }
      else if (sigLower.includes("brute") || sigLower.includes("login")) { iconClass = "bruteforce"; iconSymbol = "🔑"; }
      else if (sigLower.includes("infiltration") || sigLower.includes("smb")) { iconClass = "infiltration"; iconSymbol = "🛡️"; }
      else if (sigLower.includes("scan")) { iconClass = "portscan"; iconSymbol = "🔍"; }
      else if (sigLower.includes("dos") || sigLower.includes("flood")) { iconClass = "dos"; iconSymbol = "🔥"; }

      const sevClass = a.severity === 1 ? "sev-1" : (a.severity === 2 ? "sev-2" : "sev-3");
      const sevLabel = a.severity === 1 ? "HIGH (Sev 1)" : (a.severity === 2 ? "MED (Sev 2)" : "LOW (Sev 3)");

      item.innerHTML = `
        <div class="alert-main-row">
          <div class="alert-left">
            <div class="cat-icon ${iconClass}">${iconSymbol}</div>
            <div>
              <div class="alert-info-title">${a.signature}</div>
              <div class="alert-info-sub">${a.timestamp} · <code>${a.src_ip}:${a.src_port} ➔ ${a.dest_ip}:${a.dest_port}</code> (${a.proto})</div>
            </div>
          </div>
          <div class="alert-right">
            <span class="severity-pill ${sevClass}">${sevLabel}</span>
          </div>
        </div>
        <div class="explain-box">
          <strong>Deterministic Proof:</strong> ${a.reason}<br>
          <span style="color:#64748b; margin-top:4px; display:inline-block;">Flow Telemetry: ${a.pkts_toserver} packets · ${a.bytes_toserver} bytes</span>
        </div>
      `;

      item.addEventListener("click", () => {
        const box = item.querySelector(".explain-box");
        box.classList.toggle("open");
      });

      feedList.appendChild(item);
    });
  } catch (err) {
    console.error("Failed to load alerts:", err);
  }
}

// Professional Custom SVG Icon Helper Map
function getCategoryIconSvg(categoryKey) {
  const iconMap = {
    sqli: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
      <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
    </svg>`,
    xss: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="16 18 22 12 16 6"></polyline>
      <polyline points="8 6 2 12 8 18"></polyline>
    </svg>`,
    bruteforce: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
    </svg>`,
    infiltration: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
      <line x1="12" y1="8" x2="12" y2="12"></line>
      <line x1="12" y1="16" x2="12.01" y2="16"></line>
    </svg>`,
    portscan: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="11" cy="11" r="8"></circle>
      <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      <line x1="11" y1="8" x2="11" y2="14"></line>
      <line x1="8" y1="11" x2="14" y2="11"></line>
    </svg>`,
    dos: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
      <line x1="12" y1="9" x2="12" y2="13"></line>
      <line x1="12" y1="17" x2="12.01" y2="17"></line>
    </svg>`,
    generic: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"></circle>
      <line x1="12" y1="8" x2="12" y2="12"></line>
      <line x1="12" y1="16" x2="12.01" y2="16"></line>
    </svg>`
  };
  return iconMap[categoryKey] || iconMap.generic;
}

// Load Deduplicated Alerts Feed
async function loadAlerts() {
  try {
    const res = await fetch("/api/alerts?limit=100&grouped=true");
    const data = await res.json();
    const feedList = document.getElementById("alerts-feed-list");
    const countSummary = document.getElementById("feed-count-summary");
    feedList.innerHTML = "";

    if (!data.grouped_alerts || data.grouped_alerts.length === 0) {
      if (countSummary) countSummary.innerText = "0 alerts";
      feedList.innerHTML = `<div style="text-align:center; padding:30px; color:#9ca3af;">No alerts in database. Click "Execute PCAP Ingestion" to evaluate.</div>`;
      return;
    }

    if (countSummary) {
      countSummary.innerText = `${(data.total || 0).toLocaleString()} alerts committed (${data.grouped_alerts.length} signature clusters)`;
    }

    data.grouped_alerts.forEach((g, idx) => {
      const item = document.createElement("div");
      item.className = "alert-item";
      
      let iconClass = "sqli";
      const sigLower = g.signature.toLowerCase();
      if (sigLower.includes("xss")) { iconClass = "xss"; }
      else if (sigLower.includes("brute") || sigLower.includes("login")) { iconClass = "bruteforce"; }
      else if (sigLower.includes("infiltration") || sigLower.includes("smb")) { iconClass = "infiltration"; }
      else if (sigLower.includes("scan")) { iconClass = "portscan"; }
      else if (sigLower.includes("dos") || sigLower.includes("flood")) { iconClass = "dos"; }

      const iconSvg = getCategoryIconSvg(iconClass);
      const sevClass = g.severity === 1 ? "sev-1" : (g.severity === 2 ? "sev-2" : "sev-3");
      const sevLabel = g.severity === 1 ? "CRITICAL" : (g.severity === 2 ? "WARNING" : "INFORMATIONAL");

      const countBadge = g.count > 1 ? `<span class="grouped-badge">${g.count.toLocaleString()} triggers</span>` : "";

      let instancesHtml = "";
      if (g.count > 1) {
        instancesHtml = `
          <button class="group-toggle-btn" id="btn-toggle-${idx}">
            ▼ SID ${g.signature_id} fired ${g.count} times — expand distinct flow records (${g.count})
          </button>
          <div class="instances-container" id="inst-container-${idx}">
            ${g.instances.slice(0, 15).map(inst => `
              <div class="instance-row">
                <div><code>${inst.src_ip}:${inst.src_port} ➔ ${inst.dest_ip}:${inst.dest_port}</code></div>
                <div style="color:#64748b;">${inst.timestamp}</div>
              </div>
            `).join("")}
          </div>
        `;
      }

      item.innerHTML = `
        <div class="alert-main-row">
          <div class="alert-left">
            <div class="cat-icon ${iconClass}">${iconSvg}</div>
            <div>
              <div class="alert-info-title">${g.signature} ${countBadge}</div>
              <div class="alert-info-sub">${g.last_seen} · <code>${g.sample_src} ➔ ${g.sample_dst}</code> (${g.sample_proto})</div>
            </div>
          </div>
          <div class="alert-right">
            <span class="severity-pill ${sevClass}">${sevLabel}</span>
          </div>
        <div class="explain-box">
          <strong>Deterministic Proof:</strong> ${g.sample_reason}<br>
          <span style="color:#64748b; margin-top:4px; display:inline-block;">Observed: ${g.sample_pkts} packets · ${g.sample_bytes} bytes</span>
        </div>
        ${instancesHtml}
      `;

      item.querySelector(".alert-main-row").addEventListener("click", () => {
        const box = item.querySelector(".explain-box");
        box.classList.toggle("open");
      });

      if (g.count > 1) {
        const toggleBtn = item.querySelector(`#btn-toggle-${idx}`);
        const instBox = item.querySelector(`#inst-container-${idx}`);
        if (toggleBtn && instBox) {
          toggleBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            instBox.classList.toggle("open");
            if (instBox.classList.contains("open")) {
              toggleBtn.innerHTML = `▲ Collapse ${g.count} instances`;
            } else {
              toggleBtn.innerHTML = `▼ SID ${g.signature_id} fired ${g.count} times — expand distinct flow records (${g.count})`;
            }
          });
        }
      }

      feedList.appendChild(item);
    });
  } catch (err) {
    console.error("Failed to load alerts:", err);
  }
}

// Load Metrics Table
async function loadMetrics() {
  try {
    const res = await fetch("/api/metrics");
    const data = await res.json();
    const tbody = document.getElementById("metrics-table-body");
    tbody.innerHTML = "";

    if (!data.category_metrics || data.category_metrics.length === 0) {
      tbody.innerHTML = `<tr><td colspan="11" style="text-align:center; padding:30px; color:#9ca3af;">No evaluation data available. Run Dataset Replay to compute per-category detection metrics.</td></tr>`;
      return;
    }

    data.category_metrics.forEach(m => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${m.Category}</strong></td>
        <td>${m.Total_Flows.toLocaleString()}</td>
        <td style="color:#10b981; font-weight:700;">${m.TP.toLocaleString()}</td>
        <td style="color:${m.FP > 0 ? '#ef4444' : '#64748b'};">${m.FP.toLocaleString()}</td>
        <td>${m.TN.toLocaleString()}</td>
        <td style="color:${m.FN > 0 ? '#ea580c' : '#64748b'};">${m.FN.toLocaleString()}</td>
        <td style="color:${m.Misclassified > 0 ? '#ef4444' : '#64748b'}; font-weight:${m.Misclassified > 0 ? '700' : '400'};">${(m.Misclassified || 0).toLocaleString()}</td>
        <td><strong>${(m.Precision * 100).toFixed(1)}%</strong></td>
        <td><strong>${(m.Recall * 100).toFixed(1)}%</strong></td>
        <td style="color:#2563eb; font-weight:700;">${(m.F1_Score * 100).toFixed(1)}%</td>
        <td>${(m.FP_Rate * 100).toFixed(2)}%</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

// Load Multi-Class Confusion Matrix
async function loadConfusionMatrix() {
  try {
    const res = await fetch("/api/confusion-matrix");
    const data = await res.json();
    const container = document.getElementById("confusion-matrix-container");
    container.innerHTML = "";

    if (!data.classes || data.classes.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding:40px; color:#9ca3af;">No confusion matrix calculated yet. Click "Run Dataset Replay" to evaluate.</div>`;
      return;
    }

    let html = `<table class="ids-table"><thead><tr><th>Ground Truth Label</th>`;
    data.classes.forEach(c => {
      html += `<th style="text-align:center;">${c}</th>`;
    });
    html += `</tr></thead><tbody>`;

    data.ground_truth_labels.forEach((gt, rIdx) => {
      html += `<tr><td><strong>${gt}</strong></td>`;
      data.classes.forEach((c, cIdx) => {
        const val = data.matrix[rIdx][cIdx];
        const isDiag = (gt === c || (gt === 'Benign' && c === 'Benign'));
        const bg = val > 0 ? (isDiag ? "#dcfce7" : "#fee2e2") : "#ffffff";
        const color = val > 0 ? (isDiag ? "#15803d" : "#b91c1c") : "#94a3b8";
        html += `<td style="text-align:center; background:${bg}; color:${color}; font-weight:${val > 0 ? '700' : '400'};">${val.toLocaleString()}</td>`;
      });
      html += `</tr>`;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (err) {
    console.error("Failed to load confusion matrix:", err);
  }
}

// Load Rule Attribution
async function loadAttribution() {
  try {
    const res = await fetch("/api/metrics");
    const data = await res.json();
    const tbody = document.getElementById("attribution-table-body");
    tbody.innerHTML = "";

    if (!data.attribution_metrics || data.attribution_metrics.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:30px; color:#9ca3af;">No rule attribution metrics available. Run Dataset Replay to compute.</td></tr>`;
      return;
    }

    data.attribution_metrics.forEach(a => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${a.SID}</code></td>
        <td><strong>${a.Signature_Name}</strong></td>
        <td style="color:#10b981; font-weight:700;">${a.TP_Count.toLocaleString()}</td>
        <td>${a.FP_Count.toLocaleString()}</td>
        <td><strong>${(a.Rule_Precision * 100).toFixed(1)}%</strong></td>
        <td><span class="severity-pill ${a.Status === 'Active' ? 'sev-3' : ''}">${a.Status}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load attribution:", err);
  }
}

// Reset Database / Start New Run
async function resetDatabase() {
  const btn = document.getElementById("reset-btn");
  btn.disabled = true;
  btn.innerText = "⏳ Resetting...";
  try {
    const res = await fetch("/api/reset", { method: "POST" });
    const data = await res.json();
    
    // Clear live notification stream list
    const streamList = document.getElementById("bounded-stream-list");
    if (streamList) {
      streamList.innerHTML = `<div style="font-size:11px; color:#94a3b8; text-align:center; padding:10px;">Waiting for new detections...</div>`;
    }
    
    document.getElementById("progress-card").classList.remove("visible");
    
    await loadStatus();
    await loadDatasetComposition();
    await loadAlerts();
    await loadMetrics();
    await loadConfusionMatrix();
    await loadAttribution();
  } catch (err) {
    console.error("Reset failed:", err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span>🔄</span> Reset / Start New Run`;
  }
}

// Start Replay
async function startReplay() {
  try {
    const btn = document.getElementById("start-replay-btn");
    btn.disabled = true;
    btn.innerText = "⏳ Replay Running...";
    
    document.getElementById("progress-card").classList.add("visible");

    await fetch("/api/replay/start", { method: "POST" });
  } catch (err) {
    console.error("Replay start failed:", err);
  }
}

// Attack Injector
async function injectAttack() {
  const attackType = document.getElementById("sim-attack-select").value;
  const targetHost = document.getElementById("sim-target-ip").value;
  const msgEl = document.getElementById("sim-result-msg");
  const btn = document.getElementById("sim-inject-btn");

  btn.disabled = true;
  btn.innerText = "Constructing & Replaying...";
  msgEl.innerText = "";

  try {
    const res = await fetch("/api/inject", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attack_type: attackType, target_host: targetHost })
    });
    const data = await res.json();
    if (data.status === "success") {
      msgEl.style.color = "#10b981";
      msgEl.innerText = `✅ Injected ${data.result.packets_injected} packets for ${attackType}! Evaluated ${data.result.total_alerts} alerts.`;
      loadAlerts();
      loadMetrics();
      loadDatasetComposition();
      loadStatus();
    } else {
      msgEl.style.color = "#ef4444";
      msgEl.innerText = `❌ Error: ${data.message}`;
    }
  } catch (err) {
    msgEl.style.color = "#ef4444";
    msgEl.innerText = `Error: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.innerText = "🚀 Inject & Replay Attack";
  }
}

// Bounded Live Notification Stream (Right Sidebar Panel - No Overlay)
function appendBoundedNotification(alertData) {
  const streamList = document.getElementById("bounded-stream-list");
  if (!streamList) return;

  // Clear placeholder if present
  if (streamList.innerText.includes("Waiting for new detections")) {
    streamList.innerHTML = "";
  }

  const isCritical = alertData.severity === 1;
  const sevClass = isCritical ? "sev-1" : (alertData.severity === 2 ? "sev-2" : "");
  const badgeSvg = isCritical ? 
    `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>` :
    `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ea580c" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

  const item = document.createElement("div");
  item.className = `bounded-stream-item ${sevClass}`;
  item.innerHTML = `
    <div style="display:flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:6px; background:rgba(0,0,0,0.04); flex-shrink:0;">
      ${badgeSvg}
    </div>
    <div class="bounded-stream-info">
      <div class="bounded-stream-sig">${alertData.signature}</div>
      <div class="bounded-stream-time">${alertData.src_ip} ➔ ${alertData.dest_ip} · ${new Date().toLocaleTimeString()}</div>
    </div>
  `;

  streamList.insertBefore(item, streamList.firstChild);

  // Keep max 5 compact entries
  while (streamList.children.length > 5) {
    streamList.removeChild(streamList.lastChild);
  }
}

// Real-Time SSE Listener
function initSSE() {
  const evtSource = new EventSource("/api/stream/events");
  
  evtSource.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "progress") {
        const p = msg.data;
        const frac = p.total_pkts > 0 ? (p.current_pkts / p.total_pkts) * 100 : 0;
        
        document.getElementById("progress-card").classList.add("visible");
        document.getElementById("prog-percent-text").innerText = `${frac.toFixed(1)}%`;
        document.getElementById("prog-bar-fill").style.width = `${Math.min(100, frac)}%`;
        document.getElementById("prog-details-text").innerHTML = `
          <span>${p.current_pkts.toLocaleString()} / ${p.total_pkts.toLocaleString()} pkts</span>
          <span>Live Alerts Ingested: <strong>${p.alerts_count.toLocaleString()}</strong></span>
          <span>Elapsed: ${p.elapsed}s · ETA: ${p.eta}s</span>
        `;
        
        // If alerts arrived, refresh active tabs periodically
        if (p.alerts_count > 0 && Math.floor(p.elapsed) % 4 === 0) {
          loadMetrics();
          loadConfusionMatrix();
          loadAttribution();
          loadDatasetComposition();
        }
      } else if (msg.type === "new_alert") {
        appendBoundedNotification(msg.data);
        loadAlerts();
        loadStatus();
      } else if (msg.type === "completed") {
        document.getElementById("start-replay-btn").disabled = false;
        document.getElementById("start-replay-btn").innerHTML = `<span>⚡</span> Run Dataset Replay`;
        document.getElementById("progress-card").classList.remove("visible");
        loadAlerts();
        loadMetrics();
        loadConfusionMatrix();
        loadAttribution();
        loadDatasetComposition();
        loadStatus();
      }
    } catch (e) {
      // Keepalive message
    }
  };

  evtSource.onerror = () => {
    // Reconnects automatically
  };
}
