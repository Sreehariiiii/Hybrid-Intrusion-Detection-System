// Modern Hybrid IDS Client Application (Benchmark & Operational Large-Traffic Analysis)
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  loadStatus();
  loadBenchmarkResults();
  loadLargeTrafficStatus();
  loadAlerts();
  loadRules();
  initSSE();

  // Button Listeners
  const btnRunBm = document.getElementById("btn-run-benchmark");
  if (btnRunBm) btnRunBm.addEventListener("click", runAccuracyBenchmark);

  const btnStartLarge = document.getElementById("btn-start-large-pcap");
  if (btnStartLarge) btnStartLarge.addEventListener("click", startLargeTraffic);

  const btnStopLarge = document.getElementById("btn-stop-large-pcap");
  if (btnStopLarge) btnStopLarge.addEventListener("click", stopLargeTraffic);

  const btnReset = document.getElementById("reset-btn");
  if (btnReset) btnReset.addEventListener("click", resetDatabase);

  const btnInject = document.getElementById("sim-inject-btn");
  if (btnInject) btnInject.addEventListener("click", injectAttack);
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
        benchmark: "Accuracy Benchmark",
        "large-traffic": "Large Traffic Analysis",
        telemetry: "Intrusion Telemetry & Alerts",
        rules: "Rule Intelligence & SIDs",
        simulator: "Attack Injection Simulator"
      };
      document.getElementById("page-title").innerText = titles[targetTab] || "Intrusion Intelligence";

      if (targetTab === "benchmark") loadBenchmarkResults();
      else if (targetTab === "large-traffic") loadLargeTrafficStatus();
      else if (targetTab === "telemetry") loadAlerts();
      else if (targetTab === "rules") loadRules();
    });
  });
}

// ==============================================================================
// 1. ACCURACY BENCHMARK LOGIC (6,216 FLOWS)
// ==============================================================================

async function loadBenchmarkResults() {
  try {
    const res = await fetch("/api/benchmark/results");
    const data = await res.json();
    renderBenchmarkData(data);
  } catch (err) {
    console.error("Failed to load benchmark results:", err);
  }
}

async function runAccuracyBenchmark() {
  const btn = document.getElementById("btn-run-benchmark");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span>⏳</span> Evaluating 6,216 flows...`;
  }
  try {
    const res = await fetch("/api/benchmark/run", { method: "POST" });
    const data = await res.json();
    renderBenchmarkData(data);
  } catch (err) {
    console.error("Benchmark run failed:", err);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="5 3 19 12 5 21 5 3"></polygon>
        </svg>
        <span>RUN ACCURACY BENCHMARK</span>
      `;
    }
  }
}

function renderBenchmarkData(data) {
  const accEl = document.getElementById("bm-accuracy");
  const accSub = document.getElementById("bm-accuracy-sub");
  const behEl = document.getElementById("bm-behavioural");
  const specEl = document.getElementById("bm-specificity");
  const farSub = document.getElementById("bm-far-sub");
  const f1El = document.getElementById("bm-macro-f1");
  const f1Sub = document.getElementById("bm-macro-sub");

  const tbody = document.getElementById("benchmark-metrics-tbody");
  const confContainer = document.getElementById("benchmark-confusion-container");
  const attrTbody = document.getElementById("benchmark-attribution-tbody");

  if (!data || data.status === "unverified" || data.status === "error") {
    if (accEl) accEl.innerText = "Not yet verified";
    if (accSub) accSub.innerText = data.message || "Run benchmark to evaluate";
    if (behEl) behEl.innerText = "--";
    if (specEl) specEl.innerText = "--";
    if (farSub) farSub.innerText = "FAR: --";
    if (f1El) f1El.innerText = "--";
    if (f1Sub) f1Sub.innerText = "Prec: -- · Rec: --";

    if (tbody) tbody.innerHTML = `<tr><td colspan="11" style="text-align:center; padding:20px; color:#94a3b8;">${data.message || 'Click "RUN ACCURACY BENCHMARK" to evaluate.'}</td></tr>`;
    if (confContainer) confContainer.innerHTML = `<div style="text-align:center; padding:20px; color:#94a3b8;">No evaluation recorded yet.</div>`;
    if (attrTbody) attrTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:#94a3b8;">Attribution data available after execution.</td></tr>`;
    return;
  }

  // Populate Dynamic Summary Cards
  if (accEl) accEl.innerText = `${(data.exact_accuracy * 100).toFixed(2)}%`;
  if (accSub) accSub.innerText = `${(data.total_tp + data.total_tn).toLocaleString()} / ${data.total_flows.toLocaleString()} flows correct`;
  if (behEl) behEl.innerText = `${(data.behavioural_detection_rate * 100).toFixed(2)}%`;
  if (specEl) specEl.innerText = `${(data.benign_specificity * 100).toFixed(2)}%`;
  if (farSub) farSub.innerText = `FAR: ${(data.benign_far * 100).toFixed(2)}% (${data.total_fp} FP)`;
  if (f1El) f1El.innerText = `${(data.macro_f1 * 100).toFixed(2)}%`;
  if (f1Sub) f1Sub.innerText = `Prec: ${(data.macro_precision * 100).toFixed(1)}% · Rec: ${(data.macro_recall * 100).toFixed(1)}%`;

  // Populate Per-Category Table
  if (tbody && data.category_metrics) {
    tbody.innerHTML = "";
    data.category_metrics.forEach(m => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${m.Category}</strong></td>
        <td>${m.Total_Flows.toLocaleString()}</td>
        <td style="color:#10b981; font-weight:700;">${m.TP.toLocaleString()}</td>
        <td style="color:${m.FP > 0 ? '#ef4444' : '#64748b'};">${m.FP.toLocaleString()}</td>
        <td>${m.TN.toLocaleString()}</td>
        <td style="color:${m.FN > 0 ? '#ea580c' : '#64748b'}; font-weight:${m.FN > 0 ? '700' : '400'};">${m.FN.toLocaleString()}</td>
        <td style="color:${m.Misclassified > 0 ? '#ef4444' : '#64748b'}; font-weight:${m.Misclassified > 0 ? '700' : '400'};">${(m.Misclassified || 0).toLocaleString()}</td>
        <td><strong>${(m.Precision * 100).toFixed(1)}%</strong></td>
        <td><strong>${(m.Recall * 100).toFixed(1)}%</strong></td>
        <td style="color:#2563eb; font-weight:700;">${(m.F1_Score * 100).toFixed(1)}%</td>
        <td>${(m.FP_Rate * 100).toFixed(2)}%</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Populate Multi-Class Confusion Matrix (Exact sum = 6,216)
  if (confContainer && data.confusion_matrix) {
    const cm = data.confusion_matrix;
    let html = `<table class="ids-table"><thead><tr><th>Ground Truth</th>`;
    cm.classes.forEach(c => {
      html += `<th style="text-align:center;">${c}</th>`;
    });
    html += `</tr></thead><tbody>`;

    cm.ground_truth_labels.forEach((gt, rIdx) => {
      html += `<tr><td><strong>${gt}</strong></td>`;
      cm.classes.forEach((c, cIdx) => {
        const val = cm.matrix[rIdx][cIdx];
        const isDiag = (gt === c || (gt === 'Benign' && c === 'Benign'));
        const bg = val > 0 ? (isDiag ? "#dcfce7" : "#fee2e2") : "#ffffff";
        const color = val > 0 ? (isDiag ? "#15803d" : "#b91c1c") : "#94a3b8";
        html += `<td style="text-align:center; background:${bg}; color:${color}; font-weight:${val > 0 ? '700' : '400'};">${val.toLocaleString()}</td>`;
      });
      html += `</tr>`;
    });
    html += `</tbody></table>`;
    confContainer.innerHTML = html;
  }

  // Populate Attribution Table
  if (attrTbody && data.attribution_metrics) {
    attrTbody.innerHTML = "";
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
      attrTbody.appendChild(tr);
    });
  }
}

// ==============================================================================
// 2. LARGE TRAFFIC / OPERATIONAL REPLAY LOGIC
// ==============================================================================

async function loadLargeTrafficStatus() {
  try {
    const res = await fetch("/api/large-traffic/status");
    const data = await res.json();
    renderLargeTrafficState(data);
  } catch (err) {
    console.error("Failed to load large traffic status:", err);
  }
}

async function startLargeTraffic() {
  const btn = document.getElementById("btn-start-large-pcap");
  if (btn) btn.disabled = true;
  try {
    await fetch("/api/large-traffic/start", { method: "POST" });
    loadLargeTrafficStatus();
  } catch (err) {
    console.error("Failed to start large PCAP:", err);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function stopLargeTraffic() {
  const btn = document.getElementById("btn-stop-large-pcap");
  if (btn) btn.disabled = true;
  try {
    await fetch("/api/large-traffic/stop", { method: "POST" });
    loadLargeTrafficStatus();
  } catch (err) {
    console.error("Failed to stop large PCAP:", err);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderLargeTrafficState(st) {
  if (!st) return;

  const badge = document.getElementById("large-status-badge");
  if (badge) {
    badge.innerText = st.status;
    if (st.status === "Running") {
      badge.style.background = "#fef3c7";
      badge.style.color = "#b45309";
    } else if (st.status === "Completed") {
      badge.style.background = "#dcfce7";
      badge.style.color = "#15803d";
    } else if (st.status.includes("Stopped")) {
      badge.style.background = "#fee2e2";
      badge.style.color = "#b91c1c";
    } else {
      badge.style.background = "#f1f5f9";
      badge.style.color = "#475569";
    }
  }

  const pctEl = document.getElementById("large-pct-text");
  const barEl = document.getElementById("large-bar-fill");
  const pktsEl = document.getElementById("large-pkts-text");
  const tpEl = document.getElementById("large-tp-text");
  const timeEl = document.getElementById("large-time-text");
  const resEl = document.getElementById("large-res-text");

  const pct = st.progress_pct || 0.0;
  if (pctEl) pctEl.innerText = `${pct.toFixed(1)}%`;
  if (barEl) barEl.style.width = `${Math.min(100, pct)}%`;
  if (pktsEl) pktsEl.innerText = `${(st.current_pkts || 0).toLocaleString()} / ${(st.total_pkts || 0).toLocaleString()} pkts`;
  if (tpEl) tpEl.innerText = `${st.pkts_per_sec || 0} pkts/s (${st.mb_per_sec || 0} MB/s)`;
  if (timeEl) timeEl.innerText = `${st.elapsed_sec || 0}s (ETA: ${st.eta_sec || 0}s)`;
  if (resEl) resEl.innerText = `CPU: ${st.cpu_percent || 0}% · RAM: ${st.ram_used_mb || 0} MB`;

  // Counter Cards
  const totStat = document.getElementById("large-stat-total");
  const highStat = document.getElementById("large-stat-high");
  const medStat = document.getElementById("large-stat-med");
  const lowStat = document.getElementById("large-stat-low");
  const sigStat = document.getElementById("large-stat-sigs");
  const dropStat = document.getElementById("large-stat-drops");

  if (totStat) totStat.innerText = (st.alerts_count || 0).toLocaleString();
  if (highStat) highStat.innerText = (st.high_alerts || 0).toLocaleString();
  if (medStat) medStat.innerText = (st.med_alerts || 0).toLocaleString();
  if (lowStat) lowStat.innerText = (st.low_alerts || 0).toLocaleString();
  if (sigStat) sigStat.innerText = (st.unique_signatures || 0).toLocaleString();
  if (dropStat) dropStat.innerText = (st.packet_drops || 0).toLocaleString();

  // Render Live Circular Chart
  renderLiveCircularChart(st);

  // Render Operational Report if available
  const reportCard = document.getElementById("large-report-card");
  const reportContent = document.getElementById("large-report-content");
  if (st.completed_report && reportCard && reportContent) {
    const r = st.completed_report;
    reportCard.style.display = "block";
    reportContent.innerHTML = `
================================================================================
                    FULL PCAP OPERATIONAL ANALYSIS REPORT
================================================================================
Target Capture File         : ${r.capture_filename} (${r.capture_size_gb} GB)
Total Decoded Packets       : ${r.packets_processed.toLocaleString()} / ${r.total_packets_in_file.toLocaleString()}
Processing Wall Time        : ${r.processing_time_sec} seconds (${(r.processing_time_sec/60).toFixed(2)} mins)
Sustained Throughput        : ${r.sustained_throughput_pkts_sec.toLocaleString()} pkts/sec (${r.sustained_throughput_mb_sec} MB/sec)
Total Alerts Generated      : ${r.total_alerts_generated.toLocaleString()}
Unique Signatures Fired     : ${r.unique_signatures_triggered}
High Severity (Critical)    : ${r.high_severity_alerts.toLocaleString()}
Medium Severity (Warning)   : ${r.medium_severity_alerts.toLocaleString()}
Low Severity (Informational): ${r.low_severity_alerts.toLocaleString()}
Kernel/Driver Packet Drops  : ${r.packet_drops}
Processing Engine Status    : ${r.engine_status}
Run Type Scope              : ${r.is_partial ? 'PARTIAL RUN (Stopped by user)' : 'FULL CAPTURE COMPLETE'}
Audit Notice                : ${r.notice}
================================================================================
`;
  }
}

function renderLiveCircularChart(st) {
  const chartDiv = document.getElementById("large-circular-chart");
  if (!chartDiv) return;

  const total = (st.alerts_count || 0);
  if (total === 0) {
    chartDiv.innerHTML = `<div style="font-size:12px; color:#94a3b8; text-align:center; padding:40px;">No alerts generated yet. Run PCAP to stream live alerts.</div>`;
    Plotly.purge(chartDiv);
    return;
  }

  const values = [st.high_alerts || 0, st.med_alerts || 0, st.low_alerts || 0];
  const labels = ["High Severity", "Medium Severity", "Low Severity"];
  const colors = ["#ef4444", "#f59e0b", "#3b82f6"];

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
    showlegend: true,
    legend: { orientation: "h", y: -0.2, font: { size: 10 } },
    margin: { t: 5, b: 25, l: 5, r: 5 },
    height: 190,
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    annotations: [{
      font: { size: 14, weight: 800, color: '#0f172a' },
      showarrow: false,
      text: `${total.toLocaleString()}<br><span style="font-size:9px; color:#64748b; font-weight:400;">Alerts</span>`,
      x: 0.5,
      y: 0.5
    }]
  };

  const config = { displayModeBar: false, responsive: true };
  Plotly.react(chartDiv, plotData, layout, config);
}

// ==============================================================================
// 3. ALERTS FEED & TELEMETRY
// ==============================================================================

// SVG Icon Helper Map
function getCategoryIconSvg(categoryKey) {
  const iconMap = {
    sqli: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>`,
    xss: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
    bruteforce: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
    infiltration: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`,
    portscan: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>`,
    dos: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
    generic: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`
  };
  return iconMap[categoryKey] || iconMap.generic;
}

async function loadAlerts() {
  try {
    const res = await fetch("/api/alerts?limit=100&grouped=true");
    const data = await res.json();
    const feedList = document.getElementById("alerts-feed-list");
    const countSummary = document.getElementById("feed-count-summary");
    feedList.innerHTML = "";

    if (!data.grouped_alerts || data.grouped_alerts.length === 0) {
      if (countSummary) countSummary.innerText = "0 alerts";
      feedList.innerHTML = `<div style="text-align:center; padding:30px; color:#9ca3af;">No alerts in database. Run PCAP replay to ingest alerts.</div>`;
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

// ==============================================================================
// 4. RULES INTELLIGENCE
// ==============================================================================

async function loadRules() {
  try {
    const res = await fetch("/api/rules");
    const data = await res.json();
    const container = document.getElementById("rules-list-container");
    if (!container) return;
    container.innerHTML = "";

    if (!data.rules || data.rules.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding:30px; color:#94a3b8;">No custom rules loaded.</div>`;
      return;
    }

    data.rules.forEach(r => {
      const card = document.createElement("div");
      card.style.cssText = "background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:14px; font-size:12px;";
      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <div><strong>SID ${r.sid}: ${r.msg}</strong></div>
          <span class="severity-pill ${r.priority === 1 ? 'sev-1' : (r.priority === 2 ? 'sev-2' : 'sev-3')}">Priority ${r.priority}</span>
        </div>
        <div style="font-family:monospace; background:#f8fafc; padding:8px; border-radius:6px; color:#334155; margin-top:4px;">
          ${r.raw_rule}
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to load rules:", err);
  }
}

// ==============================================================================
// 5. STATUS, RESET & ATTACK INJECTION
// ==============================================================================

async function loadStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    
    const badgeCount = data.total_alerts > 0 ? (data.total_alerts > 999 ? "999+" : data.total_alerts) : "0";
    document.getElementById("live-badge-count").innerText = badgeCount;

    const distList = document.getElementById("threat-distribution-list");
    if (distList) {
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
    }

    document.getElementById("engine-status-text").innerHTML = `
      Engine Memory RSS: <strong>${data.ram_used_mb} MB</strong> (${data.ram_percent}%)<br>
      Total PCAP Packets: <strong>${data.total_packets.toLocaleString()}</strong><br>
      Total Alerts in DB: <strong>${data.total_alerts.toLocaleString()}</strong>
    `;
  } catch (err) {
    console.error("Failed to load status:", err);
  }
}

async function resetDatabase() {
  const btn = document.getElementById("reset-btn");
  btn.disabled = true;
  btn.innerText = "⏳ Resetting...";
  try {
    await fetch("/api/reset", { method: "POST" });
    const streamList = document.getElementById("bounded-stream-list");
    if (streamList) {
      streamList.innerHTML = `<div style="font-size:11px; color:#94a3b8; text-align:center; padding:10px;">Waiting for new detections...</div>`;
    }
    await loadStatus();
    await loadBenchmarkResults();
    await loadLargeTrafficStatus();
    await loadAlerts();
  } catch (err) {
    console.error("Reset failed:", err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span>🔄</span> Reset Session Data`;
  }
}

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
    btn.innerText = "🚀 Dispatch Synthetic Exploit";
  }
}

// Bounded Live Notification Stream
function appendBoundedNotification(alertData) {
  const streamList = document.getElementById("bounded-stream-list");
  if (!streamList) return;

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
  while (streamList.children.length > 5) {
    streamList.removeChild(streamList.lastChild);
  }
}

// SSE Live Listener
function initSSE() {
  const evtSource = new EventSource("/api/stream/events");
  
  evtSource.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "large_traffic_progress") {
        renderLargeTrafficState(msg.data);
      } else if (msg.type === "large_traffic_completed") {
        loadLargeTrafficStatus();
        loadAlerts();
        loadStatus();
      } else if (msg.type === "new_alert") {
        appendBoundedNotification(msg.data);
        loadStatus();
      } else if (msg.type === "reset") {
        loadStatus();
        loadBenchmarkResults();
        loadLargeTrafficStatus();
        loadAlerts();
      }
    } catch (e) {
      // keepalive
    }
  };

  evtSource.onerror = () => {
    // auto-reconnects
  };
}

