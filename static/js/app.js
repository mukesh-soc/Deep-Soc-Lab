/**
 * SentinelX Core Application Controller
 * Manages SPA tab routing, telemetry polling, incident workbench rendering,
 * audio alerting, and modal views.
 */

let currentTab = 'dashboard';
let telemetryData = [];
let audioAlertEnabled = true;

// Synthesized Alert Sound via Web Audio API
function playAlertBeep(severity) {
  if (!audioAlertEnabled) return;
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.type = severity === 'Critical' ? 'sawtooth' : 'sine';
    osc.frequency.setValueAtTime(severity === 'Critical' ? 880 : 587.33, audioCtx.currentTime);

    gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);

    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.start();
    osc.stop(audioCtx.currentTime + 0.35);
  } catch (e) {
    // Audio context may be restricted before user interaction
  }
}

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.style.cssText = `
    background: #0f172a;
    border: 1px solid ${type === 'error' ? '#f43f5e' : type === 'success' ? '#10b981' : '#38bdf8'};
    color: #fff;
    padding: 12px 18px;
    border-radius: 8px;
    margin-bottom: 8px;
    font-size: 13px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    display: flex;
    align-items: center;
    gap: 10px;
    animation: fadeIn 0.3s ease;
  `;

  const icon = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
  toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.5s ease';
    setTimeout(() => toast.remove(), 500);
  }, 4000);
}

// Tab Switching
function switchTab(tabId) {
  currentTab = tabId;

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });

  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });

  if (tabId === 'hunting') {
    loadTelemetry();
  } else if (tabId === 'incidents') {
    loadIncidents();
  } else if (tabId === 'soar') {
    loadSOARHistory();
  }
}

// Refresh SIEM metrics and alerts
async function refreshSIEM() {
  try {
    const res = await fetch('/api/v1/metrics', {
      headers: AuthState.token ? { 'Authorization': `Bearer ${AuthState.token}` } : {}
    });
    const metrics = await res.json();

    // Update DOM counters
    const evCount = document.getElementById('metricTotalEvents');
    const alCount = document.getElementById('metricTotalAlerts');
    const miCount = document.getElementById('metricMispHits');
    const incCount = document.getElementById('metricActiveIncidents');

    if (evCount) evCount.innerText = metrics.total_events || 0;
    if (alCount) alCount.innerText = metrics.total_alerts || 0;
    if (miCount) miCount.innerText = metrics.misp_hits || 0;
    if (incCount) incCount.innerText = metrics.active_incidents || 0;

    // Update Charts
    if (window.updateChartsData) {
      updateChartsData(metrics);
    } else if (window.initCharts) {
      initCharts(metrics);
    }

    // Render Recent Alerts list in dashboard
    renderRecentAlerts(metrics.recent_alerts || []);
  } catch (err) {
    console.error('Failed to refresh metrics:', err);
  }
}

function renderRecentAlerts(alerts) {
  const container = document.getElementById('dashboardAlertsList');
  if (!container) return;

  if (!alerts || alerts.length === 0) {
    container.innerHTML = '<div style="color: #64748b; padding: 16px; text-align: center;">No active security alerts recorded.</div>';
    return;
  }

  container.innerHTML = alerts.slice(0, 6).map(a => {
    const sevClass = (a.severity || 'medium').toLowerCase();
    return `
      <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; display: flex; align-items: center; justify-content: space-between; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 12px;">
          <span class="badge-${sevClass}">${a.severity.toUpperCase()}</span>
          <div>
            <div style="font-weight: 600; font-size: 13px; color: #fff;">${a.title}</div>
            <div style="font-size: 11px; color: #94a3b8;">
              <span class="mono-cell">${a.host}</span> · Rule: ${a.rule_id} · MITRE: <span style="color:#c4b5fd;">${a.technique_id || 'T1059'}</span>
            </div>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          ${a.misp_match ? '<span class="badge-misp">MISP MATCH</span>' : ''}
          <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="openAlertModal('${a.alert_id}')">Investigate</button>
        </div>
      </div>
    `;
  }).join('');
}

// Telemetry Hunting Table
async function loadTelemetry(query = '') {
  try {
    const res = await fetch(`/api/v1/telemetry?q=${encodeURIComponent(query)}&limit=100`, {
      headers: AuthState.token ? { 'Authorization': `Bearer ${AuthState.token}` } : {}
    });
    const data = await res.json();
    telemetryData = data.events || [];

    const tableBody = document.getElementById('telemetryTableBody');
    if (!tableBody) return;

    if (telemetryData.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">No matching telemetry records found.</td></tr>';
      return;
    }

    tableBody.innerHTML = telemetryData.map(e => {
      const sev = (e.severity || 'low').toLowerCase();
      const timeStr = (e.timestamp || '').substring(11, 19) || '12:00:00';
      const indicator = e.http_host || e.dst_ip || (e.hashes ? e.hashes.substring(0, 16) + '...' : '-');
      const processOrUri = e.process_name || e.http_uri || '-';

      return `
        <tr>
          <td class="mono-cell">${timeStr}</td>
          <td><span class="pill-badge">${e.source ? e.source.toUpperCase() : 'SYS'}</span></td>
          <td class="mono-cell">${e.host || 'Endpoint'}</td>
          <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${processOrUri}</td>
          <td class="mono-cell" style="color: ${e.misp_match ? '#f43f5e' : '#38bdf8'}; font-weight: ${e.misp_match ? '700' : '400'};">
            ${indicator} ${e.misp_match ? '🔥' : ''}
          </td>
          <td><span class="badge-${sev}">${(e.severity || 'LOW').toUpperCase()}</span></td>
          <td>
            <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="openEventDetailModal('${e.event_id}')">Inspect</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error loading telemetry:', err);
  }
}

function handleTelemetrySearch(event) {
  if (event) event.preventDefault();
  const input = document.getElementById('telemetrySearchInput');
  const query = input ? input.value.trim() : '';
  loadTelemetry(query);
}

// Search quick pills
function setTelemetryFilter(filterStr) {
  const input = document.getElementById('telemetrySearchInput');
  if (input) {
    input.value = filterStr === 'all' ? '' : filterStr;
    loadTelemetry(input.value);
  }
}

// Event Inspector Modal
function openEventDetailModal(eventId) {
  const event = telemetryData.find(e => e.event_id === eventId);
  if (!event) return;

  const modal = document.getElementById('eventDetailModal');
  const content = document.getElementById('eventDetailContent');

  content.innerHTML = `
    <div style="margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px;">
      <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase;">Event Record</div>
      <div style="font-size: 20px; font-weight: 700; color: #38bdf8; font-family: monospace;">${event.event_id}</div>
      <div style="margin-top: 4px; font-size: 12px; color: #94a3b8;">Timestamp: ${event.timestamp} · Source: ${event.source}</div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
      <div><strong style="color: #64748b; font-size: 11px; text-transform: uppercase;">Endpoint Host:</strong> <div class="mono-cell">${event.host} (${event.src_ip || '10.0.2.15'})</div></div>
      <div><strong style="color: #64748b; font-size: 11px; text-transform: uppercase;">Destination / Target:</strong> <div class="mono-cell">${event.dst_ip || event.http_host || '-'}</div></div>
      <div><strong style="color: #64748b; font-size: 11px; text-transform: uppercase;">Process Name:</strong> <div>${event.process_name || '-'}</div></div>
      <div><strong style="color: #64748b; font-size: 11px; text-transform: uppercase;">Threat Intel Match:</strong> <div>${event.misp_match ? '✅ MATCHED IN MISP' : 'No Threat Intel Match'}</div></div>
    </div>

    ${event.command_line ? `
      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 4px;">Command Line Telemetry</div>
        <div style="background: #090e1a; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #e2e8f0; word-break: break-all;">${event.command_line}</div>
      </div>
    ` : ''}

    ${event.raw_log ? `
      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 4px;">Raw Payload / Log Record</div>
        <pre style="background: #090e1a; padding: 10px; border-radius: 6px; font-size: 11px; color: #94a3b8; overflow-x: auto; white-space: pre-wrap; max-height: 180px;">${event.raw_log}</pre>
      </div>
    ` : ''}

    <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px;">
      ${(event.http_host || event.dst_ip) ? `
        <button class="btn-primary" onclick="investigateIndicator('${event.http_host || event.dst_ip}')">Investigate IOC in MISP</button>
      ` : ''}
      <button class="btn-secondary" onclick="closeEventDetailModal()">Close</button>
    </div>
  `;

  modal.style.display = 'flex';
}

function closeEventDetailModal() {
  document.getElementById('eventDetailModal').style.display = 'none';
}

function investigateIndicator(ioc) {
  closeEventDetailModal();
  switchTab('enrichment');
  const input = document.getElementById('iocSearchInput');
  if (input) {
    input.value = ioc;
    queryIOC();
  }
}

// Incident Cases
async function loadIncidents() {
  try {
    const res = await fetch('/api/v1/incidents', {
      headers: AuthState.token ? { 'Authorization': `Bearer ${AuthState.token}` } : {}
    });
    const incidents = await res.json();
    const container = document.getElementById('incidentsCardsGrid');
    if (!container) return;

    container.innerHTML = incidents.map(inc => {
      const sevClass = (inc.severity || 'low').toLowerCase();
      const statusColor = inc.status === 'Closed' ? '#10b981' : inc.status === 'Contained' ? '#38bdf8' : '#f59e0b';

      return `
        <div class="glass-panel" style="padding: 20px; display: flex; flex-direction: column; justify-content: space-between;">
          <div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
              <span class="mono-cell" style="font-weight: 700; font-size: 14px;">${inc.incident_id}</span>
              <span class="badge-${sevClass}">${(inc.severity || 'LOW').toUpperCase()}</span>
            </div>
            <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 8px;">${inc.title}</h3>
            <p style="font-size: 13px; color: #94a3b8; line-height: 1.5; margin-bottom: 14px;">${inc.summary}</p>
            <div style="font-size: 12px; color: #64748b; margin-bottom: 6px;">
              <strong>Technique:</strong> <span style="color:#c4b5fd;">${inc.mitre_technique || 'N/A'}</span>
            </div>
            <div style="font-size: 12px; color: #64748b; margin-bottom: 12px;">
              <strong>Endpoint:</strong> ${inc.endpoint} · Assignee: <span style="color:#fff;">${inc.assignee}</span>
            </div>
          </div>

          <div style="border-top: 1px solid var(--border-color); padding-top: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <div style="font-size: 12px; font-weight: 600; color: ${statusColor};">
              ● STATUS: ${inc.status.toUpperCase()}
            </div>
            <div style="display: flex; gap: 6px;">
              <a href="/investigation-report/${inc.incident_id}" target="_blank" class="btn-secondary" style="padding: 6px 10px; font-size: 11px; text-decoration: none;">
                📄 Formal Report
              </a>
              <button class="btn-primary" style="padding: 6px 10px; font-size: 11px;" onclick="openIncidentModal('${inc.incident_id}')">
                Manage Case
              </button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Error loading incidents:', err);
  }
}

// Case Management Detail & Action Modal
async function openIncidentModal(incidentId) {
  try {
    const res = await fetch(`/api/v1/incidents/${incidentId}`);
    const inc = await res.json();
    const modal = document.getElementById('incidentModal');
    const content = document.getElementById('incidentModalContent');

    const timelineHtml = (inc.timeline || []).map(t => `
      <div style="display: flex; gap: 12px; margin-bottom: 10px; font-size: 12px;">
        <span class="mono-cell" style="color: #38bdf8;">${t.time}</span>
        <span style="color: #cbd5e1;">${t.event}</span>
      </div>
    `).join('');

    const notesHtml = (inc.notes || []).map(n => `
      <div style="background: rgba(15,23,42,0.8); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-dim); margin-bottom: 4px;">
          <span>${n.author}</span>
          <span>${n.time ? n.time.substring(0, 16) : ''}</span>
        </div>
        <div style="font-size: 13px; color: #e2e8f0;">${n.text}</div>
      </div>
    `).join('');

    content.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px;">
        <div>
          <span class="mono-cell" style="font-size: 18px; font-weight: 700;">${inc.incident_id}: ${inc.title}</span>
          <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Classification: ${inc.classification}</div>
        </div>
        <div>
          <select id="updateStatusSelect" style="background: #1e293b; color: #fff; border: 1px solid var(--border-color); padding: 6px 12px; border-radius: 6px; font-size: 13px;">
            <option value="Open" ${inc.status === 'Open' ? 'selected' : ''}>Open</option>
            <option value="In Progress" ${inc.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
            <option value="Contained" ${inc.status === 'Contained' ? 'selected' : ''}>Contained</option>
            <option value="Closed" ${inc.status === 'Closed' ? 'selected' : ''}>Closed</option>
          </select>
          <button class="btn-primary" style="padding: 6px 12px; font-size: 12px; margin-left: 6px;" onclick="saveIncidentStatus('${inc.incident_id}')">Update</button>
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 6px;">Case Timeline</div>
        <div style="background: #090e1a; padding: 12px; border-radius: 8px; border: 1px solid var(--border-color); max-height: 140px; overflow-y: auto;">
          ${timelineHtml || '<div style="color:#64748b;">No timeline entries recorded.</div>'}
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 6px;">Analyst Notes & Findings</div>
        <div style="max-height: 140px; overflow-y: auto;">
          ${notesHtml || '<div style="color:#64748b; font-size:12px;">No analyst notes yet.</div>'}
        </div>
        <div style="display: flex; gap: 8px; margin-top: 10px;">
          <input type="text" id="newIncidentNoteInput" placeholder="Add analyst investigation note..." style="flex: 1; background: #090e1a; border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px; color: #fff; font-size: 12px;">
          <button class="btn-secondary" onclick="submitIncidentNote('${inc.incident_id}')">Add Note</button>
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; border-top: 1px solid var(--border-color); padding-top: 14px; margin-top: 16px;">
        <a href="/investigation-report/${inc.incident_id}" target="_blank" class="btn-recruiter" style="text-decoration:none;">
          🖨️ View & Print Official SOC Report
        </a>
        <button class="btn-secondary" onclick="closeIncidentModal()">Close</button>
      </div>
    `;

    modal.style.display = 'flex';
  } catch (err) {
    showToast('Failed to load incident details', 'error');
  }
}

function closeIncidentModal() {
  document.getElementById('incidentModal').style.display = 'none';
}

async function saveIncidentStatus(incidentId) {
  const sel = document.getElementById('updateStatusSelect');
  if (!sel) return;
  const newStatus = sel.value;

  try {
    const res = await fetch(`/api/v1/incidents/${incidentId}/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': AuthState.token ? `Bearer ${AuthState.token}` : ''
      },
      body: JSON.stringify({ status: newStatus, note: `Status transitioned to ${newStatus}` })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Incident status updated to ${newStatus}`, 'success');
      loadIncidents();
      closeIncidentModal();
    }
  } catch (err) {
    showToast('Failed to update incident status', 'error');
  }
}

async function submitIncidentNote(incidentId) {
  const input = document.getElementById('newIncidentNoteInput');
  const text = input ? input.value.trim() : '';
  if (!text) return;

  try {
    const res = await fetch(`/api/v1/incidents/${incidentId}/notes`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': AuthState.token ? `Bearer ${AuthState.token}` : ''
      },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Analyst note saved', 'success');
      openIncidentModal(incidentId); // Refresh modal
    }
  } catch (err) {
    showToast('Failed to save note', 'error');
  }
}

// Global initialization
window.addEventListener('DOMContentLoaded', () => {
  // Start polling every 5 seconds
  refreshSIEM();
  setInterval(refreshSIEM, 5000);
});
