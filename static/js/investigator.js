/**
 * SentinelX Forensic Investigator & SOAR Controller
 * Handles log ingestion, IOC threat intelligence lookup, incident case management,
 * and automated remediation execution.
 */

// Sample presets for instant testing
const LogPresets = {
  zeek: `1726848010.123456\tCQ45x8192\t10.0.2.15\t52140\t10.0.2.4\t80\t1\tGET\t192.0.2.123\t/api/v1/telemetry\t-\t1.1\tcurl/8.4.0\t-\t0\t1420\t200\tOK`,
  powershell: `{\n  "timestamp": "2026-09-20T10:15:02.450Z",\n  "rule": { "level": "Low", "description": "Powershell process spawned powershell instance", "id": "92027", "mitre": { "id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"] } },\n  "agent": { "id": "001", "name": "Windows-11-Endpoint", "ip": "10.0.2.15" },\n  "data": {\n    "win": {\n      "eventdata": {\n        "ProcessId": "4820",\n        "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",\n        "CommandLine": "powershell.exe -NoProfile -Command \\"Get-Process | Select-Object -First 5\\"",\n        "Hashes": "SHA256=9A5964EF56B72213F988220A8E3F28599E6C99596B272D0B6A786277D8DBA59D"\n      }\n    }\n  }\n}`,
  apt29: `{\n  "timestamp": "2026-10-15T09:20:12.800Z",\n  "rule": { "level": "Critical", "description": "APT29 Cobalt Strike C2 Network Beaconing Detected", "id": "SENTINELX-DET-005", "mitre": { "id": ["T1573", "T1071"], "tactic": ["Command and Control"], "technique": ["Encrypted Channel"] } },\n  "agent": { "id": "001", "name": "Windows-11-Endpoint", "ip": "10.0.2.15" },\n  "data": {\n    "win": {\n      "eventdata": {\n        "ProcessId": "5128",\n        "Image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",\n        "CommandLine": "rundll32.exe C:\\\\ProgramData\\\\payload.dll,DllRegisterServer",\n        "SourceIp": "10.0.2.15",\n        "DestinationIp": "198.51.100.45",\n        "DestinationPort": "443"\n      }\n    }\n  }\n}`,
  ransomware: `{\n  "timestamp": "2026-10-16T08:14:22.100Z",\n  "rule": { "level": "Critical", "description": "Ransomware Inhibit System Recovery (VSS Shadow Deletion)", "id": "SENTINELX-DET-006", "mitre": { "id": ["T1490"], "tactic": ["Impact"], "technique": ["Inhibit System Recovery"] } },\n  "agent": { "id": "001", "name": "Windows-11-Endpoint", "ip": "10.0.2.15" },\n  "data": {\n    "win": {\n      "eventdata": {\n        "ProcessId": "7712",\n        "Image": "C:\\\\Windows\\\\System32\\\\vssadmin.exe",\n        "CommandLine": "vssadmin.exe delete shadows /all /quiet",\n        "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n      }\n    }\n  }\n}`
};

function loadLogPreset(name) {
  const content = LogPresets[name] || '';
  const textarea = document.getElementById('rawLogInput');
  if (textarea) {
    textarea.value = content;
    showToast(`Loaded ${name.toUpperCase()} telemetry sample into ingester`, 'info');
  }
}

async function submitLogIngestion() {
  const textarea = document.getElementById('rawLogInput');
  const rawContent = textarea ? textarea.value.trim() : '';

  if (!rawContent) {
    showToast('Please paste or select a log sample to ingest', 'error');
    return;
  }

  const btn = document.getElementById('btnSubmitIngest');
  if (btn) btn.disabled = true;

  try {
    const res = await fetch('/api/v1/telemetry/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': AuthState.token ? `Bearer ${AuthState.token}` : ''
      },
      body: JSON.stringify({ raw_content: rawContent })
    });
    const data = await res.json();

    if (data.success) {
      showToast(`Successfully ingested and correlated ${data.ingested_count} event(s)!`, 'success');
      // Refresh telemetry table & metrics
      refreshSIEM();
      // Switch to Telemetry tab to view result
      switchTab('hunting');
    } else {
      showToast(`Ingestion error: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Failed to connect to SIEM ingestion endpoint', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// IOC Deep Investigator
async function queryIOC() {
  const input = document.getElementById('iocSearchInput');
  const ioc = input ? input.value.trim() : '';

  if (!ioc) {
    showToast('Please enter an IP, domain, or hash to investigate', 'error');
    return;
  }

  const resultContainer = document.getElementById('iocResultCard');
  resultContainer.innerHTML = '<div style="padding: 24px; text-align: center; color: #94a3b8;">Querying Threat Intelligence & MISP Database...</div>';
  resultContainer.style.display = 'block';

  try {
    const res = await fetch(`/api/v1/enrichment/lookup?ioc=${encodeURIComponent(ioc)}`, {
      headers: AuthState.token ? { 'Authorization': `Bearer ${AuthState.token}` } : {}
    });
    const data = await res.json();

    renderIOCResult(data);
  } catch (err) {
    resultContainer.innerHTML = '<div style="color: #f43f5e; padding: 20px;">Failed to query threat intelligence.</div>';
  }
}

function renderIOCResult(data) {
  const container = document.getElementById('iocResultCard');
  const isMalicious = data.is_malicious || data.misp_match;
  const threatScore = data.threat_score || 0;

  let scoreColor = '#10b981';
  if (threatScore >= 80) scoreColor = '#f43f5e';
  else if (threatScore >= 50) scoreColor = '#f59e0b';
  else if (threatScore >= 20) scoreColor = '#3b82f6';

  let verdictBadge = isMalicious
    ? `<span class="badge-critical">THREAT DETECTED (MISP MATCH)</span>`
    : `<span class="badge-low">BENIGN / UNCLASSIFIED</span>`;

  let tagsHtml = (data.tags || []).map(t => `<span class="pill-badge">${t}</span>`).join(' ');
  let mitreHtml = (data.mitre_techniques || []).map(m => `<span style="background: rgba(139, 92, 246, 0.2); color: #c4b5fd; padding: 3px 8px; border-radius: 4px; font-size: 11px;">${m}</span>`).join(' ');

  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; flex-wrap: wrap; gap: 12px;">
      <div>
        <div style="font-size: 12px; color: var(--text-muted); text-transform: uppercase;">Indicator Under Investigation</div>
        <div style="font-size: 24px; font-weight: 700; color: #38bdf8; font-family: monospace;">${data.ioc}</div>
        <div style="margin-top: 6px;">${verdictBadge} <span style="font-size: 12px; color: var(--text-dim); margin-left: 8px;">TYPE: ${data.type.toUpperCase()}</span></div>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Threat Score</div>
        <div style="font-size: 32px; font-weight: 800; color: ${scoreColor};">${threatScore}<span style="font-size: 16px; color: var(--text-dim);">/100</span></div>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px;">
      <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase;">Threat Attribution</div>
        <div style="font-size: 14px; font-weight: 600; color: #fff; margin-top: 4px;">${data.threat_actor || 'None'}</div>
      </div>
      <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase;">MISP Event ID</div>
        <div style="font-size: 14px; font-weight: 600; color: #38bdf8; margin-top: 4px;">${data.event_id ? 'Event #' + data.event_id : 'No MISP Link'}</div>
      </div>
      <div style="background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color);">
        <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase;">Geolocation & ASN</div>
        <div style="font-size: 14px; font-weight: 600; color: #fff; margin-top: 4px;">${data.geo ? `${data.geo.country || 'N/A'} (${data.geo.asn || 'N/A'})` : 'Internal'}</div>
      </div>
    </div>

    <div style="margin-bottom: 16px;">
      <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 6px;">Analyst Context & Comments:</div>
      <div style="background: #090e1a; padding: 12px; border-radius: 8px; font-size: 13px; color: #cbd5e1; border: 1px solid var(--border-color);">${data.comment || data.event_info || 'No commentary recorded.'}</div>
    </div>

    <div style="margin-bottom: 16px;">
      <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 6px;">Intelligence Tags:</div>
      <div style="display: flex; gap: 6px; flex-wrap: wrap;">${tagsHtml || '<span style="color:#64748b; font-size:12px;">No tags</span>'}</div>
    </div>

    ${mitreHtml ? `
    <div style="margin-bottom: 16px;">
      <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 6px;">MITRE ATT&CK Mapping:</div>
      <div style="display: flex; gap: 6px; flex-wrap: wrap;">${mitreHtml}</div>
    </div>
    ` : ''}

    <div style="display: flex; gap: 10px; margin-top: 20px; border-top: 1px solid var(--border-color); padding-top: 16px;">
      <button class="btn-danger" onclick="triggerSOARPlaybook('QUARANTINE_IP', '${data.ioc}')">🚨 Quarantine / Block IP</button>
      <button class="btn-secondary" onclick="triggerSOARPlaybook('SUBMIT_MISP_IOC', '${data.ioc}')">📌 Tag in MISP</button>
      <button class="btn-secondary" onclick="searchTelemetry('ip:${data.ioc}'); switchTab('hunting');">🔍 Correlate Telemetry</button>
    </div>
  `;
}

// SOAR Playbook Execution
async function triggerSOARPlaybook(playbook, target) {
  if (!confirm(`Are you sure you want to execute SOAR playbook [${playbook}] against target [${target}]?`)) return;

  try {
    const res = await fetch('/api/v1/soar/execute', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': AuthState.token ? `Bearer ${AuthState.token}` : ''
      },
      body: JSON.stringify({ playbook, target })
    });
    const data = await res.json();
    showToast(`SOAR Response Executed: ${data.details}`, 'success');
    loadSOARHistory();
  } catch (err) {
    showToast('Failed to execute SOAR action', 'error');
  }
}

async function loadSOARHistory() {
  try {
    const res = await fetch('/api/v1/soar/history');
    const logs = await res.json();
    const tableBody = document.getElementById('soarHistoryTableBody');
    if (!tableBody) return;

    if (!logs || logs.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#64748b;">No automated playbooks executed yet.</td></tr>';
      return;
    }

    tableBody.innerHTML = logs.map(l => `
      <tr>
        <td class="mono-cell">${l.timestamp.substring(11, 19)}</td>
        <td><strong>${l.playbook}</strong></td>
        <td class="mono-cell">${l.target}</td>
        <td><span class="badge-low">${l.status}</span></td>
        <td style="color:#cbd5e1; font-size:12px;">${l.details}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('SOAR history error:', err);
  }
}
