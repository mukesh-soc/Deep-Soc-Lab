/**
 * SentinelX Recruiter Guided Tour & Instant Scenario Replay Controller
 * Designed specifically for Technical Recruiters and SOC Hiring Managers.
 */

let tourStep = 0;
const tourSteps = [
  {
    title: "🛡️ Welcome to SentinelX SOC Platform",
    content: "Designed and engineered by <strong>Mukesh Jena (MCA)</strong>. This is an enterprise-grade SIEM & Incident Investigation platform combining Wazuh, Zeek, MISP, Sysmon, and Python security automation with Zero-Trust 2FA.",
    action: () => switchTab('dashboard')
  },
  {
    title: "🔐 Zero-Trust Security & RFC 6238 2FA",
    content: "All access is protected by PBKDF2 credential hashing, role-based access control, cryptographic session tokens, and Time-based One-Time Passwords (TOTP). Scan the QR code with Google Authenticator or use the recruiter autofill code!",
    action: () => open2FASetupModal()
  },
  {
    title: "📊 Real-Time Threat Detection & Correlation",
    content: "This live dashboard continuously tracks ingested events, active alerts, and MITRE ATT&CK tactics. Notice how endpoint events from Windows 11 and Zeek network streams are correlated in sub-milliseconds.",
    action: () => { close2FASetupModal(); switchTab('dashboard'); }
  },
  {
    title: "⚡ Validated Positive IOC Flow (192.0.2.123)",
    content: "In Mukesh's physical home lab, controlled HTTP traffic was generated with Host <code>192.0.2.123</code>. Zeek captured the packet, SentinelX extracted the indicator, and MISP returned a positive hit in Event ID 1!",
    action: () => { switchTab('enrichment'); document.getElementById('iocSearchInput').value = '192.0.2.123'; queryIOC(); }
  },
  {
    title: "📁 Incident Response & Case Management",
    content: "Every detection can be escalated into a tracked incident case (e.g. <code>INC-001</code>, <code>INC-002</code>). Analysts can manage status, review timelines, link forensic artifacts, and generate 1-click printable SOC reports.",
    action: () => switchTab('incidents')
  },
  {
    title: "🤖 Automated SOAR Containment Playbooks",
    content: "Containment is automated. When high-severity adversary activity is detected, automated playbooks can sever network traffic, isolate hosts via Wazuh active-response, or push IOCs to MISP threat events.",
    action: () => switchTab('soar')
  },
  {
    title: "🚀 Candidate Ready for Immediate Hire",
    content: "Mukesh brings deep hands-on expertise across SOC Operations, Threat Intelligence, Detection Engineering, and Python Security Automation. Click 'Contact Mukesh' to schedule an interview!",
    action: () => openCandidateModal()
  }
];

function startRecruiterTour() {
  tourStep = 0;
  showTourStep(0);
}

function showTourStep(index) {
  if (index >= tourSteps.length) {
    closeTourModal();
    return;
  }
  const step = tourSteps[index];
  const modal = document.getElementById('recruiterTourModal');
  const title = document.getElementById('tourStepTitle');
  const content = document.getElementById('tourStepContent');
  const stepIndicator = document.getElementById('tourStepIndicator');

  title.innerHTML = step.title;
  content.innerHTML = step.content;
  stepIndicator.innerText = `Step ${index + 1} of ${tourSteps.length}`;

  if (step.action) step.action();

  modal.style.display = 'flex';
}

function nextTourStep() {
  tourStep++;
  showTourStep(tourStep);
}

function prevTourStep() {
  if (tourStep > 0) {
    tourStep--;
    showTourStep(tourStep);
  }
}

function closeTourModal() {
  document.getElementById('recruiterTourModal').style.display = 'none';
}

// 1-Click Scenario Replay
async function replayScenario(scenarioId) {
  showToast(`Replaying scenario: ${scenarioId}...`, 'info');

  try {
    const res = await fetch('/api/v1/recruiter/replay', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': AuthState.token ? `Bearer ${AuthState.token}` : ''
      },
      body: JSON.stringify({ scenario_id: scenarioId })
    });
    const data = await res.json();

    if (data.success) {
      playAlertBeep('Critical');
      showToast(`Scenario replayed! Ingested ${data.ingested_count} events and triggered correlation rules.`, 'success');
      refreshSIEM();
      switchTab('dashboard');
    } else {
      showToast(`Failed to replay scenario: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Failed to connect to scenario replayer', 'error');
  }
}

// Candidate Contact & Hire Modal
function openCandidateModal() {
  document.getElementById('candidateModal').style.display = 'flex';
}

function closeCandidateModal() {
  document.getElementById('candidateModal').style.display = 'none';
}
