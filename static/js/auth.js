/**
 * SentinelX Enterprise Authentication & 2FA Client Controller
 * Handles credentials, RFC 6238 TOTP verification, QR code onboarding,
 * session persistence, and recruiter quick-access demo autofill.
 */

const AuthState = {
  token: localStorage.getItem('sentinelx_token') || '',
  user: null,
  pendingUsername: '',
  timerInterval: null
};

// Check current session on startup
async function checkAuthSession() {
  try {
    const res = await fetch('/api/v1/auth/me', {
      headers: AuthState.token ? { 'Authorization': `Bearer ${AuthState.token}` } : {}
    });
    const data = await res.json();
    if (data.authenticated) {
      AuthState.user = data;
      updateAuthUI(true, data);
    } else {
      updateAuthUI(false, null);
      // Auto-open 2FA modal if not authenticated
      openLoginModal();
    }
  } catch (err) {
    console.error('Session check failed:', err);
    updateAuthUI(false, null);
  }
}

function updateAuthUI(isAuthenticated, user) {
  const userBadge = document.getElementById('navUserBadge');
  const userRole = document.getElementById('navUserRole');
  const loginBtn = document.getElementById('navLoginBtn');
  const logoutBtn = document.getElementById('navLogoutBtn');
  const secStatus = document.getElementById('navSecurityStatus');

  if (isAuthenticated && user) {
    if (userBadge) userBadge.innerText = user.full_name || user.username;
    if (userRole) userRole.innerText = `ROLE: ${user.role.toUpperCase()}`;
    if (loginBtn) loginBtn.style.display = 'none';
    if (logoutBtn) logoutBtn.style.display = 'inline-flex';
    if (secStatus) secStatus.innerHTML = '<span class="pulse-indicator"></span> 2FA VERIFIED (ZERO-TRUST)';
  } else {
    if (userBadge) userBadge.innerText = 'Unauthenticated';
    if (userRole) userRole.innerText = 'GUEST';
    if (loginBtn) loginBtn.style.display = 'inline-flex';
    if (logoutBtn) logoutBtn.style.display = 'none';
    if (secStatus) secStatus.innerHTML = '<span style="color: #f43f5e;">●</span> 2FA REQUIRED';
  }
}

function openLoginModal() {
  document.getElementById('loginModal').style.display = 'flex';
  document.getElementById('loginStep1').style.display = 'block';
  document.getElementById('loginStep2').style.display = 'none';
  document.getElementById('loginError').style.display = 'none';
}

function closeLoginModal() {
  document.getElementById('loginModal').style.display = 'none';
}

// Step 1: Submit Credentials
async function handleLoginStep1(event) {
  if (event) event.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value.trim();
  const errBox = document.getElementById('loginError');

  errBox.style.display = 'none';

  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (!data.success) {
      errBox.innerText = data.error || 'Authentication failed';
      errBox.style.display = 'block';
      return;
    }

    AuthState.pendingUsername = data.username;

    if (data.requires_2fa) {
      // Transition to Step 2 (TOTP verification)
      document.getElementById('loginStep1').style.display = 'none';
      document.getElementById('loginStep2').style.display = 'block';
      document.getElementById('totpTargetUser').innerText = data.username;
      
      // Focus 2FA input
      document.getElementById('totpTokenInput').value = '';
      document.getElementById('totpTokenInput').focus();

      // Start countdown
      startTotpCountdown();
    } else {
      // Direct login (rare in Zero Trust)
      completeLogin(data.token, data.user);
    }
  } catch (err) {
    errBox.innerText = 'Network error contacting authentication server';
    errBox.style.display = 'block';
  }
}

// Step 2: Submit 6-digit TOTP Token
async function handleLoginStep2(event) {
  if (event) event.preventDefault();
  const token = document.getElementById('totpTokenInput').value.trim();
  const errBox = document.getElementById('loginErrorStep2');

  errBox.style.display = 'none';

  if (!token || token.length !== 6) {
    errBox.innerText = 'Please enter a valid 6-digit verification code';
    errBox.style.display = 'block';
    return;
  }

  try {
    const res = await fetch('/api/v1/auth/verify_2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: AuthState.pendingUsername,
        token: token
      })
    });
    const data = await res.json();

    if (!data.success) {
      errBox.innerText = data.error || 'Invalid 2FA code';
      errBox.style.display = 'block';
      return;
    }

    completeLogin(data.token, data.user);
  } catch (err) {
    errBox.innerText = 'Error validating 2FA token';
    errBox.style.display = 'block';
  }
}

function completeLogin(token, user) {
  AuthState.token = token;
  AuthState.user = user;
  localStorage.setItem('sentinelx_token', token);
  closeLoginModal();
  updateAuthUI(true, user);
  if (window.showToast) {
    showToast(`Welcome, ${user.full_name}! 2FA Authenticated.`, 'success');
  }
  // Refresh live telemetry
  if (window.refreshSIEM) {
    window.refreshSIEM();
  }
}

function handleLogout() {
  AuthState.token = '';
  AuthState.user = null;
  localStorage.removeItem('sentinelx_token');
  document.cookie = 'sentinelx_token=; Max-Age=0; path=/;';
  updateAuthUI(false, null);
  openLoginModal();
}

// Recruiter 1-Click Autofill 2FA Code
async function autofillRecruiter2FA() {
  try {
    const res = await fetch('/api/v1/auth/recruiter_quick_code');
    const data = await res.json();
    if (data.current_totp) {
      document.getElementById('totpTokenInput').value = data.current_totp;
      const hint = document.getElementById('totpAutofillHint');
      if (hint) {
        hint.innerText = `Autofilled live code: ${data.current_totp} (${data.seconds_remaining}s left)`;
        hint.style.color = '#10b981';
      }
    }
  } catch (err) {
    console.error('Failed to fetch demo TOTP:', err);
  }
}

// 2FA Setup QR Code Modal
async function open2FASetupModal() {
  const username = AuthState.user ? AuthState.user.username : 'recruiter';
  try {
    const res = await fetch(`/api/v1/auth/setup_2fa?username=${encodeURIComponent(username)}`);
    const data = await res.json();
    if (data.success) {
      document.getElementById('qrCodeImg').src = data.qr_code_image;
      document.getElementById('setupSecretKey').innerText = data.secret;
      document.getElementById('setupTotpUri').value = data.totp_uri;
      document.getElementById('twoFaSetupModal').style.display = 'flex';
    }
  } catch (err) {
    alert('Unable to load 2FA setup data');
  }
}

function close2FASetupModal() {
  document.getElementById('twoFaSetupModal').style.display = 'none';
}

function startTotpCountdown() {
  if (AuthState.timerInterval) clearInterval(AuthState.timerInterval);
  const timerElem = document.getElementById('totpTimerSeconds');
  function tick() {
    const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
    if (timerElem) timerElem.innerText = `${remaining}s`;
  }
  tick();
  AuthState.timerInterval = setInterval(tick, 1000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  checkAuthSession();
});
