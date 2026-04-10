/**
 * Login handler bridging the UI to the Flask ML Pipeline.
 */
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const btn = document.getElementById('loginBtn');
  const btnText = document.getElementById('btnText');
  const btnSpinner = document.getElementById('btnSpinner');
  const errorMsg = document.getElementById('errorMessage');
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  // Extract behavioral payload
  const telemetryData = Telemetry.finalize();

  // Loading state
  btn.disabled = true;
  btnText.style.display = 'none';
  btnSpinner.style.display = 'inline-block';
  errorMsg.style.display = 'none';

  try {
    // Send to Flask Auth Route (which triggers ML Routing)
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username,
        password: password,
        browser_fingerprint: navigator.userAgent,
        ...telemetryData
      })
    });

    const data = await response.json();

    if (response.ok && data.status === 'success') {
      console.log("Login Success! Routing to:", data.redirect);
      localStorage.setItem('auth_token', data.session_token || 'fake_token');
      
      let redirectUrl = data.redirect || 'dashboard.html';
      
      // Map API redirects to local file logic
      if (redirectUrl === '/dashboard') {
          redirectUrl = 'dashboard.html';
      } else if (redirectUrl === '/internal_corp_app') {
          alert("✅ SUCCESS: Legitimate access detected.");
          redirectUrl = 'index.html'; 
      }
      
      console.log("Final Redirect URL:", redirectUrl);
      window.location.href = redirectUrl;
    } else {
      // Denied (could be LEGIT error or SUSPICIOUS lock)
      throw new Error(data.message || 'Authentication failed. Incorrect credentials.');
    }

  } catch (err) {
    errorMsg.textContent = err.message || "Network timeout. Try again later.";
    errorMsg.style.display = 'block';
    
    // Reset button
    btn.disabled = false;
    btnText.style.display = 'inline-block';
    btnSpinner.style.display = 'none';
    
    // Clear password
    document.getElementById('password').value = '';
  }
});
