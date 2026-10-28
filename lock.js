const passwordInput = document.getElementById('passwordInput');
const unlockButton = document.getElementById('unlockButton');

const urlParams = new URLSearchParams(window.location.search);
const challengeId = urlParams.get('challenge');

passwordInput.focus();

async function handleUnlock() {
  const password = passwordInput.value;

  if (!password) {
    alert('Please enter password.');
    passwordInput.focus();
    return;
  }

  if (!challengeId) {
    alert('Invalid or missing lock challenge. Please reopen the website.');
    return;
  }

  unlockButton.disabled = true;

  try {
    chrome.runtime.sendMessage(
      {
        type: 'VERIFY_PASSWORD',
        challengeId: challengeId,
        password: password
      },
      (response) => {
        unlockButton.disabled = false;

        if (chrome.runtime.lastError) {
          alert('Failed to communicate with Website Locker background service.');
          passwordInput.value = '';
          passwordInput.focus();
          return;
        }

        if (response && response.success && response.redirectUrl) {
          // Replace lock screen entry in tab history and navigate to unlocked URL
          window.location.replace(response.redirectUrl);
        } else {
          alert(response?.error || 'Incorrect password.');
          passwordInput.value = '';
          passwordInput.focus();
        }
      }
    );
  } catch (err) {
    unlockButton.disabled = false;
    alert('An unexpected error occurred during verification.');
    passwordInput.value = '';
    passwordInput.focus();
  }
}

unlockButton.addEventListener('click', handleUnlock);

// Support pressing Enter key to unlock
passwordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    handleUnlock();
  }
});

