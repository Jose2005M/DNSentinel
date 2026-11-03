const form = document.querySelector('#login-form');
const button = document.querySelector('#login-submit');
const errorBox = document.querySelector('#login-error');
button.disabled = true;
async function initializeLogin() {
  try {
    const session = await api('/session');
    if (session.user) { location.replace('/'); return; }
    button.disabled = false;
    errorBox.textContent = '';
  } catch (error) { errorBox.textContent = error.message + ' Recarga la página para reintentar.'; }
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  button.disabled = true;
  errorBox.textContent = '';
  try {
    await api('/login', {method:'POST', body:JSON.stringify({
      username:form.elements.username.value,
      password:form.elements.password.value
    })});
    form.elements.password.value = '';
    location.replace('/');
  } catch (error) {
    errorBox.textContent = error.message;
    form.elements.password.value = '';
    // Renueva el token si la sesión anónima expiró.
    try { await api('/session'); } catch { /* El mensaje de conexión permanece visible. */ }
    button.disabled = false;
  }
});
initializeLogin();
