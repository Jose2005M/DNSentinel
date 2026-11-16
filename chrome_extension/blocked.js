import {webURL} from './policy.js';
let original;
try { original = decodeURIComponent(location.hash.slice(1)); } catch { original = ''; }
const url = webURL(original);
document.querySelector('#domain').textContent = url ? url.hostname : 'Dominio no disponible';
const retry = document.querySelector('#retry');
retry.disabled = !url;
retry.addEventListener('click', async () => {
  const status = await chrome.runtime.sendMessage({type: 'status'});
  if (status.active) {
    document.querySelector('#feedback').textContent = 'La protección sigue activa. Si cambiaste la regla, espera la sincronización.';
  } else if (url) location.replace(url.href);
});
