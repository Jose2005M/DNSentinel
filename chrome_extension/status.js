async function refresh() {
  const state = await chrome.runtime.sendMessage({type: 'status'});
  document.querySelector('#status').textContent = state.error || (state.active ? 'Protección activa en Chrome.' : 'Conectado. Protección detenida.');
}
document.querySelector('#connect').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({type: 'reconnect'});
  await refresh();
});
refresh();
setInterval(refresh, 1000);
