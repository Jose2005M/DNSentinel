// El token CSRF se mantiene en memoria; la sesión vive en una cookie HttpOnly.
let csrfToken = '';
async function api(path, options = {}) {
  const headers = {'Content-Type': 'application/json', ...options.headers};
  if (options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
  let response;
  try {
    response = await fetch('/api' + path, {...options, headers, credentials: 'same-origin'});
  } catch {
    throw new Error('No se pudo conectar con el servidor. Comprueba que sigue ejecutándose.');
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error('El servidor no devolvió una respuesta válida.'); }
  if (!response.ok) {
    if (response.status === 401 && path !== '/login' && location.pathname !== '/login') {
      location.assign('/login');
    }
    const error = new Error((data.error || 'No se pudo completar la operación.') +
      (response.status >= 500 && data.request_id ? ' Identificador: ' + data.request_id : ''));
    error.status = response.status;
    throw error;
  }
  if (data.csrf) csrfToken = data.csrf;
  return data;
}
