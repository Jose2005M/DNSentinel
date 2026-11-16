import {blocked, compileRules, validateState, webURL} from './policy.js';

const HOST = 'org.dnsentinel.chrome';
const BLOCK_PAGE = chrome.runtime.getURL('blocked.html');
let state = {active: false, rules: [], revision: 'startup'};
let appliedRevision = null;
let port = null;
let chain = Promise.resolve();
let connectionError = 'Esperando al lanzador.';

function enqueue(work) {
  chain = chain.then(work).catch(error => console.error('DNSentinel:', error));
  return chain;
}

function originalURL(value) {
  if (!value?.startsWith(BLOCK_PAGE + '#')) return null;
  try {
    const original = decodeURIComponent(value.slice(BLOCK_PAGE.length + 1));
    return webURL(original) ? original : null;
  } catch { return null; }
}

async function updateTab(id, url) {
  try {
    await chrome.tabs.update(id, {url});
  } catch (error) {
    // Cerrar una pestaña durante la sincronización no es un fallo de protección.
    try { await chrome.tabs.get(id); } catch { return; }
    throw error;
  }
}

async function reconcileTab(tab, candidate) {
  const url = candidate || tab.pendingUrl || tab.url;
  const original = originalURL(url);
  if (original) {
    if (!blocked(original, state)) await updateTab(tab.id, original);
  } else if (blocked(url, state)) {
    const target = BLOCK_PAGE + '#' + encodeURIComponent(url);
    if (tab.url !== target && tab.pendingUrl !== target) await updateTab(tab.id, target);
  }
}

async function reconcileTabs() {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) await reconcileTab(tab);
}

async function apply(next) {
  const rules = await compileRules(next, regex => chrome.declarativeNetRequest.isRegexSupported({regex}));
  const previous = await chrome.declarativeNetRequest.getSessionRules();
  // Chrome aplica la sustitución completa de forma atómica.
  await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds: previous.map(rule => rule.id), addRules: rules});
  state = next;
  await chrome.storage.session.set({state});
  await reconcileTabs();
  appliedRevision = next.revision;
  await chrome.action.setBadgeText({text: next.active ? 'ON' : ''});
  await chrome.action.setBadgeBackgroundColor({color: '#087f69'});
}

function acknowledge(connection, message) {
  if (port === connection) connection.postMessage(message);
}

function connect() {
  if (port) return;
  const connection = chrome.runtime.connectNative(HOST);
  port = connection;
  connection.onMessage.addListener(message => enqueue(async () => {
    if (port !== connection || message.type !== 'state') return;
    try {
      const next = validateState(message);
      if (next.revision !== appliedRevision) await apply(next);
      connectionError = next.revision === 'offline' ? 'El lanzador está cerrado.' : '';
      acknowledge(connection, {type: 'ack', revision: next.revision, ok: true});
    } catch (error) {
      connectionError = error.message;
      acknowledge(connection, {type: 'ack', revision: message.revision, ok: false, error: error.message});
    }
  }));
  connection.onDisconnect.addListener(() => {
    const reason = chrome.runtime.lastError?.message || 'Se perdió la conexión con el lanzador.';
    if (port !== connection) return;
    port = null;
    enqueue(async () => {
      connectionError = reason;
      await apply({active: false, rules: [], revision: 'disconnected'});
    });
    setTimeout(connect, 1500);
  });
}

// También cubre páginas ya abiertas, restauración de pestañas, historial y BFCache.
chrome.tabs.onUpdated.addListener((id, changes, tab) => {
  if (changes.url || changes.status === 'complete') enqueue(() => reconcileTab(tab));
});
for (const event of [chrome.webNavigation.onBeforeNavigate, chrome.webNavigation.onCommitted,
  chrome.webNavigation.onHistoryStateUpdated, chrome.webNavigation.onErrorOccurred]) {
  event.addListener(details => {
    if (details.frameId === 0) enqueue(async () => {
      let tab;
      try { tab = await chrome.tabs.get(details.tabId); } catch { return; }
      if (blocked(details.url, state)) await reconcileTab(tab, details.url);
      else await reconcileTab(tab);
    });
  });
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL(''))) return;
  if (message.type === 'status') {
    respond({active: state.active, connected: Boolean(port), error: connectionError});
  } else if (message.type === 'reconnect') {
    connect();
    respond({ok: true});
  }
});
chrome.alarms.onAlarm.addListener(() => connect());
chrome.alarms.create('reconnect', {periodInMinutes: .5});
chrome.runtime.onStartup.addListener(connect);
enqueue(async () => {
  const stored = (await chrome.storage.session.get('state')).state;
  if (stored) state = validateState(stored);
  await reconcileTabs();
  connect();
});
