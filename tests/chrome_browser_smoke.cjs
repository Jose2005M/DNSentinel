// Chromium aislado: reglas DNR y pestañas reales; el canal nativo se simula.
// El protocolo nativo real se comprueba en tests/test_chrome.py.
const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');

async function main() {
  const playwright = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
  const root = path.resolve(__dirname, '..');
  const temporary = await fs.mkdtemp(path.join(root, 'instance', 'chrome-smoke-'));
  const extension = path.join(temporary, 'extension');
  await fs.cp(path.join(root, 'chrome_extension'), extension, {recursive: true});
  const injection = `
const fakeEvent = () => ({listeners: [], addListener(fn) {this.listeners.push(fn);}, fire(message) {for (const fn of this.listeners) fn(message);}});
globalThis.testNative = {onMessage: fakeEvent(), onDisconnect: fakeEvent(), acknowledgements: [], postMessage(message) {this.acknowledgements.push(message);}};
chrome.runtime.connectNative = () => globalThis.testNative;
`;
  const background = path.join(extension, 'background.js');
  await fs.writeFile(background, injection + await fs.readFile(background, 'utf8'));
  const server = http.createServer((request, response) => {
    if (request.url === '/sw.js') {
      response.writeHead(200, {'Content-Type': 'application/javascript'});
      response.end(`self.addEventListener('install', event => event.waitUntil(self.skipWaiting())); self.addEventListener('activate', event => event.waitUntil(self.clients.claim())); self.addEventListener('fetch', event => {if(event.request.mode === 'navigate') event.respondWith(Promise.resolve(new Response('<h1>Respuesta desde service worker</h1>', {headers:{'Content-Type':'text/html'}})));});`);
    } else {
      response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'max-age=3600'});
      response.end('<!doctype html><html lang="es"><meta charset="utf-8"><title>Página de prueba local</title><h1>Página de prueba permitida</h1><a href="/second">Segunda página</a></html>');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  let context;
  const errors = [];
  try {
    context = await playwright.chromium.launchPersistentContext(path.join(temporary, 'profile'), {
      headless: true, executablePath: process.env.CHROMIUM_EXECUTABLE || undefined,
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`,
        '--host-resolver-rules=MAP *.dnsentinel.test 127.0.0.1', '--no-proxy-server',
        '--unsafely-treat-insecure-origin-as-secure=http://blocked.dnsentinel.test:' + port]
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', {timeout: 15000});
    worker.on('console', message => {if (message.type() === 'error') errors.push(message.text());});
    async function sync(revision, active, rules) {
      await worker.evaluate(message => testNative.onMessage.fire(message), {type: 'state', revision, active, rules});
      await worker.evaluate(async revision => {
        const deadline = Date.now() + 15000;
        while (!testNative.acknowledgements.some(ack => ack.revision === revision)) {
          if (Date.now() > deadline) throw Error('Chrome no confirmó: ' + revision);
          await new Promise(resolve => setTimeout(resolve, 25));
        }
        const ack = testNative.acknowledgements.find(ack => ack.revision === revision);
        if (!ack.ok) throw Error(ack.error);
      }, revision);
    }
    const rules = [{domain: 'blocked.dnsentinel.test', kind: 'block', subdomains: true},
      {domain: 'safe.blocked.dnsentinel.test', kind: 'allow', subdomains: false}];
    const target = `http://blocked.dnsentinel.test:${port}/first`;
    const page = await context.newPage();
    const allowed = await context.newPage();
    await page.goto(target);
    await allowed.goto(`http://safe.blocked.dnsentinel.test:${port}/`);
    // Calentar caché y registrar un service worker antes del primer bloqueo.
    await page.evaluate(async () => {await navigator.serviceWorker.register('/sw.js'); await navigator.serviceWorker.ready;});
    await page.reload();
    for (let cycle = 1; cycle <= 3; cycle++) {
      await sync('on-' + cycle, true, rules);
      await page.waitForURL(/chrome-extension:\/\/.*\/blocked\.html#/);
      await page.locator('h1').filter({hasText: 'Página bloqueada'}).waitFor();
      assert.match(await page.locator('#domain').innerText(), /blocked.dnsentinel.test/);
      assert.match(allowed.url(), /^http:\/\/safe\.blocked\.dnsentinel\.test/);
      const networkResult = await allowed.evaluate(async url => {
        try {await fetch(url, {mode: 'no-cors'}); return 'allowed';} catch {return 'blocked';}
      }, `http://other.blocked.dnsentinel.test:${port}/resource`);
      assert.equal(networkResult, 'blocked');
      if (cycle === 1) {
        await page.setViewportSize({width: 1280, height: 800});
        await page.screenshot({path: path.join(temporary, 'blocked-desktop.png')});
        await page.setViewportSize({width: 375, height: 740});
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        await page.screenshot({path: path.join(temporary, 'blocked-mobile.png')});
      }
      await sync('off-' + cycle, false, []);
      await page.waitForURL(target);
      await page.locator('h1').waitFor();
      assert.equal((await worker.evaluate(() => chrome.declarativeNetRequest.getSessionRules())).length, 0);
    }
    await sync('bfcache-on', true, rules);
    const fresh = await context.newPage();
    await fresh.goto(`http://other.blocked.dnsentinel.test:${port}/new`).catch(() => {});
    await fresh.waitForURL(/chrome-extension:\/\/.*\/blocked\.html#/);
    await sync('exception', true, [...rules, {domain: 'blocked.dnsentinel.test', kind: 'allow', subdomains: true}]);
    await page.waitForURL(target);
    await sync('disconnect-on', true, rules);
    await page.waitForURL(/chrome-extension:\/\/.*\/blocked\.html#/);
    await worker.evaluate(() => testNative.onDisconnect.fire());
    await page.waitForURL(target);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({result: 'PASS', cycles: 3, checks: ['DNR real', 'pestañas abiertas', 'caché y service worker', 'excepciones', 'nueva navegación', 'desconexión', 'pantallas escritorio y móvil'], artifacts: temporary}, null, 2));
  } finally {
    if (context) await context.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(error => {console.error(error); process.exitCode = 1;});
