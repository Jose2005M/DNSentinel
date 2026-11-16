import test from 'node:test';
import assert from 'node:assert/strict';
import {blocked, compileRules, regexFor, validateState} from '../chrome_extension/policy.js';

const rule = (domain, kind = 'block', subdomains = true) => ({domain, kind, subdomains});
const active = rules => ({revision: 'test', active: true, rules});
const supported = async regex => ({isSupported: new RegExp(regex).source.length < 2000});

test('DNS policy parity: labels, exception precedence, exact host, punycode, trailing dot', () => {
  const state = active([rule('example.com'), rule('safe.example.com', 'allow'), rule('exact.test', 'block', false), rule('xn--bcher-kva.test')]);
  for (const url of ['https://example.com/', 'https://child.example.com/', 'https://EXAMPLE.com.:443/a',
    'https://user:pass@example.com/a', 'https://exact.test/', 'https://bücher.test/']) assert.equal(blocked(url, state), true, url);
  for (const url of ['https://notexample.com/', 'https://example.com.evil.test/', 'https://safe.example.com/',
    'https://child.safe.example.com/', 'https://sub.exact.test/', 'chrome://extensions', 'file:///example.com', 'invalid']) {
    assert.equal(blocked(url, state), false, url);
  }
  assert.equal(blocked('https://example.com', {...state, active: false}), false);
});

test('compiled network rules agree with page policy and allow exceptions', async () => {
  const state = validateState(active([rule('example.com', 'block', 1), rule('safe.example.com', 'allow', 0), rule('exact.test', 'block', 0)]));
  const rules = await compileRules(state, supported);
  for (const url of ['https://example.com/', 'http://a.example.com:8080/', 'https://example.com./',
    'https://safe.example.com/', 'https://a.safe.example.com/', 'https://user:pass@exact.test/',
    'https://sub.exact.test/', 'https://example.com.evil.test/']) {
    const winner = rules.filter(r => new RegExp(r.condition.regexFilter, 'i').test(url)).sort((a,b) => b.priority-a.priority)[0];
    assert.equal(winner?.action.type === 'block', blocked(url, state), url);
  }
  assert.deepEqual(await compileRules({...state, active: false}, supported), []);
});

test('5000 domains fit grouped Chrome rules; invalid and unsupported input fails visibly', async () => {
  const state = active(Array.from({length: 5000}, (_, i) => rule(`site${i}.test`, 'block', false)));
  assert.equal((await compileRules(state, supported)).length, 500);
  assert.throws(() => validateState(active([rule('example.com|evil.test')])));
  await assert.rejects(compileRules(active([rule('example.com')]), async () => ({isSupported: false})));
  assert.equal(new RegExp(regexFor([rule('example.com')], false)).test('https://sub.example.com/'), false);
});

function event() {
  const listeners = [];
  return {addListener: fn => listeners.push(fn), fire: (...args) => listeners.forEach(fn => fn(...args))};
}

test('worker repeats activate/deactivate cycles, protects open and cached tabs, and clears on disconnect', async () => {
  const tabs = new Map([[1, {id: 1, url: 'https://example.com/already-open'}], [2, {id: 2, url: 'https://safe.example.com/'}]]);
  const updates = [];
  const onUpdated = event();
  const native = {onMessage: event(), onDisconnect: event(), sent: [], postMessage(message) {this.sent.push(message);}};
  let sessionRules = [];
  const navigation = Object.fromEntries(['onBeforeNavigate', 'onCommitted', 'onHistoryStateUpdated', 'onErrorOccurred'].map(k => [k, event()]));
  globalThis.chrome = {
    runtime: {getURL: path => 'chrome-extension://test/' + path, connectNative: () => native,
      onMessage: event(), onStartup: event(), id: 'test'},
    tabs: {onUpdated, query: async () => [...tabs.values()].map(t => ({...t})),
      get: async id => {if (!tabs.has(id)) throw Error('No tab'); return {...tabs.get(id)};},
      update: async (id, change) => {Object.assign(tabs.get(id), change); updates.push({id, ...change}); onUpdated.fire(id, change, {...tabs.get(id)});}},
    webNavigation: navigation,
    declarativeNetRequest: {isRegexSupported: async () => ({isSupported: true}),
      getSessionRules: async () => sessionRules, updateSessionRules: async change => {sessionRules = change.addRules;}},
    storage: {session: {get: async () => ({}), set: async () => {}}},
    action: {setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}},
    alarms: {onAlarm: event(), create: () => {}}
  };
  await import('../chrome_extension/background.js');
  const tick = () => new Promise(resolve => setImmediate(resolve));
  await tick();
  async function sync(revision, enabled, rules = [rule('example.com'), rule('safe.example.com', 'allow')]) {
    native.onMessage.fire({type: 'state', revision, active: enabled, rules});
    for (let i = 0; i < 100 && !native.sent.some(ack => ack.revision === revision); i++) await tick();
    assert.deepEqual(native.sent.find(ack => ack.revision === revision), {type: 'ack', revision, ok: true});
  }
  for (let cycle = 0; cycle < 3; cycle++) {
    await sync('on' + cycle, true);
    assert.ok(tabs.get(1).url.startsWith('chrome-extension://test/blocked.html#'));
    assert.equal(tabs.get(2).url, 'https://safe.example.com/');
    assert.ok(sessionRules.length);
    await sync('off' + cycle, false, []);
    assert.equal(tabs.get(1).url, 'https://example.com/already-open');
    assert.deepEqual(sessionRules, []);
  }
  await sync('live', true);
  tabs.set(3, {id: 3, url: 'https://example.com/from-bfcache'});
  navigation.onCommitted.fire({tabId: 3, frameId: 0, url: tabs.get(3).url});
  await tick();
  assert.ok(tabs.get(3).url.startsWith('chrome-extension://test/blocked.html#'));
  await sync('allow-now', true, [rule('example.com'), rule('example.com', 'allow')]);
  assert.equal(tabs.get(1).url, 'https://example.com/already-open');
  await sync('again', true);
  native.onDisconnect.fire();
  await tick();
  assert.equal(tabs.get(1).url, 'https://example.com/already-open');
  assert.deepEqual(sessionRules, []);
  assert.ok(updates.length >= 10);
});
