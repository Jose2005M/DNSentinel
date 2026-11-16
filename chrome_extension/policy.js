// La misma semántica que dnsentinel/policy.py: cualquier excepción gana.
export function webURL(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url : null;
  } catch { return null; }
}

export function blocked(value, state) {
  const url = webURL(value);
  if (!state.active || !url) return false;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const matches = state.rules.filter(rule => host === rule.domain ||
    (rule.subdomains && host.endsWith('.' + rule.domain)));
  return !matches.some(rule => rule.kind === 'allow') && matches.some(rule => rule.kind === 'block');
}

export function validateState(message) {
  if (typeof message.revision !== 'string' || message.revision.length > 128 ||
      typeof message.active !== 'boolean' || !Array.isArray(message.rules) || message.rules.length > 5000) {
    throw new Error('El estado del lanzador no es válido.');
  }
  const rules = message.rules.map(rule => {
    if (!['block', 'allow'].includes(rule.kind) || ![true, false, 0, 1].includes(rule.subdomains) ||
        typeof rule.domain !== 'string' || rule.domain.length > 253 || !rule.domain.includes('.') ||
        rule.domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw new Error('Hay una regla incompatible con Chrome.');
    }
    return {domain: rule.domain, kind: rule.kind, subdomains: Boolean(rule.subdomains)};
  });
  return {revision: message.revision, active: message.active, rules};
}

export function regexFor(rules, subdomains) {
  const domains = rules.map(rule => rule.domain.replace(/\./g, '\\.')).join('|');
  // Incluye credenciales, puerto explícito y punto DNS final; respeta etiquetas.
  return '^(https?|wss?)://([^/@]*@)?' + (subdomains ? '([a-z0-9-]+\\.)*' : '') +
    '(' + domains + ')\\.?(:[0-9]+)?([/?#]|$)';
}

export async function compileRules(state, supported) {
  if (!state.active) return [];
  const output = [];
  async function add(group, kind, subdomains) {
    const regexFilter = regexFor(group, subdomains);
    if (!(await supported(regexFilter)).isSupported) {
      if (group.length === 1) throw new Error('Chrome no admite una regla de esta lista.');
      const middle = Math.ceil(group.length / 2);
      await add(group.slice(0, middle), kind, subdomains);
      await add(group.slice(middle), kind, subdomains);
      return;
    }
    output.push({
      id: output.length + 1, priority: kind === 'allow' ? 2 : 1,
      action: {type: kind === 'allow' ? 'allow' : 'block'},
      condition: {regexFilter, isUrlFilterCaseSensitive: false,
        resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
          'object', 'xmlhttprequest', 'ping', 'media', 'websocket', 'other']}
    });
    if (output.length > 1000) throw new Error('Esta lista supera el límite de expresiones de Chrome.');
  }
  for (const kind of ['block', 'allow']) {
    for (const subdomains of [false, true]) {
      const group = state.rules.filter(rule => rule.kind === kind && rule.subdomains === subdomains);
      for (let index = 0; index < group.length; index += 10) {
        await add(group.slice(index, index + 10), kind, subdomains);
      }
    }
  }
  return output;
}
