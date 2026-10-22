/* Run the production pairing screen with deterministic UI/native boundaries.
 * No React Native runtime is needed: handlers and effects are the real TSX code.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

const root = path.resolve(__dirname, '..');
function load(relative, dependencies) {
  const source = fs.readFileSync(path.join(root, relative), 'utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020,
    jsx: ts.JsxEmit.ReactJSX,
  }}).outputText;
  const module = { exports: {} };
  vm.runInNewContext(compiled, {
    module, exports: module.exports, console, setTimeout, clearTimeout,
    require(name) {
      if (!(name in dependencies)) throw new Error(`Unexpected dependency: ${name}`);
      return dependencies[name];
    },
  }, { filename: relative });
  return module.exports;
}

const setup = { ver: 'v1', name: 'WOL_a1b2c3', transport: 'ble', security: 2,
  username: 'wol', pop: '0123456789abcdef' };
const { parseSetupCode } = load('src/provisioning/client.ts', {
  'expo-modules-core': { requireNativeModule() { throw new Error('native not expected'); } },
  'react-native': {},
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = async () => { await new Promise(setImmediate); await new Promise(setImmediate); };

function mount({ owned = false, pendingConnect = null } = {}) {
  let cursor = 0;
  const slots = [];
  let appState;
  let scans = [];
  const calls = { claims: [], configurations: [], lists: 0, cancels: 0 };
  const info = { deviceId: 'A'.repeat(43), paired: owned };
  let online = false;
  const provisioning = {
    connect: () => pendingConnect ? pendingConnect.promise : Promise.resolve(info),
    scanNetworks: () => scans.length ? scans.shift() : Promise.resolve([{ ssid: 'Home', rssi: -40 }]),
    configure: async (...args) => { calls.configurations.push(args); online = true; },
    cancel: async () => { calls.cancels++; },
  };
  const api = {
    listDevices: async () => {
      calls.lists++;
      return owned || online ? [{ id: info.deviceId, name: 'Box', online }] : [];
    },
    createClaim: async (...args) => { calls.claims.push(args); return 'test-claim'; },
  };
  const strings = new Proxy({}, { get: (_, name) => new Proxy({}, { get: (_, field) => `${name}.${field}` }) });
  const jsx = (type, props) => ({ type, props: props || {} });
  const { default: Screen } = load('app/device/pair.tsx', {
    'react/jsx-runtime': { jsx, jsxs: jsx, Fragment: 'Fragment' },
    'react': {
      useState(initial) {
        const index = cursor++;
        if (!(index in slots)) slots[index] = initial;
        return [slots[index], value => { slots[index] = typeof value === 'function' ? value(slots[index]) : value; }];
      },
      useRef(initial) {
        const index = cursor++;
        if (!(index in slots)) slots[index] = { current: initial };
        return slots[index];
      },
      useEffect(effect) {
        const index = cursor++;
        if (!(index in slots)) slots[index] = effect();
      },
    },
    'expo-camera': { CameraView: 'CameraView', useCameraPermissions: () => [{ granted: true }, async () => ({ granted: true })] },
    'expo-router': { useRouter: () => ({ back() {} }) },
    'react-native': { AppState: { addEventListener(_, callback) { appState = callback; return { remove() {} }; } }, Text: 'Text', View: 'View' },
    '@/api/client': { api },
    '@/api/errors': { WolError: class WolError extends Error {}, describeError: () => 'api-error' },
    '@/i18n': { t: strings },
    '@/provisioning/client': { parseSetupCode, provisioning },
    '@/ui/components': Object.fromEntries(['Button', 'Card', 'ErrorText', 'Field', 'FormScreen', 'Muted'].map(name => [name, name]).concat([['styles', {}]])),
    '@/validation': { labelError: value => value.trim() ? null : 'missing name' },
  });
  function render() { cursor = 0; return Screen(); }
  function nodes(tree, predicate) {
    if (!tree || typeof tree !== 'object') return [];
    if (Array.isArray(tree)) return tree.flatMap(item => nodes(item, predicate));
    return [...(predicate(tree) ? [tree] : []), ...nodes(tree.props?.children, predicate)];
  }
  function find(type, prop, value) {
    const result = nodes(render(), item => item.type === type && (!prop || item.props[prop] === value));
    assert.equal(result.length, 1, `Expected one ${type} ${value ?? ''}`);
    return result[0].props;
  }
  async function connect() {
    find('Button', 'title', 'pair.scan').onPress();
    await flush();
    find('CameraView').onBarcodeScanned({ data: JSON.stringify(setup) });
    await flush();
  }
  render();
  return { calls, find, connect, render, info, background: () => appState('background'),
    enqueueScan: promise => scans.push(promise) };
}

async function main() {
  const test = process.argv[2];
  if (test === 'setup_code') {
    assert.equal(parseSetupCode(JSON.stringify(setup)).name, setup.name);
    for (const value of [null, [], {}, { ...setup, security: 1 }, { ...setup, transport: 'softap' },
      { ...setup, name: 'other-device' }, { ...setup, username: 'with space' }, { ...setup, pop: 'too-short' }]) {
      assert.throws(() => parseSetupCode(JSON.stringify(value)), /invalid_setup_code/);
    }
    assert.throws(() => parseSetupCode('not json'), /invalid_setup_code/);
    assert.throws(() => parseSetupCode(' '.repeat(1025)), /invalid_setup_code/);
  } else if (test === 'new_device' || test === 'owned_device') {
    const screen = mount({ owned: test === 'owned_device' });
    await screen.connect();
    if (test === 'new_device') screen.find('Field', 'label', 'pair.name').onChangeText('Office box');
    screen.find('Field', 'label', 'pair.ssid').onChangeText('Home');
    screen.find('Field', 'label', 'pair.password').onChangeText('wifi-test-password');
    screen.find('Button', 'title', 'pair.submit').onPress();
    await flush();
    assert.equal(screen.find('Muted', 'children', 'pair.success').children, 'pair.success');
    assert.equal(screen.calls.claims.length, test === 'new_device' ? 1 : 0);
    assert.equal(screen.calls.configurations[0][2], test === 'new_device' ? 'test-claim' : null);
    if (test === 'new_device') assert.equal(screen.calls.claims[0][1], screen.info.deviceId);
  } else if (test === 'stale_connect') {
    const pending = deferred();
    const screen = mount({ pendingConnect: pending });
    await screen.connect();
    screen.background();
    pending.resolve(screen.info);
    await flush();
    assert.equal(screen.calls.lists, 0);
    assert.equal(screen.find('Button', 'title', 'pair.scan').title, 'pair.scan');
    assert.ok(screen.calls.cancels > 0);
  } else if (test === 'background_refresh') {
    const screen = mount();
    await screen.connect();
    const pending = deferred();
    screen.enqueueScan(pending.promise);
    screen.find('Button', 'title', 'pair.rescan').onPress();
    assert.equal(screen.find('Button', 'title', 'pair.rescan').loading, true);
    screen.background();
    pending.reject(new Error('Native operation canceled'));
    await flush();
    await screen.connect();
    assert.equal(screen.find('Button', 'title', 'pair.rescan').loading, false,
      'A canceled refresh must not keep the reconnected pairing form busy');
    assert.equal(screen.find('Button', 'title', 'pair.submit').disabled, false);
  } else {
    throw new Error(`Unknown scenario ${test}`);
  }
  console.log(`PASS ${test}`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
