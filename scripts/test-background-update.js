/**
 * Dependency-free regression through the registered extension lifecycle handler.
 * Only Chrome and service-worker boundaries are synthetic; application modules are real.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';

let moduleInstance = 0;

async function loadBackground(t) {
  const previousChrome = globalThis.chrome;
  const previousSelf = globalThis.self;
  const saved = {
    amount: '72.50',
    frequency: 'hourly',
    currencySymbol: '€',
    currencyCode: 'EUR',
    thousands: 'spacesAndDots',
    decimal: 'comma',
    disabled: true,
    debounceIntervalMs: 400,
    enableDynamicScanning: false,
    debugMode: true,
  };
  const writes = [];
  let installed;
  const errors = [];

  for (const level of ['debug', 'info']) t.mock.method(console, level, () => {});
  t.mock.method(console, 'error', (...args) => errors.push(args));
  globalThis.chrome = {
    runtime: {
      getManifest: () => ({ version: '4.3.0' }),
      openOptionsPage: () => {},
      onInstalled: { addListener: (callback) => (installed = callback) },
    },
    action: { onClicked: { addListener: () => {} }, setIcon: () => {} },
    storage: {
      sync: {
        get: (defaults, callback) => callback({ ...defaults, ...saved }),
        set: (settings, callback) => {
          writes.push(settings);
          Object.assign(saved, settings);
          callback();
        },
      },
      onChanged: { addListener: () => {} },
    },
  };
  globalThis.self = { addEventListener: () => {}, skipWaiting: () => {} };
  t.after(() => {
    globalThis.chrome = previousChrome;
    globalThis.self = previousSelf;
  });

  await import(`../src/background/background.js?update-regression=${++moduleInstance}`);
  await nextTurn();
  assert.equal(typeof installed, 'function');
  return { saved, writes, installed, errors };
}

test('update preserves accepted settings after a rejected storage read', async (t) => {
  const { saved, writes, installed, errors } = await loadBackground(t);
  const before = { ...saved };
  chrome.storage.sync.get = (defaults, callback) => {
    chrome.runtime.lastError = { message: 'Synthetic read failure' };
    callback(undefined);
    delete chrome.runtime.lastError;
  };

  installed({ reason: 'update' });
  await nextTurn();
  assert.equal(writes.length, 0);
  assert.deepEqual(saved, before);
  assert.equal(errors.length, 1);
});

test('update preserves settings when the storage read throws', async (t) => {
  const { saved, writes, installed } = await loadBackground(t);
  const before = { ...saved };
  chrome.storage.sync.get = () => {
    throw new Error('Synthetic unavailable storage');
  };

  installed({ reason: 'update' });
  await nextTurn();
  assert.equal(writes.length, 0);
  assert.deepEqual(saved, before);
});

test('a timed-out update read and its late callback never write defaults', async (t) => {
  const { saved, writes, installed } = await loadBackground(t);
  const before = { ...saved };
  let finishRead;
  chrome.storage.sync.get = (defaults, callback) => {
    finishRead = callback;
  };

  installed({ reason: 'update' });
  await delay(3100);
  assert.equal(writes.length, 0);
  assert.deepEqual(saved, before);

  // A newer accepted user choice must also survive the obsolete callback.
  saved.amount = '81.25';
  finishRead(before);
  await nextTurn();
  assert.equal(writes.length, 0);
  assert.equal(saved.amount, '81.25');
});

test('failed update write is not followed by a destructive defaults retry', async (t) => {
  const { saved, writes, installed } = await loadBackground(t);
  const before = { ...saved };
  chrome.storage.sync.set = (settings, callback) => {
    writes.push(settings);
    if (writes.length === 1) {
      chrome.runtime.lastError = { message: 'Synthetic write failure' };
      callback();
      delete chrome.runtime.lastError;
    } else {
      Object.assign(saved, settings);
      callback();
    }
  };

  installed({ reason: 'update' });
  await nextTurn();
  assert.equal(writes.length, 1);
  assert.deepEqual(saved, before);
});

test('successful update retains accepted custom values and unrelated settings', async (t) => {
  const { saved, installed } = await loadBackground(t);
  const before = { ...saved };

  installed({ reason: 'update' });
  await nextTurn();
  assert.deepEqual(saved, before);
});

test('fresh install retains its existing initialization defaults', async (t) => {
  const { saved, writes, installed } = await loadBackground(t);

  installed({ reason: 'install' });
  await nextTurn();
  assert.equal(writes.length, 1);
  assert.equal(saved.amount, '15.00');
  assert.equal(saved.currencyCode, 'USD');
  assert.equal(saved.disabled, false);
  assert.equal(saved.enableDynamicScanning, true);
});
