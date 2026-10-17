/**
 * Popup storage interactions with real handlers and deferred Chrome API callbacks.
 */
import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
  resetTestMocks,
  setupChromeApi,
} from '../../setup/vitest-imports.js';
import popupHtml from '../../../popup/index.html?raw';
import { handleDOMContentLoaded } from '../../../popup/popup.js';

describe('Popup storage interactions', () => {
  let toggle;
  let status;
  let readSettings;
  let pendingWrites;
  let savedDisabled;

  beforeEach(() => {
    resetTestMocks();
    setupChromeApi({ i18nMessages: { saveError: 'Save failed', loadError: 'Load failed' } });
    vi.useFakeTimers();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    document.body.innerHTML = popupHtml;
    toggle = document.getElementById('enabled');
    status = document.getElementById('status');
    pendingWrites = [];
    savedDisabled = false;
    chrome.storage.sync.get.mockImplementation((defaults, callback) => {
      readSettings = callback;
    });
    chrome.storage.sync.set.mockImplementation((settings, callback) => {
      pendingWrites.push({ settings, callback });
    });
    handleDOMContentLoaded();
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    resetTestMocks();
  });

  const finishRead = async (error = null) => {
    chrome.runtime.lastError = error;
    readSettings({ disabled: savedDisabled });
    chrome.runtime.lastError = null;
    await vi.advanceTimersByTimeAsync(0);
  };

  const finishWrite = async (error = null) => {
    const { settings, callback } = pendingWrites.shift();
    if (!error) {
      savedDisabled = settings.disabled;
    }
    chrome.runtime.lastError = error;
    callback();
    chrome.runtime.lastError = null;
    await vi.advanceTimersByTimeAsync(0);
  };

  it('waits for the saved setting before allowing changes', async () => {
    toggle.click();
    expect(chrome.storage.sync.set).not.toHaveBeenCalled();
    expect(toggle.disabled).toBe(true);

    await finishRead();
    expect(toggle.checked).toBe(true);
    expect(toggle.disabled).toBe(false);
  });

  it('keeps the toggle unavailable when loading fails', async () => {
    await finishRead({ message: 'Storage unavailable' });

    await vi.advanceTimersByTimeAsync(5000);
    expect(status.textContent).toBe('Load failed');
    expect(toggle.disabled).toBe(true);
    toggle.click();
    expect(chrome.storage.sync.set).not.toHaveBeenCalled();
  });

  it.each([false, true])(
    'serializes successful changes when disabled is initially %s',
    async (initialDisabled) => {
      savedDisabled = initialDisabled;
      await finishRead();
      toggle.click();
      toggle.click();

      expect(chrome.storage.sync.set).toHaveBeenCalledTimes(1);
      expect(pendingWrites[0].settings).toEqual({ disabled: !initialDisabled });
      toggle.dispatchEvent(new Event('change'));
      expect(chrome.storage.sync.set).toHaveBeenCalledTimes(1);
      expect(toggle.disabled).toBe(true);

      await finishWrite();
      expect(toggle.checked).toBe(!savedDisabled);
      expect(toggle.disabled).toBe(false);
      expect(status.textContent).toBe('');

      toggle.click();
      await finishWrite();
      expect(chrome.storage.sync.set).toHaveBeenCalledTimes(2);
      expect(savedDisabled).toBe(initialDisabled);
      expect(toggle.checked).toBe(!savedDisabled);
    }
  );

  it.each([false, true])(
    'restores the saved state after failure and allows retry when disabled is initially %s',
    async (initialDisabled) => {
      savedDisabled = initialDisabled;
      await finishRead();
      toggle.click();
      toggle.click();
      await finishWrite({ message: 'QUOTA_BYTES quota exceeded' });

      expect(toggle.checked).toBe(!savedDisabled);
      expect(toggle.disabled).toBe(false);
      expect(status.textContent).toBe('Save failed');
      expect(status.classList.contains('error')).toBe(true);
      expect(chrome.storage.sync.set).toHaveBeenCalledTimes(1);

      toggle.click();
      await finishWrite();
      expect(savedDisabled).toBe(!initialDisabled);
      expect(toggle.checked).toBe(!savedDisabled);
      expect(toggle.disabled).toBe(false);
      expect(status.textContent).toBe('');
      expect(status.classList.contains('error')).toBe(false);
    }
  );

  it('ignores a late read after timeout and retries when the popup is reopened', async () => {
    await vi.advanceTimersByTimeAsync(3000);
    expect(status.textContent).toBe('Load failed');
    expect(toggle.disabled).toBe(true);

    await finishRead();
    toggle.click();
    expect(toggle.disabled).toBe(true);
    expect(status.textContent).toBe('Load failed');
    expect(chrome.storage.sync.set).not.toHaveBeenCalled();

    document.body.innerHTML = popupHtml;
    toggle = document.getElementById('enabled');
    status = document.getElementById('status');
    handleDOMContentLoaded();
    await finishRead();
    expect(toggle.checked).toBe(!savedDisabled);
    expect(toggle.disabled).toBe(false);
    expect(status.textContent).toBe('');
  });

  it('restores the toggle when the Chrome storage call throws', async () => {
    await finishRead();
    chrome.storage.sync.set.mockImplementation(() => {
      throw new Error('Extension context invalidated');
    });

    toggle.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(toggle.checked).toBe(!savedDisabled);
    expect(toggle.disabled).toBe(false);
    expect(status.textContent).toBe('Save failed');
  });
});
