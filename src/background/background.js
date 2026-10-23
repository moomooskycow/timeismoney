/**
 * Background script for the Time Is Money extension.
 * Handles extension lifecycle events, icon updates, and user interactions.
 * Adapted for Manifest V3 service worker context.
 *
 * @module background/background
 */

import { getSettings, saveSettings, onSettingsChanged } from '../utils/storage.js';
import * as logger from '../utils/logger.js';

// Default settings - defined at the top level for easy access
const DEFAULT_SETTINGS = {
  disabled: false,
  currencySymbol: '$',
  currencyCode: 'USD',
  frequency: 'hourly',
  amount: '15.00',
  thousands: 'commas',
  decimal: 'dot',
  debounceIntervalMs: 200, // Default debounce interval for MutationObserver
  enableDynamicScanning: true, // Default to enable dynamic DOM scanning
};

/**
 * Event handler for action click
 * Opens the options page when user clicks the extension icon
 *
 * @returns {void}
 */
function handleActionClick() {
  chrome.runtime.openOptionsPage();
}

/**
 * Event handler for extension installation or update
 * Sets up default options and opens the options page
 * Preserves existing settings during updates
 *
 * @param {object} details - Installation details from Chrome
 * @param {string} details.reason - Reason for installation ('install' or 'update')
 * @returns {void}
 */
function handleExtensionInstalled(details) {
  // In MV3, we should open the options page after the service worker is fully initialized
  chrome.runtime.openOptionsPage();

  // For new installations, use defaults
  if (details.reason === 'install') {
    saveSettings(DEFAULT_SETTINGS).catch((error) => {
      logger.error('Failed to save default settings on extension install:', error);
    });
    return;
  }

  // For updates, preserve existing settings
  if (details.reason === 'update') {
    getSettings()
      .then((existingSettings) => {
        // Create a merged settings object
        const mergedSettings = {};

        // Only fill in values that don't exist
        for (const key in DEFAULT_SETTINGS) {
          mergedSettings[key] =
            existingSettings[key] !== undefined ? existingSettings[key] : DEFAULT_SETTINGS[key];
        }

        // Only save if there are differences
        if (JSON.stringify(existingSettings) !== JSON.stringify(mergedSettings)) {
          return saveSettings(mergedSettings);
        }
        return undefined; // Explicit return to satisfy promise chain
      })
      .catch((error) => {
        // An unavailable read or failed migration is not permission to reset saved settings.
        logger.error('Failed to preserve settings during extension update:', error);
      });
  }
}

/**
 * Updates the extension icon based on disabled state
 *
 * @param {object} settings - Object containing updated settings
 * @param {boolean} [settings.disabled] - Whether the extension is disabled
 * @returns {void}
 */
function updateIcon(settings) {
  if ('disabled' in settings) {
    if (settings.disabled) {
      chrome.action.setIcon({ path: '/images/icon_disabled_38.png' });
    } else {
      chrome.action.setIcon({ path: '/images/icon_38.png' });
    }
  }
}

/**
 * Initializes the extension icon on startup based on current settings
 * In service workers, we need to do this when the worker starts
 *
 * @returns {Promise<void>} Promise that resolves when icon is initialized
 * @throws {Error} If there's an error retrieving settings
 */
async function initializeIcon() {
  try {
    const settings = await getSettings();
    updateIcon({ disabled: settings.disabled });
    logger.debug('Extension icon initialized');
  } catch (error) {
    logger.error('Failed to initialize extension icon due to storage error:', error);
  }
}

/**
 * Sets up service worker lifecycle event handlers
 *
 * @returns {void}
 */
function setupServiceWorkerEvents() {
  self.addEventListener('activate', () => {
    logger.debug('Service worker activated');
  });

  self.addEventListener('install', () => {
    logger.debug('Service worker installed');
    self.skipWaiting(); // Ensure service worker activates immediately
  });
}

// In Manifest V3, listeners must be registered at the top level
// Register all event listeners synchronously
chrome.action.onClicked.addListener(handleActionClick);
chrome.runtime.onInstalled.addListener(handleExtensionInstalled);
onSettingsChanged(updateIcon);

// Set up service worker events
setupServiceWorkerEvents();

// Initialize icon (async operation but called immediately)
initializeIcon().catch((err) => {
  logger.error('Failed to initialize extension:', err);
});

// Log service worker startup
logger.info('Time Is Money background service worker initialized');
