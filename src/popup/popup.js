/**
 * Popup UI controller module
 * Handles toggle state management and user interactions for the popup UI
 *
 * @module popup/popup
 */

import { getSettings, saveSettings } from '../utils/storage.js';
import * as logger from '../utils/logger.js';

/**
 * Restores the enabled/disabled state of the extension toggle
 * Reads from Chrome storage and updates the UI accordingly
 *
 * @function
 */
export const restoreOptions = () => {
  const status = document.getElementById('status');
  const enable = document.getElementById('enabled');
  enable.disabled = true;

  getSettings()
    .then((settings) => {
      enable.checked = !settings.disabled;
      enable.disabled = false;
      // Clear any previous error messages
      status.textContent = '';
      status.classList.remove('error');
    })
    .catch((error) => {
      logger.error('Storage operation failed:', error.message);
      // Keep the error visible while the toggle is unavailable. Reopening the popup retries.
      status.textContent =
        chrome.i18n.getMessage('loadError') || 'Failed to load your settings. Please try again.';
      status.classList.add('error');
    });
};

/**
 * Event handler for the extension enable/disable toggle
 * Updates the storage with the new disabled state
 * This triggers the background script to update tab icons accordingly
 *
 * @param {Event} event - The change event from the toggle checkbox
 * @function
 */
export function handleEnableToggle(event) {
  const status = document.getElementById('status');
  const enable = event.target;
  if (enable.disabled) {
    return;
  }

  const previousEnabled = !enable.checked;
  // Serialize changes so a failed save cannot revert a newer user selection.
  enable.disabled = true;

  saveSettings({ disabled: previousEnabled })
    .then(() => {
      // Clear any previous error messages
      status.textContent = '';
      status.classList.remove('error');
    })
    .catch((error) => {
      logger.error('Storage operation failed:', error.message);

      // Show user-friendly error message
      status.textContent =
        chrome.i18n.getMessage('saveError') || 'Failed to save your settings. Please try again.';
      status.classList.add('error');

      // Revert the toggle to its previous state since the save failed
      enable.checked = previousEnabled;

      // Clear error after 5 seconds
      setTimeout(() => {
        status.textContent = '';
        status.classList.remove('error');
      }, 5000);
    })
    .finally(() => {
      enable.disabled = false;
    });
}

/**
 * Event handler for options button click
 * Opens the extension's options page in a new tab
 * Uses Chrome API to open the correct options page
 *
 * @returns {void}
 * @function
 */
export function handleOptionsClick() {
  chrome.runtime.openOptionsPage();
}

/**
 * Event handler for DOMContentLoaded event
 * Initializes the popup UI and sets up event listeners
 * This is the main initialization function for the popup
 *
 * @returns {void}
 * @function
 */
export function handleDOMContentLoaded() {
  restoreOptions();

  const enable = document.getElementById('enabled');
  enable.addEventListener('change', handleEnableToggle);

  const options = document.getElementById('options');
  options.onclick = handleOptionsClick;
}

// Initial display for popup menu when opened
document.addEventListener('DOMContentLoaded', handleDOMContentLoaded);
