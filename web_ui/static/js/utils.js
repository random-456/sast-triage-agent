/**
 * Utility functions shared across the application
 */

/**
 * Escape HTML to prevent XSS attacks
 *
 * @param {string} text - Text to escape
 * @returns {string} HTML-escaped text safe for innerHTML
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Truncate text to specified length with ellipsis
 *
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated text
 */
function truncate(text, maxLength) {
    if (!text || text.length <= maxLength) return text || '';
    return text.substring(0, maxLength) + '...';
}