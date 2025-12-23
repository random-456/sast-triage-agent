/**
 * Findings Table Component
 * Handles rendering and interaction with findings table
 */

class FindingsTable {
    constructor() {
        this.tbody = document.getElementById('findings-table-body');
        this.selectAllCheckbox = document.getElementById('select-all-findings');

        this.setupEventListeners();
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Select all checkbox
        if (this.selectAllCheckbox) {
            this.selectAllCheckbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    stateManager.selectAllFindings();
                } else {
                    stateManager.deselectAllFindings();
                }
                this.updateCheckboxes();
            });
        }
    }

    /**
     * Render findings table
     */
    render(findings) {
        if (!findings || findings.length === 0) {
            this.tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="p-8 text-center text-gray-500">
                        No findings to display
                    </td>
                </tr>
            `;
            return;
        }

        this.tbody.innerHTML = findings.map(finding => this.renderRow(finding)).join('');
        this.attachRowEventListeners();
        this.updateCheckboxes();
    }

    /**
     * Render a single finding row
     */
    renderRow(finding) {
        const analysis = finding.analysis || {};
        const isSelected = stateManager.getState().selectedFindings.includes(finding.resultHash);

        // Determine row class based on analysis result
        let rowClass = 'finding-row';
        if (isSelected) rowClass += ' selected';
        if (analysis.result) rowClass += ` result-${analysis.result}`;

        return `
            <tr class="${rowClass}" data-result-hash="${finding.resultHash}">
                <td class="p-3">
                    <input type="checkbox" class="finding-checkbox form-checkbox"
                           data-result-hash="${finding.resultHash}"
                           ${isSelected ? 'checked' : ''}>
                </td>
                <td class="p-3">
                    <div class="font-medium">${this.escapeHtml(finding.queryName)}</div>
                    ${analysis.status ? this.renderAnalysisStatus(analysis) : ''}
                    ${analysis.justification ? this.renderJustification(analysis.justification) : ''}
                </td>
                <td class="p-3">${finding.cweID || '-'}</td>
                <td class="p-3">${this.renderSeverityBadge(finding.severity)}</td>
                <td class="p-3">${this.renderStateBadge(finding.state)}</td>
                <td class="p-3 text-xs">${this.escapeHtml(finding.category)}</td>
                <td class="p-3 text-xs">${this.escapeHtml(finding.languageName)}</td>
                <td class="p-3">
                    ${finding.checkmarx_url ? `
                        <a href="${finding.checkmarx_url}" target="_blank" class="text-blue-400 hover:text-blue-300">
                            <i class="fas fa-external-link-alt"></i>
                        </a>
                    ` : '-'}
                    ${analysis.status === 'completed' ? `
                        <button class="ml-2 text-gray-400 hover:text-white"
                                data-action="view-details"
                                data-result-hash="${finding.resultHash}">
                            <i class="fas fa-info-circle"></i>
                        </button>
                    ` : ''}
                    ${analysis.result && analysis.result !== 'REFUSED' ? `
                        <button class="ml-2 text-gray-400 hover:text-white"
                                data-action="writeback"
                                data-result-hash="${finding.resultHash}">
                            <i class="fas fa-upload"></i>
                        </button>
                    ` : ''}
                </td>
            </tr>
        `;
    }

    /**
     * Render analysis status (spinner + latest action)
     */
    renderAnalysisStatus(analysis) {
        if (analysis.status === 'in_progress') {
            return `
                <div class="analysis-status text-gray-400 mt-1">
                    <i class="fas fa-spinner spinner"></i>
                    <span class="text-xs">${this.escapeHtml(analysis.last_action || 'Analyzing...')}</span>
                </div>
            `;
        } else if (analysis.status === 'completed') {
            const resultIcon = analysis.result === 'CONFIRMED' ? 'exclamation-circle text-red-400' :
                              analysis.result === 'NOT_EXPLOITABLE' ? 'check-circle text-green-400' :
                              'question-circle text-gray-400';

            return `
                <div class="text-xs text-gray-400 mt-1">
                    <i class="fas fa-${resultIcon}"></i>
                    <span class="font-semibold">${analysis.result}</span>
                    <span class="ml-2">${Math.round(analysis.confidence * 100)}% confidence</span>
                </div>
            `;
        } else if (analysis.status === 'failed') {
            return `
                <div class="text-xs text-red-400 mt-1">
                    <i class="fas fa-exclamation-triangle"></i>
                    Failed
                </div>
            `;
        }
        return '';
    }

    /**
     * Render justification text (collapsed)
     */
    renderJustification(justification) {
        return `
            <div class="justification-text justification-collapsed mt-1"
                 data-full-text="${this.escapeHtml(justification)}">
                ${this.escapeHtml(justification)}
            </div>
        `;
    }

    /**
     * Render severity badge
     */
    renderSeverityBadge(severity) {
        return `<span class="badge badge-${severity}">${severity}</span>`;
    }

    /**
     * Render state badge
     */
    renderStateBadge(state) {
        return `<span class="state-badge state-${state}">${state.replace(/_/g, ' ')}</span>`;
    }

    /**
     * Attach event listeners to row elements
     */
    attachRowEventListeners() {
        // Checkbox listeners
        const checkboxes = this.tbody.querySelectorAll('.finding-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const resultHash = e.target.dataset.resultHash;
                stateManager.toggleFindingSelection(resultHash);
                this.updateRowSelection(resultHash);
            });
        });

        // View details buttons
        const detailButtons = this.tbody.querySelectorAll('[data-action="view-details"]');
        detailButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const resultHash = e.target.closest('[data-action="view-details"]').dataset.resultHash;
                window.dispatchEvent(new CustomEvent('view-finding-details', { detail: { resultHash } }));
            });
        });

        // Writeback buttons
        const writebackButtons = this.tbody.querySelectorAll('[data-action="writeback"]');
        writebackButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const resultHash = e.target.closest('[data-action="writeback"]').dataset.resultHash;
                window.dispatchEvent(new CustomEvent('writeback-finding', { detail: { resultHash } }));
            });
        });
    }

    /**
     * Update checkbox states based on state manager
     */
    updateCheckboxes() {
        const state = stateManager.getState();
        const checkboxes = this.tbody.querySelectorAll('.finding-checkbox');

        checkboxes.forEach(checkbox => {
            const resultHash = checkbox.dataset.resultHash;
            checkbox.checked = state.selectedFindings.includes(resultHash);
        });

        // Update select all checkbox
        if (this.selectAllCheckbox) {
            const allChecked = state.findings.length > 0 &&
                             state.selectedFindings.length === state.findings.length;
            this.selectAllCheckbox.checked = allChecked;
        }
    }

    /**
     * Update row selection visual state
     */
    updateRowSelection(resultHash) {
        const row = this.tbody.querySelector(`[data-result-hash="${resultHash}"]`);
        if (!row) return;

        const state = stateManager.getState();
        const isSelected = state.selectedFindings.includes(resultHash);

        if (isSelected) {
            row.classList.add('selected');
        } else {
            row.classList.remove('selected');
        }
    }

    /**
     * Update a single finding row (for progressive updates during analysis)
     */
    updateFindingRow(finding) {
        const row = this.tbody.querySelector(`[data-result-hash="${finding.resultHash}"]`);
        if (!row) return;

        // Get current selection state
        const checkbox = row.querySelector('.finding-checkbox');
        const isChecked = checkbox ? checkbox.checked : false;

        // Replace row HTML
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = this.renderRow(finding);
        const newRow = tempDiv.firstElementChild;

        // Preserve checkbox state
        const newCheckbox = newRow.querySelector('.finding-checkbox');
        if (newCheckbox) newCheckbox.checked = isChecked;

        row.replaceWith(newRow);

        // Re-attach event listeners for this row
        this.attachRowEventListeners();
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize findings table
const findingsTable = new FindingsTable();
