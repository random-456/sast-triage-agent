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
                    <td colspan="7" class="p-8 text-center text-gray-500">
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

        // Determine row class based on selection state
        let rowClass = 'finding-row';
        if (isSelected) rowClass += ' selected';

        // Conditionally render checkbox only if finding can be analyzed
        const checkboxCell = this.isFindingAnalyzable(finding) ? `
            <td class="p-3">
                <input type="checkbox" class="finding-checkbox form-checkbox"
                       data-result-hash="${finding.resultHash}"
                       ${isSelected ? 'checked' : ''}>
            </td>
        ` : `
            <td class="p-3"></td>
        `;

        return `
            <tr class="${rowClass}" data-result-hash="${finding.resultHash}">
                ${checkboxCell}
                <td class="p-3">
                    <div class="font-medium">${escapeHtml(finding.queryName)}</div>
                    <div class="text-xxs text-gray-500 font-mono mt-1">
                        ${finding.resultHash.substring(0, 50)}...
                    </div>
                    ${analysis.status ? this.renderAnalysisStatus(analysis) : ''}
                    ${analysis.justification ? this.renderJustification(analysis.justification) : ''}
                </td>
                <td class="p-3">${finding.cweID || '-'}</td>
                <td class="p-3">${this.renderSeverityBadge(finding.severity)}</td>
                <td class="p-3">${this.renderStateBadge(finding.state)}</td>
                <td class="p-3 text-xs">${escapeHtml(finding.category)}</td>
                <td class="p-3 text-xs">${escapeHtml(finding.languageName)}</td>
            </tr>
        `;
    }

    /**
     * Check if a finding can be analyzed
     */
    isFindingAnalyzable(finding) {
        // No analysis data = can analyze
        if (!finding.analysis) return true;

        // No result yet (pending or failed) = can analyze
        if (!finding.analysis.result) return true;

        // REFUSED = can re-analyze
        if (finding.analysis.result === 'REFUSED') return true;

        // Completed with CONFIRMED or NOT_EXPLOITABLE = cannot re-analyze
        return false;
    }

    /**
     * Render analysis status (spinner + latest action)
     */
    renderAnalysisStatus(analysis) {
        if (analysis.status === 'in_progress') {
            return `
                <div class="analysis-status text-gray-400 mt-1">
                    <i class="fas fa-spinner spinner"></i>
                    <span class="text-xs">${escapeHtml(analysis.last_action || 'Analyzing...')}</span>
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
                 data-full-text="${escapeHtml(justification)}">
                ${escapeHtml(justification)}
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
                this.updateCheckboxRowSelection(resultHash);
            });
        });

        // Row click for detail panel selection
        const rows = this.tbody.querySelectorAll('.finding-row');
        rows.forEach(row => {
            row.addEventListener('click', (e) => {
                // Ignore if clicking checkbox
                if (e.target.classList.contains('finding-checkbox') ||
                    e.target.type === 'checkbox' ||
                    e.target.closest('.finding-checkbox')) {
                    return;
                }

                const resultHash = row.dataset.resultHash;

                // Update visual selection
                this.updateDetailPanelRowSelection(resultHash);

                // Dispatch event for detail panel
                window.dispatchEvent(new CustomEvent('finding-selected', {
                    detail: { resultHash }
                }));
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
            // Hide select-all checkbox if there are no analyzable findings
            if (checkboxes.length === 0) {
                this.selectAllCheckbox.style.visibility = 'hidden';
            } else {
                this.selectAllCheckbox.style.visibility = 'visible';
                const allChecked = state.findings.length > 0 &&
                                 state.selectedFindings.length === state.findings.length;
                this.selectAllCheckbox.checked = allChecked;
            }
        }
    }

    /**
     * Update row selection visual state for checkboxes (bulk selection)
     */
    updateCheckboxRowSelection(resultHash) {
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
     * Update row selection visual state for detail panel (viewing selection)
     */
    updateDetailPanelRowSelection(resultHash) {
        // Remove all selected classes
        this.tbody.querySelectorAll('.finding-row').forEach(r => {
            r.classList.remove('selected');
        });

        // Add selected class to current row
        const row = this.tbody.querySelector(`[data-result-hash="${resultHash}"]`);
        if (row) {
            row.classList.add('selected');
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

        // Replace row HTML - use tbody element for correct TR parsing
        const tempTbody = document.createElement('tbody');
        tempTbody.innerHTML = this.renderRow(finding);
        const newRow = tempTbody.firstElementChild;

        // Preserve checkbox state
        const newCheckbox = newRow.querySelector('.finding-checkbox');
        if (newCheckbox) newCheckbox.checked = isChecked;

        // Preserve detail panel selection
        const state = stateManager.getState();
        if (state.selectedFinding === finding.resultHash) {
            newRow.classList.add('selected');
        }

        row.replaceWith(newRow);

        // Re-attach event listeners for this row
        this.attachRowEventListeners();

        // Update select-all checkbox visibility (hide if no analyzable findings remain)
        this.updateCheckboxes();
    }

}

// Initialize findings table
const findingsTable = new FindingsTable();
