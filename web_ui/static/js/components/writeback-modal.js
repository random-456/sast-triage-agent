/**
 * Write-back Modal Component
 * Shows write-back confirmation and challenge functionality
 */

class WritebackModal {
    constructor() {
        this.modal = document.getElementById('writeback-modal');
        this.content = document.getElementById('writeback-content');
        this.saveBtn = document.getElementById('writeback-save');
        this.currentFinding = null;

        this.setupEventListeners();
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Close button
        const closeBtn = this.modal.querySelector('.modal-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.close());
        }

        // Click outside modal to close
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.close();
            }
        });

        // Save button
        if (this.saveBtn) {
            this.saveBtn.addEventListener('click', () => this.save());
        }

        // Listen for writeback events
        window.addEventListener('writeback-finding', (e) => {
            this.show(e.detail.resultHash);
        });
    }

    /**
     * Show modal for a finding
     */
    show(resultHash) {
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === resultHash);

        if (!finding || !finding.analysis || !finding.analysis.result) {
            alert('No analysis result available');
            return;
        }

        this.currentFinding = finding;
        this.render(finding);
        this.modal.classList.remove('hidden');
    }

    /**
     * Close modal
     */
    close() {
        this.modal.classList.add('hidden');
        this.currentFinding = null;
    }

    /**
     * Render write-back content
     */
    render(finding) {
        const analysis = finding.analysis;

        this.content.innerHTML = `
            <div class="space-y-4">
                <!-- Finding Info -->
                <div class="bg-gray-700 rounded p-3">
                    <div class="font-semibold mb-1">${this.escapeHtml(finding.queryName)}</div>
                    <div class="text-xs text-gray-400">
                        ${finding.severity} | ${finding.cweID}
                    </div>
                </div>

                <!-- Agent Decision -->
                <div>
                    <label class="block text-sm font-medium mb-2">Agent Decision</label>
                    <div class="bg-gray-700 rounded p-3">
                        <div class="text-lg font-semibold ${analysis.result === 'CONFIRMED' ? 'text-red-400' : 'text-green-400'}">
                            ${analysis.result}
                        </div>
                        <div class="text-xs text-gray-400 mt-1">
                            Confidence: ${Math.round(analysis.confidence * 100)}%
                        </div>
                    </div>
                </div>

                <!-- Agent Justification -->
                <div>
                    <label class="block text-sm font-medium mb-2">Agent Justification</label>
                    <div class="bg-gray-700 rounded p-3 text-xs max-h-40 overflow-y-auto">
                        ${this.escapeHtml(analysis.justification)}
                    </div>
                </div>

                <!-- Challenge Checkbox -->
                <div class="border-t border-gray-600 pt-4">
                    <label class="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" id="challenge-checkbox" class="form-checkbox">
                        <span class="font-medium">Challenge AI Decision</span>
                    </label>
                    <p class="text-xs text-gray-400 mt-1">
                        Check this if you disagree with the AI assessment
                    </p>
                </div>

                <!-- Override Fields (hidden by default) -->
                <div id="override-fields" class="hidden space-y-3 border-t border-gray-600 pt-4">
                    <div>
                        <label class="block text-sm font-medium mb-2">Your Decision</label>
                        <select id="override-decision" class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2">
                            <option value="CONFIRMED">CONFIRMED</option>
                            <option value="NOT_EXPLOITABLE">NOT_EXPLOITABLE</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-medium mb-2">Your Justification</label>
                        <textarea id="override-justification"
                                  class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 h-24 resize-none"
                                  placeholder="Explain why you disagree with the AI assessment..."></textarea>
                    </div>
                </div>

                <!-- Info Message -->
                <div class="bg-blue-900 bg-opacity-30 border border-blue-700 rounded p-3 text-xs text-blue-300">
                    <i class="fas fa-info-circle"></i>
                    This will save the decision to the session file. Actual write-back to Checkmarx will be implemented in a future phase.
                </div>
            </div>
        `;

        // Setup challenge checkbox toggle
        const challengeCheckbox = this.content.querySelector('#challenge-checkbox');
        const overrideFields = this.content.querySelector('#override-fields');

        if (challengeCheckbox && overrideFields) {
            challengeCheckbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    overrideFields.classList.remove('hidden');
                } else {
                    overrideFields.classList.add('hidden');
                }
            });
        }
    }

    /**
     * Save write-back decision
     */
    async save() {
        if (!this.currentFinding) return;

        const challengeCheckbox = this.content.querySelector('#challenge-checkbox');
        const isChallenged = challengeCheckbox && challengeCheckbox.checked;

        let userOverride = null;
        if (isChallenged) {
            const decision = this.content.querySelector('#override-decision')?.value;
            const justification = this.content.querySelector('#override-justification')?.value;

            if (!justification || justification.trim() === '') {
                alert('Please provide justification for your decision');
                return;
            }

            userOverride = {
                decision,
                justification
            };
        }

        const payload = {
            session_id: stateManager.getState().currentSession.session_id,
            finding_hash: this.currentFinding.resultHash,
            decision: this.currentFinding.analysis.result,
            justification: this.currentFinding.analysis.justification,
            user_override: userOverride
        };

        try {
            this.saveBtn.disabled = true;
            this.saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';

            const response = await fetch('/api/writeback/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to save write-back');
            }

            // Success
            alert('Write-back decision saved successfully!');
            this.close();

            // Reload session to get updated data
            sidebar.loadSession(stateManager.getState().currentSession.session_id);

        } catch (error) {
            console.error('Error saving write-back:', error);
            alert(`Failed to save write-back: ${error.message}`);
        } finally {
            this.saveBtn.disabled = false;
            this.saveBtn.innerHTML = 'Save Decision';
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Initialize writeback modal
const writebackModal = new WritebackModal();
