/**
 * Enhanced Analysis Modal Component
 * Shows finding details, analysis steps, and writeback functionality in tabs
 */

class AnalysisModal {
    constructor() {
        // Modal elements
        this.modal = document.getElementById('analysis-modal');
        this.findingHeader = document.getElementById('finding-header-section');
        this.aiAssessment = document.getElementById('ai-assessment-section');
        this.conversationLog = document.getElementById('analysis-conversation-log');
        this.writebackContent = document.getElementById('writeback-form-content');
        this.writebackFooter = document.getElementById('modal-footer-writeback');
        this.writebackSaveBtn = document.getElementById('writeback-save-btn');

        // Tab elements
        this.tabAnalysis = document.getElementById('tab-analysis');
        this.tabWriteback = document.getElementById('tab-writeback');
        this.tabContentAnalysis = document.getElementById('tab-content-analysis');
        this.tabContentWriteback = document.getElementById('tab-content-writeback');

        // Current state
        this.currentFinding = null;
        this.activeTab = 'analysis';

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

        // Tab switching
        this.tabAnalysis?.addEventListener('click', () => this.switchTab('analysis'));
        this.tabWriteback?.addEventListener('click', () => this.switchTab('writeback'));

        // Save button
        this.writebackSaveBtn?.addEventListener('click', () => this.saveWriteback());

        // Listen for view details events (from info icon)
        window.addEventListener('view-finding-details', (e) => {
            this.show(e.detail.resultHash, 'analysis');
        });

        // Listen for writeback events (from upload icon)
        window.addEventListener('writeback-finding', (e) => {
            this.show(e.detail.resultHash, 'writeback');
        });
    }

    /**
     * Show modal for a finding
     * @param {string} resultHash - Finding result hash
     * @param {string} initialTab - Initial tab to show ('analysis' or 'writeback')
     */
    show(resultHash, initialTab = 'analysis') {
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === resultHash);

        if (!finding) {
            alert('Finding not found');
            return;
        }

        // Check if analysis exists for analysis tab
        if (initialTab === 'analysis' && !finding.analysis) {
            alert('No analysis details available');
            return;
        }

        // Check if can writeback
        if (initialTab === 'writeback' && (!finding.analysis || !finding.analysis.result || finding.analysis.result === 'REFUSED')) {
            alert('No analysis result available for writeback');
            return;
        }

        this.currentFinding = finding;
        this.renderFindingHeader(finding);
        this.renderAIAssessment(finding);
        this.renderConversationLog(finding);
        this.renderWritebackForm(finding);

        // Switch to requested tab
        this.switchTab(initialTab);

        this.modal.classList.remove('hidden');
    }

    /**
     * Close modal
     */
    close() {
        this.modal.classList.add('hidden');
        this.currentFinding = null;
        this.switchTab('analysis'); // Reset to analysis tab
    }

    /**
     * Switch between tabs
     * @param {string} tabName - 'analysis' or 'writeback'
     */
    switchTab(tabName) {
        this.activeTab = tabName;

        if (tabName === 'analysis') {
            // Show analysis tab
            this.tabAnalysis?.classList.add('tab-active');
            this.tabAnalysis?.classList.remove('text-gray-400');
            this.tabAnalysis?.classList.add('text-blue-400');
            this.tabAnalysis?.classList.remove('border-transparent');
            this.tabAnalysis?.classList.add('border-blue-500');

            this.tabWriteback?.classList.remove('tab-active');
            this.tabWriteback?.classList.remove('text-blue-400');
            this.tabWriteback?.classList.add('text-gray-400');
            this.tabWriteback?.classList.add('border-transparent');
            this.tabWriteback?.classList.remove('border-blue-500');

            this.tabContentAnalysis?.classList.remove('hidden');
            this.tabContentWriteback?.classList.add('hidden');
            this.writebackFooter?.classList.add('hidden');
        } else if (tabName === 'writeback') {
            // Show writeback tab
            this.tabWriteback?.classList.add('tab-active');
            this.tabWriteback?.classList.remove('text-gray-400');
            this.tabWriteback?.classList.add('text-blue-400');
            this.tabWriteback?.classList.remove('border-transparent');
            this.tabWriteback?.classList.add('border-blue-500');

            this.tabAnalysis?.classList.remove('tab-active');
            this.tabAnalysis?.classList.remove('text-blue-400');
            this.tabAnalysis?.classList.add('text-gray-400');
            this.tabAnalysis?.classList.add('border-transparent');
            this.tabAnalysis?.classList.remove('border-blue-500');

            this.tabContentWriteback?.classList.remove('hidden');
            this.tabContentAnalysis?.classList.add('hidden');
            this.writebackFooter?.classList.remove('hidden');
        }
    }

    /**
     * Render finding header section
     */
    renderFindingHeader(finding) {
        this.findingHeader.innerHTML = `
            <div class="flex items-start justify-between mb-3">
                <h4 class="text-lg font-bold text-white">${this.escapeHtml(finding.queryName)}</h4>
                ${finding.checkmarx_url ? `
                    <a href="${this.escapeHtml(finding.checkmarx_url)}" target="_blank" rel="noopener noreferrer"
                       class="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1">
                        <i class="fas fa-external-link-alt"></i>
                        <span>View in Checkmarx</span>
                    </a>
                ` : ''}
            </div>
            <div class="finding-metadata">
                <div class="metadata-item">
                    <span class="metadata-label">CWE:</span>
                    <span class="metadata-value">CWE-${this.escapeHtml(finding.cweID)}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Query:</span>
                    <span class="metadata-value">${this.escapeHtml(finding.queryName)}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Category:</span>
                    <span class="metadata-value">${this.escapeHtml(finding.category)}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Finding ID:</span>
                    <span class="metadata-value font-mono text-xs">${this.escapeHtml(finding.resultHash.substring(0, 48))}${finding.resultHash.length > 48 ? '...' : ''}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Severity:</span>
                    <span class="font-semibold ${this.getSeverityColor(finding.severity)}">${this.escapeHtml(finding.severity)}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">State:</span>
                    <span class="metadata-value">${this.escapeHtml(finding.state)}</span>
                </div>
            </div>
        `;
    }

    /**
     * Render AI assessment section
     */
    renderAIAssessment(finding) {
        const analysis = finding.analysis;

        if (!analysis || !analysis.result) {
            this.aiAssessment.innerHTML = `
                <div class="text-gray-500 text-center py-4">
                    <i class="fas fa-info-circle mr-2"></i>No analysis available
                </div>
            `;
            return;
        }

        this.aiAssessment.innerHTML = `
            <h5 class="text-md font-semibold text-white mb-3">Agent Assessment</h5>
            <div class="assessment-grid">
                <div class="flex items-center gap-3">
                    <span class="px-3 py-1 rounded ${this.getResultBadgeColor(analysis.result)} font-semibold">
                        ${this.escapeHtml(analysis.result || 'PENDING')}
                    </span>
                </div>
                <div class="flex items-center gap-4 text-sm text-gray-400">
                    <span>
                        Confidence: <span class="text-white font-medium">
                            ${analysis.confidence ? Math.round(analysis.confidence * 100) + '%' : 'N/A'}
                        </span>
                    </span>
                    <span>
                        Analysis steps: <span class="text-white font-medium">${analysis.iterations_used || 0}</span>
                    </span>
                </div>
                ${analysis.justification ? `
                    <div class="justification-box">
                        <div class="text-xs text-gray-400 mb-1 font-semibold">Justification:</div>
                        ${this.escapeHtml(analysis.justification)}
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Render conversation log (Tab 1 content)
     */
    renderConversationLog(finding) {
        const analysis = finding.analysis;

        if (!analysis || !analysis.conversation_log || analysis.conversation_log.length === 0) {
            this.conversationLog.innerHTML = `
                <div class="text-gray-500 text-center py-8">
                    <i class="fas fa-comments mr-2"></i>No conversation log available
                </div>
            `;
            return;
        }

        // Render conversation log
        const conversationHtml = analysis.conversation_log.map((entry, index) => {
            if (entry.type === 'system' || entry.type === 'human') {
                return ''; // Skip
            } else if (entry.type === 'assistant') {
                return this.renderAssistantMessage(entry, index);
            } else if (entry.type === 'tool_result') {
                return this.renderToolResult(entry, index);
            }
            return '';
        }).filter(Boolean).join('');

        this.conversationLog.innerHTML = conversationHtml;
    }

    /**
     * Render writeback form (Tab 2 content)
     */
    renderWritebackForm(finding) {
        const analysis = finding.analysis;

        if (!analysis || !analysis.result || analysis.result === 'REFUSED') {
            this.writebackContent.innerHTML = `
                <div class="text-gray-500 text-center py-8">
                    <i class="fas fa-exclamation-triangle mr-2"></i>
                    No valid analysis result available for writeback
                </div>
            `;
            return;
        }

        // Determine what to pre-fill: saved writeback data or original AI analysis
        let prefilledDecision = analysis.result;
        let prefilledJustification = analysis.justification;

        if (finding.writeback && finding.writeback.saved) {
            // If writeback was saved, use saved data
            if (finding.writeback.user_override) {
                // User override exists, use that
                prefilledDecision = finding.writeback.user_override.decision;
                prefilledJustification = finding.writeback.user_override.justification;
            } else {
                // No override, use saved AI decision
                prefilledDecision = finding.writeback.decision;
                prefilledJustification = finding.writeback.justification;
            }
        }

        this.writebackContent.innerHTML = `
            <!-- Modify Decision Checkbox -->
            <div>
                <label class="flex items-center space-x-2 cursor-pointer">
                    <input type="checkbox" id="challenge-checkbox" class="form-checkbox">
                    <span class="font-medium">Modify Decision</span>
                </label>
                <p class="text-xs text-gray-400 mt-1 ml-6">
                    Check this to challenge the agent's decision
                </p>
            </div>

            <!-- Override Fields (hidden by default) -->
            <div id="override-fields" class="hidden override-fields">
                <div class="space-y-3">
                    <div>
                        <label class="block text-sm font-medium mb-2">Decision</label>
                        <select id="override-decision" class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2">
                            <option value="CONFIRMED" ${prefilledDecision === 'CONFIRMED' ? 'selected' : ''}>CONFIRMED</option>
                            <option value="NOT_EXPLOITABLE" ${prefilledDecision === 'NOT_EXPLOITABLE' ? 'selected' : ''}>NOT_EXPLOITABLE</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-medium mb-2">Justification</label>
                        <textarea id="override-justification"
                                  class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 h-32 resize-none"
                                  placeholder="Provide justification for the decision...">${this.escapeHtml(prefilledJustification)}</textarea>
                    </div>
                </div>
            </div>

            <!-- Info Banner -->
            <div class="info-banner info-blue">
                <i class="fas fa-info-circle"></i>
                <span>This will save the decision to the session file. No write-back to Checkmarx implemented yet.</span>
            </div>
        `;

        // Setup challenge checkbox toggle
        const challengeCheckbox = this.writebackContent.querySelector('#challenge-checkbox');
        const overrideFields = this.writebackContent.querySelector('#override-fields');

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
     * Save writeback decision
     */
    async saveWriteback() {
        if (!this.currentFinding) return;

        const challengeCheckbox = this.writebackContent.querySelector('#challenge-checkbox');
        const isChallenged = challengeCheckbox && challengeCheckbox.checked;

        let userOverride = null;
        if (isChallenged) {
            const decision = this.writebackContent.querySelector('#override-decision')?.value;
            const justification = this.writebackContent.querySelector('#override-justification')?.value;

            // Validate decision value
            if (!decision || !['CONFIRMED', 'NOT_EXPLOITABLE'].includes(decision)) {
                alert('Invalid decision value');
                return;
            }

            // Validate justification
            if (!justification || justification.trim() === '') {
                alert('Please provide justification for your decision');
                return;
            }

            // Validate justification length (max 10000 characters)
            if (justification.length > 10000) {
                alert('Justification is too long (maximum 10000 characters)');
                return;
            }

            userOverride = {
                decision,
                justification: justification.trim()
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
            this.writebackSaveBtn.disabled = true;
            this.writebackSaveBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';

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
            // Don't expose internal error details to user
            alert('Failed to save write-back. Please try again or contact support.');
        } finally {
            this.writebackSaveBtn.disabled = false;
            this.writebackSaveBtn.innerHTML = 'Save Decision';
        }
    }

    // === HELPER RENDERING METHODS ===

    /**
     * Render assistant message
     */
    renderAssistantMessage(entry, index) {
        const hasToolCalls = entry.tool_calls && entry.tool_calls.length > 0;

        // Handle content that might be an array or object (defensive)
        let contentText = '';
        if (entry.content) {
            if (typeof entry.content === 'string') {
                contentText = entry.content;
            } else if (Array.isArray(entry.content)) {
                // Extract text from content blocks
                contentText = entry.content.map(block => {
                    if (typeof block === 'string') {
                        return block;
                    } else if (block && typeof block === 'object') {
                        // Handle content block format: {type: "text", text: "..."}
                        return block.text || block.content || '';
                    }
                    return '';
                }).filter(Boolean).join(' ');
            } else if (typeof entry.content === 'object') {
                // If it's an object, try to extract text field or stringify
                contentText = entry.content.text || entry.content.content ||
                              JSON.stringify(entry.content);
            } else {
                contentText = String(entry.content);
            }
        }

        return `
            <div class="bg-gray-700 rounded p-3">
                <div class="text-xs text-gray-400 mb-2">
                    <i class="fas fa-robot"></i> Agent (#${index + 1})
                </div>
                ${contentText ? `
                    <div class="text-sm mb-2 whitespace-pre-wrap">${this.escapeHtml(contentText)}</div>
                ` : ''}
                ${hasToolCalls ? `
                    <div class="mt-2 flex flex-wrap gap-2">
                        ${entry.tool_calls.map(tc => `
                            <span class="inline-flex items-center gap-1 text-xs bg-gray-800 rounded px-2 py-1">
                                <i class="fas fa-wrench text-blue-400"></i>
                                <span class="font-mono text-blue-300">${this.escapeHtml(tc.name)}</span>
                            </span>
                        `).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Render tool result
     */
    renderToolResult(entry, index) {
        // Special rendering for read_file tool
        if (entry.tool === 'read_file') {
            return this.renderReadFileResult(entry);
        }

        // Special rendering for search_in_files tool
        if (entry.tool === 'search_in_files') {
            return this.renderSearchResult(entry);
        }

        // Special rendering for verify_analysis tool
        if (entry.tool === 'verify_analysis') {
            return this.renderVerifyResult(entry);
        }

        // Default rendering for other tools
        return this.renderDefaultToolResult(entry);
    }

    /**
     * Render read_file tool result with scrollable code view
     */
    renderReadFileResult(entry) {
        let fileName = 'unknown';
        let totalLines = 0;
        let content = '';

        // Try to get filename from args first (works for both success and error cases)
        if (entry.args && entry.args.file_path) {
            fileName = entry.args.file_path;
        }

        if (entry.result && typeof entry.result === 'object') {
            // Override with result.file if available
            if (entry.result.file) {
                fileName = entry.result.file;
            }
            totalLines = entry.result.total_lines || 0;

            // Extract content from array or string
            if (Array.isArray(entry.result.content)) {
                content = entry.result.content.join('\n');
            } else if (typeof entry.result.content === 'string') {
                content = entry.result.content;
            } else if (entry.result.error) {
                content = entry.result.error;
            }
        } else if (typeof entry.result === 'string') {
            content = entry.result;
        }

        return `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex items-center gap-2 text-xs mb-2">
                    <i class="fas fa-file-code text-gray-400"></i>
                    <span class="font-mono text-blue-400">${this.escapeHtml(fileName)}</span>
                    ${totalLines > 0 ? `<span class="text-gray-500">(${totalLines} lines)</span>` : ''}
                </div>
                <div class="bg-gray-900 rounded overflow-hidden">
                    <pre class="text-xs text-gray-300 font-mono p-3 overflow-y-auto" style="max-height: 8rem; line-height: 1.4;"><code>${this.escapeHtml(content)}</code></pre>
                </div>
            </div>
        `;
    }

    /**
     * Render search_in_files tool result
     */
    renderSearchResult(entry) {
        let pattern = '';
        let matchCount = 0;
        let results = [];

        if (entry.result && typeof entry.result === 'object') {
            pattern = entry.result.pattern || entry.args?.pattern || '';
            matchCount = entry.result.matches_found || entry.result.total_matches || 0;
            results = entry.result.results || entry.result.matches || [];
        }

        return `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex items-center gap-2 text-xs text-gray-400 mb-2">
                    <i class="fas fa-search"></i>
                    <span class="font-mono text-green-400">search_in_files</span>
                    <span class="text-gray-500">•</span>
                    <span>Pattern: <code class="text-blue-300">${this.escapeHtml(pattern)}</code></span>
                    <span class="text-gray-500">•</span>
                    <span>${matchCount} matches</span>
                </div>
                ${results.length > 0 ? `
                    <div class="bg-gray-900 rounded p-2 space-y-1 max-h-48 overflow-y-auto">
                        ${results.slice(0, 10).map(match => `
                            <div class="text-xs">
                                <span class="text-gray-400">${this.escapeHtml(match.file)}:${match.line}</span>
                                <code class="ml-2 text-gray-300">${this.escapeHtml(match.content)}</code>
                            </div>
                        `).join('')}
                        ${results.length > 10 ? `
                            <div class="text-xs text-gray-500 italic mt-2">
                                ... and ${results.length - 10} more matches
                            </div>
                        ` : ''}
                    </div>
                ` : `
                    <div class="text-xs text-gray-500 italic">No matches found</div>
                `}
            </div>
        `;
    }

    /**
     * Render verify_analysis tool result
     */
    renderVerifyResult(entry) {
        let status = '';
        let nextStep = '';
        let hasData = false;

        if (entry.result && typeof entry.result === 'object') {
            status = entry.result.status || '';
            nextStep = entry.result.next_step || '';
            hasData = status || nextStep;
        } else if (typeof entry.result === 'string') {
            nextStep = entry.result;
            hasData = true;
        }

        // If no structured data found, show raw result
        if (!hasData && entry.result) {
            return this.renderDefaultToolResult(entry);
        }

        return `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex items-center gap-2 text-xs text-gray-400 mb-2">
                    <i class="fas fa-check-circle"></i>
                    <span class="font-mono text-purple-400">verify_analysis</span>
                </div>
                <div class="bg-gray-900 rounded p-3 space-y-2">
                    ${status ? `
                        <div class="text-xs">
                            <span class="text-gray-400">Status:</span>
                            <span class="ml-2 text-green-400">${this.escapeHtml(status)}</span>
                        </div>
                    ` : ''}
                    ${nextStep ? `
                        <div class="text-xs text-gray-300">
                            ${this.escapeHtml(nextStep)}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    /**
     * Render default tool result (fallback)
     */
    renderDefaultToolResult(entry) {
        let resultText = '';

        if (typeof entry.result === 'string') {
            resultText = entry.result;
        } else if (typeof entry.result === 'object') {
            resultText = JSON.stringify(entry.result, null, 2);
        } else {
            resultText = String(entry.result);
        }

        // Limit to 500 characters for very long results
        const maxLength = 500;
        const truncated = resultText.length > maxLength;
        const displayText = truncated ? resultText.substring(0, maxLength) + '...' : resultText;

        return `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex items-center gap-2 text-xs text-gray-400 mb-2">
                    <i class="fas fa-tools"></i>
                    <span class="font-mono text-green-400">${this.escapeHtml(entry.tool)}</span>
                </div>
                <div class="text-xs text-gray-300 font-mono whitespace-pre-wrap overflow-x-auto bg-gray-900 rounded p-2">
                    ${this.escapeHtml(displayText)}
                </div>
            </div>
        `;
    }

    /**
     * Get color class for severity badge
     */
    getSeverityColor(severity) {
        const colors = {
            'HIGH': 'text-red-400',
            'MEDIUM': 'text-orange-400',
            'LOW': 'text-yellow-400',
            'INFO': 'text-blue-400'
        };
        return colors[severity] || 'text-gray-400';
    }

    /**
     * Get color class for result badge
     */
    getResultBadgeColor(result) {
        const colors = {
            'CONFIRMED': 'bg-red-600 text-white',
            'NOT_EXPLOITABLE': 'bg-green-600 text-white',
            'REFUSED': 'bg-yellow-600 text-white'
        };
        return colors[result] || 'bg-gray-600 text-white';
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

// Initialize analysis modal
const analysisModal = new AnalysisModal();
