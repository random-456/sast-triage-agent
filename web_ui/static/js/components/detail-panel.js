/**
 * Detail Panel Component
 * Displays finding details in persistent right panel
 */
class DetailPanel {
    constructor() {
        // DOM elements
        this.panel = document.getElementById('detail-panel');
        this.currentFindingHash = null;
        this.activeTab = 'analysis';
        this.unsubscribeState = null;

        this.setupEventListeners();
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Listen for finding selection
        window.addEventListener('finding-selected', (e) => {
            this.showFinding(e.detail.resultHash);
        });

        // Listen for real-time conversation updates (new event)
        window.addEventListener('analysis-conversation-update', (e) => {
            this.appendConversationEntry(e.detail);
        });

        // Listen for live analysis updates (completion handling)
        window.addEventListener('analysis-live-update', (e) => {
            this.updateLive(e.detail);
        });

        // Listen for state changes (finding updates)
        // Store unsubscribe function for potential cleanup
        this.unsubscribeState = stateManager.subscribe(() => {
            // Re-render if current finding was updated
            if (this.currentFindingHash) {
                const state = stateManager.getState();
                const finding = state.findings.find(f => f.resultHash === this.currentFindingHash);
                if (finding) {
                    this.refreshCurrentFinding();
                }
            }
        });
    }

    /**
     * Show finding details
     * @param {string} resultHash - Finding identifier
     */
    showFinding(resultHash) {
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === resultHash);

        if (!finding) {
            this.renderEmptyState();
            return;
        }

        this.currentFindingHash = resultHash;
        this.panel.classList.remove('empty');

        // Render panel structure
        this.renderPanelStructure(finding);
    }

    /**
     * Render empty state
     */
    renderEmptyState() {
        this.currentFindingHash = null;
        this.panel.classList.add('empty');
        this.panel.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-chart-pie empty-state-icon"></i>
                <div class="empty-state-text">
                    Select a finding to view details and analysis
                </div>
            </div>
        `;
    }

    /**
     * Render full panel structure
     * @param {Object} finding - Finding object
     */
    renderPanelStructure(finding) {
        this.panel.innerHTML = `
            <div class="detail-header">
                <div class="detail-title" id="detail-title"></div>
                <div class="detail-subtitle" id="detail-subtitle"></div>
                <div class="detail-tags" id="detail-tags"></div>
            </div>

            <div class="detail-result" id="detail-result"></div>

            <div class="detail-tabs">
                <button class="tab-btn tab-active" data-tab="analysis">
                    <i class="fas fa-list-ul mr-2"></i>Analysis Steps
                </button>
                <button class="tab-btn" data-tab="writeback">
                    <i class="fas fa-upload mr-2"></i>Write-back
                </button>
            </div>

            <div class="detail-content">
                <div id="tab-analysis" class="tab-pane active"></div>
                <div id="tab-writeback" class="tab-pane"></div>
            </div>
        `;

        // Attach tab click handlers
        this.panel.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.switchTab(btn.dataset.tab);
            });
        });

        // Render sections
        this.renderHeader(finding);
        this.renderResult(finding);
        this.renderAnalysisTab(finding);
        this.renderWritebackTab(finding);
    }

    /**
     * Switch tabs
     * @param {string} tabName - 'analysis' or 'writeback'
     */
    switchTab(tabName) {
        this.activeTab = tabName;

        // Update tab buttons
        this.panel.querySelectorAll('.tab-btn').forEach(btn => {
            if (btn.dataset.tab === tabName) {
                btn.classList.add('tab-active');
            } else {
                btn.classList.remove('tab-active');
            }
        });

        // Update tab panes
        this.panel.querySelectorAll('.tab-pane').forEach(pane => {
            if (pane.id === `tab-${tabName}`) {
                pane.classList.add('active');
            } else {
                pane.classList.remove('active');
            }
        });
    }

    /**
     * Render header section
     * @param {Object} finding - Finding object
     */
    renderHeader(finding) {
        const title = document.getElementById('detail-title');
        const subtitle = document.getElementById('detail-subtitle');
        const tags = document.getElementById('detail-tags');

        title.textContent = finding.queryName;

        // Show finding ID in small text
        const shortHash = finding.resultHash.substring(0, 50);
        subtitle.textContent = `${shortHash}...`;

        // Render tags
        const severityClass = finding.severity.toLowerCase();
        const stateFormatted = finding.state.replace(/_/g, ' ');

        tags.innerHTML = `
            <span class="badge badge-${finding.severity}">${finding.severity}</span>
            <span class="state-badge state-${finding.state}">${stateFormatted}</span>
            <span class="badge badge-INFO">CWE-${finding.cweID || 'N/A'}</span>
        `;
    }

    /**
     * Render result section (always visible)
     * @param {Object} finding - Finding object
     */
    renderResult(finding) {
        const resultDiv = document.getElementById('detail-result');
        const analysis = finding.analysis;

        if (!analysis || !analysis.result) {
            resultDiv.innerHTML = `
                <div class="empty-state-text">
                    Not analyzed yet. Select this finding and run analysis.
                </div>
            `;
            return;
        }

        const result = analysis.result;
        const resultClass = result === 'CONFIRMED' ? 'confirmed' :
                          result === 'NOT_EXPLOITABLE' ? 'not-exploitable' : 'refused';

        const confidence = Math.round((analysis.confidence || 0) * 100);
        const justification = analysis.justification || 'No justification provided';

        resultDiv.innerHTML = `
            <div class="result-badge ${resultClass}">
                ${result.replace(/_/g, ' ')}
            </div>

            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidence}%"></div>
            </div>
            <div class="confidence-text">${confidence}% confidence</div>

            <div class="justification-text">
                ${escapeHtml(justification)}
            </div>
        `;
    }

    /**
     * Render analysis tab (conversation log)
     * @param {Object} finding - Finding object
     */
    renderAnalysisTab(finding) {
        const tabDiv = document.getElementById('tab-analysis');
        const analysis = finding.analysis;

        // If analysis is in progress, show empty conversation (will be populated in real-time)
        if (analysis && analysis.status === 'in_progress') {
            tabDiv.innerHTML = `<div class="conversation-log" id="conversation-log"></div>`;
            return;
        }

        // If analysis is complete and conversation_log exists, render it
        if (analysis && analysis.conversation_log && analysis.conversation_log.length > 0) {
            const conversationHTML = this.renderConversation(analysis.conversation_log);
            tabDiv.innerHTML = `<div class="conversation-log" id="conversation-log">${conversationHTML}</div>`;
            return;
        }

        // Otherwise show empty state
        tabDiv.innerHTML = `
            <div class="empty-state-text">
                No conversation log available
            </div>
        `;
    }

    /**
     * Render conversation log as chat bubbles
     * @param {Array} conversationLog - Array of log entries
     * @returns {string} HTML string
     */
    renderConversation(conversationLog) {
        return conversationLog
            .filter(entry => entry.type === 'assistant' || entry.type === 'tool_result')
            .map(entry => {
                if (entry.type === 'assistant') {
                    return this.renderAgentMessage(entry);
                } else {
                    return this.renderToolMessage(entry);
                }
            })
            .join('');
    }

    /**
     * Render agent message bubble
     * @param {Object} entry - Log entry
     * @returns {string} HTML string
     */
    renderAgentMessage(entry) {
        const toolCallsHTML = entry.tool_calls ? entry.tool_calls.map(tc =>
            `<span class="tool-badge"><i class="fas fa-wrench"></i> ${escapeHtml(tc.name)}</span>`
        ).join('') : '';

        return `
            <div class="message-agent">
                <div class="message-header">
                    <i class="fas fa-robot"></i> Agent
                </div>
                <div class="message-content">
                    ${escapeHtml(entry.content)}
                </div>
                ${toolCallsHTML ? `<div class="mt-2">${toolCallsHTML}</div>` : ''}
            </div>
        `;
    }

    /**
     * Render tool result message bubble
     * @param {Object} entry - Log entry
     * @returns {string} HTML string
     */
    renderToolMessage(entry) {
        const toolName = entry.tool || 'Tool';
        const formattedResult = this.formatToolResult(entry);

        return `
            <div class="message-tool">
                <div class="message-header">
                    <i class="fas fa-wrench"></i> ${toolName}
                </div>
                <div class="message-content">
                    ${formattedResult}
                </div>
            </div>
        `;
    }

    /**
     * Format tool result based on tool type
     * @param {Object} entry - Tool result entry
     * @returns {string} Formatted HTML
     */
    formatToolResult(entry) {
        const tool = entry.tool;
        const content = entry.content;

        // Handle missing content
        if (!content) {
            return '<div class="text-xs text-gray-400">No result data</div>';
        }

        // Specialized formatting for known tools
        if (tool === 'read_file') {
            return this.formatReadFileResult(content);
        } else if (tool === 'search_in_files') {
            return this.formatSearchResult(content);
        } else if (tool === 'verify_analysis') {
            return this.formatVerifyResult(content);
        } else {
            // Default formatting
            return this.formatDefaultResult(content);
        }
    }

    /**
     * Format read_file tool result
     * @param {Object|string} content - Tool result
     * @returns {string} HTML
     */
    formatReadFileResult(content) {
        if (typeof content === 'string') {
            return `<pre class="tool-code">${escapeHtml(content.substring(0, 500))}</pre>`;
        }

        const filepath = content.filepath || 'unknown file';
        const codeSnippet = content.content ? content.content.substring(0, 500) : '';
        const totalLines = content.total_lines || '?';

        return `
            <div class="text-xs mb-2"><i class="fas fa-file-code"></i> ${escapeHtml(filepath)}</div>
            <pre class="tool-code">${escapeHtml(codeSnippet)}</pre>
            <div class="text-xs mt-2 text-gray-500">${totalLines} lines total</div>
        `;
    }

    /**
     * Format search_in_files result
     * @param {Object|string} content - Tool result
     * @returns {string} HTML
     */
    formatSearchResult(content) {
        if (typeof content === 'string') {
            return escapeHtml(content);
        }

        const pattern = content.pattern || '';
        const matches = content.matches || [];
        const displayMatches = matches.slice(0, 10);
        const hasMore = matches.length > 10;

        return `
            <div class="text-xs mb-2">Pattern: <code>${escapeHtml(pattern)}</code></div>
            <div class="text-xs mb-2">${matches.length} matches found</div>
            <div class="tool-code">
                ${displayMatches.map(m => `${escapeHtml(m.file)}:${m.line}`).join('<br>')}
                ${hasMore ? `<br>...and ${matches.length - 10} more` : ''}
            </div>
        `;
    }

    /**
     * Format verify_analysis result
     * @param {Object|string} content - Tool result
     * @returns {string} HTML
     */
    formatVerifyResult(content) {
        if (typeof content === 'string') {
            return escapeHtml(content);
        }

        const status = content.status || 'unknown';
        const nextStep = content.next_step || 'N/A';

        return `
            <div class="mb-2"><strong>Status:</strong> ${escapeHtml(status)}</div>
            <div><strong>Next Step:</strong> ${escapeHtml(nextStep)}</div>
        `;
    }

    /**
     * Format default tool result
     * @param {*} content - Tool result
     * @returns {string} HTML
     */
    formatDefaultResult(content) {
        let display;

        if (typeof content === 'string') {
            display = content.substring(0, 500);
        } else if (typeof content === 'object') {
            display = JSON.stringify(content, null, 2).substring(0, 500);
        } else {
            display = String(content);
        }

        return `<pre class="tool-code">${escapeHtml(display)}</pre>`;
    }

    /**
     * Render writeback tab (form)
     * @param {Object} finding - Finding object
     */
    renderWritebackTab(finding) {
        const tabDiv = document.getElementById('tab-writeback');
        const analysis = finding.analysis;

        if (!analysis || !analysis.result || analysis.result === 'REFUSED') {
            tabDiv.innerHTML = `
                <div class="empty-state-text">
                    Write-back not available for this finding
                </div>
            `;
            return;
        }

        // Pre-fill form with saved data or original analysis
        const savedWriteback = finding.writeback?.user_override;
        const decision = savedWriteback?.decision || analysis.result;
        const justification = savedWriteback?.justification || analysis.justification;
        const isChallenged = !!savedWriteback;

        tabDiv.innerHTML = `
            <div class="space-y-4">
                <!-- AI Result Display -->
                <div class="bg-gray-700 rounded p-4">
                    <div class="text-sm font-semibold mb-2">AI Decision</div>
                    <div class="flex items-center gap-2 mb-2">
                        <span class="badge badge-${analysis.result}">${analysis.result}</span>
                        <span class="text-xs text-gray-400">${Math.round(analysis.confidence * 100)}% confidence</span>
                    </div>
                    <div class="text-xs text-gray-400">${escapeHtml(analysis.justification)}</div>
                </div>

                <!-- Challenge Checkbox -->
                <div>
                    <label class="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" id="challenge-checkbox" ${isChallenged ? 'checked' : ''}>
                        <span class="text-sm font-medium">Modify Decision</span>
                    </label>
                </div>

                <!-- Override Fields -->
                <div id="override-fields" class="space-y-3 bg-gray-700 rounded p-4 ${isChallenged ? '' : 'hidden'}">
                    <div>
                        <label class="block text-sm font-medium mb-2">Decision</label>
                        <select id="override-decision" class="w-full bg-gray-600 border border-gray-500 rounded px-3 py-2">
                            <option value="CONFIRMED" ${decision === 'CONFIRMED' ? 'selected' : ''}>CONFIRMED</option>
                            <option value="NOT_EXPLOITABLE" ${decision === 'NOT_EXPLOITABLE' ? 'selected' : ''}>NOT_EXPLOITABLE</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-2">Justification</label>
                        <textarea id="override-justification"
                                  class="w-full bg-gray-600 border border-gray-500 rounded px-3 py-2 h-32"
                                  placeholder="Provide justification for the decision...">${escapeHtml(justification)}</textarea>
                    </div>
                </div>

                <!-- Info Banner -->
                <div class="info-banner info-blue">
                    <i class="fas fa-info-circle"></i>
                    <span class="text-xs">This will save the decision to the session file. No write-back to Checkmarx implemented yet.</span>
                </div>

                <!-- Save Button -->
                <div>
                    <button id="writeback-save-btn" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded">
                        Save Decision
                    </button>
                </div>
            </div>
        `;

        // Attach event listeners
        const challengeCheckbox = document.getElementById('challenge-checkbox');
        const overrideFields = document.getElementById('override-fields');
        const saveBtn = document.getElementById('writeback-save-btn');

        challengeCheckbox.addEventListener('change', () => {
            if (challengeCheckbox.checked) {
                overrideFields.classList.remove('hidden');
            } else {
                overrideFields.classList.add('hidden');
            }
        });

        saveBtn.addEventListener('click', () => {
            this.saveWriteback(finding);
        });
    }

    /**
     * Save writeback decision
     * @param {Object} finding - Finding object
     */
    async saveWriteback(finding) {
        const challengeCheckbox = document.getElementById('challenge-checkbox');
        const decision = document.getElementById('override-decision')?.value;
        const justification = document.getElementById('override-justification')?.value;

        // Validation
        if (challengeCheckbox.checked) {
            if (!decision || !justification || justification.trim().length === 0) {
                alert('Please provide both a decision and justification');
                return;
            }
            if (justification.length > 10000) {
                alert('Justification too long (max 10,000 characters)');
                return;
            }
        }

        // Prepare payload
        const payload = {
            session_id: stateManager.getState().currentSession.session_id,
            finding_hash: finding.resultHash,
            decision: finding.analysis.result,
            justification: finding.analysis.justification,
            user_override: challengeCheckbox.checked ? {
                decision: decision,
                justification: justification
            } : null
        };

        // Show loading
        const saveBtn = document.getElementById('writeback-save-btn');
        const originalText = saveBtn.innerHTML;
        saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';
        saveBtn.disabled = true;

        try {
            const response = await fetch('/api/writeback/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error('Save failed');
            }

            alert('Decision saved successfully');

            // Reload session to get updated data
            const sessionId = stateManager.getState().currentSession.session_id;
            const sessionResponse = await fetch(`/api/sessions/${sessionId}`);
            const session = await sessionResponse.json();
            stateManager.setCurrentSession(session);
            stateManager.setFindings(session.findings);

        } catch (error) {
            console.error('Error saving writeback:', error);
            alert('Failed to save decision');
        } finally {
            saveBtn.innerHTML = originalText;
            saveBtn.disabled = false;
        }
    }

    /**
     * Update live during analysis
     * @param {Object} message - WebSocket message
     */
    updateLive(message) {
        // Only update if this is the selected finding
        if (message.finding_hash !== this.currentFindingHash) {
            return;
        }

        // Get updated finding from state
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === message.finding_hash);

        if (!finding) return;

        // Update result section (for status, confidence, justification)
        this.renderResult(finding);

        // Handle completion - render write-back tab
        if (message.type === 'complete') {
            this.renderWritebackTab(finding);
        }
    }

    /**
     * Append conversation entry in real-time (agent message or tool result)
     * @param {Object} detail - Event detail with type, finding_hash, and entry
     */
    appendConversationEntry(detail) {
        // Only update if this is the selected finding
        if (detail.finding_hash !== this.currentFindingHash) {
            return;
        }

        // Only append if on analysis tab
        if (this.activeTab !== 'analysis') {
            return;
        }

        const conversationLog = document.getElementById('conversation-log');
        if (!conversationLog) {
            console.warn('[DetailPanel] conversation-log div not found - cannot append entry');
            return;
        }

        let entryHTML = '';

        if (detail.entry.type === 'assistant') {
            // Render agent message bubble
            entryHTML = this.renderAgentMessage(detail.entry);
        } else if (detail.entry.type === 'tool_result') {
            // Render tool result bubble
            entryHTML = this.renderToolMessage(detail.entry);
        }

        if (entryHTML) {
            conversationLog.insertAdjacentHTML('beforeend', entryHTML);
            conversationLog.scrollTop = conversationLog.scrollHeight;
        }
    }

    /**
     * Refresh current finding (called on state change)
     */
    refreshCurrentFinding() {
        if (!this.currentFindingHash) return;

        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === this.currentFindingHash);

        if (finding) {
            // Always refresh result section
            this.renderResult(finding);

            // If analysis just started, ensure conversation-log div exists
            if (finding.analysis?.status === 'in_progress') {
                const conversationLog = document.getElementById('conversation-log');
                if (!conversationLog) {
                    // Create the empty conversation container
                    this.renderAnalysisTab(finding);
                }
            }
        }
    }
}

// Initialize detail panel
const detailPanel = new DetailPanel();
