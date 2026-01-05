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

        // NOTE: Removed 'analysis-conversation-update' event listener
        // Conversation is now updated via state (single source of truth)

        // Listen for live analysis updates (completion handling)
        window.addEventListener('analysis-live-update', (e) => {
            this.updateLive(e.detail);
        });

        // Listen for state changes (finding updates)
        // This is the SINGLE SOURCE OF TRUTH for conversation updates
        this.unsubscribeState = stateManager.subscribe(() => {
            if (this.currentFindingHash) {
                const state = stateManager.getState();
                const finding = state.findings.find(f => f.resultHash === this.currentFindingHash);
                if (finding) {
                    this.refreshCurrentFinding(finding);
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
     * Agent bubble shows ONLY reasoning text - no tool badges
     * @param {Object} entry - Log entry
     * @returns {string} HTML string
     */
    renderAgentMessage(entry) {
        return `
            <div class="message-agent">
                <div class="message-header">
                    <i class="fas fa-robot"></i> Agent
                </div>
                <div class="message-content">
                    ${escapeHtml(entry.content || '')}
                </div>
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
     * Routes to specific formatters that show args + result
     * @param {Object} entry - Tool result entry
     * @returns {string} Formatted HTML
     */
    formatToolResult(entry) {
        const tool = entry.tool;
        const content = entry.content;
        const args = entry.args || {};

        // Handle missing content
        if (!content) {
            return '<div class="text-xs text-gray-400">No result data</div>';
        }

        // Handle error results
        if (content.type === 'error') {
            return this.formatErrorResult(content);
        }

        // Route to specific formatters
        switch (tool) {
            case 'read_file':
                return this.formatReadFileResult(content, args);
            case 'search_in_files':
                return this.formatSearchResult(content, args);
            case 'list_directory':
                return this.formatListDirectoryResult(content, args);
            case 'verify_analysis':
                return this.formatVerifyResult(content, args);
            case 'submit_triage_decision':
                return this.formatDecisionResult(content, args);
            default:
                return this.formatDefaultResult(content);
        }
    }

    /**
     * Format read_file tool result - Show file path (clickable) + line count
     * @param {Object} content - Tool result with file and total_lines
     * @param {Object} args - Tool arguments with file_path
     * @returns {string} HTML
     */
    formatReadFileResult(content, args) {
        const file = content.file || (args && args.file_path) || 'unknown';
        const totalLines = content.total_lines || 0;

        // Get repo URL from session metadata for clickable link
        const state = stateManager.getState();
        const repoUrl = state.currentSession?.metadata?.github_url;

        let fileDisplay;
        if (repoUrl) {
            const cleanFile = file.replace(/^\//, '');
            const fileUrl = `${repoUrl}/blob/main/${cleanFile}`;
            fileDisplay = `<a href="${fileUrl}" target="_blank" rel="noopener" class="tool-file-link">${escapeHtml(file)}</a>`;
        } else {
            fileDisplay = `<span class="tool-file-path">${escapeHtml(file)}</span>`;
        }

        return `
            <div class="tool-read-file">
                <div class="tool-input">
                    <i class="fas fa-file-code"></i>
                    ${fileDisplay}
                </div>
                <div class="tool-output">
                    <i class="fas fa-check text-green-400"></i>
                    <span>${totalLines} lines read</span>
                </div>
            </div>
        `;
    }

    /**
     * Format search_in_files result - Show pattern + extension + matches
     * @param {Object} content - Tool result with pattern, file_extension, matches_found, results
     * @param {Object} args - Tool arguments
     * @returns {string} HTML
     */
    formatSearchResult(content, args) {
        const pattern = content.pattern || (args && args.pattern) || '';
        const fileExt = content.file_extension || (args && args.file_extension) || '*';
        const matchesFound = content.matches_found || 0;
        const results = content.results || [];

        // Show first few matches
        const matchList = results.slice(0, 5).map(r =>
            `<div class="search-match"><code>${escapeHtml(r.file)}:${r.line}</code></div>`
        ).join('');

        const moreText = results.length > 5
            ? `<div class="search-more">+${results.length - 5} more matches</div>`
            : '';

        return `
            <div class="tool-search">
                <div class="tool-input">
                    <span class="search-label">Pattern:</span> <code>${escapeHtml(pattern)}</code>
                    <span class="search-sep">|</span>
                    <span class="search-label">Files:</span> <code>*.${escapeHtml(fileExt)}</code>
                </div>
                <div class="tool-output">
                    <div class="search-count">${matchesFound} matches found</div>
                    ${matchList ? `<div class="search-results">${matchList}${moreText}</div>` : ''}
                </div>
            </div>
        `;
    }

    /**
     * Format verify_analysis result - Show investigation summary, evidence, assessment, gaps
     * @param {Object} content - Tool result with verification details
     * @param {Object} args - Tool arguments (contains the actual useful info)
     * @returns {string} HTML
     */
    formatVerifyResult(content, args) {
        // The useful info is in the content (passed from backend which gets it from args)
        const summary = content.investigation_summary || (args && args.investigation_summary) || '';
        const evidence = content.key_evidence || (args && args.key_evidence) || '';
        const assessment = content.preliminary_assessment || (args && args.preliminary_assessment) || '';
        const gaps = content.potential_gaps || (args && args.potential_gaps) || '';

        return `
            <div class="tool-verify">
                <div class="verify-header">
                    <i class="fas fa-clipboard-check text-green-400"></i>
                    <span>Analysis Verified</span>
                </div>
                <div class="verify-details">
                    ${summary ? `<div class="verify-row"><span class="verify-label">Summary:</span> ${escapeHtml(summary.substring(0, 150))}${summary.length > 150 ? '...' : ''}</div>` : ''}
                    ${evidence ? `<div class="verify-row"><span class="verify-label">Evidence:</span> ${escapeHtml(evidence.substring(0, 150))}${evidence.length > 150 ? '...' : ''}</div>` : ''}
                    ${assessment ? `<div class="verify-row"><span class="verify-label">Assessment:</span> <strong>${escapeHtml(assessment)}</strong></div>` : ''}
                    ${gaps ? `<div class="verify-row"><span class="verify-label">Gaps:</span> ${escapeHtml(gaps.substring(0, 100))}${gaps.length > 100 ? '...' : ''}</div>` : ''}
                </div>
            </div>
        `;
    }

    /**
     * Format list_directory result - Show path + items
     * @param {Object} content - Tool result with directory, total_items, items
     * @param {Object} args - Tool arguments
     * @returns {string} HTML
     */
    formatListDirectoryResult(content, args) {
        const directory = content.directory || (args && args.directory_path) || '.';
        const items = content.items || [];
        const totalItems = content.total_items || items.length;

        const itemList = items.slice(0, 8).map(item => {
            const icon = item.type === 'directory' ? 'fa-folder text-yellow-400' : 'fa-file text-gray-400';
            return `<span class="dir-item"><i class="fas ${icon}"></i> ${escapeHtml(item.name)}</span>`;
        }).join('');

        const moreText = items.length > 8 ? `<span class="dir-more">+${items.length - 8} more</span>` : '';

        return `
            <div class="tool-directory">
                <div class="tool-input">
                    <i class="fas fa-folder-open"></i>
                    <span>${escapeHtml(directory)}</span>
                </div>
                <div class="tool-output">
                    <div class="dir-count">${totalItems} items</div>
                    <div class="dir-items">${itemList}${moreText}</div>
                </div>
            </div>
        `;
    }

    /**
     * Format submit_triage_decision result - Show decision, confidence %, justification
     * @param {Object} content - Tool result with assessment_result, confidence
     * @param {Object} args - Tool arguments with is_exploitable, confidence, justification
     * @returns {string} HTML
     */
    formatDecisionResult(content, args) {
        // Get from content (tool result) or args (what agent passed)
        const isExploitable = args && args.is_exploitable;
        const decision = content.assessment_result || (isExploitable ? 'CONFIRMED' : 'NOT_EXPLOITABLE');
        const confidence = content.confidence || (args && args.confidence) || 0;
        const justification = content.justification || (args && args.justification) || '';

        const confidencePercent = Math.round(confidence * 100);
        const decisionClass = decision === 'CONFIRMED' ? 'text-red-400' : 'text-green-400';

        return `
            <div class="tool-decision">
                <div class="decision-header">
                    <i class="fas fa-gavel"></i>
                    <span class="decision-result ${decisionClass}">${escapeHtml(decision)}</span>
                    <span class="decision-confidence">(${confidencePercent}% confidence)</span>
                </div>
                ${justification ? `<div class="decision-justification">${escapeHtml(justification.substring(0, 300))}${justification.length > 300 ? '...' : ''}</div>` : ''}
            </div>
        `;
    }

    /**
     * Format error result - Handle errors gracefully
     * @param {Object} content - Error content with error message
     * @returns {string} HTML
     */
    formatErrorResult(content) {
        return `
            <div class="tool-error">
                <i class="fas fa-exclamation-triangle text-red-400"></i>
                <span>${escapeHtml(content.error || 'Unknown error')}</span>
            </div>
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
     * Uses incremental updates to avoid re-rendering entire conversation
     * @param {Object} finding - Finding object from state
     */
    refreshCurrentFinding(finding) {
        if (!this.currentFindingHash || !finding) return;

        // Always refresh result section
        this.renderResult(finding);

        // Handle conversation updates
        if (finding.analysis) {
            let conversationLog = document.getElementById('conversation-log');

            // If conversation container doesn't exist, create it
            if (!conversationLog) {
                const tabDiv = document.getElementById('tab-analysis');
                if (tabDiv) {
                    tabDiv.innerHTML = `<div class="conversation-log" id="conversation-log"></div>`;
                    conversationLog = document.getElementById('conversation-log');
                }
            }

            // Incrementally append only NEW conversation entries
            if (conversationLog && finding.analysis.conversation_log) {
                const entries = finding.analysis.conversation_log;
                const currentCount = conversationLog.children.length;
                const newCount = entries.length;

                // Only render entries we haven't rendered yet
                for (let i = currentCount; i < newCount; i++) {
                    const entry = entries[i];
                    let entryHTML = '';

                    if (entry.type === 'assistant') {
                        entryHTML = this.renderAgentMessage(entry);
                    } else if (entry.type === 'tool_result') {
                        entryHTML = this.renderToolMessage(entry);
                    }

                    if (entryHTML) {
                        conversationLog.insertAdjacentHTML('beforeend', entryHTML);
                    }
                }

                // Auto-scroll to bottom if new entries were added
                if (newCount > currentCount) {
                    conversationLog.scrollTop = conversationLog.scrollHeight;
                }
            }
        }
    }
}

// Initialize detail panel
const detailPanel = new DetailPanel();
