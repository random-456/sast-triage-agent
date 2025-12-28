/**
 * Analysis Detail Modal Component
 * Shows analysis conversation log and tool calls
 */

class AnalysisModal {
    constructor() {
        this.modal = document.getElementById('analysis-modal');
        this.content = document.getElementById('analysis-details-content');

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

        // Listen for view details events
        window.addEventListener('view-finding-details', (e) => {
            this.show(e.detail.resultHash);
        });
    }

    /**
     * Show modal for a finding
     */
    show(resultHash) {
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === resultHash);

        if (!finding || !finding.analysis) {
            alert('No analysis details available');
            return;
        }

        this.render(finding);
        this.modal.classList.remove('hidden');
    }

    /**
     * Close modal
     */
    close() {
        this.modal.classList.add('hidden');
    }

    /**
     * Render analysis details
     */
    render(finding) {
        const analysis = finding.analysis;

        if (!analysis.conversation_log || analysis.conversation_log.length === 0) {
            this.content.innerHTML = `
                <div class="text-gray-500 text-center py-8">
                    No conversation log available
                </div>
            `;
            return;
        }

        this.content.innerHTML = `
            <!-- Section 1: Finding Details Header -->
            <div class="bg-gray-800 rounded-lg p-4 mb-4">
                <h4 class="text-lg font-bold mb-3 text-white">${this.escapeHtml(finding.queryName)}</h4>
                <div class="flex flex-wrap items-center gap-x-8 gap-y-2 text-sm">
                    <div class="flex items-center gap-2 whitespace-nowrap">
                        <span class="text-gray-400">Severity:</span>
                        <span class="font-semibold ${this.getSeverityColor(finding.severity)}">${finding.severity}</span>
                        <span class="text-gray-400">(CWE-${finding.cweID})</span>
                    </div>
                    <div class="flex items-center gap-2 whitespace-nowrap">
                        <span class="text-gray-400">Language:</span>
                        <span class="text-white">${finding.languageName}</span>
                    </div>
                </div>
            </div>

            <!-- Section 2: Agent Assessment Verdict -->
            <div class="bg-gray-800 rounded-lg p-4 mb-4">
                <h5 class="text-md font-semibold text-white mb-3">Agent Assessment</h5>
                <div class="flex items-center gap-3 mb-3">
                        <span class="px-3 py-1 rounded ${this.getResultBadgeColor(analysis.result)} font-semibold">
                            ${analysis.result || 'PENDING'}
                        </span>
                        <span class="text-sm text-gray-400">
                            Confidence: <span class="text-white font-medium">
                                ${analysis.confidence ? Math.round(analysis.confidence * 100) + '%' : 'N/A'}
                            </span>
                        </span>
                    </div>
                <div class="mb-3 text-sm">
                    <span class="text-gray-400">Analysis steps:</span>
                    <span class="ml-2 text-white">${analysis.iterations_used || 0}</span>
                </div>
                ${analysis.justification ? `
                    <div class="mt-2 p-3 bg-gray-900 rounded text-sm text-gray-300">
                        ${this.escapeHtml(analysis.justification)}
                    </div>
                ` : ''}
            </div>

            <!-- Section 3: Agent Conversation -->
            <div class="bg-gray-800 rounded-lg p-4">
                <h5 class="text-md font-semibold text-white mb-3">Analysis Steps</h5>
                <div class="space-y-3">
                    ${this.renderConversationLog(analysis.conversation_log)}
                </div>
            </div>
        `;
    }

    /**
     * Render conversation log
     */
    renderConversationLog(log) {
        return log.map((entry, index) => {
            if (entry.type === 'system') {
                return ''; // Skip system messages in modal
            } else if (entry.type === 'human') {
                return ''; // Skip human messages in modal
            } else if (entry.type === 'assistant') {
                return this.renderAssistantMessage(entry, index);
            } else if (entry.type === 'tool_result') {
                return this.renderToolResult(entry, index);
            }
            return '';
        }).filter(Boolean).join('');
    }

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
                    <i class="fas fa-file-code text-gray-400"></i><span class="font-mono text-blue-400">${this.escapeHtml(fileName)}</span>${totalLines > 0 ? ` <span class="text-gray-500">(${totalLines} lines)</span>` : ''}
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
