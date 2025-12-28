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
            <div class="mb-4">
                <h4 class="font-semibold mb-2">${this.escapeHtml(finding.queryName)}</h4>
                <div class="text-xs text-gray-400">
                    Result: ${analysis.result} (${Math.round(analysis.confidence * 100)}% confidence)
                </div>
            </div>

            <div class="space-y-3">
                ${this.renderConversationLog(analysis.conversation_log)}
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

        return `
            <div class="bg-gray-700 rounded p-3">
                <div class="text-xs text-gray-400 mb-2">
                    <i class="fas fa-robot"></i> Agent (#${index + 1})
                </div>
                ${entry.content ? `
                    <div class="text-sm mb-2 whitespace-pre-wrap">${this.escapeHtml(entry.content)}</div>
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
                <div class="text-xs text-gray-300 font-mono whitespace-pre-wrap overflow-x-auto">
                    ${this.escapeHtml(displayText)}
                </div>
            </div>
        `;
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
