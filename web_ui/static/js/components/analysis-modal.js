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
                <div class="text-xs text-gray-400 mb-1">
                    <i class="fas fa-robot"></i> Agent (#${index + 1})
                </div>
                ${entry.content ? `
                    <div class="text-xs mb-2">${this.escapeHtml(entry.content).substring(0, 200)}...</div>
                ` : ''}
                ${hasToolCalls ? `
                    <div class="mt-2">
                        <div class="text-xs text-gray-400 mb-1">Tool Calls:</div>
                        ${entry.tool_calls.map(tc => `
                            <div class="text-xs bg-gray-800 rounded px-2 py-1 mb-1">
                                <i class="fas fa-wrench text-blue-400"></i>
                                <span class="font-mono">${this.escapeHtml(tc.tool)}</span>
                            </div>
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
        const resultPreview = typeof entry.result === 'string' ?
                             entry.result.substring(0, 100) :
                             JSON.stringify(entry.result).substring(0, 100);

        return `
            <div class="bg-gray-800 rounded p-3">
                <div class="text-xs text-gray-400 mb-1">
                    <i class="fas fa-tools"></i> ${this.escapeHtml(entry.tool)}
                </div>
                <div class="text-xxs text-gray-500 font-mono">
                    ${this.escapeHtml(resultPreview)}...
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
