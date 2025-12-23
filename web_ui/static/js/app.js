/**
 * Main Application Logic
 * Orchestrates all components and handles screen transitions
 */

class App {
    constructor() {
        this.screens = {
            projectInput: document.getElementById('screen-project-input'),
            findingsDisplay: document.getElementById('screen-findings-display')
        };

        this.elements = {
            sidebarToggle: document.getElementById('sidebar-toggle'),
            sidebar: document.getElementById('sidebar'),
            settingsBtn: document.getElementById('settings-btn'),
            settingsModal: document.getElementById('settings-modal'),
            btnFetchFindings: document.getElementById('btn-fetch-findings'),
            btnBackToInput: document.getElementById('btn-back-to-input'),
            btnRunTriage: document.getElementById('btn-run-triage'),
            fetchStatus: document.getElementById('fetch-status')
        };

        this.setupEventListeners();
        this.subscribeToState();
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Sidebar toggle
        this.elements.sidebarToggle?.addEventListener('click', () => {
            stateManager.toggleSidebar();
        });

        // Settings button
        this.elements.settingsBtn?.addEventListener('click', () => {
            this.openSettings();
        });

        // Settings modal close
        const settingsClose = this.elements.settingsModal?.querySelector('.modal-close');
        settingsClose?.addEventListener('click', () => {
            this.elements.settingsModal.classList.add('hidden');
        });

        // Settings save
        document.getElementById('settings-save')?.addEventListener('click', () => {
            this.saveSettings();
        });

        // Fetch findings button
        this.elements.btnFetchFindings?.addEventListener('click', () => {
            this.fetchFindings();
        });

        // Back to input button
        this.elements.btnBackToInput?.addEventListener('click', () => {
            stateManager.switchScreen('project-input');
        });

        // Run triage button
        this.elements.btnRunTriage?.addEventListener('click', () => {
            this.runTriage();
        });

        // Session loaded event
        window.addEventListener('session-loaded', (e) => {
            this.handleSessionLoaded(e.detail);
        });
    }

    /**
     * Subscribe to state changes
     */
    subscribeToState() {
        stateManager.subscribe((state) => {
            this.renderScreen(state.currentScreen);
            this.updateSidebarVisibility(state.settings.sidebarVisible);
            this.updateRunTriageButton(state.selectedFindings.length);
        });
    }

    /**
     * Render active screen
     */
    renderScreen(screenName) {
        // Hide all screens
        Object.values(this.screens).forEach(screen => {
            if (screen) screen.classList.add('hidden');
        });

        // Show active screen
        if (screenName === 'project-input') {
            this.screens.projectInput?.classList.remove('hidden');
        } else if (screenName === 'findings-display') {
            this.screens.findingsDisplay?.classList.remove('hidden');
        }
    }

    /**
     * Update sidebar visibility
     */
    updateSidebarVisibility(visible) {
        if (visible) {
            this.elements.sidebar?.classList.remove('collapsed');
        } else {
            this.elements.sidebar?.classList.add('collapsed');
        }
    }

    /**
     * Update run triage button state
     */
    updateRunTriageButton(selectedCount) {
        if (this.elements.btnRunTriage) {
            this.elements.btnRunTriage.disabled = selectedCount === 0;
        }
    }

    /**
     * Open settings modal
     */
    openSettings() {
        const state = stateManager.getState();
        const modelSelect = document.getElementById('settings-model');

        if (modelSelect) {
            modelSelect.value = state.settings.modelName;
        }

        this.elements.settingsModal?.classList.remove('hidden');
    }

    /**
     * Save settings
     */
    saveSettings() {
        const modelSelect = document.getElementById('settings-model');

        stateManager.updateSettings({
            modelName: modelSelect?.value || 'gemini-2.5-pro'
        });

        this.elements.settingsModal?.classList.add('hidden');
    }

    /**
     * Fetch findings from Checkmarx
     */
    async fetchFindings() {
        const projectName = document.getElementById('input-project-name')?.value.trim();
        const branch = document.getElementById('input-branch')?.value.trim();

        if (!projectName) {
            this.showStatus('error', 'Please enter a project name');
            return;
        }

        if (!branch) {
            this.showStatus('error', 'Please enter a branch name');
            return;
        }

        // Get selected severities
        const severityCheckboxes = document.querySelectorAll('input[name="severity"]:checked');
        const severities = Array.from(severityCheckboxes).map(cb => cb.value);

        if (severities.length === 0) {
            this.showStatus('error', 'Please select at least one severity');
            return;
        }

        // Get selected states
        const stateCheckboxes = document.querySelectorAll('input[name="state"]:checked');
        const states = Array.from(stateCheckboxes).map(cb => cb.value);

        if (states.length === 0) {
            this.showStatus('error', 'Please select at least one state');
            return;
        }

        // Show loading
        this.elements.btnFetchFindings.disabled = true;
        this.elements.btnFetchFindings.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Fetching...';
        this.showStatus('info', 'Fetching findings from Checkmarx...');

        try {
            const response = await fetch('/api/findings/fetch', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    project_name: projectName,
                    branch: branch,
                    severity_filters: severities,
                    status_filters: states
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to fetch findings');
            }

            const data = await response.json();

            this.showStatus('success', `Fetched ${data.total_findings} findings`);

            // Load the session
            setTimeout(async () => {
                await sidebar.loadSession(data.session_id);
            }, 1000);

        } catch (error) {
            console.error('Error fetching findings:', error);
            this.showStatus('error', `Failed to fetch findings: ${error.message}`);
        } finally {
            this.elements.btnFetchFindings.disabled = false;
            this.elements.btnFetchFindings.innerHTML = '<i class="fas fa-download mr-2"></i>Fetch Findings';
        }
    }

    /**
     * Handle session loaded
     */
    handleSessionLoaded(session) {
        // Update header
        document.getElementById('findings-project-name').textContent = session.metadata.project_name;
        document.getElementById('findings-branch').textContent = session.metadata.branch;
        document.getElementById('findings-count').textContent = session.findings.length;

        const githubLink = document.getElementById('findings-github-link');
        if (session.metadata.github_url) {
            githubLink.href = session.metadata.github_url;
            githubLink.style.display = '';
        } else {
            githubLink.style.display = 'none';
        }

        // Render findings table
        findingsTable.render(session.findings);
    }

    /**
     * Run triage analysis
     */
    async runTriage() {
        const state = stateManager.getState();

        if (state.selectedFindings.length === 0) {
            alert('Please select at least one finding');
            return;
        }

        if (!state.currentSession) {
            alert('No session loaded');
            return;
        }

        // Disable run button during analysis
        this.elements.btnRunTriage.disabled = true;
        this.elements.btnRunTriage.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Starting Analysis...';

        try {
            // Connect to WebSocket first
            websocketClient.connect(state.currentSession.session_id);

            // Start analysis
            const response = await fetch('/api/analysis/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    session_id: state.currentSession.session_id,
                    selected_finding_hashes: state.selectedFindings,
                    model_name: state.settings.modelName
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to start analysis');
            }

            const data = await response.json();

            if (data.status === 'running') {
                this.showStatus('success', `Analysis started for ${state.selectedFindings.length} findings`);
                this.elements.btnRunTriage.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Analysis Running...';
            } else {
                this.showStatus('warning', data.message || 'Analysis could not be started');
                this.elements.btnRunTriage.disabled = false;
                this.elements.btnRunTriage.innerHTML = '<i class="fas fa-play mr-2"></i>Run Triage';
            }

        } catch (error) {
            console.error('Error starting analysis:', error);
            this.showStatus('error', `Failed to start analysis: ${error.message}`);
            this.elements.btnRunTriage.disabled = false;
            this.elements.btnRunTriage.innerHTML = '<i class="fas fa-play mr-2"></i>Run Triage';
        }
    }

    /**
     * Show status message
     */
    showStatus(type, message) {
        if (!this.elements.fetchStatus) return;

        const icons = {
            info: 'info-circle',
            success: 'check-circle',
            error: 'exclamation-triangle',
            warning: 'exclamation-circle'
        };

        this.elements.fetchStatus.className = `alert alert-${type}`;
        this.elements.fetchStatus.innerHTML = `
            <i class="fas fa-${icons[type]} mr-2"></i>${this.escapeHtml(message)}
        `;
        this.elements.fetchStatus.classList.remove('hidden');

        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(() => {
                this.elements.fetchStatus?.classList.add('hidden');
            }, 3000);
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const app = new App();
    console.log('SAST Triage Agent UI initialized');
});
