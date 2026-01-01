/**
 * State Manager for SAST Triage Agent Web UI
 * Manages client-side application state
 */

class StateManager {
    constructor() {
        this.state = {
            currentScreen: 'project-input', // project-input, findings-display
            currentSession: null,
            sessions: [],
            findings: [],
            selectedFindings: [],
            analysisRunning: false,
            settings: {
                modelName: 'gemini-2.5-pro',
                sidebarVisible: true
            }
        };

        this.listeners = [];
        this.loadSettings();
    }

    /**
     * Subscribe to state changes
     */
    subscribe(listener) {
        this.listeners.push(listener);
        return () => {
            this.listeners = this.listeners.filter(l => l !== listener);
        };
    }

    /**
     * Update state and notify listeners
     */
    setState(updates) {
        this.state = { ...this.state, ...updates };
        this.notifyListeners();
    }

    /**
     * Get current state
     */
    getState() {
        return this.state;
    }

    /**
     * Notify all listeners of state change
     */
    notifyListeners() {
        this.listeners.forEach(listener => listener(this.state));
    }

    /**
     * Load settings from localStorage
     */
    loadSettings() {
        const saved = localStorage.getItem('sast_triage_settings');
        if (saved) {
            try {
                this.state.settings = { ...this.state.settings, ...JSON.parse(saved) };
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
        }
    }

    /**
     * Save settings to localStorage
     */
    saveSettings() {
        localStorage.setItem('sast_triage_settings', JSON.stringify(this.state.settings));
    }

    /**
     * Update settings
     */
    updateSettings(newSettings) {
        this.state.settings = { ...this.state.settings, ...newSettings };
        this.saveSettings();
        this.notifyListeners();
    }

    /**
     * Set current session
     */
    setCurrentSession(session) {
        this.setState({ currentSession: session });
    }

    /**
     * Set findings
     */
    setFindings(findings) {
        this.setState({ findings });
    }

    /**
     * Toggle finding selection
     */
    toggleFindingSelection(resultHash) {
        const selected = [...this.state.selectedFindings];
        const index = selected.indexOf(resultHash);

        if (index > -1) {
            selected.splice(index, 1);
        } else {
            selected.push(resultHash);
        }

        this.setState({ selectedFindings: selected });
    }

    /**
     * Select all findings
     */
    selectAllFindings() {
        const allHashes = this.state.findings.map(f => f.resultHash);
        this.setState({ selectedFindings: allHashes });
    }

    /**
     * Deselect all findings
     */
    deselectAllFindings() {
        this.setState({ selectedFindings: [] });
    }

    /**
     * Toggle sidebar visibility
     */
    toggleSidebar() {
        const visible = !this.state.settings.sidebarVisible;
        this.updateSettings({ sidebarVisible: visible });
    }

    /**
     * Switch screen
     */
    switchScreen(screenName) {
        this.setState({ currentScreen: screenName });
    }

    /**
     * Set analysis running state
     */
    setAnalysisRunning(running) {
        this.setState({ analysisRunning: running });
    }

    /**
     * Check if any findings can be analyzed
     * Returns filtered list of findings that haven't been analyzed (or were REFUSED)
     */
    getAnalyzableFindings() {
        const findings = this.state.selectedFindings
            .map(hash => this.state.findings.find(f => f.resultHash === hash))
            .filter(f => f);

        return findings.filter(finding => {
            // No analysis data = can analyze
            if (!finding.analysis) return true;

            // No result yet (pending or failed) = can analyze
            if (!finding.analysis.result) return true;

            // REFUSED = can re-analyze
            if (finding.analysis.result === 'REFUSED') return true;

            // Completed with result (not REFUSED) = cannot re-analyze
            return false;
        });
    }
}

// Global state manager instance
const stateManager = new StateManager();