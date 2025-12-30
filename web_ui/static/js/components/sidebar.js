/**
 * Sidebar Component
 * Manages session history display
 */

class Sidebar {
    constructor() {
        this.container = document.getElementById('session-list');
        this.loadSessions();
    }

    /**
     * Load sessions from API
     */
    async loadSessions() {
        try {
            const response = await fetch('/api/sessions');
            if (!response.ok) throw new Error('Failed to load sessions');

            const sessions = await response.json();
            stateManager.setState({ sessions });
            this.render(sessions);
        } catch (error) {
            console.error('Error loading sessions:', error);
            this.renderError();
        }
    }

    /**
     * Render sessions list
     */
    render(sessions) {
        if (!sessions || sessions.length === 0) {
            this.container.innerHTML = `
                <div class="text-gray-500 text-sm text-center py-8">
                    No sessions yet
                </div>
            `;
            return;
        }

        this.container.innerHTML = sessions.map(session => this.renderSessionCard(session)).join('');

        // Attach event listeners
        this.attachEventListeners();
    }

    /**
     * Render a single session card
     */
    renderSessionCard(session) {
        const date = new Date(session.created_at);
        const dateStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

        // Always use gray list-check icon for the counter
        const statusIcon = 'list-check';
        const statusColor = 'text-gray-500';

        return `
            <div class="session-card" data-session-id="${session.session_id}">
                <div class="session-delete" data-action="delete">
                    <i class="fas fa-times"></i>
                </div>
                <div class="session-name">${this.escapeHtml(session.project_name)}</div>
                <div class="session-meta">
                    <div>${session.branch}</div>
                    <div class="text-xxs">${dateStr}</div>
                    <div class="mt-1">
                        <i class="fas fa-${statusIcon} ${statusColor}"></i>
                        <span class="text-xxs">${session.analyzed_count}/${session.total_findings}</span>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError() {
        this.container.innerHTML = `
            <div class="text-red-400 text-sm text-center py-8">
                <i class="fas fa-exclamation-triangle mb-2"></i>
                <div>Failed to load sessions</div>
            </div>
        `;
    }

    /**
     * Attach event listeners to session cards
     */
    attachEventListeners() {
        const cards = this.container.querySelectorAll('.session-card');

        cards.forEach(card => {
            const sessionId = card.dataset.sessionId;

            // Click on card to load session
            card.addEventListener('click', (e) => {
                // Don't trigger if clicking delete button
                if (e.target.closest('[data-action="delete"]')) return;

                this.loadSession(sessionId);
            });

            // Delete button
            const deleteBtn = card.querySelector('[data-action="delete"]');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.deleteSession(sessionId);
                });
            }
        });
    }

    /**
     * Load a session
     */
    async loadSession(sessionId) {
        try {
            const response = await fetch(`/api/sessions/${sessionId}`);
            if (!response.ok) throw new Error('Failed to load session');

            const session = await response.json();

            // Mark active session
            document.querySelectorAll('.session-card').forEach(card => {
                card.classList.remove('active');
            });
            document.querySelector(`[data-session-id="${sessionId}"]`)?.classList.add('active');

            // Update state and switch to findings display
            stateManager.setCurrentSession(session);
            stateManager.setFindings(session.findings);
            stateManager.switchScreen('findings-display');

            // Trigger render in main app
            window.dispatchEvent(new CustomEvent('session-loaded', { detail: session }));

        } catch (error) {
            console.error('Error loading session:', error);
            alert('Failed to load session');
        }
    }

    /**
     * Delete a session
     */
    async deleteSession(sessionId) {
        if (!confirm('Are you sure you want to delete this session?')) return;

        try {
            const response = await fetch(`/api/sessions/${sessionId}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to delete session');

            // Reload sessions
            await this.loadSessions();

        } catch (error) {
            console.error('Error deleting session:', error);
            alert('Failed to delete session');
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

// Initialize sidebar
const sidebar = new Sidebar();
