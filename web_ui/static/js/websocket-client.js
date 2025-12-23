/**
 * WebSocket Client
 * Handles real-time communication for analysis progress updates
 */

class WebSocketClient {
    constructor() {
        this.ws = null;
        this.sessionId = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000; // 2 seconds
        this.pingInterval = null;
    }

    /**
     * Connect to WebSocket server
     */
    connect(sessionId) {
        this.sessionId = sessionId;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/${sessionId}`;

        console.log(`Connecting to WebSocket: ${wsUrl}`);

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.reconnectAttempts = 0;
                this.startPingInterval();

                // Dispatch connection event
                window.dispatchEvent(new CustomEvent('websocket-connected', {
                    detail: { sessionId }
                }));
            };

            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleMessage(message);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };

            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.stopPingInterval();

                // Dispatch disconnection event
                window.dispatchEvent(new CustomEvent('websocket-disconnected', {
                    detail: { sessionId }
                }));

                // Attempt reconnection
                this.attemptReconnect();
            };

        } catch (error) {
            console.error('Error creating WebSocket:', error);
        }
    }

    /**
     * Handle incoming WebSocket message
     */
    handleMessage(message) {
        console.log('WebSocket message received:', message.type);

        switch (message.type) {
            case 'connected':
                console.log('WebSocket connection confirmed');
                break;

            case 'pong':
                // Keep-alive response
                break;

            case 'analysis_started':
                this.handleAnalysisStarted(message.data);
                break;

            case 'analysis_progress':
                this.handleAnalysisProgress(message.data);
                break;

            case 'tool_execution':
                this.handleToolExecution(message.data);
                break;

            case 'analysis_complete':
                this.handleAnalysisComplete(message.data);
                break;

            case 'analysis_failed':
                this.handleAnalysisFailed(message.data);
                break;

            case 'batch_progress':
                this.handleBatchProgress(message.data);
                break;

            default:
                console.warn('Unknown WebSocket message type:', message.type);
        }
    }

    /**
     * Handle analysis started event
     */
    handleAnalysisStarted(data) {
        console.log(`Analysis started for finding: ${data.finding_hash}`);

        // Update finding status in state
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === data.finding_hash);

        if (finding) {
            finding.analysis = {
                status: 'in_progress',
                started_at: data.timestamp,
                last_action: 'Starting analysis...'
            };
            stateManager.setState({ findings: state.findings });

            // Update table row
            findingsTable.updateFindingRow(finding);
        }
    }

    /**
     * Handle analysis progress event
     */
    handleAnalysisProgress(data) {
        console.log(`Analysis progress: ${data.finding_hash} - ${data.last_action}`);

        // Update finding with latest action
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === data.finding_hash);

        if (finding && finding.analysis) {
            finding.analysis.last_action = data.last_action;
            finding.analysis.iteration = data.iteration;
            finding.analysis.max_iterations = data.max_iterations;
            stateManager.setState({ findings: state.findings });

            // Update table row
            findingsTable.updateFindingRow(finding);
        }
    }

    /**
     * Handle tool execution event
     */
    handleToolExecution(data) {
        console.log(`Tool executed: ${data.tool_name} for ${data.finding_hash}`);

        // Optional: Could be used to show detailed tool execution in modal
        // For now, this is just logged
    }

    /**
     * Handle analysis complete event
     */
    handleAnalysisComplete(data) {
        console.log(`Analysis complete for finding: ${data.finding_hash}`);

        // Update finding with final results
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === data.finding_hash);

        if (finding && finding.analysis) {
            finding.analysis.status = 'completed';
            finding.analysis.completed_at = data.timestamp;
            finding.analysis.result = data.result;
            finding.analysis.confidence = data.confidence;
            finding.analysis.justification = data.justification;
            finding.analysis.duration_seconds = data.duration_seconds;
            stateManager.setState({ findings: state.findings });

            // Update table row
            findingsTable.updateFindingRow(finding);
        }
    }

    /**
     * Handle analysis failed event
     */
    handleAnalysisFailed(data) {
        console.error(`Analysis failed for finding: ${data.finding_hash}`);

        // Update finding with error status
        const state = stateManager.getState();
        const finding = state.findings.find(f => f.resultHash === data.finding_hash);

        if (finding && finding.analysis) {
            finding.analysis.status = 'failed';
            finding.analysis.completed_at = data.timestamp;
            finding.analysis.last_action = `Error: ${data.error}`;
            stateManager.setState({ findings: state.findings });

            // Update table row
            findingsTable.updateFindingRow(finding);
        }
    }

    /**
     * Handle batch progress event
     */
    handleBatchProgress(data) {
        console.log(`Batch progress: ${data.completed}/${data.total}`);

        // Optional: Could show overall progress in header
        // For now, individual finding updates are sufficient
    }

    /**
     * Start ping interval to keep connection alive
     */
    startPingInterval() {
        this.pingInterval = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'ping', data: {} }));
            }
        }, 30000); // Ping every 30 seconds
    }

    /**
     * Stop ping interval
     */
    stopPingInterval() {
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
    }

    /**
     * Attempt to reconnect after disconnection
     */
    attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        console.log(`Attempting reconnection (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);

        setTimeout(() => {
            if (this.sessionId) {
                this.connect(this.sessionId);
            }
        }, this.reconnectDelay);
    }

    /**
     * Disconnect from WebSocket server
     */
    disconnect() {
        this.stopPingInterval();

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        this.sessionId = null;
        this.reconnectAttempts = 0;
    }

    /**
     * Check if WebSocket is connected
     */
    isConnected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    }
}

// Initialize WebSocket client
const websocketClient = new WebSocketClient();
