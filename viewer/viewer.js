/* SAST Triage Session Log Viewer
   Single-file vanilla JS. Loads a session-log JSONL via the file picker
   or drag-drop, parses it into typed events, and renders a findings
   picker, a topology + traversal panel, a one-line timeline and an
   inspector pane. All content is rendered through textContent / DOM
   creation; no innerHTML, no string templates, no eval. The CSP in
   index.html also blocks network and dynamic script.
*/

(function () {
  "use strict";

  // ===== Constants =====

  const NODE_NAMES = ["research", "analyst", "critic", "aggregate"];

  const EVENT_TYPES = [
    "session_start",
    "preprocessing_complete",
    "finding_start",
    "graph_invoke_start",
    "node_enter",
    "node_exit",
    "llm_call",
    "tool_call",
    "route_decision",
    "error",
    "graph_invoke_end",
    "finding_complete",
    "session_end",
  ];

  const INLINE_CONTENT_LIMIT = 4000; // chars; longer goes to a "Show all" modal

  // ===== Safe DOM helpers =====

  function el(tag, opts, children) {
    const node = document.createElement(tag);
    if (opts) {
      if (opts.cls) node.className = opts.cls;
      if (opts.text != null) node.textContent = String(opts.text);
      if (opts.title) node.title = String(opts.title);
      if (opts.id) node.id = opts.id;
      if (opts.attrs) {
        for (const k in opts.attrs) {
          node.setAttribute(k, String(opts.attrs[k]));
        }
      }
      if (opts.on) {
        for (const ev in opts.on) {
          node.addEventListener(ev, opts.on[ev]);
        }
      }
      if (opts.html === true && opts.text != null) {
        // explicit no-op; we never set innerHTML.
      }
    }
    if (children) {
      for (let i = 0; i < children.length; i++) {
        const c = children[i];
        if (c == null) continue;
        node.appendChild(
          typeof c === "string" ? document.createTextNode(c) : c
        );
      }
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  // ===== Number / format helpers =====

  function fmtTime(iso) {
    if (!iso) return "";
    // Show HH:MM:SS.mmm from the ISO timestamp.
    const t = String(iso);
    const tIdx = t.indexOf("T");
    if (tIdx < 0) return t;
    const time = t.slice(tIdx + 1);
    const m = time.match(/^(\d{2}):(\d{2}):(\d{2})\.(\d{1,6})/);
    if (!m) return time;
    return m[1] + ":" + m[2] + ":" + m[3] + "." + m[4].slice(0, 3);
  }

  function fmtMs(ms) {
    if (ms == null) return "—";
    if (ms < 1000) return ms.toFixed(0) + "ms";
    if (ms < 60000) return (ms / 1000).toFixed(1) + "s";
    const s = Math.round(ms / 1000);
    return Math.floor(s / 60) + "m" + (s % 60) + "s";
  }

  function fmtTokens(n) {
    if (n == null) return "—";
    if (n < 1000) return String(n);
    if (n < 10000) return (n / 1000).toFixed(2) + "k";
    if (n < 1000000) return (n / 1000).toFixed(1) + "k";
    return (n / 1000000).toFixed(2) + "M";
  }

  function fmtBytes(n) {
    if (n == null) return "—";
    if (n < 1024) return n + "B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + "KB";
    return (n / 1024 / 1024).toFixed(2) + "MB";
  }

  function jsonPretty(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch (e) {
      return String(value);
    }
  }

  function approxStringSize(value) {
    if (value == null) return 0;
    if (typeof value === "string") return value.length;
    try {
      return JSON.stringify(value).length;
    } catch (e) {
      return String(value).length;
    }
  }

  function shortenHash(h) {
    if (!h) return "";
    return h.length > 16 ? h.slice(0, 16) + "…" : h;
  }

  // ===== Parser =====

  function parseJsonl(text) {
    const lines = text.split(/\r?\n/);
    const events = [];
    let lineNo = 0;
    for (const raw of lines) {
      lineNo += 1;
      const t = raw.trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t);
        if (obj && typeof obj === "object" && obj.type) {
          events.push(obj);
        }
      } catch (e) {
        console.warn("viewer: failed to parse line " + lineNo + ": " + e.message);
      }
    }
    return events;
  }

  function buildSession(fileName, events) {
    const session = {
      fileName: fileName,
      sessionId: null,
      events: events,
      startEvent: null,
      endEvent: null,
      preprocessingEvent: null,
      findings: new Map(),
      findingOrder: [],
      totals: {
        llmCalls: 0,
        toolCalls: 0,
        tokens: { input: 0, output: 0, total: 0 },
        durationMs: 0,
      },
    };

    let currentFinding = null;

    for (const ev of events) {
      if (ev.session_id && !session.sessionId) session.sessionId = ev.session_id;

      switch (ev.type) {
        case "session_start":
          session.startEvent = ev;
          break;
        case "session_end":
          session.endEvent = ev;
          if (ev.total_tokens) {
            session.totals.tokens.input = ev.total_tokens.input || 0;
            session.totals.tokens.output = ev.total_tokens.output || 0;
            session.totals.tokens.total = ev.total_tokens.total || 0;
          }
          if (ev.llm_calls_count != null) session.totals.llmCalls = ev.llm_calls_count;
          if (ev.tool_calls_count != null) session.totals.toolCalls = ev.tool_calls_count;
          if (ev.total_duration_ms != null) session.totals.durationMs = ev.total_duration_ms;
          break;
        case "preprocessing_complete":
          session.preprocessingEvent = ev;
          break;
        case "finding_start":
          currentFinding = {
            findingId: ev.finding_id,
            startEvent: ev,
            completeEvent: null,
            events: [],
            order: session.findingOrder.length,
          };
          session.findings.set(ev.finding_id, currentFinding);
          session.findingOrder.push(ev.finding_id);
          currentFinding.events.push(ev);
          break;
        case "finding_complete":
          if (currentFinding && currentFinding.findingId === ev.finding_id) {
            currentFinding.completeEvent = ev;
            currentFinding.events.push(ev);
            currentFinding = null;
          } else if (session.findings.has(ev.finding_id)) {
            const f = session.findings.get(ev.finding_id);
            f.completeEvent = ev;
            f.events.push(ev);
          }
          break;
        default:
          // Attribute by finding_id when present; otherwise to current.
          if (ev.finding_id) {
            const f = session.findings.get(ev.finding_id);
            if (f) f.events.push(ev);
          } else if (currentFinding) {
            currentFinding.events.push(ev);
          }
          break;
      }
    }

    return session;
  }

  function findingNodeStats(finding) {
    const visits = {};
    const durations = {};
    for (const n of NODE_NAMES) {
      visits[n] = 0;
      durations[n] = 0;
    }
    for (const ev of finding.events) {
      if (ev.type === "node_enter" && ev.node && visits[ev.node] != null) {
        visits[ev.node] += 1;
      } else if (ev.type === "node_exit" && ev.node && durations[ev.node] != null) {
        durations[ev.node] += ev.duration_ms || 0;
      }
    }
    return { visits: visits, durations: durations };
  }

  function findingTraversal(finding) {
    const steps = [];
    for (const ev of finding.events) {
      if (ev.type === "node_enter" && ev.node) {
        steps.push({ node: ev.node, visitIndex: ev.visit_index || 0 });
      }
    }
    return steps;
  }

  // ===== State =====

  const State = {
    sessions: new Map(), // fileName -> session
    tabs: [], // [{ id, type: "session" | "compare", fileName?: , compare?: {a, b} }]
    activeTabId: null,
    nextTabId: 1,
    perTab: new Map(), // tabId -> { selectedFinding, searchQuery, activeEventKey }
  };

  // ===== Sidebar =====

  function renderSidebar() {
    const list = document.getElementById("session-list");
    clear(list);

    if (State.sessions.size === 0) {
      const empty = el("div", { cls: "session-entry muted", text: "No sessions loaded yet." });
      list.appendChild(empty);
    } else {
      for (const [fileName, session] of State.sessions.entries()) {
        const entry = el(
          "div",
          {
            cls: "session-entry",
            attrs: { role: "button", tabindex: "0" },
            on: {
              click: () => openSessionTab(fileName),
              keydown: (e) => {
                if (e.key === "Enter" || e.key === " ") openSessionTab(fileName);
              },
            },
          },
          [
            el("div", { cls: "name", text: fileName }),
            el("div", {
              cls: "meta",
              text:
                (session.startEvent ? session.startEvent.model || "" : "") +
                (session.findings.size > 0
                  ? " · " + session.findings.size + " finding" + (session.findings.size === 1 ? "" : "s")
                  : ""),
            }),
          ]
        );
        list.appendChild(entry);
      }
    }

    const launcher = document.getElementById("compare-launcher");
    if (State.sessions.size >= 2) {
      launcher.hidden = false;
    } else {
      launcher.hidden = true;
    }
  }

  // ===== Tabs =====

  function openSessionTab(fileName) {
    for (const t of State.tabs) {
      if (t.type === "session" && t.fileName === fileName) {
        setActiveTab(t.id);
        return;
      }
    }
    const id = "tab-" + State.nextTabId++;
    State.tabs.push({ id: id, type: "session", fileName: fileName });
    State.perTab.set(id, { selectedFinding: null, searchQuery: "", activeEventKey: null });
    setActiveTab(id);
  }

  function openCompareTab() {
    const id = "tab-" + State.nextTabId++;
    const names = Array.from(State.sessions.keys());
    State.tabs.push({
      id: id,
      type: "compare",
      compare: { a: names[0] || null, b: names[1] || names[0] || null },
    });
    State.perTab.set(id, {});
    setActiveTab(id);
  }

  function closeTab(tabId) {
    const idx = State.tabs.findIndex((t) => t.id === tabId);
    if (idx < 0) return;
    State.tabs.splice(idx, 1);
    State.perTab.delete(tabId);
    if (State.activeTabId === tabId) {
      const next = State.tabs[idx] || State.tabs[idx - 1];
      State.activeTabId = next ? next.id : null;
    }
    renderTabs();
    renderTabContent();
  }

  function setActiveTab(tabId) {
    State.activeTabId = tabId;
    renderTabs();
    renderTabContent();
  }

  function tabLabel(tab) {
    if (tab.type === "session") return tab.fileName;
    if (tab.type === "compare") return "Compare";
    return "Tab";
  }

  function renderTabs() {
    const bar = document.getElementById("tab-bar");
    clear(bar);
    for (const t of State.tabs) {
      const tab = el(
        "div",
        {
          cls: "tab" + (t.id === State.activeTabId ? " active" : ""),
          attrs: { role: "tab" },
          on: { click: () => setActiveTab(t.id) },
        },
        [
          el("span", { text: tabLabel(t) }),
          el("button", {
            cls: "tab-close",
            text: "×",
            attrs: { "aria-label": "Close tab", type: "button" },
            on: {
              click: (e) => {
                e.stopPropagation();
                closeTab(t.id);
              },
            },
          }),
        ]
      );
      bar.appendChild(tab);
    }
  }

  function renderTabContent() {
    const content = document.getElementById("tab-content");
    clear(content);
    const tab = State.tabs.find((t) => t.id === State.activeTabId);
    if (!tab) {
      content.appendChild(
        el("div", { cls: "empty-state" }, [
          el("p", null, ["Pick a ", el("code", { text: ".jsonl" }), " session log from the sidebar to begin."]),
          el("p", { cls: "muted" }, [
            "Logs live under ",
            el("code", { text: "logs/" }),
            " in the project root.",
          ]),
        ])
      );
      return;
    }
    if (tab.type === "session") {
      const session = State.sessions.get(tab.fileName);
      if (!session) {
        content.appendChild(el("div", { cls: "empty-state", text: "Session not loaded." }));
        return;
      }
      content.appendChild(renderSessionView(tab, session));
    } else if (tab.type === "compare") {
      content.appendChild(renderCompareView(tab));
    }
  }

  // ===== Session view =====

  function renderSessionView(tab, session) {
    const root = el("div", { cls: "session-view" });
    root.appendChild(renderSessionHeader(tab, session));
    root.appendChild(renderSessionBody(tab, session));
    return root;
  }

  function renderSessionHeader(tab, session) {
    const tabState = State.perTab.get(tab.id);
    const start = session.startEvent || {};
    const totals = session.totals;
    const summary = el("div", { cls: "session-summary" }, [
      summaryItem("Model", start.model || "—"),
      summaryItem("Project", start.project_name || "—"),
      summaryItem("Branch", start.branch || "—"),
      summaryItem("Findings", String(session.findings.size)),
      summaryItem("LLM calls", String(totals.llmCalls)),
      summaryItem("Tool calls", String(totals.toolCalls)),
      summaryItem("Tokens", fmtTokens(totals.tokens.total)),
      summaryItem("Duration", fmtMs(totals.durationMs)),
      summaryItem("Mode", start.log_mode || "—"),
    ]);

    const searchInput = el("input", {
      attrs: { type: "search", placeholder: "Search this session..." },
    });
    searchInput.value = tabState.searchQuery || "";
    searchInput.addEventListener("input", () => {
      tabState.searchQuery = searchInput.value;
      const timelineEl = document.querySelector(".timeline");
      if (timelineEl) {
        const parent = timelineEl.parentElement;
        const newTimeline = renderTimeline(tab, session);
        parent.replaceChild(newTimeline, timelineEl);
      }
    });
    const searchBox = el("div", { cls: "search-box" }, [
      el("span", { cls: "muted", text: "Search:" }),
      searchInput,
    ]);

    return el("div", { cls: "session-header" }, [summary, searchBox]);
  }

  function summaryItem(label, value) {
    return el("div", { cls: "summary-item" }, [
      el("span", { cls: "label", text: label + ":" }),
      el("span", { cls: "value", text: value }),
    ]);
  }

  function renderSessionBody(tab, session) {
    const findings = el("section", { cls: "findings-section" });
    findings.appendChild(renderFindingsTable(tab, session));

    const flowAndTimeline = el("div", { cls: "timeline-pane" });
    flowAndTimeline.appendChild(findings);
    flowAndTimeline.appendChild(renderFlowAndTimeline(tab, session));

    const inspector = el("aside", { cls: "inspector-pane" });
    inspector.appendChild(
      el("div", { cls: "inspector-empty", text: "Click an event row to inspect it." })
    );

    return el("div", { cls: "session-body" }, [flowAndTimeline, inspector]);
  }

  function renderFlowAndTimeline(tab, session) {
    const wrap = el("div", { cls: "timeline-pane" });
    wrap.style.flex = "1";
    const tabState = State.perTab.get(tab.id);
    const finding = tabState.selectedFinding
      ? session.findings.get(tabState.selectedFinding)
      : null;

    if (finding) {
      wrap.appendChild(renderFindingHeader(finding));
      wrap.appendChild(renderFlow(finding));
    } else {
      wrap.appendChild(
        el("div", { cls: "flow-section" }, [
          el("div", { cls: "muted", text: "Select a finding above to see its topology and timeline." }),
        ])
      );
    }
    wrap.appendChild(renderTimeline(tab, session));
    return wrap;
  }

  function renderFindingsTable(tab, session) {
    const tabState = State.perTab.get(tab.id);

    const headers = [
      { key: "order", label: "#" },
      { key: "findingId", label: "resultHash" },
      { key: "state", label: "state" },
      { key: "confidence", label: "conf" },
      { key: "samples", label: "samples" },
      { key: "research", label: "research" },
      { key: "reanalysis", label: "reanalysis" },
      { key: "tokens", label: "tokens" },
      { key: "duration", label: "duration" },
      { key: "stopReason", label: "stop reason" },
    ];

    const rows = [];
    for (const fid of session.findingOrder) {
      const f = session.findings.get(fid);
      const c = f.completeEvent;
      const decision = c ? c.final_decision || {} : {};
      const tokens = c && c.total_tokens ? c.total_tokens.total : 0;
      const duration = c ? c.total_duration_ms : null;
      const visits = c && c.per_node_visit_counts ? c.per_node_visit_counts : {};
      rows.push({
        order: f.order + 1,
        findingId: fid,
        state: decision.suggested_state || "—",
        confidence: decision.confidence != null ? decision.confidence : null,
        samples: c ? (decision.sample_count != null ? decision.sample_count : findingSampleCount(f)) : 0,
        research: visits.research || 0,
        reanalysis: c ? reanalysisCount(c) : 0,
        tokens: tokens,
        duration: duration,
        stopReason: c ? c.stop_reason || "—" : "—",
        _f: f,
      });
    }

    if (!tabState.findingsSort) {
      tabState.findingsSort = { key: "order", dir: 1 };
    }
    const sort = tabState.findingsSort;
    rows.sort((a, b) => {
      const av = a[sort.key];
      const bv = b[sort.key];
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * sort.dir;
      return String(av).localeCompare(String(bv)) * sort.dir;
    });

    const table = el("table", { cls: "findings-table" });
    const thead = el("thead");
    const trh = el("tr");
    for (const h of headers) {
      const th = el(
        "th",
        {
          on: {
            click: () => {
              if (sort.key === h.key) sort.dir = -sort.dir;
              else {
                sort.key = h.key;
                sort.dir = 1;
              }
              const newTable = renderFindingsTable(tab, session);
              table.replaceWith(newTable);
            },
          },
        },
        [
          h.label,
          sort.key === h.key
            ? el("span", { cls: "sort-marker", text: sort.dir > 0 ? " ▲" : " ▼" })
            : null,
        ]
      );
      trh.appendChild(th);
    }
    thead.appendChild(trh);
    table.appendChild(thead);

    const tbody = el("tbody");
    for (const r of rows) {
      const isActive = tabState.selectedFinding === r.findingId;
      const tr = el(
        "tr",
        {
          cls: isActive ? "active" : "",
          on: {
            click: () => {
              tabState.selectedFinding = r.findingId;
              tabState.activeEventKey = null;
              renderTabContent();
            },
          },
        },
        [
          el("td", { cls: "num", text: r.order }),
          el("td", { cls: "mono", text: shortenHash(r.findingId), title: r.findingId }),
          el("td", null, [
            el("span", { cls: "state-badge state-" + r.state, text: r.state }),
          ]),
          el("td", {
            cls: "num mono",
            text: r.confidence != null ? r.confidence.toFixed(2) : "—",
          }),
          el("td", { cls: "num mono", text: r.samples }),
          el("td", { cls: "num mono", text: r.research }),
          el("td", { cls: "num mono", text: r.reanalysis }),
          el("td", { cls: "num mono", text: fmtTokens(r.tokens) }),
          el("td", { cls: "num mono", text: fmtMs(r.duration) }),
          el("td", { cls: "mono", text: r.stopReason }),
        ]
      );
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);

    return el(
      "div",
      null,
      [
        el("h2", { text: "Findings (" + rows.length + ")" }),
        table,
      ]
    );
  }

  function findingSampleCount(finding) {
    // Each structured analyst LLM call adds a sample.
    let n = 0;
    for (const ev of finding.events) {
      if (ev.type === "llm_call" && ev.structured_schema === "AnalystVerdict") n += 1;
    }
    return n;
  }

  function reanalysisCount(c) {
    if (c.process_summary && c.process_summary.reanalysis_count != null) {
      return c.process_summary.reanalysis_count;
    }
    const visits = c.per_node_visit_counts || {};
    return visits.analyst != null && visits.analyst > 1 ? visits.analyst - 1 : 0;
  }

  function criticTrail(finding) {
    const trail = [];
    for (const ev of finding.events) {
      if (ev.type === "node_exit" && ev.node === "critic" && ev.state_writes) {
        const lc = ev.state_writes.last_critique;
        if (lc) trail.push({ decision: lc.decision || "?", weakest_point: lc.weakest_point || "" });
      }
    }
    if (!trail.length) {
      let prev = null;
      for (const ev of finding.events) {
        if (ev.type === "node_enter" && ev.state_snapshot && ev.state_snapshot.last_critique_decision) {
          const dec = ev.state_snapshot.last_critique_decision;
          if (dec !== prev) {
            trail.push({ decision: dec, weakest_point: "" });
            prev = dec;
          }
        }
      }
    }
    return trail;
  }

  function dispositionReason(d, bd) {
    if (d.is_vulnerable === true) return "Positive verdict → CONFIRMED regardless of confidence.";
    if (d.is_vulnerable == null) return "No majority verdict → REFUSED for manual review.";
    if (bd && bd.final_confidence != null && bd.threshold != null) {
      return bd.final_confidence >= bd.threshold
        ? "Negative at/above threshold " + bd.threshold.toFixed(2) + " → NOT_EXPLOITABLE."
        : "Negative below threshold " + bd.threshold.toFixed(2) + " → PROPOSED_NOT_EXPLOITABLE for human review.";
    }
    return "";
  }

  function renderConfidenceBreakdown(d, bd) {
    const det = el("details", { cls: "collapsible fh-block" });
    det.appendChild(el("summary", null, [el("span", { text: "Confidence breakdown" })]));
    const body = el("div", { cls: "body" });
    if (!bd) {
      body.appendChild(renderKvTable([
        ["confidence", d.confidence != null ? d.confidence.toFixed(4) : "—"],
        ["agreement_rate", d.agreement_rate != null ? d.agreement_rate : "—"],
        ["sample_count", d.sample_count],
      ]));
      body.appendChild(el("div", { cls: "muted", text: "Detailed breakdown not in this log (pre-v2)." }));
      det.appendChild(body);
      return det;
    }
    const W = bd.agreement_weight;
    const agr = bd.agreement_rate;
    let formula;
    if (d.is_vulnerable == null) {
      // Split or no-majority vote: raw is forced to 0, so the blend does not apply.
      formula = "no majority vote → raw " + bd.raw_confidence.toFixed(2);
    } else {
      const evTerm = (1 - W).toFixed(2) + " x evidence(" + bd.evidence_strength.toFixed(2) + ")";
      formula = agr != null
        ? W.toFixed(2) + " x agreement(" + agr.toFixed(2) + ") + " + evTerm
        : evTerm + " (agreement not credited: single sample)";
      formula += " = " + bd.raw_confidence.toFixed(2) + " raw";
    }
    if (bd.cap_applied) formula += " → capped " + bd.cap_value.toFixed(2);
    formula += " → final " + bd.final_confidence.toFixed(2);
    body.appendChild(el("div", { cls: "fh-formula mono", text: formula }));
    body.appendChild(renderKvTable([
      ["agreement_rate", agr != null ? agr : "—"],
      ["evidence_strength", bd.evidence_strength],
      ["agreement_weight", W],
      ["raw_confidence", bd.raw_confidence],
      ["cap_applied", String(bd.cap_applied)],
      ["cap_value", bd.cap_value],
      ["final_confidence", bd.final_confidence],
      ["threshold", bd.threshold],
    ]));
    const reason = dispositionReason(d, bd);
    if (reason) body.appendChild(el("div", { cls: "muted", text: reason }));
    det.appendChild(body);
    return det;
  }

  function renderSampleVotes(bd) {
    const votes = bd && bd.sample_votes ? bd.sample_votes : null;
    const n = votes ? votes.length : 0;
    const det = el("details", { cls: "collapsible fh-block" });
    det.appendChild(el("summary", null, [el("span", { text: "Sample votes (" + n + ")" })]));
    const body = el("div", { cls: "body" });
    if (!votes) {
      body.appendChild(el("div", { cls: "muted", text: "Per-sample votes not in this log (pre-v2)." }));
      det.appendChild(body);
      return det;
    }
    const tbl = el("table", { cls: "kv-table fh-votes" });
    tbl.appendChild(el("tr", null, [
      el("td", { cls: "key", text: "vuln" }),
      el("td", { cls: "key", text: "self-conf" }),
      el("td", { cls: "key", text: "temp" }),
      el("td", { cls: "key", text: "cites" }),
      el("td", { cls: "key", text: "evidence" }),
    ]));
    for (const v of votes) {
      tbl.appendChild(el("tr", null, [
        el("td", { cls: "val", text: String(v.is_vulnerable) }),
        el("td", { cls: "val", text: v.self_confidence != null ? v.self_confidence.toFixed(2) : "—" }),
        el("td", { cls: "val", text: v.temperature != null ? v.temperature : "—" }),
        el("td", { cls: "val", text: v.n_citations }),
        el("td", { cls: "val", text: v.n_evidence_refs }),
      ]));
    }
    body.appendChild(tbl);
    det.appendChild(body);
    return det;
  }

  function renderProcessDiagnostics(finding, c) {
    const ps = c.process_summary || null;
    const det = el("details", { cls: "collapsible fh-block" });
    det.appendChild(el("summary", null, [el("span", { text: "Process diagnostics" })]));
    const body = el("div", { cls: "body" });
    const rows = [];
    if (ps) {
      rows.push(["evidence_items", ps.evidence_items_count]);
      rows.push(["failed_tool_calls", ps.failed_tool_calls_count]);
      rows.push(["reanalysis_count", ps.reanalysis_count]);
      rows.push(["research_stall_streak", ps.research_stall_streak]);
    }
    rows.push(["llm_calls", c.llm_calls_count]);
    rows.push(["tool_calls", c.tool_calls_count]);
    rows.push(["total_tokens", c.total_tokens ? c.total_tokens.total : null]);
    rows.push(["duration", fmtMs(c.total_duration_ms)]);
    body.appendChild(renderKvTable(rows));
    const trail = criticTrail(finding);
    if (trail.length) {
      body.appendChild(el("h4", { text: "Critic trail" }));
      body.appendChild(el("div", { cls: "mono", text: trail.map((t) => t.decision).join(" → ") }));
      const last = trail[trail.length - 1];
      if (last && last.weakest_point) body.appendChild(dim("weakest point: " + last.weakest_point));
    }
    if (!ps) body.appendChild(el("div", { cls: "muted", text: "Process counters not in this log (pre-v2)." }));
    det.appendChild(body);
    return det;
  }

  function renderFindingHeader(finding) {
    const card = el("div", { cls: "finding-header" });
    card.appendChild(el("div", { cls: "fh-title", text: "Finding " + shortenHash(finding.findingId) }));
    const c = finding.completeEvent;
    if (!c) {
      card.appendChild(el("div", { cls: "muted", text: "Finding incomplete (no finding_complete event)." }));
      return card;
    }
    const d = c.final_decision || {};
    const bd = c.confidence_breakdown || null;
    const ps = c.process_summary || null;
    const s = finding.startEvent;

    const parts = [];
    parts.push("conf " + (d.confidence != null ? d.confidence.toFixed(2) : "—"));
    parts.push("vuln=" + String(d.is_vulnerable));
    if (s && s.finding && s.finding.cweID) parts.push("CWE-" + s.finding.cweID);
    if (s && s.checklist_id) parts.push("checklist " + s.checklist_id + " (" + (s.checklist_selection_method || "?") + ")");
    if (c.stop_reason) parts.push("stop " + c.stop_reason);

    const voted = d.sample_count != null ? d.sample_count : findingSampleCount(finding);
    const loops = ps ? ps.reanalysis_count : reanalysisCount(c);
    const attempts = findingSampleCount(finding);
    let countText = voted + " voted";
    if (loops) countText += " · " + loops + " reanalysis loop" + (loops === 1 ? "" : "s");
    if (attempts && attempts !== voted) countText += " · " + attempts + " attempts";
    parts.push(countText);
    parts.push(fmtMs(c.total_duration_ms));
    if (c.total_tokens && c.total_tokens.total) parts.push(fmtTokens(c.total_tokens.total) + " tok");

    const verdict = el("div", { cls: "fh-verdict" }, [
      el("span", { cls: "state-badge state-" + (d.suggested_state || ""), text: d.suggested_state || "—" }),
      document.createTextNode(" "),
      dim(parts.join(" · ")),
    ]);
    card.appendChild(verdict);

    card.appendChild(renderConfidenceBreakdown(d, bd));
    card.appendChild(renderSampleVotes(bd));
    card.appendChild(renderProcessDiagnostics(finding, c));
    return card;
  }

  function renderFlow(finding) {
    const stats = findingNodeStats(finding);
    const topo = el("div", { cls: "topology" });
    NODE_NAMES.forEach((node, idx) => {
      if (idx > 0) topo.appendChild(el("span", { cls: "topo-arrow", text: "→" }));
      const visited = stats.visits[node] > 0;
      const box = el("div", { cls: "topo-node" + (visited ? " visited" : "") }, [
        el("div", { text: node }),
        el("div", {
          cls: "visit-count",
          text:
            stats.visits[node] +
            "× · " +
            fmtMs(stats.durations[node]),
        }),
      ]);
      topo.appendChild(box);
    });

    const traversalSteps = findingTraversal(finding);
    const traversal = el("div", { cls: "traversal" }, [
      el("span", { cls: "flow-label", text: "Traversal:" }),
    ]);
    traversalSteps.forEach((step, idx) => {
      if (idx > 0) traversal.appendChild(el("span", { cls: "arrow", text: " → " }));
      traversal.appendChild(
        el("span", { cls: "step " + step.node, text: step.node + "(" + (step.visitIndex + 1) + ")" })
      );
    });

    return el("div", { cls: "flow-section" }, [topo, traversal]);
  }

  function renderTimeline(tab, session) {
    const tabState = State.perTab.get(tab.id);
    const wrap = el("div", { cls: "timeline" });

    const finding = tabState.selectedFinding
      ? session.findings.get(tabState.selectedFinding)
      : null;

    const q = (tabState.searchQuery || "").trim().toLowerCase();

    // Always show session-level events as a header section.
    const headerEvents = session.events.filter((ev) =>
      ev.type === "session_start" ||
      ev.type === "preprocessing_complete" ||
      ev.type === "session_end"
    );

    if (headerEvents.length) {
      wrap.appendChild(el("div", { cls: "timeline-section-header", text: "Session lifecycle" }));
      for (const ev of headerEvents) {
        if (!matchesSearch(ev, q)) continue;
        wrap.appendChild(renderEventRow(tab, session, ev));
      }
    }

    if (finding) {
      wrap.appendChild(
        el("div", {
          cls: "timeline-section-header",
          text: "Finding " + shortenHash(finding.findingId),
        })
      );
      for (const ev of finding.events) {
        if (!matchesSearch(ev, q)) continue;
        wrap.appendChild(renderEventRow(tab, session, ev));
      }
    } else if (!q) {
      wrap.appendChild(
        el("div", {
          cls: "empty-state",
          text: "Click a finding row above to load its timeline.",
        })
      );
    } else {
      // Search across all findings if no finding selected.
      for (const fid of session.findingOrder) {
        const f = session.findings.get(fid);
        let added = false;
        for (const ev of f.events) {
          if (!matchesSearch(ev, q)) continue;
          if (!added) {
            wrap.appendChild(
              el("div", {
                cls: "timeline-section-header",
                text: "Finding " + shortenHash(fid),
              })
            );
            added = true;
          }
          wrap.appendChild(renderEventRow(tab, session, ev));
        }
      }
    }
    return wrap;
  }

  function matchesSearch(ev, q) {
    if (!q) return true;
    const blob = JSON.stringify(ev).toLowerCase();
    return blob.indexOf(q) >= 0;
  }

  function eventKey(ev) {
    return ev.session_id + ":" + ev.seq;
  }

  function renderEventRow(tab, session, ev) {
    const tabState = State.perTab.get(tab.id);
    const isActive = tabState.activeEventKey === eventKey(ev);
    const row = el(
      "div",
      {
        cls: "event-row" + (isActive ? " active" : ""),
        on: {
          click: () => {
            tabState.activeEventKey = eventKey(ev);
            const inspector = document.querySelector(".inspector-pane");
            if (inspector) {
              clear(inspector);
              inspector.appendChild(renderInspector(ev, session));
            }
            for (const r of document.querySelectorAll(".event-row.active")) {
              r.classList.remove("active");
            }
            row.classList.add("active");
          },
        },
      },
      [
        el("span", { cls: "ts", text: fmtTime(ev.ts) }),
        el("span", { cls: "etype " + ev.type, text: ev.type }),
        renderEventSummary(ev),
      ]
    );
    return row;
  }

  function renderEventSummary(ev) {
    const sum = el("span", { cls: "summary" });
    switch (ev.type) {
      case "session_start":
        sum.appendChild(document.createTextNode(ev.model || ""));
        if (ev.project_name) {
          sum.appendChild(dim(" · " + ev.project_name));
        }
        break;
      case "preprocessing_complete": {
        const parts = [];
        const o = ev.obfuscation_report;
        if (o) {
          parts.push((o.total_files_modified || 0) + " files");
          parts.push((o.total_replacements || 0) + " obfuscations");
        }
        const m = ev.masking_report;
        if (m) {
          parts.push((m.total_secrets_masked || 0) + " secrets masked");
        }
        sum.appendChild(document.createTextNode(parts.join(" · ") || "—"));
        break;
      }
      case "finding_start":
        sum.appendChild(document.createTextNode(shortenHash(ev.finding_id)));
        if (ev.finding && ev.finding.cweID) sum.appendChild(dim(" · CWE-" + ev.finding.cweID));
        if (ev.checklist_id) sum.appendChild(dim(" · checklist=" + ev.checklist_id));
        if (ev.checklist_selection_method)
          sum.appendChild(dim(" (" + ev.checklist_selection_method + ")"));
        break;
      case "graph_invoke_start":
        sum.appendChild(document.createTextNode("recursion_limit=" + (ev.recursion_limit || "?")));
        break;
      case "graph_invoke_end":
        sum.appendChild(document.createTextNode(fmtMs(ev.duration_ms)));
        break;
      case "node_enter":
        sum.appendChild(
          document.createTextNode(ev.node + " #" + ((ev.visit_index || 0) + 1))
        );
        if (ev.state_snapshot) {
          const ss = ev.state_snapshot;
          const parts = [];
          if (ss.evidence_items_count != null) parts.push("evidence=" + ss.evidence_items_count);
          if (ss.samples_count) parts.push("samples=" + ss.samples_count);
          if (ss.reanalysis_count) parts.push("reanalysis=" + ss.reanalysis_count);
          if (ss.last_critique_decision) parts.push("critique=" + ss.last_critique_decision);
          if (parts.length) sum.appendChild(dim(" · " + parts.join(", ")));
        }
        break;
      case "node_exit":
        sum.appendChild(document.createTextNode(ev.node + " · " + fmtMs(ev.duration_ms)));
        break;
      case "llm_call": {
        const parts = [];
        if (ev.node) parts.push(ev.node);
        const tag = [];
        if (ev.mode) tag.push(ev.mode);
        if (ev.structured_schema) tag.push(ev.structured_schema);
        if (tag.length) parts.push(tag.join(" "));
        if (ev.temperature != null) parts.push("T=" + ev.temperature);
        const u = ev.usage_metadata;
        if (u) parts.push(fmtTokens(u.input_tokens) + "→" + fmtTokens(u.output_tokens) + " tok");
        parts.push(fmtMs(ev.duration_ms));
        sum.appendChild(document.createTextNode(parts.join(" · ")));
        break;
      }
      case "tool_call": {
        const name = ev.tool_name || "?";
        let head = name;
        if (ev.args) {
          const firstKey = Object.keys(ev.args)[0];
          if (firstKey) {
            const v = ev.args[firstKey];
            const sv = typeof v === "string" ? v : JSON.stringify(v);
            head += "(" + (sv.length > 60 ? sv.slice(0, 60) + "…" : sv) + ")";
          }
        }
        sum.appendChild(document.createTextNode(head));
        const tail = [];
        if (ev.result_chars != null) tail.push(fmtBytes(ev.result_chars));
        else if (ev.result != null) tail.push(fmtBytes(approxStringSize(ev.result)));
        tail.push(fmtMs(ev.duration_ms));
        sum.appendChild(dim(" · " + tail.join(" · ")));
        break;
      }
      case "route_decision":
        sum.appendChild(document.createTextNode(ev.from_node + " → " + ev.to_node));
        if (ev.predicate) sum.appendChild(dim(" (" + ev.predicate + ")"));
        break;
      case "error":
        sum.appendChild(document.createTextNode((ev.scope || "?") + " · " + (ev.error_type || "")));
        if (ev.error_message)
          sum.appendChild(dim(" · " + ev.error_message.slice(0, 80)));
        break;
      case "finding_complete": {
        const d = ev.final_decision || {};
        const parts = [];
        if (d.suggested_state) parts.push(d.suggested_state);
        if (d.confidence != null) parts.push("conf=" + d.confidence.toFixed(2));
        if (ev.total_duration_ms != null) parts.push(fmtMs(ev.total_duration_ms));
        if (ev.llm_calls_count != null) parts.push(ev.llm_calls_count + " LLM");
        if (ev.tool_calls_count != null) parts.push(ev.tool_calls_count + " tools");
        if (ev.total_tokens && ev.total_tokens.total)
          parts.push(fmtTokens(ev.total_tokens.total) + " tok");
        sum.appendChild(document.createTextNode(parts.join(" · ")));
        break;
      }
      case "session_end":
        sum.appendChild(
          document.createTextNode(
            (ev.total_findings || 0) + " findings · " + fmtMs(ev.total_duration_ms)
          )
        );
        break;
      default:
        sum.appendChild(document.createTextNode(""));
    }
    return sum;
  }

  function dim(text) {
    return el("span", { cls: "dim", text: text });
  }

  // ===== Inspector =====

  function renderInspector(ev, session) {
    const wrap = el("div");
    wrap.appendChild(el("h3", { text: ev.type }));
    wrap.appendChild(renderKvTable(eventMeta(ev)));
    const body = inspectorBody(ev, session);
    if (body) wrap.appendChild(body);
    wrap.appendChild(collapsibleJson("Raw event", ev));
    return wrap;
  }

  function eventMeta(ev) {
    const meta = [
      ["timestamp", ev.ts],
      ["seq", ev.seq],
      ["session_id", ev.session_id],
    ];
    if (ev.finding_id) meta.push(["finding_id", ev.finding_id]);
    if (ev.node) meta.push(["node", ev.node]);
    if (ev.run_id) meta.push(["run_id", ev.run_id]);
    if (ev.parent_run_id) meta.push(["parent_run_id", ev.parent_run_id]);
    return meta;
  }

  function renderKvTable(pairs) {
    const t = el("table", { cls: "kv-table" });
    for (const [k, v] of pairs) {
      if (v == null || v === "") continue;
      t.appendChild(
        el("tr", null, [
          el("td", { cls: "key", text: k }),
          el("td", { cls: "val", text: String(v) }),
        ])
      );
    }
    return t;
  }

  function collapsibleJson(label, value) {
    const size = approxStringSize(value);
    const det = el("details", { cls: "collapsible" });
    const sum = el("summary", null, [
      el("span", { text: label }),
      el("span", { cls: "summary-meta", text: fmtBytes(size) }),
    ]);
    det.appendChild(sum);
    let opened = false;
    det.addEventListener("toggle", () => {
      if (det.open && !opened) {
        opened = true;
        const body = el("div", { cls: "body" });
        if (size > INLINE_CONTENT_LIMIT) {
          body.textContent = jsonPretty(value).slice(0, INLINE_CONTENT_LIMIT) + "\n…";
          body.appendChild(
            el(
              "div",
              { cls: "truncated" },
              [
                "Content truncated (" + fmtBytes(size) + ").",
                el("button", {
                  text: "Show all",
                  on: { click: () => openModal(label, jsonPretty(value)) },
                }),
              ]
            )
          );
        } else {
          body.textContent = jsonPretty(value);
        }
        det.appendChild(body);
      }
    });
    return det;
  }

  function collapsibleText(label, text) {
    const size = (text || "").length;
    const det = el("details", { cls: "collapsible" });
    det.appendChild(
      el("summary", null, [
        el("span", { text: label }),
        el("span", { cls: "summary-meta", text: fmtBytes(size) }),
      ])
    );
    let opened = false;
    det.addEventListener("toggle", () => {
      if (det.open && !opened) {
        opened = true;
        const body = el("div", { cls: "body" });
        if (size > INLINE_CONTENT_LIMIT) {
          body.textContent = (text || "").slice(0, INLINE_CONTENT_LIMIT) + "\n…";
          body.appendChild(
            el(
              "div",
              { cls: "truncated" },
              [
                "Truncated (" + fmtBytes(size) + ").",
                el("button", {
                  text: "Show all",
                  on: { click: () => openModal(label, text || "") },
                }),
              ]
            )
          );
        } else {
          body.textContent = text || "";
        }
        det.appendChild(body);
      }
    });
    return det;
  }

  function inspectorBody(ev, session) {
    switch (ev.type) {
      case "session_start":
        return renderKvTable([
          ["model", ev.model],
          ["project_name", ev.project_name],
          ["project_id", ev.project_id],
          ["scan_id", ev.scan_id],
          ["branch", ev.branch],
          ["repo_url", ev.repo_url],
          ["log_mode", ev.log_mode],
          ["agent_config", el("pre", { text: jsonPretty(ev.agent_config) })],
        ].map((p) => [p[0], typeof p[1] === "object" ? p[1] : p[1]])); // identity, leaves nodes as nodes
      case "preprocessing_complete":
        return inspectPreprocessing(ev);
      case "finding_start":
        return inspectFindingStart(ev);
      case "graph_invoke_start":
        return renderKvTable([["recursion_limit", ev.recursion_limit]]);
      case "graph_invoke_end":
        return renderKvTable([["duration_ms", fmtMs(ev.duration_ms)]]);
      case "node_enter":
        return inspectNodeEnter(ev);
      case "node_exit":
        return inspectNodeExit(ev);
      case "llm_call":
        return inspectLlmCall(ev);
      case "tool_call":
        return inspectToolCall(ev);
      case "route_decision":
        return inspectRouteDecision(ev);
      case "error":
        return renderKvTable([
          ["scope", ev.scope],
          ["error_type", ev.error_type],
          ["error_message", ev.error_message],
          ["retry_attempted", String(!!ev.retry_attempted)],
        ]);
      case "finding_complete":
        return inspectFindingComplete(ev, session);
      case "session_end":
        return inspectSessionEnd(ev);
      default:
        return null;
    }
  }

  function inspectPreprocessing(ev) {
    const wrap = el("div");
    if (ev.obfuscation_report) {
      wrap.appendChild(el("h4", { text: "Obfuscation" }));
      const o = ev.obfuscation_report;
      wrap.appendChild(
        renderKvTable([
          ["total_files_processed", o.total_files_processed],
          ["total_files_modified", o.total_files_modified],
          ["total_replacements", o.total_replacements],
          ["by_type", o.replacements_by_type ? JSON.stringify(o.replacements_by_type) : "—"],
        ])
      );
      if (o.entries) wrap.appendChild(collapsibleJson("Entries", o.entries));
    }
    if (ev.masking_report) {
      wrap.appendChild(el("h4", { text: "Secret masking" }));
      const m = ev.masking_report;
      wrap.appendChild(
        renderKvTable([
          ["csv_path", m.csv_path],
          ["total_entries_in_csv", m.total_entries_in_csv],
          ["total_secrets_masked", m.total_secrets_masked],
          ["files_modified", m.files_modified],
        ])
      );
      if (m.entries) wrap.appendChild(collapsibleJson("Entries", m.entries));
      if (m.skipped_entries) wrap.appendChild(collapsibleJson("Skipped entries", m.skipped_entries));
    }
    return wrap;
  }

  function inspectFindingStart(ev) {
    const wrap = el("div");
    wrap.appendChild(el("h4", { text: "Finding" }));
    if (ev.finding) {
      const f = ev.finding;
      wrap.appendChild(
        renderKvTable([
          ["resultHash", f.resultHash],
          ["queryName", f.queryName],
          ["cweID", f.cweID],
          ["severity", f.severity],
          ["language", f.language],
          ["state", f.state],
        ])
      );
      wrap.appendChild(collapsibleJson("Finding (full)", f));
    }
    wrap.appendChild(el("h4", { text: "Checklist" }));
    wrap.appendChild(
      renderKvTable([
        ["checklist_id", ev.checklist_id],
        ["selection_method", ev.checklist_selection_method],
      ])
    );
    return wrap;
  }

  function inspectNodeEnter(ev) {
    const wrap = el("div");
    wrap.appendChild(el("h4", { text: "State snapshot" }));
    const ss = ev.state_snapshot || {};
    wrap.appendChild(
      renderKvTable([
        ["evidence_items_count", ss.evidence_items_count],
        ["failed_tool_calls_count", ss.failed_tool_calls_count],
        ["samples_count", ss.samples_count],
        ["research_iterations", ss.research_iterations],
        ["reanalysis_count", ss.reanalysis_count],
        ["last_critique_decision", ss.last_critique_decision],
        ["visit_index", ev.visit_index],
      ])
    );
    if (ss.code_bank_summary) {
      wrap.appendChild(el("h4", { text: "Code bank (" + ss.code_bank_summary.length + " items)" }));
      const tbl = el("table", { cls: "kv-table" });
      for (const item of ss.code_bank_summary) {
        tbl.appendChild(
          el("tr", null, [
            el("td", { cls: "key", text: item.file_path || "—" }),
            el("td", {
              cls: "val",
              text: (item.relevance || "—") + " · " + fmtBytes(item.content_chars || 0),
            }),
          ])
        );
      }
      wrap.appendChild(tbl);
    }
    return wrap;
  }

  function inspectNodeExit(ev) {
    const wrap = el("div");
    wrap.appendChild(
      renderKvTable([
        ["visit_index", ev.visit_index],
        ["duration", fmtMs(ev.duration_ms)],
      ])
    );
    if (ev.state_writes) {
      wrap.appendChild(collapsibleJson("State writes", ev.state_writes));
    }
    return wrap;
  }

  function inspectLlmCall(ev) {
    const wrap = el("div");
    wrap.appendChild(
      renderKvTable([
        ["model", ev.model],
        ["mode", ev.mode],
        ["structured_schema", ev.structured_schema],
        ["temperature", ev.temperature],
        ["duration", fmtMs(ev.duration_ms)],
        ["input tokens", ev.usage_metadata ? ev.usage_metadata.input_tokens : null],
        ["output tokens", ev.usage_metadata ? ev.usage_metadata.output_tokens : null],
        ["total tokens", ev.usage_metadata ? ev.usage_metadata.total_tokens : null],
      ])
    );

    if (ev.messages_in) {
      wrap.appendChild(el("h4", { text: "Messages in" }));
      for (const msg of ev.messages_in) {
        wrap.appendChild(renderMessageBlock(msg));
      }
    } else if (ev.messages_in_hash) {
      wrap.appendChild(
        renderKvTable([
          ["messages_in_hash", ev.messages_in_hash],
          ["messages_in_chars", fmtBytes(ev.messages_in_chars)],
        ])
      );
    }

    if (ev.response) {
      const parsed = extractStructuredFromResponse(ev);
      if (parsed) {
        wrap.appendChild(el("h4", { text: "Parsed structured output" }));
        wrap.appendChild(renderKvTable(Object.entries(parsed)));
      }
      wrap.appendChild(collapsibleJson("Raw LLMResult", ev.response));
    } else if (ev.response_hash) {
      wrap.appendChild(
        renderKvTable([
          ["response_hash", ev.response_hash],
          ["response_chars", fmtBytes(ev.response_chars)],
        ])
      );
    }
    return wrap;
  }

  function extractStructuredFromResponse(ev) {
    if (ev.mode !== "structured" || !ev.response) return null;
    try {
      const gens = ev.response.generations;
      if (!gens || !gens[0] || !gens[0][0]) return null;
      const msg = gens[0][0].message;
      if (!msg) return null;
      // The structured output is in tool_calls[0].args for the function-calling path.
      const tc = msg.tool_calls;
      if (tc && tc[0] && tc[0].args) return tc[0].args;
      // Fallback: parse JSON content.
      if (typeof msg.content === "string") {
        try {
          return JSON.parse(msg.content);
        } catch (e) {
          return null;
        }
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  function renderMessageBlock(msg) {
    const role = msg.type ? msg.type.toUpperCase().replace("MESSAGE", "") : "MSG";
    const content = typeof msg.content === "string" ? msg.content : jsonPretty(msg.content);
    const len = content.length;
    const block = el("div", { cls: "message-block" });
    block.appendChild(
      el("div", { cls: "head" }, [
        el("span", { cls: "role " + role, text: role }),
        el("span", { text: fmtBytes(len) }),
      ])
    );
    const body = el("div", { cls: "body" });
    if (len > INLINE_CONTENT_LIMIT) {
      body.textContent = content.slice(0, INLINE_CONTENT_LIMIT) + "\n…";
      block.appendChild(body);
      block.appendChild(
        el("div", { cls: "truncated" }, [
          "Truncated.",
          el("button", {
            text: "Show all",
            on: { click: () => openModal(role + " message", content) },
          }),
        ])
      );
    } else {
      body.textContent = content;
      block.appendChild(body);
    }
    // Tool calls embedded in AI messages.
    if (msg.tool_calls && msg.tool_calls.length) {
      const tcBlock = el("div", { cls: "body" });
      tcBlock.style.borderTop = "1px solid var(--border)";
      tcBlock.textContent = "tool_calls: " + jsonPretty(msg.tool_calls);
      block.appendChild(tcBlock);
    }
    return block;
  }

  function inspectToolCall(ev) {
    const wrap = el("div");
    wrap.appendChild(
      renderKvTable([
        ["tool_name", ev.tool_name],
        ["duration", fmtMs(ev.duration_ms)],
      ])
    );
    if (ev.args) wrap.appendChild(collapsibleJson("Args", ev.args));
    if (ev.result != null) {
      const isStr = typeof ev.result === "string";
      if (isStr) {
        wrap.appendChild(collapsibleText("Result", ev.result));
      } else {
        wrap.appendChild(collapsibleJson("Result", ev.result));
      }
    } else if (ev.result_hash) {
      wrap.appendChild(
        renderKvTable([
          ["result_hash", ev.result_hash],
          ["result_chars", fmtBytes(ev.result_chars)],
          ["result_type", ev.result_type],
        ])
      );
    }
    return wrap;
  }

  function inspectRouteDecision(ev) {
    return el("div", null, [
      renderKvTable([
        ["from_node", ev.from_node],
        ["to_node", ev.to_node],
        ["predicate", ev.predicate],
      ]),
      el("h4", { text: "State inputs" }),
      renderKvTable(Object.entries(ev.state_inputs || {})),
    ]);
  }

  function inspectFindingComplete(ev, session) {
    const wrap = el("div");
    const d = ev.final_decision || {};
    wrap.appendChild(el("h4", { text: "Verdict" }));
    wrap.appendChild(
      renderKvTable([
        ["resultHash", d.resultHash],
        ["is_vulnerable", String(d.is_vulnerable)],
        ["confidence", d.confidence != null ? d.confidence.toFixed(2) : null],
        ["suggested_state", d.suggested_state],
      ])
    );
    if (d.justification) wrap.appendChild(collapsibleText("Justification", d.justification));
    if (ev.confidence_breakdown || d.confidence != null) {
      wrap.appendChild(renderConfidenceBreakdown(d, ev.confidence_breakdown || null));
    }
    if (ev.confidence_breakdown) wrap.appendChild(renderSampleVotes(ev.confidence_breakdown));
    const finding = session.findings.get(ev.finding_id);
    if (finding) wrap.appendChild(renderProcessDiagnostics(finding, ev));
    wrap.appendChild(el("h4", { text: "Totals" }));
    wrap.appendChild(
      renderKvTable([
        ["stop_reason", ev.stop_reason],
        ["total_duration", fmtMs(ev.total_duration_ms)],
        ["llm_calls", ev.llm_calls_count],
        ["tool_calls", ev.tool_calls_count],
        ["total_tokens", ev.total_tokens ? ev.total_tokens.total : null],
      ])
    );
    if (ev.per_node_visit_counts) {
      wrap.appendChild(el("h4", { text: "Per-node visits" }));
      wrap.appendChild(renderKvTable(Object.entries(ev.per_node_visit_counts)));
    }
    if (ev.per_node_durations_ms) {
      wrap.appendChild(el("h4", { text: "Per-node durations" }));
      const pairs = [];
      for (const [k, v] of Object.entries(ev.per_node_durations_ms)) pairs.push([k, fmtMs(v)]);
      wrap.appendChild(renderKvTable(pairs));
    }
    if (ev.per_node_token_totals) {
      wrap.appendChild(el("h4", { text: "Per-node tokens" }));
      const pairs = [];
      for (const [k, v] of Object.entries(ev.per_node_token_totals))
        pairs.push([k, (v.input || 0) + " → " + (v.output || 0) + " (" + (v.total || 0) + ")"]);
      wrap.appendChild(renderKvTable(pairs));
    }
    return wrap;
  }

  function inspectSessionEnd(ev) {
    const wrap = el("div");
    wrap.appendChild(
      renderKvTable([
        ["ended_at", ev.ended_at],
        ["total_findings", ev.total_findings],
        ["total_duration", fmtMs(ev.total_duration_ms)],
        ["llm_calls", ev.llm_calls_count],
        ["tool_calls", ev.tool_calls_count],
        ["total_tokens", ev.total_tokens ? ev.total_tokens.total : null],
        ["refusal_rate", ev.refusal_rate],
      ])
    );
    if (ev.suggested_state_counts) {
      wrap.appendChild(el("h4", { text: "Suggested states" }));
      wrap.appendChild(renderKvTable(Object.entries(ev.suggested_state_counts)));
    }
    return wrap;
  }

  // ===== Compare view =====

  function renderCompareView(tab) {
    const wrap = el("div", { cls: "compare-view" });
    const names = Array.from(State.sessions.keys());

    const pickA = compareSelect("Session A", names, tab.compare.a, (v) => {
      tab.compare.a = v;
      renderTabContent();
    });
    const pickB = compareSelect("Session B", names, tab.compare.b, (v) => {
      tab.compare.b = v;
      renderTabContent();
    });
    wrap.appendChild(el("div", { cls: "compare-header" }, [pickA, pickB]));

    const body = el("div", { cls: "compare-body" });
    const a = State.sessions.get(tab.compare.a);
    const b = State.sessions.get(tab.compare.b);
    if (!a || !b) {
      body.appendChild(el("div", { cls: "muted", text: "Pick two sessions to compare." }));
    } else if (a === b) {
      body.appendChild(el("div", { cls: "muted", text: "Pick two different sessions." }));
    } else {
      body.appendChild(renderCompareTable(a, b));
    }
    wrap.appendChild(body);
    return wrap;
  }

  function compareSelect(label, names, current, onChange) {
    const sel = el("select");
    for (const n of names) {
      const opt = el("option", { text: n, attrs: { value: n } });
      if (n === current) opt.selected = true;
      sel.appendChild(opt);
    }
    sel.addEventListener("change", () => onChange(sel.value));
    return el("div", { cls: "compare-pick" }, [
      el("label", { text: label }),
      sel,
    ]);
  }

  function renderCompareTable(a, b) {
    const wrap = el("div");
    const summary = el("div", { cls: "compare-summary" });
    summary.appendChild(summaryItem("A model", (a.startEvent && a.startEvent.model) || "—"));
    summary.appendChild(summaryItem("B model", (b.startEvent && b.startEvent.model) || "—"));
    summary.appendChild(
      summaryItem(
        "Δ tokens",
        fmtTokens(b.totals.tokens.total) +
          " − " +
          fmtTokens(a.totals.tokens.total) +
          " = " +
          fmtTokens(b.totals.tokens.total - a.totals.tokens.total)
      )
    );
    summary.appendChild(
      summaryItem(
        "Δ duration",
        fmtMs(b.totals.durationMs - a.totals.durationMs)
      )
    );
    wrap.appendChild(summary);

    const allHashes = new Set([...a.findings.keys(), ...b.findings.keys()]);
    const rows = [];
    for (const h of allHashes) {
      const fa = a.findings.get(h);
      const fb = b.findings.get(h);
      rows.push({
        hash: h,
        a: findingCompact(fa),
        b: findingCompact(fb),
      });
    }
    rows.sort((x, y) => {
      const sa = x.a.state || "";
      const sb = y.a.state || "";
      return sa.localeCompare(sb) || x.hash.localeCompare(y.hash);
    });

    const tbl = el("table", { cls: "compare-table" });
    const head = el("thead");
    head.appendChild(
      el("tr", null, [
        el("th", { text: "resultHash" }),
        el("th", { text: "A state" }),
        el("th", { text: "B state" }),
        el("th", { text: "A conf" }),
        el("th", { text: "B conf" }),
        el("th", { text: "Δ conf" }),
        el("th", { text: "A tok" }),
        el("th", { text: "B tok" }),
        el("th", { text: "Δ tok" }),
        el("th", { text: "A dur" }),
        el("th", { text: "B dur" }),
      ])
    );
    tbl.appendChild(head);
    const tbody = el("tbody");
    for (const r of rows) {
      const dConf =
        r.a.confidence != null && r.b.confidence != null
          ? r.b.confidence - r.a.confidence
          : null;
      const dTok =
        r.a.tokens != null && r.b.tokens != null ? r.b.tokens - r.a.tokens : null;
      tbody.appendChild(
        el("tr", null, [
          el("td", { cls: "mono", text: shortenHash(r.hash) }),
          el("td", { text: r.a.state || "—" }),
          el("td", { text: r.b.state || "—" }),
          el("td", { cls: "num", text: r.a.confidence != null ? r.a.confidence.toFixed(2) : "—" }),
          el("td", { cls: "num", text: r.b.confidence != null ? r.b.confidence.toFixed(2) : "—" }),
          deltaCell(dConf, (x) => x.toFixed(2)),
          el("td", { cls: "num", text: fmtTokens(r.a.tokens) }),
          el("td", { cls: "num", text: fmtTokens(r.b.tokens) }),
          deltaCell(dTok, fmtTokens),
          el("td", { cls: "num", text: fmtMs(r.a.duration) }),
          el("td", { cls: "num", text: fmtMs(r.b.duration) }),
        ])
      );
    }
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    return wrap;
  }

  function findingCompact(f) {
    if (!f || !f.completeEvent) return {};
    const c = f.completeEvent;
    const d = c.final_decision || {};
    return {
      state: d.suggested_state,
      confidence: d.confidence,
      tokens: c.total_tokens ? c.total_tokens.total : null,
      duration: c.total_duration_ms,
    };
  }

  function deltaCell(v, fmt) {
    if (v == null) return el("td", { cls: "num delta-zero", text: "—" });
    if (v === 0) return el("td", { cls: "num delta-zero", text: "0" });
    const cls = v > 0 ? "num delta-pos" : "num delta-neg";
    return el("td", { cls: cls, text: (v > 0 ? "+" : "") + fmt(v) });
  }

  // ===== Modal =====

  function openModal(title, content) {
    const dlg = document.getElementById("modal");
    document.getElementById("modal-title").textContent = title || "";
    const body = document.getElementById("modal-body");
    body.textContent = String(content || "");
    if (typeof dlg.showModal === "function") dlg.showModal();
    else dlg.setAttribute("open", "");
  }

  function closeModal() {
    const dlg = document.getElementById("modal");
    if (typeof dlg.close === "function" && dlg.open) dlg.close();
    else dlg.removeAttribute("open");
  }

  // ===== File loading =====

  function loadFiles(fileList) {
    const tasks = [];
    for (const f of fileList) {
      tasks.push(
        new Promise((resolve) => {
          const reader = new FileReader();
          reader.onload = () => {
            try {
              const events = parseJsonl(String(reader.result));
              const session = buildSession(f.name, events);
              State.sessions.set(f.name, session);
            } catch (e) {
              console.error("viewer: failed to parse " + f.name, e);
              alert("Failed to parse " + f.name + ": " + e.message);
            }
            resolve();
          };
          reader.onerror = () => {
            alert("Failed to read " + f.name);
            resolve();
          };
          reader.readAsText(f);
        })
      );
    }
    Promise.all(tasks).then(() => {
      renderSidebar();
      // Auto-open the first newly loaded session.
      if (fileList.length > 0) openSessionTab(fileList[0].name);
    });
  }

  function setupFileLoader() {
    const input = document.getElementById("file-input");
    input.addEventListener("change", () => {
      if (input.files && input.files.length) loadFiles(input.files);
      input.value = "";
    });

    const drop = document.getElementById("drop-zone");
    const stop = (e) => {
      e.preventDefault();
      e.stopPropagation();
    };
    ["dragenter", "dragover", "dragleave", "drop"].forEach((ev) =>
      drop.addEventListener(ev, stop)
    );
    drop.addEventListener("dragover", () => drop.classList.add("dragover"));
    drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
    drop.addEventListener("drop", (e) => {
      drop.classList.remove("dragover");
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length) loadFiles(dt.files);
    });
  }

  function setupCompareButton() {
    const btn = document.getElementById("compare-btn");
    btn.addEventListener("click", openCompareTab);
  }

  function setupModal() {
    document.getElementById("modal-close").addEventListener("click", closeModal);
    const dlg = document.getElementById("modal");
    dlg.addEventListener("click", (e) => {
      if (e.target === dlg) closeModal();
    });
  }

  // ===== Init =====

  document.addEventListener("DOMContentLoaded", () => {
    setupFileLoader();
    setupCompareButton();
    setupModal();
    renderSidebar();
    renderTabs();
    renderTabContent();
  });
})();
