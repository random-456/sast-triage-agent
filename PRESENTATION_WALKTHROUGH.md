# Triage agent: presentation walkthrough

> Personal speaking aid, not part of the shipped docs. Do not merge this file
> into `dev` or `main`. It explains the functional analysis flow in plain words
> and gives a running order for presenting it. The authoritative reference is
> `docs/architecture.md`; this just makes it talkable.

---

## 1. The one-sentence pitch

A SAST scanner (Checkmarx) produces a long list of "possible vulnerabilities".
Most are false alarms. A human has to read each one and decide: real problem or
not? This agent does that first pass automatically. For every finding it reads
the relevant code, decides whether the finding is a real exploitable bug, says
how sure it is, and hands the unclear ones to a human. It only reads. It never
changes anything in Checkmarx. The verdicts are advice, written to a local file.

---

## 2. The mental model: four jobs, four workers

Think of one finding being handed to a small team of four. Each has one job.

1. **Researcher** reads the codebase. It uses three tools: read a file, search
   files, list a directory. It collects the relevant code into one shared
   notebook we call the **CODE BANK**. It does not decide anything.
2. **Analyst** looks at the CODE BANK and decides: is this exploitable, yes, no
   or "I can't tell". It also says how confident it feels. It has no tools, it
   just reasons over what the researcher gathered. One run of the analyst is
   called a **sample**.
3. **Critic** is the adversary. It reads the analyst's verdict and tries to find
   the weakest point. It then says one of three things: APPROVED, "go research
   more", or "rethink this". It runs hotter (more independent minded) than the
   analyst on purpose, so it does not just nod along.
4. **Aggregator** is not an AI. It is plain arithmetic. It takes all the analyst
   samples, holds a vote, and produces the one final answer plus a calibrated
   confidence number.

Why split them up? Three reasons, all worth saying out loud:
- Reading code and judging code are different skills. Mixing them makes the
  model wander between investigating and concluding.
- A separate critic beats "marking your own homework". A model asked to check
  itself almost always says "looks fine".
- A trustworthy confidence number comes from several independent opinions
  agreeing, not from one model saying "I'm 95% sure" (models say that about
  everything).

---

## 3. Vocabulary (say these once, early)

- **Finding**: one alert from Checkmarx. "Possible SQL injection at line 88."
- **Sample**: one complete run of the analyst giving its verdict. We run the
  analyst more than once on the same finding to get independent opinions.
- **Corroboration**: independent confirmation. If a second analyst run, done
  separately, lands on the same answer, it *corroborates* (backs up) the first.
  One run alone has nothing confirming it, so it has "no corroboration". The
  word just means "a second source agrees".
- **Agreement rate**: of all the samples, what fraction voted for the winning
  answer. 3 samples, 2 say "not exploitable", 1 says "exploitable" gives an
  agreement rate of 2 out of 3, so 0.67 (67%).
- **Confidence**: a number from 0 to 1 saying how sure the system is. Important:
  this is *not* the analyst's own gut feeling. It is computed by the aggregator
  from how much the samples agree and how much evidence backs them.
- **Disposition / suggested_state**: the final label we put on the finding.
  There are four: CONFIRMED, NOT_EXPLOITABLE, PROPOSED_NOT_EXPLOITABLE, REFUSED.
- **Circuit breaker**: a safety limit that stops a loop from running forever.

---

## 4. The flow, step by step

For each finding the team runs this little loop:

```
research  ->  analyst  ->  critic  ->  (loop back, or finish)
                                  ->  aggregate  ->  final answer
```

In words:

1. **Research** gathers code into the CODE BANK.
2. **Analyst** produces one sample (one verdict).
3. **Critic** reviews that sample and decides:
   - **APPROVED**: good enough. Now the system asks "do we have enough samples?"
     If not, it goes back to the analyst for *another* independent sample. If
     yes, it goes to the aggregator.
   - **Go research more** (NEEDS_MORE_RESEARCH): the verdict can't be backed by
     what we have. Back to the researcher.
   - **Rethink** (REANALYZE): we have enough code, but the reasoning is flawed.
     Back to the analyst, who *rewrites the same sample* instead of adding a new
     one.
4. **Aggregate** votes over the samples and produces the final answer.

The key thing to stress: a *new, independent* sample is only collected after an
APPROVED verdict. "Go research more" and "rethink" both rework the *current*
sample, they do not add a fresh independent opinion.

---

## 5. How many samples? (the question you will get asked)

The system wants at least **2** independent samples, and normally gets 2 or 3.
It is adaptive so it does not pay for samples it does not need:

- It aims for **2 samples** to start.
- If those 2 agree, it stops at 2.
- If those 2 disagree (a 1 to 1 tie), it adds a **3rd tiebreaker** sample, and
  3 is the maximum.

**Can a single sample be enough?** Technically yes, but only when the loop gets
cut short before a second sample is ever collected. That happens when the critic
keeps rejecting the first sample and the system hits a safety limit (a circuit
breaker) and gives up. In that case we are left with one never-approved sample.

That single sample's agreement rate is **trivially 1.0** (one voter agreeing
with itself, 1 out of 1 = 100%). That looks like perfect confidence but it is
meaningless: nobody corroborated it. The system knows this, so:

- It does **not** credit any agreement for a lone sample. Its confidence rests
  only on how much evidence backs it, and the agreement rate is reported as
  "undefined" rather than a fake 100%.
- And if that lone sample said "not exploitable", the system caps its confidence
  below the threshold and routes it to a human (see section 7).

So: one sample is possible, but it is treated as weak by design and pushed to
human review, never accepted as a confident "all clear".

---

## 6. How the confidence number is built

When there is a clear majority and at least 2 samples:

```
confidence = 0.7 * agreement_rate  +  0.3 * evidence_strength
```

- **agreement_rate**: how much the samples agree (section 3).
- **evidence_strength**: a 0 to 1 measure of how well grounded the samples are.
  It rewards consulting several distinct files and citing specific lines. More
  files and more citations means higher evidence strength.

So confidence is high when the independent opinions agree *and* they cite real
code. Both the 0.7 weight and the evidence measure are deliberate placeholders,
to be tuned against a labelled "gold set" later.

---

## 7. The four outcomes (the payoff slide)

The final label is derived by a plain rule from two things: the classification
(exploitable / not / undecided) and the confidence number. There is one
threshold, `CONFIDENCE_THRESHOLD = 0.85`.

| Outcome | When it happens | Plain meaning |
|---|---|---|
| **CONFIRMED** | Majority says "exploitable". Always, even at low confidence. | "Looks like a real bug, a human should fix it." |
| **NOT_EXPLOITABLE** | Majority says "not exploitable" AND confidence >= 0.85. | "Confident false alarm, safe to dismiss." |
| **PROPOSED_NOT_EXPLOITABLE** | Majority says "not exploitable" BUT confidence < 0.85. | "Probably a false alarm, but not sure enough. Human, please glance." |
| **REFUSED** | No majority, or no samples at all. | "I genuinely cannot decide. Human, please review." |

Two things worth emphasising:

- **A positive always wins, regardless of confidence.** Missing a real
  vulnerability is the worst outcome, so a "yes it is exploitable" is never
  downgraded for low confidence. This protects recall.
- **There are two ways to land in PROPOSED_NOT_EXPLOITABLE:**
  1. The confidence genuinely came out below 0.85.
  2. The "not exploitable" verdict came from a circuit breaker (the loop gave up
     without a real critic approval). In that case the system distrusts it and
     caps its confidence at 0.8, which is below 0.85, so it routes to a human.
     This second rule is the `NON_CONVERGENT_CONFIDENCE_CAP`. It only ever pulls
     things *toward* human review, and it never touches CONFIRMED.

So PROPOSED_NOT_EXPLOITABLE is the "I lean towards false alarm but I am not
confident enough to say so on my own" bucket. It is a safety net, not a verdict.

---

## 8. When does REFUSED happen?

REFUSED means "the system could not decide" (classification is undecided). Two
ways:

1. **No samples were produced at all** (the analyst never committed). Rare edge
   case.
2. **The votes split with no clear winner.** For example 3 samples vote
   "exploitable", "not exploitable", "undecided": no answer has a majority. The
   system refuses to guess and hands it to a human.

Is REFUSED the common default? No. The normal path is a clear majority that
becomes CONFIRMED or NOT_EXPLOITABLE. REFUSED is the deliberate "this one is
genuinely ambiguous" escape hatch. It is not an error, it is the system being
honest that a person is needed.

---

## 9. Two worked examples (good for the live demo)

**Example A: a clean confirmed bug (the happy path).**
SQL injection finding. Research reads the controller and the repository and sees
user input concatenated straight into a SQL string. Analyst sample 1 says
"exploitable, 0.92". Critic APPROVES. System collects a second independent
sample, which also says "exploitable". Two out of two agree, agreement rate 1.0.
Aggregator computes confidence around 0.82. Final label: **CONFIRMED** (a
positive is always confirmed). A human should fix it.

**Example B: a lone unapproved "all clear" (why PROPOSED exists).**
A finding gets one analyst sample saying "not exploitable, 0.9". The critic keeps
asking for more research, research can't find what it wants, the system hits its
limit and gives up. We have one never-approved sample. Its agreement rate is a
meaningless 1.0. Because it is a lone "not exploitable" from a circuit breaker,
the system caps its confidence at 0.8. 0.8 is below 0.85, so the final label is
**PROPOSED_NOT_EXPLOITABLE**, with a justification saying the analysis stopped
early and needs a human glance. The system refused to quietly mark it safe.

---

## 10. Safety limits (mention briefly, do not dwell)

The loop can never run forever. The limits:

- Research can be visited at most 5 times per finding.
- The "rethink" loop runs at most 2 times.
- Within one research visit, at most 10 tool calls.
- If research comes back empty twice in a row, stop honestly rather than burn
  the whole budget.

Whichever limit fires, the finding still ends at the aggregator with a recorded
reason for stopping, and that reason feeds the confidence cap from section 7.

---

## 11. Two constraints to repeat at the end

- **Read only.** The tool reads from Checkmarx and never writes back. Every
  label is advice, stored in a local file. A human stays in the loop.
- **The thresholds are placeholders.** 0.85 and 0.8 are conservative starting
  values, to be calibrated against a labelled gold set. Tuning them shifts
  findings between NOT_EXPLOITABLE and PROPOSED_NOT_EXPLOITABLE without changing
  the underlying classification.

---

## 12. Suggested running order for the talk

A 20 to 30 minute flow, each step has a repo doc to show on screen.

| Step | What you say | Show from the repo |
|---|---|---|
| 1. Problem | "Scanners cry wolf, humans drown in alerts." | `README.md` intro |
| 2. The four roles | Section 2 here. The team metaphor. | `docs/architecture.md` "Overview" + the topology diagram |
| 3. Vocabulary | Section 3 here. Define sample, agreement, confidence. | this doc |
| 4. The loop | Walk the research to analyst to critic to aggregate flow. | `docs/architecture.md` topology mermaid diagram |
| 5. How many samples | Section 5. The adaptive 2 to 3 sampling and the lone-sample case. | `docs/architecture.md` "Sampling-loop scenarios" (3 traces) |
| 6. Confidence | Section 6. Why agreement, not gut feeling. | `docs/architecture.md` "Aggregate node" |
| 7. The four outcomes | Section 7, the payoff table. The two thresholds. | `docs/usage-guide.md#suggested-state` |
| 8. Worked example | Walk Example A end to end live. | `docs/architecture.md` "Worked example: a SQL injection finding" |
| 9. Checklists | One line: every finding gets a CWE-specific evidence checklist that steers research, analyst and critic. | `docs/checklists.md` |
| 10. Read-only + next steps | Section 11. Advisory only, thresholds need calibration. | `docs/decisions.md`, `docs/benchmark.md` |

If you only have 10 minutes: steps 2, 4, 7, 8. The four roles, the loop, the
four outcomes, one worked example. That is the whole story.

---

## 13. Anticipated questions and crisp answers

- **"Does it change anything in Checkmarx?"** No. Read only. Output is a local
  advisory file.
- **"Can it miss a real bug?"** A positive is never downgraded for low
  confidence, so the design biases toward flagging. Genuinely ambiguous cases go
  to a human, not to "all clear".
- **"Why not just ask the model once?"** One model run says "95% sure" about
  everything. Several independent runs agreeing is a real signal. That is where
  the confidence number comes from.
- **"What's the difference between NOT_EXPLOITABLE and PROPOSED_NOT_EXPLOITABLE?"**
  Both mean "looks like a false alarm". The first is confident enough to dismiss;
  the second is not, so a human should glance. The 0.85 threshold separates them.
- **"What if the analysts disagree?"** A 1 to 1 tie adds a third sample. A real
  three-way split with no majority becomes REFUSED and goes to a human.
- **"Is this final?"** No. The thresholds are conservative placeholders pending
  calibration against a labelled dataset.
