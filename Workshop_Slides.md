# SAST Triage Agent - Workshop Slides

## Slide 1: Three AI Security Use Cases

### AppSec Team AI Initiative

**1. SAST Triage Agent**
- **Tool**: Checkmarx One findings → AI analysis → Triage decisions
- **Status**: Validation phase, benchmarking in progress
- **Impact**: 70-80% reduction in manual triage time

**2. Secrets Triage Agent**
- **Tool**: GitLeaks findings → AI validation → Context-aware filtering
- **Status**: Most mature, actively deployed
- **Impact**: Significant false positive reduction

**3. WAF Alert Qualification**
- **Tool**: WAF alerts → AI analysis → Attack vs. benign classification
- **Status**: Similar maturity to secrets triage
- **Impact**: Intelligent alert prioritization

---

## Slide 2: SAST Triage Agent Deep Dive

### Problem
- Checkmarx scans generate 100-200 findings per application
- Manual review: 5 minutes × 150 findings = 12.5 hours per scan
- Analyst fatigue leads to inconsistent decisions

### Solution Architecture
- **Input**: Checkmarx One API + Git repository clone
- **Engine**: LangChain + Vertex AI (Gemini 2.5 Flash)
- **Analysis**: AI uses 4 tools across max 15 iterations per finding
  - `read_file`: Read any source file with line numbers
  - `search_in_files`: Pattern search across entire codebase
  - `list_directory`: Explore project structure
  - `submit_triage_decision`: Final assessment with confidence

### Output
- **CONFIRMED**: Exploitable vulnerability (requires action)
- **NOT_EXPLOITABLE**: False positive (can be ignored)
- **REFUSED**: Insufficient information (human review needed)
- Interactive HTML report with full audit trail

---

## Slide 3: Implementation & Results

### Current Status
- **Phase**: Proof of concept complete, validation in progress
- **Benchmarking**: Testing against historical findings with known outcomes
- **Metrics**: Measuring accuracy, consistency, and time savings

### Technical Approach
- **Security-first design**: Path traversal protection, input validation
- **Enterprise integration**: Existing Checkmarx workflows
- **Scalability**: Handles 100+ findings per scan
- **Flexibility**: Supports different severities, branches, single findings

### Expected Impact
- **Time savings**: 8 hours → 2.5 hours per scan (65% reduction)
- **Consistency**: Same analysis standards for every finding
- **Documentation**: Complete reasoning for audit/compliance
- **Scalability**: Handle volume growth without additional headcount

### Next Steps
- Complete validation benchmarking
- Pilot deployment on high-volume applications
- Integration with existing security workflows