"""Tests for benchmark.benchmark_metrics — pure metric computation functions."""

import pytest

from benchmark.benchmark_metrics import (
    TRIAGE_CLASSES,
    extract_finding_pairs,
    compute_confusion_matrix,
    compute_per_class_metrics,
    compute_classification_metrics,
    compute_legacy_metrics,
    compute_dimensional_metrics,
    build_full_kpi_output,
)


# ---------------------------------------------------------------------------
# Helpers — reusable fixture data
# ---------------------------------------------------------------------------

def _make_finding(
    analyst_result: str,
    agent_result: str,
    score: int = 3,
    confidence: float = 0.9,
    language: str = "Java",
    category: str = "SQL_Injection",
    complexity: str = "MEDIUM",
    severity: str = "HIGH",
) -> dict:
    """Build a single enriched finding dict as stored in project data."""
    return {
        "id": "abc123",
        "language": language,
        "category": category,
        "severity": severity,
        "complexity": complexity,
        "analyst_triage": {"result": analyst_result, "justification": "..."},
        "agent_triage": {
            "result": agent_result,
            "justification": "...",
            "confidence": confidence,
        },
        "score": score,
        "confidence": confidence,
    }


def _make_project(findings: list, average_score: float = 2.5) -> dict:
    return {"project": "test-project", "findings": findings, "average_score": average_score}


@pytest.fixture
def perfect_pairs_data():
    """Dataset where analyst and agent always agree."""
    findings = [
        _make_finding("CONFIRMED", "CONFIRMED"),
        _make_finding("CONFIRMED", "CONFIRMED"),
        _make_finding("NOT_EXPLOITABLE", "NOT_EXPLOITABLE"),
        _make_finding("NOT_EXPLOITABLE", "NOT_EXPLOITABLE"),
        _make_finding("REFUSED", "REFUSED"),
    ]
    return [_make_project(findings)]


@pytest.fixture
def mixed_pairs_data():
    """Dataset with some misclassifications."""
    findings = [
        _make_finding("CONFIRMED", "CONFIRMED", score=3),
        _make_finding("CONFIRMED", "NOT_EXPLOITABLE", score=0),
        _make_finding("NOT_EXPLOITABLE", "NOT_EXPLOITABLE", score=3),
        _make_finding("NOT_EXPLOITABLE", "CONFIRMED", score=0),
        _make_finding("REFUSED", "REFUSED", score=3),
        _make_finding("REFUSED", "NOT_EXPLOITABLE", score=0),
    ]
    return [_make_project(findings)]


@pytest.fixture
def multi_project_data():
    """Two projects with different languages."""
    proj1 = _make_project([
        _make_finding("CONFIRMED", "CONFIRMED", language="Java"),
        _make_finding("NOT_EXPLOITABLE", "NOT_EXPLOITABLE", language="Java"),
    ])
    proj2 = _make_project([
        _make_finding("CONFIRMED", "CONFIRMED", language="Python"),
        _make_finding("CONFIRMED", "NOT_EXPLOITABLE", language="Python"),
    ])
    return [proj1, proj2]


# ---------------------------------------------------------------------------
# TestExtractFindingPairs
# ---------------------------------------------------------------------------

class TestExtractFindingPairs:

    def test_correct_count(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        assert len(pairs) == 5

    def test_analyst_and_agent_results_present(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        for pair in pairs:
            assert "analyst_result" in pair
            assert "agent_result" in pair

    def test_dimensional_data_present(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        for pair in pairs:
            assert "language" in pair
            assert "category" in pair
            assert "complexity" in pair
            assert "severity" in pair

    def test_empty_input(self):
        assert extract_finding_pairs([]) == []

    def test_project_without_findings(self):
        data = [{"project": "empty", "findings": []}]
        assert extract_finding_pairs(data) == []

    def test_multi_project_flattening(self, multi_project_data):
        pairs = extract_finding_pairs(multi_project_data)
        assert len(pairs) == 4


# ---------------------------------------------------------------------------
# TestConfusionMatrix
# ---------------------------------------------------------------------------

class TestConfusionMatrix:

    def test_perfect_classification(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        cm = compute_confusion_matrix(pairs)

        assert cm["CONFIRMED"]["CONFIRMED"] == 2
        assert cm["NOT_EXPLOITABLE"]["NOT_EXPLOITABLE"] == 2
        assert cm["REFUSED"]["REFUSED"] == 1

    def test_all_classes_present(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        cm = compute_confusion_matrix(pairs)

        for cls in TRIAGE_CLASSES:
            assert cls in cm
            for inner_cls in TRIAGE_CLASSES:
                assert inner_cls in cm[cls]

    def test_misclassifications(self, mixed_pairs_data):
        pairs = extract_finding_pairs(mixed_pairs_data)
        cm = compute_confusion_matrix(pairs)

        assert cm["CONFIRMED"]["NOT_EXPLOITABLE"] == 1
        assert cm["NOT_EXPLOITABLE"]["CONFIRMED"] == 1
        assert cm["REFUSED"]["NOT_EXPLOITABLE"] == 1

    def test_empty_input(self):
        cm = compute_confusion_matrix([])
        for cls in TRIAGE_CLASSES:
            for inner_cls in TRIAGE_CLASSES:
                assert cm[cls][inner_cls] == 0

    def test_off_diagonal_zeros_for_perfect(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        cm = compute_confusion_matrix(pairs)
        for actual in TRIAGE_CLASSES:
            for predicted in TRIAGE_CLASSES:
                if actual != predicted:
                    assert cm[actual][predicted] == 0


# ---------------------------------------------------------------------------
# TestPerClassMetrics
# ---------------------------------------------------------------------------

class TestPerClassMetrics:

    def test_perfect_scores(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        cm = compute_confusion_matrix(pairs)
        metrics = compute_per_class_metrics(cm)

        for cls in TRIAGE_CLASSES:
            assert metrics[cls]["precision"] == 1.0
            assert metrics[cls]["recall"] == 1.0
            assert metrics[cls]["f1_score"] == 1.0

    def test_zero_division_returns_zero(self):
        cm = {cls: {p: 0 for p in TRIAGE_CLASSES} for cls in TRIAGE_CLASSES}
        metrics = compute_per_class_metrics(cm)
        for cls in TRIAGE_CLASSES:
            assert metrics[cls]["precision"] == 0.0
            assert metrics[cls]["recall"] == 0.0
            assert metrics[cls]["f1_score"] == 0.0

    def test_precision_formula(self, mixed_pairs_data):
        pairs = extract_finding_pairs(mixed_pairs_data)
        cm = compute_confusion_matrix(pairs)
        metrics = compute_per_class_metrics(cm)

        # CONFIRMED: TP=1, FP=1 (NOT_EXPLOITABLE predicted as CONFIRMED)
        # precision = 1/(1+1) = 0.5
        assert metrics["CONFIRMED"]["precision"] == 0.5

    def test_recall_formula(self, mixed_pairs_data):
        pairs = extract_finding_pairs(mixed_pairs_data)
        cm = compute_confusion_matrix(pairs)
        metrics = compute_per_class_metrics(cm)

        # CONFIRMED: TP=1, FN=1 (CONFIRMED predicted as NOT_EXPLOITABLE)
        # recall = 1/(1+1) = 0.5
        assert metrics["CONFIRMED"]["recall"] == 0.5

    def test_f1_formula(self, mixed_pairs_data):
        pairs = extract_finding_pairs(mixed_pairs_data)
        cm = compute_confusion_matrix(pairs)
        metrics = compute_per_class_metrics(cm)

        # CONFIRMED: precision=0.5, recall=0.5 => F1 = 2*0.5*0.5/(0.5+0.5) = 0.5
        assert metrics["CONFIRMED"]["f1_score"] == 0.5


# ---------------------------------------------------------------------------
# TestClassificationMetrics
# ---------------------------------------------------------------------------

class TestClassificationMetrics:

    def test_sample_count(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        result = compute_classification_metrics(pairs)
        assert result["sample_count"] == 5

    def test_confusion_matrix_present(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        result = compute_classification_metrics(pairs)
        assert "confusion_matrix" in result

    def test_per_class_metrics_present(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        result = compute_classification_metrics(pairs)
        assert "per_class_metrics" in result
        for cls in TRIAGE_CLASSES:
            assert cls in result["per_class_metrics"]

    def test_empty_input(self):
        result = compute_classification_metrics([])
        assert result["sample_count"] == 0


# ---------------------------------------------------------------------------
# TestLegacyMetrics
# ---------------------------------------------------------------------------

class TestLegacyMetrics:

    def test_accuracy_calculation(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        legacy = compute_legacy_metrics(pairs)
        assert legacy["average_accuracy"] == 100.0

    def test_partial_accuracy(self, mixed_pairs_data):
        pairs = extract_finding_pairs(mixed_pairs_data)
        legacy = compute_legacy_metrics(pairs)
        # 3 correct out of 6 => 50%
        assert legacy["average_accuracy"] == 50.0

    def test_empty_input(self):
        legacy = compute_legacy_metrics([])
        assert legacy["average_accuracy"] == 0.0
        assert legacy["average_score"] == 0.0
        assert legacy["average_confidence"] == 0.0

    def test_score_and_confidence_averages(self):
        findings = [
            _make_finding("CONFIRMED", "CONFIRMED", score=4, confidence=0.8),
            _make_finding("CONFIRMED", "CONFIRMED", score=2, confidence=0.6),
        ]
        pairs = extract_finding_pairs([_make_project(findings)])
        legacy = compute_legacy_metrics(pairs)
        assert legacy["average_score"] == 3.0
        assert legacy["average_confidence"] == 0.7


# ---------------------------------------------------------------------------
# TestDimensionalMetrics
# ---------------------------------------------------------------------------

class TestDimensionalMetrics:

    def test_grouping_by_language(self, multi_project_data):
        pairs = extract_finding_pairs(multi_project_data)
        result = compute_dimensional_metrics(pairs, "language")

        group_names = [list(d.keys())[0] for d in result]
        assert "Java" in group_names
        assert "Python" in group_names

    def test_sample_count_per_group(self, multi_project_data):
        pairs = extract_finding_pairs(multi_project_data)
        result = compute_dimensional_metrics(pairs, "language")

        for entry in result:
            name = list(entry.keys())[0]
            assert entry[name]["sample_count"] == 2

    def test_classification_and_legacy_metrics_per_group(self, multi_project_data):
        pairs = extract_finding_pairs(multi_project_data)
        result = compute_dimensional_metrics(pairs, "language")

        for entry in result:
            name = list(entry.keys())[0]
            data = entry[name]
            assert "confusion_matrix" in data
            assert "per_class_metrics" in data
            assert "average_accuracy" in data
            assert "average_score" in data
            assert "average_confidence" in data

    def test_single_group(self, perfect_pairs_data):
        pairs = extract_finding_pairs(perfect_pairs_data)
        result = compute_dimensional_metrics(pairs, "language")
        assert len(result) == 1
        assert list(result[0].keys())[0] == "Java"


# ---------------------------------------------------------------------------
# TestBuildFullKpiOutput
# ---------------------------------------------------------------------------

class TestBuildFullKpiOutput:

    def test_all_sections_present(self, perfect_pairs_data):
        output = build_full_kpi_output(perfect_pairs_data)

        assert "sample_count" in output
        assert "confusion_matrix" in output
        assert "per_class_metrics" in output
        assert "average_accuracy" in output
        assert "average_score" in output
        assert "average_confidence" in output
        assert "language_kpi" in output
        assert "category_kpi" in output
        assert "complexity_kpi" in output
        assert "severity_kpi" in output

    def test_classification_metrics_ordered_before_legacy(self, perfect_pairs_data):
        output = build_full_kpi_output(perfect_pairs_data)
        keys = list(output.keys())

        # Classification keys come before legacy keys
        assert keys.index("sample_count") < keys.index("average_accuracy")
        assert keys.index("confusion_matrix") < keys.index("average_score")
        assert keys.index("per_class_metrics") < keys.index("average_confidence")

    def test_empty_input(self):
        output = build_full_kpi_output([])
        assert output["sample_count"] == 0
        assert output["average_accuracy"] == 0.0

    def test_dimensional_kpis_have_sample_count(self, multi_project_data):
        output = build_full_kpi_output(multi_project_data)

        for kpi_key in ("language_kpi", "category_kpi", "complexity_kpi", "severity_kpi"):
            for entry in output[kpi_key]:
                name = list(entry.keys())[0]
                assert "sample_count" in entry[name]

    def test_multi_project_aggregation(self, multi_project_data):
        output = build_full_kpi_output(multi_project_data)
        assert output["sample_count"] == 4
