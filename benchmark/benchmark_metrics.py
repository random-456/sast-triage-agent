"""
Pure-function module for benchmark classification and legacy metrics.

All functions are stateless — no I/O, no logging.
"""

from typing import Dict, List

TRIAGE_CLASSES = ["CONFIRMED", "NOT_EXPLOITABLE", "REFUSED"]


def extract_finding_pairs(raw_dataset_data: List[Dict]) -> List[Dict]:
    """
    Flatten project dicts into a list of finding-pair dicts.

    Each dict contains analyst_result, agent_result, score, confidence,
    and dimensional fields (language, category, complexity, severity).

    Args:
        raw_dataset_data: List of project dicts, each with a "findings" list.

    Returns:
        List of finding-pair dicts.
    """
    pairs: List[Dict] = []
    for project in raw_dataset_data:
        for finding in project.get("findings", []):
            pairs.append({
                "analyst_result": finding.get("analyst_triage", {}).get("result", ""),
                "agent_result": finding.get("agent_triage", {}).get("result", ""),
                "score": finding.get("score", 0),
                "confidence": finding.get("confidence", 0),
                "language": finding.get("language", "Unknown"),
                "category": finding.get("category", "Unknown"),
                "complexity": finding.get("complexity", "Unknown"),
                "severity": finding.get("severity", "Unknown"),
            })
    return pairs


def compute_confusion_matrix(pairs: List[Dict]) -> Dict[str, Dict[str, int]]:
    """
    Build a 3x3 confusion matrix from finding pairs.

    Rows = actual (analyst), columns = predicted (agent).
    All three TRIAGE_CLASSES are always present even if count is 0.

    Args:
        pairs: List of finding-pair dicts with analyst_result and agent_result.

    Returns:
        Nested dict {actual: {predicted: count}}.
    """
    matrix: Dict[str, Dict[str, int]] = {
        actual: {predicted: 0 for predicted in TRIAGE_CLASSES}
        for actual in TRIAGE_CLASSES
    }
    for pair in pairs:
        actual = pair["analyst_result"]
        predicted = pair["agent_result"]
        if actual in matrix and predicted in matrix[actual]:
            matrix[actual][predicted] += 1
    return matrix


def compute_per_class_metrics(
    confusion_matrix: Dict[str, Dict[str, int]],
) -> Dict[str, Dict[str, float]]:
    """
    Compute precision, recall, and F1 per class from a confusion matrix.

    Uses safe division — returns 0.0 when the denominator is 0.

    Args:
        confusion_matrix: {actual: {predicted: count}} for all TRIAGE_CLASSES.

    Returns:
        {class_name: {precision, recall, f1_score}} for each class.
    """
    metrics: Dict[str, Dict[str, float]] = {}
    for cls in TRIAGE_CLASSES:
        tp = confusion_matrix.get(cls, {}).get(cls, 0)

        # FP = other classes predicted as cls
        fp = sum(
            confusion_matrix.get(actual, {}).get(cls, 0)
            for actual in TRIAGE_CLASSES
            if actual != cls
        )

        # FN = cls predicted as other classes
        fn = sum(
            confusion_matrix.get(cls, {}).get(predicted, 0)
            for predicted in TRIAGE_CLASSES
            if predicted != cls
        )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        metrics[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
        }
    return metrics


def compute_classification_metrics(pairs: List[Dict]) -> Dict:
    """
    Combine sample_count, confusion_matrix, and per_class_metrics.

    Args:
        pairs: List of finding-pair dicts.

    Returns:
        Dict with sample_count, confusion_matrix, and per_class_metrics.
    """
    cm = compute_confusion_matrix(pairs)
    return {
        "sample_count": len(pairs),
        "confusion_matrix": cm,
        "per_class_metrics": compute_per_class_metrics(cm),
    }


def compute_legacy_metrics(pairs: List[Dict]) -> Dict[str, float]:
    """
    Compute existing legacy metrics: average_accuracy, average_score,
    average_confidence.

    Args:
        pairs: List of finding-pair dicts.

    Returns:
        Dict with average_accuracy, average_score, average_confidence.
    """
    if not pairs:
        return {
            "average_accuracy": 0.0,
            "average_score": 0.0,
            "average_confidence": 0.0,
        }

    accurate = sum(
        1 for p in pairs if p["analyst_result"] == p["agent_result"]
    )
    total = len(pairs)
    return {
        "average_accuracy": round(accurate / total * 100, 2),
        "average_score": round(
            sum(p["score"] for p in pairs) / total, 4
        ),
        "average_confidence": round(
            sum(p["confidence"] for p in pairs) / total, 4
        ),
    }


def compute_dimensional_metrics(
    pairs: List[Dict], dimension: str,
) -> List[Dict]:
    """
    Group pairs by a dimension and compute metrics per group.

    Args:
        pairs: List of finding-pair dicts.
        dimension: Key to group by (language, category, complexity, severity).

    Returns:
        List of single-key dicts: [{dimension_value: {metrics}}].
    """
    groups: Dict[str, List[Dict]] = {}
    for pair in pairs:
        key = pair.get(dimension, "Unknown")
        groups.setdefault(key, []).append(pair)

    result: List[Dict] = []
    for group_name, group_pairs in sorted(groups.items()):
        classification = compute_classification_metrics(group_pairs)
        legacy = compute_legacy_metrics(group_pairs)
        result.append({
            group_name: {**classification, **legacy},
        })
    return result


def build_full_kpi_output(raw_dataset_data: List[Dict]) -> Dict:
    """
    Build the complete KPI dict from raw dataset data.

    Classification metrics appear first, then legacy average_score,
    then dimensional KPIs (language, category, complexity, severity).

    Args:
        raw_dataset_data: List of project dicts with enriched findings.

    Returns:
        Complete KPI output dict.
    """
    pairs = extract_finding_pairs(raw_dataset_data)
    classification = compute_classification_metrics(pairs)
    legacy = compute_legacy_metrics(pairs)

    output: Dict = {
        "sample_count": classification["sample_count"],
        "confusion_matrix": classification["confusion_matrix"],
        "per_class_metrics": classification["per_class_metrics"],
        "average_accuracy": legacy["average_accuracy"],
        "average_score": legacy["average_score"],
        "average_confidence": legacy["average_confidence"],
    }

    for dimension in ("language", "category", "complexity", "severity"):
        output[f"{dimension}_kpi"] = compute_dimensional_metrics(
            pairs, dimension,
        )

    return output
