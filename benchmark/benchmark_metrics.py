"""
Pure-function module for benchmark classification and legacy metrics.

All functions are stateless — no I/O, no logging.
"""

from typing import Dict, List, Optional

TRIAGE_CLASSES = ["CONFIRMED", "NOT_EXPLOITABLE", "REFUSED"]


def _result_to_is_vulnerable(result: str) -> Optional[bool]:
    """Map an analyst/agent result label to a binary classification.

    Returns None for REFUSED or any unrecognized label, so refusals are
    excluded from binary precision/recall.
    """
    if result == "CONFIRMED":
        return True
    if result == "NOT_EXPLOITABLE":
        return False
    return None


def extract_finding_pairs(raw_dataset_data: List[Dict]) -> List[Dict]:
    """
    Flatten project dicts into a list of finding-pair dicts.

    Each dict contains analyst_result, agent_result, the binary
    classifications (analyst_is_vulnerable, agent_is_vulnerable), the agent
    disposition (suggested_state), score, confidence and dimensional fields
    (language, category, complexity, severity).

    Args:
        raw_dataset_data: List of project dicts, each with a "findings" list.

    Returns:
        List of finding-pair dicts.
    """
    pairs: List[Dict] = []
    for project in raw_dataset_data:
        for finding in project.get("findings", []):
            analyst = finding.get("analyst_triage", {})
            agent = finding.get("agent_triage", {})
            analyst_result = analyst.get("result", "")
            agent_result = agent.get("result", "")

            # Prefer the explicit classification/disposition when present;
            # fall back to the result label for older enriched datasets.
            agent_is_vulnerable = agent.get("is_vulnerable", "missing")
            if agent_is_vulnerable == "missing":
                agent_is_vulnerable = _result_to_is_vulnerable(agent_result)
            suggested_state = agent.get("suggested_state") or agent_result

            pairs.append({
                "analyst_result": analyst_result,
                "agent_result": agent_result,
                "analyst_is_vulnerable": _result_to_is_vulnerable(analyst_result),
                "agent_is_vulnerable": agent_is_vulnerable,
                "suggested_state": suggested_state,
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


def compute_binary_classification_metrics(pairs: List[Dict]) -> Dict:
    """
    Precision, recall and F1 on the binary `is_vulnerable` classification.

    Positive class = vulnerable. Pairs where either side has a None
    classification (REFUSED / undecided) are excluded from precision and
    recall and counted under `refusal_rate` instead. These metrics never read
    `suggested_state`, so tuning the confidence threshold leaves them
    unchanged.

    Args:
        pairs: List of finding-pair dicts from extract_finding_pairs.

    Returns:
        Dict with tp/fp/fn/tn counts, precision, recall, f1_score,
        evaluated_count and refusal_rate.
    """
    total = len(pairs)
    refusals = sum(1 for p in pairs if p["agent_is_vulnerable"] is None)

    evaluable = [
        p
        for p in pairs
        if p["agent_is_vulnerable"] is not None
        and p["analyst_is_vulnerable"] is not None
    ]
    tp = sum(
        1 for p in evaluable
        if p["analyst_is_vulnerable"] and p["agent_is_vulnerable"]
    )
    fp = sum(
        1 for p in evaluable
        if not p["analyst_is_vulnerable"] and p["agent_is_vulnerable"]
    )
    fn = sum(
        1 for p in evaluable
        if p["analyst_is_vulnerable"] and not p["agent_is_vulnerable"]
    )
    tn = sum(
        1 for p in evaluable
        if not p["analyst_is_vulnerable"] and not p["agent_is_vulnerable"]
    )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "evaluated_count": len(evaluable),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "refusal_rate": round(refusals / total, 4) if total else 0.0,
    }


def compute_operational_metrics(pairs: List[Dict]) -> Dict:
    """
    Operational metrics computed on the agent disposition (`suggested_state`).

    These are an overlay on top of the classification metrics: they describe
    review burden and dismissal safety, not classification quality.

    Args:
        pairs: List of finding-pair dicts from extract_finding_pairs.

    Returns:
        Dict with human_review_rate, confident_dismissal_precision,
        near_miss_save_rate and refusal_rate.
    """
    total = len(pairs)

    proposed = sum(
        1 for p in pairs
        if p["suggested_state"] == "PROPOSED_NOT_EXPLOITABLE"
    )
    refusals = sum(1 for p in pairs if p["suggested_state"] == "REFUSED")

    # Among confident dismissals, the fraction truly non-exploitable.
    dismissed = [
        p for p in pairs if p["suggested_state"] == "NOT_EXPLOITABLE"
    ]
    correct_dismissals = sum(
        1 for p in dismissed if p["analyst_is_vulnerable"] is False
    )

    # Among true positives the agent classified as non-exploitable, the
    # fraction the threshold rescued into PROPOSED_NOT_EXPLOITABLE.
    near_misses = [
        p for p in pairs
        if p["analyst_is_vulnerable"] is True
        and p["agent_is_vulnerable"] is False
    ]
    rescued = sum(
        1 for p in near_misses
        if p["suggested_state"] == "PROPOSED_NOT_EXPLOITABLE"
    )

    return {
        "human_review_rate": round(proposed / total, 4) if total else 0.0,
        "confident_dismissal_precision": (
            round(correct_dismissals / len(dismissed), 4) if dismissed else None
        ),
        "near_miss_save_rate": (
            round(rescued / len(near_misses), 4) if near_misses else None
        ),
        "refusal_rate": round(refusals / total, 4) if total else 0.0,
    }


def compute_calibration(pairs: List[Dict], num_bins: int = 10) -> Dict:
    """
    Confidence-vs-correctness calibration on the binary classification.

    Bins evaluable pairs by confidence and reports per-bin average confidence,
    accuracy and count, plus the Expected Calibration Error (ECE): the
    count-weighted mean absolute gap between confidence and accuracy.

    Args:
        pairs: List of finding-pair dicts from extract_finding_pairs.
        num_bins: Number of equal-width confidence bins over [0, 1].

    Returns:
        Dict with an `ece` scalar and a `bins` table.
    """
    evaluable = [
        p
        for p in pairs
        if p["agent_is_vulnerable"] is not None
        and p["analyst_is_vulnerable"] is not None
    ]
    total = len(evaluable)

    bins: List[Dict] = []
    ece = 0.0
    for i in range(num_bins):
        low = i / num_bins
        high = (i + 1) / num_bins
        # The last bin is closed on the right so confidence 1.0 lands in it.
        in_bin = [
            p for p in evaluable
            if (low <= p["confidence"] < high)
            or (i == num_bins - 1 and p["confidence"] == 1.0)
        ]
        count = len(in_bin)
        if count == 0:
            bins.append({
                "range": [round(low, 2), round(high, 2)],
                "count": 0,
                "avg_confidence": None,
                "accuracy": None,
            })
            continue

        avg_conf = sum(p["confidence"] for p in in_bin) / count
        correct = sum(
            1 for p in in_bin
            if p["agent_is_vulnerable"] == p["analyst_is_vulnerable"]
        )
        accuracy = correct / count
        ece += (count / total) * abs(accuracy - avg_conf)

        bins.append({
            "range": [round(low, 2), round(high, 2)],
            "count": count,
            "avg_confidence": round(avg_conf, 4),
            "accuracy": round(accuracy, 4),
        })

    return {
        "ece": round(ece, 4) if total else 0.0,
        "sample_count": total,
        "bins": bins,
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
        "binary_classification": compute_binary_classification_metrics(pairs),
        "operational_metrics": compute_operational_metrics(pairs),
        "calibration": compute_calibration(pairs),
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
