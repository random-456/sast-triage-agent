"""
Pure-function module for benchmark classification and legacy metrics.

All functions are stateless — no I/O, no logging.
"""

from typing import Dict, List, Optional


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
        Dict with tp/fp/fn/tn counts, the vulnerable (positive) class
        precision/recall/f1_score, the non_exploitable (negative) class
        metrics, evaluated_count and refusal_rate.
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

    def _prf(hit: int, pred_pos: int, actual_pos: int) -> tuple:
        precision = hit / pred_pos if pred_pos > 0 else 0.0
        recall = hit / actual_pos if actual_pos > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        return round(precision, 4), round(recall, 4), round(f1, 4)

    # Vulnerable (positive) class maps to CONFIRMED.
    precision, recall, f1_score = _prf(tp, tp + fp, tp + fn)
    # Non-exploitable (negative) class: the dismissal-quality gate.
    ne_precision, ne_recall, ne_f1 = _prf(tn, tn + fn, tn + fp)

    return {
        "evaluated_count": len(evaluable),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "not_exploitable_precision": ne_precision,
        "not_exploitable_recall": ne_recall,
        "not_exploitable_f1": ne_f1,
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
        classification = compute_binary_classification_metrics(group_pairs)
        legacy = compute_legacy_metrics(group_pairs)
        result.append({
            group_name: {
                "sample_count": len(group_pairs),
                "binary_classification": classification,
                **legacy,
            },
        })
    return result


def build_full_kpi_output(raw_dataset_data: List[Dict]) -> Dict:
    """
    Build the complete KPI dict from raw dataset data.

    Classification metrics appear first, then the operational overlay and
    calibration, then legacy averages, then dimensional KPIs (language,
    category, complexity, severity).

    Args:
        raw_dataset_data: List of project dicts with enriched findings.

    Returns:
        Complete KPI output dict.
    """
    pairs = extract_finding_pairs(raw_dataset_data)
    legacy = compute_legacy_metrics(pairs)

    output: Dict = {
        "sample_count": len(pairs),
        "binary_classification": compute_binary_classification_metrics(pairs),
        "operational_metrics": compute_operational_metrics(pairs),
        "calibration": compute_calibration(pairs),
        "average_accuracy": legacy["average_accuracy"],
        "average_score": legacy["average_score"],
        "average_confidence": legacy["average_confidence"],
    }

    for dimension in ("language", "category", "complexity", "severity"):
        output[f"{dimension}_kpi"] = compute_dimensional_metrics(
            pairs, dimension,
        )

    return output
