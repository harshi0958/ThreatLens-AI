from __future__ import annotations

import uuid
import math
from datetime import datetime, timezone
from typing import Any

from backend.app.database.fallback_store import DEFAULT_SETTINGS


def severity_from_risk(score: float) -> str:
    if score >= 90:
        return 'CRITICAL'
    if score >= 70:
        return 'HIGH'
    if score >= 40:
        return 'MEDIUM'
    return 'LOW'


def _number(record: dict[str, Any], key: str) -> float:
    value = record.get(key, 0)
    if value is None or value == '':
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{key} must be numeric.') from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f'{key} must be finite and nonnegative.')
    return number


def get_rule_indicators(
    record: dict[str, Any],
    settings: dict[str, float] | None = None,
) -> list[dict[str, str | int]]:
    thresholds = {**DEFAULT_SETTINGS, **(settings or {})}
    indicators: list[dict[str, str | int]] = []
    failed = _number(record, 'failed_login_count')
    attempts = _number(record, 'login_attempts')
    packets = _number(record, 'packet_count')
    volume = _number(record, 'traffic_volume')
    anomaly = _number(record, 'anomaly_score')
    state = str(record.get('connection_state', '')).upper()

    if failed >= 3 or attempts >= 6:
        indicators.append({
            'rule_id': 'AUTH_FAILURE_BURST',
            'weight': 25,
            'reason': 'Repeated authentication failures/attempts are consistent with brute-force-like behavior.',
        })
    if state == 'SYN_SCAN' and anomaly >= thresholds['portscan_threshold']:
        indicators.append({
            'rule_id': 'SCAN_STATE_ANOMALY',
            'weight': 20,
            'reason': 'A scan-like connection state and elevated anomaly score were observed; this single record does not establish a port scan.',
        })
    if packets >= 350 and volume >= 500 and anomaly >= thresholds['dos_threshold']:
        indicators.append({
            'rule_id': 'HIGH_VOLUME_ANOMALY',
            'weight': 20,
            'reason': 'High packet count, traffic volume, and anomaly score indicate a denial-of-service-like traffic pattern, not a confirmed attack.',
        })
    if anomaly >= thresholds['anomaly_threshold']:
        indicators.append({
            'rule_id': 'ANOMALY_SCORE_ELEVATED',
            'weight': 15,
            'reason': 'The supplied anomaly score meets or exceeds the configured threshold.',
        })
    if volume >= 300:
        indicators.append({
            'rule_id': 'TRAFFIC_VOLUME_ELEVATED',
            'weight': 10,
            'reason': 'Traffic volume is elevated for this record; no baseline comparison is available.',
        })
    return indicators


def determine_category(
    record: dict[str, Any],
    indicators: list[dict[str, str | int]] | None = None,
) -> str:
    rule_ids = {item['rule_id'] for item in (indicators or [])}
    if 'AUTH_FAILURE_BURST' in rule_ids:
        return 'brute_force_like_activity'
    if 'SCAN_STATE_ANOMALY' in rule_ids:
        return 'port_scan_like_activity'
    if 'HIGH_VOLUME_ANOMALY' in rule_ids:
        return 'denial_of_service_like_traffic'
    if rule_ids:
        return 'suspicious_network_activity'
    if record.get('prediction') == 'malicious':
        return 'suspicious_network_activity'
    return 'benign'


def risk_score_from_prediction(
    prediction: str,
    confidence: float,
    record: dict[str, Any],
    settings: dict[str, float] | None = None,
) -> tuple[int, list[dict[str, str | int]], list[str]]:
    if prediction not in {'benign', 'malicious'}:
        raise ValueError('prediction must be benign or malicious.')
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError('confidence must be between 0 and 1.')
    indicators = get_rule_indicators(record, settings)
    model_contribution = 15 if prediction == 'malicious' else 0
    confidence_contribution = int(round(confidence * 15)) if prediction == 'malicious' else 0
    rule_contribution = sum(int(item['weight']) for item in indicators)
    score = min(100, model_contribution + confidence_contribution + rule_contribution)
    reasons = [str(item['reason']) for item in indicators]
    if prediction == 'malicious':
        reasons.insert(0, 'The classifier predicted malicious traffic; its confidence is uncalibrated and is not a probability guarantee.')
    if not reasons:
        reasons.append('No configured rule indicators were triggered; the classifier predicted benign traffic.')
    return score, indicators, reasons


def build_alert_payload(
    prediction: str,
    confidence: float,
    record: dict[str, Any],
    alert_id: str | None = None,
    settings: dict[str, float] | None = None,
) -> dict[str, Any]:
    risk_score, indicators, reasons = risk_score_from_prediction(prediction, confidence, record, settings)
    category = determine_category({**record, 'prediction': prediction}, indicators)
    created_at = record.get('timestamp')
    if created_at:
        try:
            parsed = datetime.fromisoformat(str(created_at).replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError('timestamp must be a valid ISO-8601 datetime.') from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        created_at = parsed.astimezone(timezone.utc).isoformat()
    else:
        created_at = datetime.now(timezone.utc).isoformat()
    thresholds = {**DEFAULT_SETTINGS, **(settings or {})}
    return {
        'alert_id': alert_id or f'ALERT-{uuid.uuid4().hex[:12].upper()}',
        'timestamp': created_at,
        'severity': severity_from_risk(risk_score),
        'category': category,
        'source_ip': record.get('src_ip', 'unknown'),
        'destination_ip': record.get('dst_ip', 'unknown'),
        'risk_score': risk_score,
        'confidence': round(float(confidence), 4),
        'confidence_type': 'uncalibrated_model_confidence',
        'alert_triggered': risk_score >= thresholds['risk_threshold'],
        'prediction': prediction,
        'rule_indicators': indicators,
        'reasons': reasons,
        'metadata': {
            'protocol': record.get('protocol', 'TCP'),
            'src_port': record.get('src_port', 0),
            'dst_port': record.get('dst_port', 0),
            'packet_count': record.get('packet_count', 0),
            'failed_login_count': record.get('failed_login_count', 0),
            'traffic_volume': record.get('traffic_volume', 0),
            'anomaly_score': record.get('anomaly_score', 0),
            'is_simulated': record.get('is_simulated', True),
        },
    }
