from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from backend.app.core.config import ARTIFACTS_DIR
from backend.app.ml.feature_schema import EXPECTED_FEATURES, REQUIRED_RECORD_FIELDS, prepare_feature_row
from backend.app.services.threat_detection import build_alert_payload

MODEL_PATH = ARTIFACTS_DIR / 'demo_model.joblib'
METADATA_PATH = ARTIFACTS_DIR / 'model_metadata.json'


def load_model_metadata() -> dict[str, Any]:
    if not METADATA_PATH.exists():
        return {
            'model_name': 'demo_model',
            'status': 'not_trained',
            'feature_schema': EXPECTED_FEATURES,
            'created_at': None,
            'evaluation_type': 'DEMO',
        }
    try:
        metadata = json.loads(METADATA_PATH.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError('Model metadata is unreadable; retrain the model.') from exc
    if not isinstance(metadata, dict):
        raise RuntimeError('Model metadata has an invalid format; retrain the model.')
    return metadata


@lru_cache(maxsize=2)
def _load_artifact(path: str, modified_ns: int) -> dict[str, Any]:
    del modified_ns
    bundle = joblib.load(path)
    if (
        not isinstance(bundle, dict)
        or not callable(getattr(bundle.get('model'), 'predict_proba', None))
        or bundle.get('feature_columns') != EXPECTED_FEATURES
    ):
        raise RuntimeError('The local model artifact is incompatible; retrain the model.')
    return bundle


def load_model_bundle() -> dict[str, Any]:
    if not MODEL_PATH.is_file():
        raise FileNotFoundError('The trained model is not available. Run the training script.')
    return _load_artifact(str(MODEL_PATH), MODEL_PATH.stat().st_mtime_ns)


def prepare_inference_frame(raw_record: dict[str, Any]) -> pd.DataFrame:
    missing = [name for name in REQUIRED_RECORD_FIELDS if name not in raw_record]
    if missing:
        raise ValueError(f'Missing required record fields: {", ".join(missing)}.')
    try:
        features = prepare_feature_row(raw_record)
    except ValueError as exc:
        raise ValueError(f'Invalid feature value: {exc}') from exc
    frame = pd.DataFrame([features], columns=EXPECTED_FEATURES)
    if frame.isin([float('inf'), float('-inf')]).any().any():
        raise ValueError('Feature values must be finite.')
    return frame


def predict_record(
    payload: dict[str, Any],
    settings: dict[str, float] | None = None,
) -> dict[str, Any]:
    bundle = load_model_bundle()
    prepared = prepare_inference_frame(payload)
    model = bundle['model']
    probabilities = model.predict_proba(prepared)[0]
    class_values = list(model.named_steps['model'].classes_)
    try:
        malicious_probability = float(probabilities[class_values.index(1)])
    except (ValueError, IndexError) as exc:
        raise RuntimeError('The model artifact does not support the expected class labels.') from exc
    threshold = (settings or {}).get('alert_threshold', 0.5)
    prediction = 'malicious' if malicious_probability >= threshold else 'benign'
    confidence = malicious_probability if prediction == 'malicious' else 1.0 - malicious_probability
    alert = build_alert_payload(prediction, confidence, payload, settings=settings)
    return {
        'prediction': prediction,
        'confidence': confidence,
        'confidence_type': 'uncalibrated_model_confidence',
        'risk_score': alert['risk_score'],
        'severity': alert['severity'],
        'category': alert['category'],
        'rule_indicators': alert['rule_indicators'],
        'reasons': alert['reasons'],
        'alert': alert,
    }


def score_dataset(records: list[dict[str, Any]], settings: dict[str, float] | None = None) -> dict[str, Any]:
    bundle = load_model_bundle()
    del bundle
    rows = []
    for record in records:
        result = predict_record(record, settings)
        rows.append({
            **record,
            'prediction': result['prediction'],
            'confidence': result['confidence'],
            'risk_score': result['risk_score'],
            'severity': result['severity'],
            'category': result['category'],
            'rule_indicators': result['rule_indicators'],
            'reasons': result['reasons'],
        })
    return {'records': rows, 'total': len(records), 'model_name': 'demo_model'}
