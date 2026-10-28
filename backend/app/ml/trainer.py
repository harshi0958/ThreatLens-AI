from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.app.core.config import ARTIFACTS_DIR, DATASET_DIR
from backend.app.ml.feature_schema import EXPECTED_FEATURES, prepare_feature_row, validate_row_for_schema

DEMO_DATASET = DATASET_DIR / 'sample' / 'network_traffic_sample.csv'
MODEL_VERSION = '1.0.0'


def load_demo_dataset(path: str | Path | None = None) -> pd.DataFrame:
    dataset_path = Path(path) if path else DEMO_DATASET
    if not dataset_path.is_file():
        raise FileNotFoundError(f'Dataset not found: {dataset_path}')
    raw = pd.read_csv(dataset_path, keep_default_na=True)
    if 'label' not in raw:
        raise ValueError('Dataset must include a label column containing benign or malicious.')
    if raw.empty:
        raise ValueError('Dataset contains no records.')

    rows: list[dict[str, float | int | str]] = []
    labels: list[int] = []
    invalid_rows: list[str] = []
    for index, row in raw.iterrows():
        record = row.to_dict()
        errors = validate_row_for_schema(record)
        label = str(record.get('label', '')).strip().casefold()
        if label not in {'benign', 'malicious'}:
            errors.append('label must be benign or malicious.')
        if errors:
            invalid_rows.append(f'row {index + 2}: {"; ".join(errors)}')
            continue
        try:
            rows.append(prepare_feature_row(record))
            labels.append(1 if label == 'malicious' else 0)
        except ValueError as exc:
            invalid_rows.append(f'row {index + 2}: {exc}')
    if invalid_rows:
        raise ValueError('Invalid training dataset: ' + ' | '.join(invalid_rows[:5]))
    if len(set(labels)) < 2 or min(np.bincount(labels)) < 2:
        raise ValueError('Training requires at least two records for each of benign and malicious classes.')
    features = pd.DataFrame(rows, columns=EXPECTED_FEATURES)
    features.replace([np.inf, -np.inf], np.nan, inplace=True)
    features['target'] = labels
    return features


def build_pipeline(model: Any) -> Pipeline:
    return Pipeline([
        ('imputer', SimpleImputer(strategy='median', keep_empty_features=True)),
        ('scaler', StandardScaler()),
        ('model', model),
    ])


def _evaluate(model: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> dict[str, Any]:
    predictions = model.predict(X_test)
    positive_index = list(model.named_steps['model'].classes_).index(1)
    probabilities = model.predict_proba(X_test)[:, positive_index]
    try:
        auc: float | None = float(roc_auc_score(y_test, probabilities))
    except ValueError:
        auc = None
    return {
        'precision': float(precision_score(y_test, predictions, zero_division=0)),
        'recall': float(recall_score(y_test, predictions, zero_division=0)),
        'f1_score': float(f1_score(y_test, predictions, zero_division=0)),
        'roc_auc': auc,
        'confusion_matrix': confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        'class_labels': ['benign', 'malicious'],
        'n_samples': int(len(y_test)),
    }


def train_models(dataset_path: str | Path | None = None) -> dict[str, Any]:
    dataset_path = Path(dataset_path) if dataset_path else DEMO_DATASET
    data = load_demo_dataset(dataset_path)
    X = data[EXPECTED_FEATURES]
    y = data['target'].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    candidates = {
        'random_forest': RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight='balanced_subsample',
        ),
        'logistic_regression': LogisticRegression(
            max_iter=2000,
            class_weight='balanced',
            solver='liblinear',
            random_state=42,
        ),
    }
    results: dict[str, Any] = {}
    for name, estimator in candidates.items():
        candidate = build_pipeline(estimator)
        candidate.fit(X_train, y_train)
        results[name] = _evaluate(candidate, X_test, y_test)

    best_model_name = max(results, key=lambda name: results[name]['f1_score'])
    final_pipeline = build_pipeline(candidates[best_model_name])
    final_pipeline.fit(X, y)
    trained_at = datetime.now(timezone.utc).isoformat()
    dataset_type = 'synthetic_demo' if dataset_path.resolve() == DEMO_DATASET.resolve() else 'user_supplied_csv'
    evaluation_type = 'DEMO' if dataset_type == 'synthetic_demo' else 'CUSTOM'
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    metadata = {
        'model_name': 'demo_model',
        'model_version': MODEL_VERSION,
        'best_model': best_model_name,
        'status': 'trained',
        'evaluation_type': evaluation_type,
        'dataset_type': dataset_type,
        'dataset_path': str(dataset_path.resolve()),
        'dataset_rows': int(len(data)),
        'training_timestamp': trained_at,
        'created_at': trained_at,
        'split': {'test_size': 0.25, 'random_state': 42, 'stratified': True},
        'class_distribution': {
            'benign': int((y == 0).sum()),
            'malicious': int((y == 1).sum()),
        },
        'feature_schema': EXPECTED_FEATURES,
        'results': results,
        'notes': (
            'Metrics are measured on a held-out split of synthetic demo data. They are not benchmark or real-world performance claims.'
            if dataset_type == 'synthetic_demo'
            else 'Metrics are measured on a held-out split of the user-supplied CSV. They are not independently verified benchmark or real-world performance claims.'
        ),
    }
    bundle = {
        'model_name': 'demo_model',
        'model_version': MODEL_VERSION,
        'model': final_pipeline,
        'feature_columns': EXPECTED_FEATURES,
        'training_timestamp': trained_at,
        'dataset_path': str(dataset_path.resolve()),
        'dataset_type': dataset_type,
        'evaluation_type': evaluation_type,
        'results': results,
        'best_model': best_model_name,
    }
    joblib.dump(bundle, ARTIFACTS_DIR / 'demo_model.joblib')
    joblib.dump(bundle, ARTIFACTS_DIR / f'demo_model_v{MODEL_VERSION}.joblib')
    metadata_json = json.dumps(metadata, indent=2, allow_nan=False)
    (ARTIFACTS_DIR / 'model_metadata.json').write_text(metadata_json, encoding='utf-8')
    (ARTIFACTS_DIR / 'evaluation_metrics.json').write_text(metadata_json, encoding='utf-8')
    return metadata
