from __future__ import annotations

import csv
import io
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Literal, TypeVar

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import PyMongoError

from backend.app.core.config import (
    API_HOST,
    API_PORT,
    APP_ENV,
    APP_NAME,
    ARTIFACTS_DIR,
    BATCH_SIZE,
    DATASET_DIR,
    DEMO_MODE,
    FRONTEND_ORIGIN,
    MAX_ROWS_PER_UPLOAD,
    MAX_UPLOAD_SIZE_MB,
)
from backend.app.core.logging import logger
from backend.app.database.fallback_store import (
    activate_fallback,
    configure_store,
    get_store,
    get_database_status,
)
from backend.app.ml.feature_schema import (
    ALLOWED_DATASET_COLUMNS,
    EXPECTED_FEATURES,
    REQUIRED_RECORD_FIELDS,
    validate_row_for_schema,
)
from backend.app.ml.trainer import train_models
from backend.app.models.schemas import DatasetValidationResult, SettingsUpdate, TrafficRecord
from backend.app.services.demo_dataset import generate_demo_dataset
from backend.app.services.model_service import load_model_bundle, load_model_metadata, predict_record

T = TypeVar('T')


@asynccontextmanager
async def lifespan(_: FastAPI):
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    configure_store()
    sample_path = DATASET_DIR / 'sample' / 'network_traffic_sample.csv'
    dataset_path = generate_demo_dataset() if not sample_path.exists() else None
    model_path = ARTIFACTS_DIR / 'demo_model.joblib'
    if not model_path.exists():
        logger.info('Training the synthetic demo model because no local model artifact exists.')
        train_models()
    try:
        get_store().register_model_metadata(load_model_metadata())
    except PyMongoError as exc:
        activate_fallback(type(exc).__name__)
    logger.info('ThreatLens AI started in %s mode; database mode=%s.', APP_ENV, get_database_status())
    if dataset_path:
        logger.info('Generated sample data at %s.', dataset_path)
    yield


app = FastAPI(
    title=APP_NAME,
    version='1.0.0',
    description='Defensive network traffic analytics. Predictions are heuristic/model-assisted and may be wrong.',
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'PUT'],
    allow_headers=['Content-Type', 'X-Request-ID'],
)


@app.middleware('http')
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers['X-Request-ID'] = request_id
    return response


def _database_call(callable_operation: Callable[[], T]) -> T:
    try:
        return callable_operation()
    except PyMongoError as exc:
        logger.error('Database operation failed (%s).', type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='A database operation did not complete; verify stored records before retrying.',
        ) from exc


def _public_model_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in metadata.items() if key != 'dataset_path'}
    if metadata.get('dataset_type') == 'synthetic_demo':
        public['dataset_path'] = 'datasets/sample/network_traffic_sample.csv'
    elif metadata.get('dataset_path'):
        public['dataset_path'] = 'user-supplied CSV (local path not exposed)'
    return public


def _analyze_and_persist(record: dict[str, Any]) -> dict[str, Any]:
    store = get_store()
    detection_settings = _database_call(store.get_settings)
    try:
        outcome = predict_record(record, detection_settings)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='The model is unavailable. Train the demo model and restart the backend.',
        ) from exc
    except Exception as exc:
        logger.exception('Model inference failed (%s).', type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Model inference failed. Check the backend model artifact and logs.',
        ) from exc

    saved_alert = _database_call(lambda: store.add_alert(outcome['alert']))
    _database_call(lambda: store.record_analysis({
        'analysis_type': 'record',
        'alert_id': saved_alert['alert_id'],
        'prediction': outcome['prediction'],
        'risk_score': outcome['risk_score'],
        'severity': outcome['severity'],
    }))
    outcome['alert'] = saved_alert
    return outcome


async def _read_csv_upload(file: UploadFile) -> tuple[list[dict[str, str]], list[str]]:
    filename = (file.filename or '').lower()
    if not filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail='Only files with a .csv extension are supported.')
    max_bytes = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f'Uploaded file exceeds the {MAX_UPLOAD_SIZE_MB} MB limit.')
    try:
        text = content.decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise HTTPException(status_code=400, detail='CSV must include a header row.')
        columns = [column.strip() for column in reader.fieldnames]
        if len(set(columns)) != len(columns):
            raise HTTPException(status_code=422, detail='CSV column names must be unique.')
        rows: list[dict[str, str]] = []
        for row_number, values in enumerate(reader, start=2):
            if row_number - 1 > MAX_ROWS_PER_UPLOAD:
                raise HTTPException(
                    status_code=413,
                    detail=f'CSV exceeds the {MAX_ROWS_PER_UPLOAD}-row limit.',
                )
            if None in values:
                raise HTTPException(status_code=422, detail=f'Row {row_number} has more values than its header.')
            rows.append({str(key).strip(): (value or '').strip() for key, value in values.items() if key is not None})
        return rows, columns
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail='CSV must be UTF-8 encoded.') from exc
    except csv.Error as exc:
        raise HTTPException(status_code=400, detail='CSV could not be parsed.') from exc


def _validate_csv(rows: list[dict[str, str]], columns: list[str]) -> dict[str, Any]:
    errors: list[str] = []
    if not rows:
        errors.append('The uploaded CSV does not contain any data rows.')
    missing_columns = sorted(set(REQUIRED_RECORD_FIELDS) - set(columns))
    if missing_columns:
        errors.append(f'Missing required columns: {", ".join(missing_columns)}.')
    unknown_columns = sorted(set(columns) - ALLOWED_DATASET_COLUMNS)
    if unknown_columns:
        errors.append(f'Unsupported columns: {", ".join(unknown_columns)}.')
    for index, row in enumerate(rows, start=2):
        row_errors = validate_row_for_schema(row)
        errors.extend(f'Row {index}: {error}' for error in row_errors)
        if len(errors) >= 50:
            errors.append('Additional validation errors omitted.')
            break
    warnings = ['Blank numeric fields are imputed by the fitted training pipeline.'] if any(
        not row.get(field, '').strip()
        for row in rows
        for field in ('src_port', 'dst_port', 'duration', 'bytes_sent', 'bytes_received', 'packet_count',
                      'failed_login_count', 'login_attempts', 'traffic_volume', 'anomaly_score')
    ) else []
    return DatasetValidationResult(
        valid=not errors,
        row_count=len(rows),
        columns=columns,
        errors=errors,
        warnings=warnings,
    ).model_dump()


@app.get('/api/health')
def health() -> dict[str, Any]:
    try:
        model_metadata = load_model_metadata()
        model_state = 'loaded' if (ARTIFACTS_DIR / 'demo_model.joblib').is_file() else 'missing_model'
    except RuntimeError:
        model_metadata = {'status': 'invalid_metadata'}
        model_state = 'metadata_error'
    return {
        'status': 'ok' if model_state == 'loaded' else 'degraded',
        'app': APP_NAME,
        'environment': APP_ENV,
        'demo_mode': DEMO_MODE,
        'database_mode': get_database_status(),
        'dependencies': {'mongodb': get_database_status(), 'model': model_state},
        'model_evaluation_type': model_metadata.get('evaluation_type', 'DEMO'),
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.get('/api/dashboard/summary')
def dashboard_summary() -> dict[str, Any]:
    store = get_store()
    data = _database_call(store.get_dashboard_summary)
    try:
        model_metadata = _public_model_metadata(load_model_metadata())
    except RuntimeError as exc:
        logger.error('Dashboard model metadata unavailable: %s', exc)
        raise HTTPException(status_code=503, detail='Model metadata is unavailable; retrain the model.') from exc
    return {
        **data,
        'model_status': model_metadata,
        'database_mode': get_database_status(),
        'demo_mode': DEMO_MODE,
    }


@app.get('/api/alerts')
def get_alerts(
    severity: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] | None = None,
    category: str | None = Query(default=None, min_length=1, max_length=64),
    search: str | None = Query(default=None, max_length=128),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
) -> dict[str, Any]:
    store = get_store()
    offset = (page - 1) * page_size
    items, total = _database_call(lambda: store.get_alerts(
        severity=severity, category=category, search=search, limit=page_size, offset=offset
    ))
    return {
        'items': items,
        'page': page,
        'page_size': page_size,
        'total': total,
        'pages': (total + page_size - 1) // page_size,
    }


@app.get('/api/alerts/{alert_id}')
def get_alert(alert_id: str) -> dict[str, Any]:
    item = _database_call(lambda: get_store().get_alert(alert_id))
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Alert not found.')
    return item


@app.post('/api/analyze/record')
def analyze_record(payload: TrafficRecord, request: Request) -> dict[str, Any]:
    outcome = _analyze_and_persist(payload.model_dump())
    return {
        'request_id': request.state.request_id,
        **{key: outcome[key] for key in (
            'prediction', 'confidence', 'confidence_type', 'risk_score', 'severity',
            'category', 'rule_indicators', 'reasons', 'alert',
        )},
    }


@app.post('/api/analyze/batch')
def analyze_batch(records: list[TrafficRecord], request: Request) -> dict[str, Any]:
    if not records:
        raise HTTPException(status_code=400, detail='Batch must include at least one record.')
    if len(records) > BATCH_SIZE:
        raise HTTPException(status_code=413, detail=f'Batch exceeds the configured limit of {BATCH_SIZE} records.')
    results = []
    for record in records:
        outcome = _analyze_and_persist(record.model_dump())
        results.append({
            'prediction': outcome['prediction'],
            'confidence': outcome['confidence'],
            'confidence_type': outcome['confidence_type'],
            'risk_score': outcome['risk_score'],
            'severity': outcome['severity'],
            'category': outcome['category'],
            'rule_indicators': outcome['rule_indicators'],
            'reasons': outcome['reasons'],
            'alert': outcome['alert'],
        })
    return {'request_id': request.state.request_id, 'results': results, 'total_processed': len(results)}


@app.post('/api/datasets/validate')
async def validate_dataset(file: UploadFile = File(...)) -> dict[str, Any]:
    rows, columns = await _read_csv_upload(file)
    return _validate_csv(rows, columns)


@app.post('/api/datasets/analyze')
async def analyze_dataset(request: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    rows, columns = await _read_csv_upload(file)
    validation = _validate_csv(rows, columns)
    if not validation['valid']:
        raise HTTPException(status_code=422, detail=validation)
    store = get_store()
    results = []
    for row in rows:
        record: dict[str, Any] = dict(row)
        record['is_simulated'] = str(record.get('is_simulated', 'true')).strip().casefold() in {'true', '1', 'yes'}
        record.pop('label', None)
        outcome = _analyze_and_persist(record)
        results.append({
            'record': {key: record.get(key) for key in ('src_ip', 'dst_ip', 'protocol', 'timestamp')},
            'prediction': outcome['prediction'],
            'confidence': outcome['confidence'],
            'confidence_type': outcome['confidence_type'],
            'risk_score': outcome['risk_score'],
            'severity': outcome['severity'],
            'category': outcome['category'],
            'rule_indicators': outcome['rule_indicators'],
            'reasons': outcome['reasons'],
            'alert_id': outcome['alert']['alert_id'],
        })
    _database_call(lambda: store.record_analysis({
        'analysis_type': 'csv',
        'row_count': len(results),
        'threat_count': sum(row['prediction'] == 'malicious' for row in results),
        'request_id': request.state.request_id,
    }))
    return {
        'request_id': request.state.request_id if request else None,
        'rows_processed': len(results),
        'results': results,
        'status': 'ok',
    }


@app.get('/api/models/status')
def model_status() -> dict[str, Any]:
    try:
        bundle = load_model_bundle()
        metadata = load_model_metadata()
    except FileNotFoundError:
        return {
            'model_name': 'demo_model',
            'status': 'missing_model',
            'feature_schema': EXPECTED_FEATURES,
            'model_path': 'backend/artifacts/demo_model.joblib',
            'has_training_data': False,
            'created_at': None,
            'evaluation_type': 'DEMO',
        }
    except RuntimeError as exc:
        logger.error('Model status unavailable: %s', exc)
        raise HTTPException(status_code=503, detail='The model artifact or metadata is invalid; retrain the model.') from exc
    public_metadata = _public_model_metadata(metadata)
    return {
        'model_name': bundle['model_name'],
        'model_version': bundle.get('model_version', 'unknown'),
        'status': 'loaded',
        'feature_schema': bundle['feature_columns'],
        'model_path': 'backend/artifacts/demo_model.joblib',
        'has_training_data': True,
        'created_at': metadata.get('created_at'),
        'evaluation_type': metadata.get('evaluation_type', 'DEMO'),
        'metadata': public_metadata,
    }


@app.get('/api/models/metrics')
def model_metrics() -> dict[str, Any]:
    try:
        metadata = load_model_metadata()
    except RuntimeError as exc:
        logger.error('Model metrics unavailable: %s', exc)
        raise HTTPException(status_code=503, detail='Saved model evaluation metadata is invalid.') from exc
    return {
        'status': metadata.get('status', 'unknown'),
        'evaluation_type': metadata.get('evaluation_type', 'DEMO'),
        'dataset_type': metadata.get('dataset_type', 'unknown'),
        'dataset_rows': metadata.get('dataset_rows'),
        'model_name': metadata.get('model_name', 'demo_model'),
        'model_version': metadata.get('model_version', 'unknown'),
        'best_model': metadata.get('best_model', 'unknown'),
        'results': metadata.get('results', {}),
        'dataset_path': 'datasets/sample/network_traffic_sample.csv' if metadata.get('dataset_type') == 'synthetic_demo' else None,
        'feature_schema': metadata.get('feature_schema', []),
        'training_timestamp': metadata.get('training_timestamp'),
        'notes': metadata.get('notes', 'No trained model metrics are available.'),
    }


@app.get('/api/events')
def events(limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
    return {'items': _database_call(lambda: get_store().get_latest_events(limit=limit))}


@app.get('/api/settings')
def settings() -> dict[str, Any]:
    return {
        'settings': _database_call(get_store().get_settings),
        'demo_mode': DEMO_MODE,
        'database_mode': get_database_status(),
    }


@app.put('/api/settings')
def update_settings(payload: SettingsUpdate) -> dict[str, Any]:
    saved = _database_call(lambda: get_store().set_settings(payload.model_dump()))
    return {'settings': saved, 'updated': True}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('backend.app.main:app', host=API_HOST, port=API_PORT, reload=APP_ENV == 'development')
