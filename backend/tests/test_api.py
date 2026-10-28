from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from backend.app.database.fallback_store import DEFAULT_SETTINGS, FallbackStore, fallback_store
from backend.app.main import app
from backend.app.services.threat_detection import (
    build_alert_payload,
    get_rule_indicators,
    risk_score_from_prediction,
    severity_from_risk,
)


@pytest.fixture
def client():
    fallback_store.alerts.clear()
    fallback_store.events.clear()
    fallback_store.analysis_history.clear()
    fallback_store.settings = DEFAULT_SETTINGS.copy()
    yield TestClient(app)
    fallback_store.alerts.clear()
    fallback_store.events.clear()
    fallback_store.analysis_history.clear()
    fallback_store.settings = DEFAULT_SETTINGS.copy()


def valid_record(**overrides):
    return {
        'src_ip': '10.0.0.5',
        'dst_ip': '192.168.10.7',
        'protocol': 'TCP',
        'src_port': 49152,
        'dst_port': 22,
        'duration': 1.2,
        'bytes_sent': 1500,
        'bytes_received': 700,
        'packet_count': 180,
        'failed_login_count': 6,
        'login_attempts': 9,
        'connection_state': 'SYN_SCAN',
        'traffic_volume': 420,
        'anomaly_score': 0.8,
        'is_simulated': True,
        **overrides,
    }


def csv_upload(filename='sample.csv', **overrides):
    values = {
        'timestamp': '2024-01-01T00:00:00Z',
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'protocol': 'TCP',
        'src_port': '49152',
        'dst_port': '443',
        'duration': '1.2',
        'bytes_sent': '200',
        'bytes_received': '150',
        'packet_count': '50',
        'connection_state': 'ESTABLISHED',
        'failed_login_count': '0',
        'login_attempts': '1',
        'traffic_volume': '20',
        'anomaly_score': '0.1',
        'label': 'benign',
    }
    values.update(overrides)
    content = ','.join(values) + '\n' + ','.join(str(value) for value in values.values()) + '\n'
    return {'file': (filename, BytesIO(content.encode()), 'text/csv')}


def test_health_endpoint_and_database_mode(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    payload = response.json()
    assert payload['status'] == 'ok'
    assert payload['app'] == 'ThreatLens AI'
    assert payload['database_mode'] == 'memory-fallback'
    assert payload['dependencies']['model'] == 'loaded'


def test_model_status_and_demo_metrics_are_real_saved_artifact_data(client):
    status_response = client.get('/api/models/status')
    assert status_response.status_code == 200
    assert status_response.json()['status'] == 'loaded'
    assert status_response.json()['evaluation_type'] == 'DEMO'
    assert 'D:\\' not in status_response.text

    metrics = client.get('/api/models/metrics').json()
    assert metrics['evaluation_type'] == 'DEMO'
    assert metrics['dataset_type'] == 'synthetic_demo'
    assert metrics['dataset_rows'] == 400
    for result in metrics['results'].values():
        assert result['n_samples'] > 0
        assert 0 <= result['precision'] <= 1
        assert 0 <= result['recall'] <= 1
        assert 0 <= result['f1_score'] <= 1
        assert len(result['confusion_matrix']) == 2


def test_invalid_record_and_unknown_fields_are_rejected(client):
    assert client.post('/api/analyze/record', json={'src_ip': '10.0.0.1'}).status_code == 422
    invalid = valid_record(unexpected_feature=5)
    assert client.post('/api/analyze/record', json=invalid).status_code == 422
    invalid_protocol = valid_record(protocol='ICMP')
    assert client.post('/api/analyze/record', json=invalid_protocol).status_code == 422
    invalid_port = valid_record(src_port=65536)
    assert client.post('/api/analyze/record', json=invalid_port).status_code == 422


def test_valid_record_is_analyzed_and_persisted_once(client):
    response = client.post('/api/analyze/record', json=valid_record())
    assert response.status_code == 200
    result = response.json()
    assert result['request_id']
    assert result['prediction'] in {'benign', 'malicious'}
    assert result['confidence_type'] == 'uncalibrated_model_confidence'
    assert 0 <= result['risk_score'] <= 100
    assert result['severity'] in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
    assert isinstance(result['rule_indicators'], list)
    assert result['alert']['timestamp'].endswith('+00:00')
    assert len(fallback_store.alerts) == 1

    client.get('/api/dashboard/summary')
    client.get('/api/alerts')
    assert len(fallback_store.alerts) == 1


def test_model_loading_failure_returns_safe_service_error(client, monkeypatch):
    from backend.app.services import model_service

    def fail_loading():
        raise FileNotFoundError('local artifact location should not be exposed')

    monkeypatch.setattr(model_service, 'load_model_bundle', fail_loading)
    response = client.post('/api/analyze/record', json=valid_record())
    assert response.status_code == 503
    assert 'artifact location' not in response.text


def test_batch_limit_is_enforced_and_valid_batch_analyzes(client):
    response = client.post('/api/analyze/batch', json=[valid_record() for _ in range(51)])
    assert response.status_code == 413
    assert not fallback_store.alerts

    response = client.post('/api/analyze/batch', json=[valid_record(), valid_record(failed_login_count=0)])
    assert response.status_code == 200
    assert response.json()['total_processed'] == 2
    assert len(fallback_store.alerts) == 2


def test_csv_validation_rejects_missing_and_incompatible_features(client):
    missing = 'src_ip,dst_ip,protocol\n10.0.0.1,10.0.0.2,TCP\n'
    response = client.post(
        '/api/datasets/validate',
        files={'file': ('missing.csv', BytesIO(missing.encode()), 'text/csv')},
    )
    assert response.status_code == 200
    assert response.json()['valid'] is False
    assert any('Missing required columns' in item for item in response.json()['errors'])

    unsupported = csv_upload()
    unsupported['file'] = (
        'unknown.csv',
        BytesIO(unsupported['file'][1].getvalue().replace(b'label', b'unknown')),
        'text/csv',
    )
    response = client.post('/api/datasets/validate', files=unsupported)
    assert response.status_code == 200
    assert response.json()['valid'] is False
    assert any('Unsupported columns' in item for item in response.json()['errors'])


def test_csv_validate_and_analyze_work_with_missing_numeric_values(client):
    form = csv_upload()
    assert client.post('/api/datasets/validate', files=form).json()['valid'] is True

    response = client.post('/api/datasets/analyze', files=csv_upload())
    assert response.status_code == 200
    assert response.json()['rows_processed'] == 1
    assert response.json()['results'][0]['alert_id']
    assert len(fallback_store.alerts) == 1

    blank_numeric = csv_upload(duration='')
    assert client.post('/api/datasets/validate', files=blank_numeric).json()['valid'] is True
    assert client.post('/api/datasets/analyze', files=csv_upload(duration='')).status_code == 200


def test_csv_rejects_non_csv_extension_and_invalid_protocol(client):
    assert client.post('/api/datasets/validate', files=csv_upload('sample.txt')).status_code == 400
    response = client.post('/api/datasets/validate', files=csv_upload(protocol='ICMP'))
    assert response.status_code == 200
    assert response.json()['valid'] is False


def test_csv_upload_size_and_row_limits_are_enforced(client, monkeypatch):
    from backend.app import main

    monkeypatch.setattr(main, 'MAX_ROWS_PER_UPLOAD', 1)
    original = csv_upload()['file'][1].getvalue()
    header, row = original.splitlines()
    too_many_rows = header + b'\n' + row + b'\n' + row + b'\n'
    response = client.post(
        '/api/datasets/validate',
        files={'file': ('too-many.csv', BytesIO(too_many_rows), 'text/csv')},
    )
    assert response.status_code == 413

    monkeypatch.setattr(main, 'MAX_UPLOAD_SIZE_MB', 1)
    oversized = client.post(
        '/api/datasets/validate',
        files={'file': ('large.csv', BytesIO(b'x' * (1024 * 1024 + 1)), 'text/csv')},
    )
    assert oversized.status_code == 413


def test_alert_search_severity_category_and_pagination(client):
    for index in range(7):
        payload = valid_record(
            src_ip=f'10.0.0.{index + 1}',
            failed_login_count=6 if index % 2 else 0,
            login_attempts=8 if index % 2 else 1,
        )
        assert client.post('/api/analyze/record', json=payload).status_code == 200

    first = client.get('/api/alerts', params={'page': 1, 'page_size': 3})
    second = client.get('/api/alerts', params={'page': 2, 'page_size': 3})
    assert first.json()['total'] == 7
    assert len(first.json()['items']) == 3
    assert len(second.json()['items']) == 3
    assert {item['alert_id'] for item in first.json()['items']}.isdisjoint(
        item['alert_id'] for item in second.json()['items']
    )

    searched = client.get('/api/alerts', params={'search': '10.0.0.1'})
    assert searched.json()['total'] >= 1
    filtered = client.get('/api/alerts', params={'category': 'brute_force_like_activity'})
    assert all(item['category'] == 'brute_force_like_activity' for item in filtered.json()['items'])
    assert client.get('/api/alerts', params={'severity': 'NOT_A_SEVERITY'}).status_code == 422


def test_alert_detail_and_not_found(client):
    result = client.post('/api/analyze/record', json=valid_record()).json()
    alert_id = result['alert']['alert_id']
    assert client.get(f'/api/alerts/{alert_id}').json()['alert_id'] == alert_id
    assert client.get('/api/alerts/missing').status_code == 404


def test_risk_score_and_severity_boundaries_are_stable():
    assert [severity_from_risk(value) for value in (0, 39, 40, 69, 70, 89, 90, 100)] == [
        'LOW', 'LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'HIGH', 'CRITICAL', 'CRITICAL',
    ]
    benign_score, benign_rules, _ = risk_score_from_prediction('benign', 0.9, {})
    malicious_score, _, _ = risk_score_from_prediction('malicious', 0.9, {})
    assert benign_score == 0
    assert benign_rules == []
    assert malicious_score == 29
    indicators = get_rule_indicators(valid_record())
    assert {item['rule_id'] for item in indicators} >= {'AUTH_FAILURE_BURST', 'SCAN_STATE_ANOMALY'}
    assert build_alert_payload('malicious', 0.75, valid_record())['risk_score'] <= 100


def test_invalid_timestamp_is_rejected_by_threat_analysis():
    with pytest.raises(ValueError, match='ISO-8601'):
        build_alert_payload('benign', 0.7, valid_record(timestamp='not-a-date'))


def test_settings_validation_and_detection_threshold_update(client):
    settings = client.get('/api/settings')
    assert settings.status_code == 200
    assert settings.json()['database_mode'] == 'memory-fallback'
    invalid = client.put('/api/settings', json={**DEFAULT_SETTINGS, 'alert_threshold': 2})
    assert invalid.status_code == 422
    updated = client.put('/api/settings', json={**DEFAULT_SETTINGS, 'risk_threshold': 80})
    assert updated.status_code == 200
    assert updated.json()['settings']['risk_threshold'] == 80
    result = client.post('/api/analyze/record', json=valid_record()).json()
    assert result['alert']['alert_triggered'] == (result['risk_score'] >= 80)


def test_fallback_store_explicitly_has_process_memory_semantics():
    store = FallbackStore()
    assert store.mode == 'memory-fallback'
    store.record_analysis({'analysis_type': 'test'})
    assert len(store.analysis_history) == 1
    assert store.get_dashboard_summary()['total_records'] == 0


def test_dashboard_and_events_contract(client):
    assert client.get('/api/dashboard/summary').status_code == 200
    summary = client.get('/api/dashboard/summary').json()
    assert {'total_records', 'total_threats', 'severity_counts', 'alert_trends', 'database_mode'} <= set(summary)
    assert client.get('/api/events', params={'limit': 0}).status_code == 422
    assert client.get('/api/events').json() == {'items': []}
