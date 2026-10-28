from __future__ import annotations

import math
from typing import Dict, List

EXPECTED_FEATURES = [
    'duration', 'bytes_sent', 'bytes_received', 'packet_count', 'src_port', 'dst_port',
    'failed_login_count', 'login_attempts', 'traffic_volume', 'anomaly_score',
    'protocol_TCP', 'protocol_UDP', 'connection_state_ESTABLISHED',
    'connection_state_FIN_WAIT', 'connection_state_REJECTED', 'connection_state_SYN_SCAN',
    'connection_state_SYN_SENT', 'connection_state_TIME_WAIT',
]

NUMERIC_COLUMNS = [
    'duration', 'bytes_sent', 'bytes_received', 'packet_count', 'src_port', 'dst_port',
    'failed_login_count', 'login_attempts', 'traffic_volume', 'anomaly_score',
    'protocol_TCP', 'protocol_UDP', 'connection_state_ESTABLISHED',
    'connection_state_FIN_WAIT', 'connection_state_REJECTED', 'connection_state_SYN_SCAN',
    'connection_state_SYN_SENT', 'connection_state_TIME_WAIT',
]
REQUIRED_RECORD_FIELDS = [
    'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'duration', 'bytes_sent',
    'bytes_received', 'packet_count', 'connection_state', 'failed_login_count',
    'login_attempts', 'traffic_volume', 'anomaly_score',
]
ALLOWED_DATASET_COLUMNS = set(REQUIRED_RECORD_FIELDS + ['timestamp', 'label', 'is_simulated'])


def _numeric(value: object) -> float:
    if value is None or (isinstance(value, str) and not value.strip()):
        return math.nan
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'Expected a numeric feature, received {value!r}.') from exc
    return number if math.isfinite(number) else math.nan


def prepare_feature_row(row: Dict[str, object]) -> Dict[str, float | int | str]:
    protocol = str(row.get('protocol', 'TCP')).upper()
    state = str(row.get('connection_state', 'ESTABLISHED')).upper()
    supported_states = {'ESTABLISHED', 'FIN_WAIT', 'REJECTED', 'SYN_SCAN', 'SYN_SENT', 'TIME_WAIT'}
    if protocol not in {'TCP', 'UDP'}:
        raise ValueError(f'Unsupported protocol {protocol!r}; expected TCP or UDP.')
    if state not in supported_states:
        raise ValueError(f'Unsupported connection state {state!r}.')
    output = {
        'duration': _numeric(row.get('duration')),
        'bytes_sent': _numeric(row.get('bytes_sent')),
        'bytes_received': _numeric(row.get('bytes_received')),
        'packet_count': _numeric(row.get('packet_count')),
        'src_port': _numeric(row.get('src_port')),
        'dst_port': _numeric(row.get('dst_port')),
        'failed_login_count': _numeric(row.get('failed_login_count')),
        'login_attempts': _numeric(row.get('login_attempts')),
        'traffic_volume': _numeric(row.get('traffic_volume')),
        'anomaly_score': _numeric(row.get('anomaly_score')),
        'protocol_TCP': 1 if protocol == 'TCP' else 0,
        'protocol_UDP': 1 if protocol == 'UDP' else 0,
        'connection_state_ESTABLISHED': 1 if state == 'ESTABLISHED' else 0,
        'connection_state_FIN_WAIT': 1 if state == 'FIN_WAIT' else 0,
        'connection_state_REJECTED': 1 if state == 'REJECTED' else 0,
        'connection_state_SYN_SCAN': 1 if state == 'SYN_SCAN' else 0,
        'connection_state_SYN_SENT': 1 if state == 'SYN_SENT' else 0,
        'connection_state_TIME_WAIT': 1 if state == 'TIME_WAIT' else 0,
    }
    return output


def validate_row_for_schema(row: Dict[str, object]) -> List[str]:
    errors: List[str] = []
    for key in REQUIRED_RECORD_FIELDS:
        if key not in row:
            errors.append(f'Missing required field: {key}')
    unknown = sorted(set(row) - ALLOWED_DATASET_COLUMNS)
    if unknown:
        errors.append(f'Unknown feature columns: {", ".join(unknown)}')
    for field in ('src_ip', 'dst_ip'):
        if field in row and not str(row[field]).strip():
            errors.append(f'{field} must not be empty.')
    if str(row.get('protocol', '')).upper() not in {'TCP', 'UDP'}:
        errors.append('Unsupported protocol. Expected TCP or UDP.')
    if str(row.get('connection_state', '')).upper() not in {'ESTABLISHED', 'SYN_SCAN', 'SYN_SENT', 'TIME_WAIT', 'FIN_WAIT', 'REJECTED'}:
        errors.append('Unsupported connection state value.')
    numeric_bounds = {
        'src_port': (0, 65535),
        'dst_port': (0, 65535),
        'duration': (0, math.inf),
        'bytes_sent': (0, math.inf),
        'bytes_received': (0, math.inf),
        'packet_count': (0, math.inf),
        'failed_login_count': (0, math.inf),
        'login_attempts': (0, math.inf),
        'traffic_volume': (0, math.inf),
        'anomaly_score': (0, 1),
    }
    for field, (minimum, maximum) in numeric_bounds.items():
        value = row.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            errors.append(f'{field} must be numeric.')
            continue
        if math.isnan(number):
            continue
        if not math.isfinite(number) or number < minimum or number > maximum:
            errors.append(f'{field} must be between {minimum} and {maximum}.')
        elif field in {'src_port', 'dst_port', 'failed_login_count', 'login_attempts'} and not number.is_integer():
            errors.append(f'{field} must be a whole number.')
    return errors
