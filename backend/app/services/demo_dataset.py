from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path
from random import Random

from backend.app.core.config import DATASET_DIR


def generate_demo_dataset(output_path: str | Path | None = None, rows: int = 400) -> Path:
    rng = Random(42)
    target = Path(output_path) if output_path else DATASET_DIR / 'sample' / 'network_traffic_sample.csv'
    target.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        'timestamp', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'duration',
        'bytes_sent', 'bytes_received', 'packet_count', 'connection_state', 'failed_login_count',
        'login_attempts', 'traffic_volume', 'anomaly_score', 'label'
    ]

    start = datetime(2024, 1, 1, 10, 0, 0)
    with target.open('w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(rows):
            ts = (start + timedelta(minutes=i)).isoformat()
            if i < rows * 0.7:
                protocol = rng.choice(['TCP', 'UDP'])
                src_port = rng.randint(1024, 65535)
                dst_port = rng.choice([80, 443, 22, 21, 53])
                duration = round(rng.uniform(0.01, 3.5), 3)
                bytes_sent = round(rng.uniform(150, 3000), 1)
                bytes_received = round(rng.uniform(100, 2500), 1)
                packet_count = int(rng.uniform(5, 80))
                connection_state = rng.choice(['ESTABLISHED', 'SYN_SENT', 'FIN_WAIT'])
                failed_login_count = rng.randint(0, 2)
                login_attempts = rng.randint(1, 5)
                traffic_volume = round(rng.uniform(30, 180), 1)
                anomaly_score = round(rng.uniform(0.0, 0.25), 3)
                label = 'benign'
            else:
                protocol = rng.choice(['TCP', 'UDP'])
                src_port = rng.choice([22, 23, 3389, 445, 80])
                dst_port = rng.choice([22, 23, 80, 443])
                duration = round(rng.uniform(0.4, 12.0), 3)
                bytes_sent = round(rng.uniform(1200, 200000), 1)
                bytes_received = round(rng.uniform(500, 600000), 1)
                packet_count = int(rng.uniform(60, 900))
                connection_state = rng.choice(['SYN_SCAN', 'TIME_WAIT', 'ESTABLISHED', 'REJECTED'])
                failed_login_count = rng.randint(3, 15)
                login_attempts = rng.randint(4, 20)
                traffic_volume = round(rng.uniform(200, 1500), 1)
                anomaly_score = round(rng.uniform(0.55, 0.98), 3)
                label = 'malicious'

            src_ip = f'10.0.0.{rng.randint(2, 250)}'
            dst_ip = f'192.168.10.{rng.randint(2, 200)}'
            writer.writerow({
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'duration': duration,
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_count': packet_count,
                'connection_state': connection_state,
                'failed_login_count': failed_login_count,
                'login_attempts': login_attempts,
                'traffic_volume': traffic_volume,
                'anomaly_score': anomaly_score,
                'label': label,
            })
    return target
