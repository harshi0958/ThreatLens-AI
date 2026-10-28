# Dataset setup and canonical schema

## Included synthetic demo

`sample/network_traffic_sample.csv` is deterministically generated with a fixed random seed. It contains simulated network records only; it was not captured from real hosts or attacks. The `label` column is used by model training and must not be included as an inference feature.

Generate it from the project root:

```powershell
python -m backend.scripts.generate_demo_dataset
```

## Supported canonical input columns

The single-record API and CSV endpoints support one row per flow with these required fields:

| Column | Meaning |
| --- | --- |
| `src_ip`, `dst_ip` | Source and destination address/host labels |
| `protocol` | `TCP` or `UDP` |
| `src_port`, `dst_port` | Integer port values from 0 through 65535 |
| `duration` | Nonnegative flow duration |
| `bytes_sent`, `bytes_received` | Nonnegative byte totals |
| `packet_count` | Nonnegative packet count |
| `connection_state` | `ESTABLISHED`, `SYN_SCAN`, `SYN_SENT`, `TIME_WAIT`, `FIN_WAIT`, or `REJECTED` |
| `failed_login_count`, `login_attempts` | Nonnegative authentication counters |
| `traffic_volume` | Nonnegative volume measure in the dataset's chosen units |
| `anomaly_score` | Value from 0 to 1 supplied by the data producer |

Optional columns are `timestamp`, `is_simulated`, and (training only) `label`. Training labels must be `benign` or `malicious`. Blank numeric CSV values may be imputed by the trained pipeline; invalid text, non-finite values, unknown columns, and unsupported categories are rejected.

## External benchmark datasets

CIC-IDS2017 and UNSW-NB15 are possible sources for academic work, but neither is read as-is by this app. Download from the dataset publisher and check its license/access conditions. Before using either dataset:

1. Review the dataset documentation, units, label taxonomy, and feature construction.
2. Create a separate conversion step mapping only defensible source features to this canonical schema.
3. Explicitly map labels to benign/malicious; avoid unsupported attack-specific labels.
4. Validate the converted file and record the transformation methodology.
5. Train with `python -m backend.scripts.train_demo_model --dataset path\to\canonical.csv`.

The resulting custom report is marked `CUSTOM`. The application does not claim that these metrics are benchmark-comparable or representative of real-world performance.
