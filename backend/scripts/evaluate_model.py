import json

from backend.app.core.config import ARTIFACTS_DIR


if __name__ == '__main__':
    metrics_path = ARTIFACTS_DIR / 'evaluation_metrics.json'
    if not metrics_path.is_file():
        raise SystemExit('No saved evaluation report. Run backend/scripts/train_demo_model.py first.')
    report = json.loads(metrics_path.read_text(encoding='utf-8'))
    print(f"Evaluation type: {report.get('evaluation_type', 'unknown')}")
    print(f"Dataset: {report.get('dataset_type', 'unknown')} ({report.get('dataset_rows', 'unknown')} rows)")
    print(f"Best model: {report.get('best_model', 'unknown')}")
    print(json.dumps(report.get('results', {}), indent=2))
