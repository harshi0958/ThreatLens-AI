import argparse

from backend.app.ml.trainer import train_models

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train the ThreatLens demo classifier.')
    parser.add_argument(
        '--dataset',
        help='Optional CSV using the documented ThreatLens feature schema and benign/malicious labels.',
    )
    args = parser.parse_args()
    metadata = train_models(args.dataset)
    print('Model training complete.')
    print(f"Evaluation type: {metadata['evaluation_type']}")
    print(f"Dataset rows: {metadata['dataset_rows']}")
    print(f"Best model by held-out F1: {metadata['best_model']}")
    print(f"Metrics saved to backend/artifacts/evaluation_metrics.json")
