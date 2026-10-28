import json

import pandas as pd

from backend.app.services.demo_dataset import generate_demo_dataset


def test_demo_dataset_generation_is_reproducible(tmp_path):
    first = generate_demo_dataset(tmp_path / 'first.csv', rows=40)
    second = generate_demo_dataset(tmp_path / 'second.csv', rows=40)
    assert first.read_bytes() == second.read_bytes()
    assert len(pd.read_csv(first)) == 40


def test_training_fits_preprocessing_and_saves_versioned_metrics(tmp_path, monkeypatch):
    from backend.app.ml import trainer

    dataset = generate_demo_dataset(tmp_path / 'custom.csv', rows=80)
    frame = pd.read_csv(dataset)
    frame['duration'] = frame['duration'].astype(object)
    frame.loc[0, 'duration'] = ''
    frame.to_csv(dataset, index=False)
    artifacts = tmp_path / 'artifacts'
    monkeypatch.setattr(trainer, 'ARTIFACTS_DIR', artifacts)

    report = trainer.train_models(dataset)
    assert report['evaluation_type'] == 'CUSTOM'
    assert report['dataset_type'] == 'user_supplied_csv'
    assert report['dataset_rows'] == 80
    assert report['split']['stratified'] is True
    assert set(report['results']) == {'random_forest', 'logistic_regression'}
    assert (artifacts / 'demo_model.joblib').is_file()
    assert (artifacts / 'demo_model_v1.0.0.joblib').is_file()
    metrics = json.loads((artifacts / 'evaluation_metrics.json').read_text(encoding='utf-8'))
    assert metrics['evaluation_type'] == 'CUSTOM'
    for values in metrics['results'].values():
        assert values['n_samples'] == 20
        assert len(values['confusion_matrix']) == 2
        assert values['roc_auc'] is None or 0 <= values['roc_auc'] <= 1
