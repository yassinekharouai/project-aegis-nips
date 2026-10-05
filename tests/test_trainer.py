"""
Tests for the Aegis ML Training Pipeline.
"""

import sys
import os
import pytest
import numpy as np

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from config import CANONICAL_FEATURES


class TestSyntheticDataGeneration:
    """Test that synthetic data generation produces valid data."""

    def test_generate_returns_dataframe(self):
        from trainer import generate_synthetic_data
        df = generate_synthetic_data(n_normal=50, n_attack=50, save=False)
        assert len(df) == 100

    def test_labels_correct(self):
        from trainer import generate_synthetic_data
        df = generate_synthetic_data(n_normal=30, n_attack=20, save=False)
        assert (df["label"] == 0).sum() == 30
        assert (df["label"] == 1).sum() == 20

    def test_all_canonical_features_present(self):
        from trainer import generate_synthetic_data
        df = generate_synthetic_data(n_normal=10, n_attack=10, save=False)
        for feat in CANONICAL_FEATURES:
            assert feat in df.columns, f"Missing feature: {feat}"


class TestFeatureCleaning:
    """Test feature cleaning and extraction."""

    def test_clean_features_shape(self):
        from trainer import generate_synthetic_data, clean_features
        df = generate_synthetic_data(n_normal=50, n_attack=50, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))

        assert X.shape == (100, len(CANONICAL_FEATURES))
        assert y.shape == (100,)

    def test_no_nans_in_output(self):
        from trainer import generate_synthetic_data, clean_features
        df = generate_synthetic_data(n_normal=50, n_attack=50, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))

        assert not np.any(np.isnan(X))
        assert not np.any(np.isnan(y))

    def test_labels_are_binary(self):
        from trainer import generate_synthetic_data, clean_features
        df = generate_synthetic_data(n_normal=50, n_attack=50, save=False)
        _, y = clean_features(df, list(CANONICAL_FEATURES))

        assert set(np.unique(y)) == {0, 1}


class TestModelTraining:
    """Test end-to-end model training on synthetic data."""

    def test_train_model_returns_components(self):
        from trainer import generate_synthetic_data, clean_features, train_model

        df = generate_synthetic_data(n_normal=200, n_attack=200, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))
        model, scaler, X_test, y_test, y_pred, y_prob = train_model(X, y, list(CANONICAL_FEATURES))

        assert model is not None
        assert scaler is not None
        assert len(y_pred) == len(y_test)
        assert len(y_prob) == len(y_test)

    def test_model_predictions_are_binary(self):
        from trainer import generate_synthetic_data, clean_features, train_model

        df = generate_synthetic_data(n_normal=200, n_attack=200, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))
        _, _, _, _, y_pred, _ = train_model(X, y, list(CANONICAL_FEATURES))

        assert set(np.unique(y_pred)).issubset({0, 1})

    def test_model_accuracy_above_threshold(self):
        """Model should achieve at least 70% accuracy on synthetic data."""
        from trainer import generate_synthetic_data, clean_features, train_model
        from sklearn.metrics import accuracy_score

        df = generate_synthetic_data(n_normal=500, n_attack=500, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))
        _, _, _, y_test, y_pred, _ = train_model(X, y, list(CANONICAL_FEATURES))

        acc = accuracy_score(y_test, y_pred)
        assert acc > 0.70, f"Accuracy too low: {acc:.4f}"

    def test_probabilities_valid(self):
        from trainer import generate_synthetic_data, clean_features, train_model

        df = generate_synthetic_data(n_normal=200, n_attack=200, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))
        _, _, _, _, _, y_prob = train_model(X, y, list(CANONICAL_FEATURES))

        assert np.all(y_prob >= 0.0)
        assert np.all(y_prob <= 1.0)


class TestModelPersistence:
    """Test model save and load."""

    def test_save_and_load(self, tmp_path):
        import pickle
        from trainer import generate_synthetic_data, clean_features, train_model

        df = generate_synthetic_data(n_normal=100, n_attack=100, save=False)
        X, y = clean_features(df, list(CANONICAL_FEATURES))
        model, scaler, _, _, _, _ = train_model(X, y, list(CANONICAL_FEATURES))

        # Save
        model_path = str(tmp_path / "test_model.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        # Load
        with open(model_path, "rb") as f:
            loaded = pickle.load(f)

        # Verify predictions match
        test_pkt = np.zeros((1, len(CANONICAL_FEATURES)))
        assert model.predict(test_pkt)[0] == loaded.predict(test_pkt)[0]
