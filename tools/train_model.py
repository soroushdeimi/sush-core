#!/usr/bin/env python3
"""
Train and serialize pre-trained ML models for censorship detection.

This script generates realistic training data and trains the IsolationForest
and GaussianNB models used by CensorshipDetector.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pickle

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler

from data.real_training_data import RealTrainingDataProvider


def train_models(num_samples: int = 10000, output_path: str = "models/censorship_detector"):
    """
    Train ML models for censorship detection.

    Args:
        num_samples: Number of training samples to generate
        output_path: Path to save the trained models
    """
    print("=" * 60)
    print("Training Pre-trained Censorship Detection Models")
    print("=" * 60)
    print(f"Generating {num_samples} training samples...")

    # Generate training data
    data_provider = RealTrainingDataProvider(random_seed=42)
    all_features, all_labels = data_provider.generate_dataset(num_samples)

    print(f"Generated {len(all_features)} samples:")
    print(f"  Normal: {sum(1 for l in all_labels if l == 0)}")
    print(f"  Threat: {sum(1 for l in all_labels if l == 1)}")

    # Split data
    print("\nSplitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        all_features, all_labels, test_size=0.2, random_state=42
    )

    print(f"  Training set: {len(X_train)} samples")
    print(f"  Test set: {len(X_test)} samples")

    # Scale features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train IsolationForest (unsupervised - use only normal data)
    print("\nTraining IsolationForest (anomaly detector)...")
    normal_train_data = [X_train_scaled[i] for i, label in enumerate(y_train) if label == 0]
    print(f"  Using {len(normal_train_data)} normal samples for training")

    anomaly_detector = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100,
    )
    anomaly_detector.fit(normal_train_data)
    print("  ✓ IsolationForest trained")

    # Train GaussianNB (supervised classifier)
    print("\nTraining GaussianNB (threat classifier)...")
    threat_classifier = GaussianNB()
    threat_classifier.fit(X_train_scaled, y_train)
    print("  ✓ GaussianNB trained")

    # Evaluate models
    print("\nEvaluating models...")
    classifier_score = threat_classifier.score(X_test_scaled, y_test)
    print(f"  Threat Classifier Accuracy: {classifier_score:.3f}")

    # Anomaly detection evaluation
    anomaly_detector.predict(X_test_scaled)
    normal_test_data = [X_test_scaled[i] for i, label in enumerate(y_test) if label == 0]
    if normal_test_data:
        normal_predictions = anomaly_detector.predict(normal_test_data)
        normal_accuracy = np.sum(normal_predictions == 1) / len(normal_predictions)
        print(f"  Anomaly Detector (Normal Detection): {normal_accuracy:.3f}")

    # Save models
    print(f"\nSaving models to {output_path}...")
    model_dir = Path(output_path)
    model_dir.mkdir(parents=True, exist_ok=True)

    model_data = {
        "anomaly_detector": anomaly_detector,
        "threat_classifier": threat_classifier,
        "feature_scaler": scaler,
        "ml_models_trained": True,
        "training_samples": num_samples,
        "classifier_accuracy": classifier_score,
    }

    model_file = model_dir / "models.pkl"
    with open(model_file, "wb") as f:
        pickle.dump(model_data, f)

    print(f"  ✓ Models saved to {model_file}")
    print("\n" + "=" * 60)
    print("Training completed successfully!")
    print("=" * 60)
    print("\nTo use these models, ensure CensorshipDetector loads from:")
    print(f"  {model_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train pre-trained censorship detection models")
    parser.add_argument(
        "--samples",
        type=int,
        default=10000,
        help="Number of training samples to generate (default: 10000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="models/censorship_detector",
        help="Output path for models (default: models/censorship_detector)",
    )

    args = parser.parse_args()

    train_models(num_samples=args.samples, output_path=args.output)
