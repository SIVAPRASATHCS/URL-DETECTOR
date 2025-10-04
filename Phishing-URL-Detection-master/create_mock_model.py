"""
Create a simple mock model for testing the upgraded system
This replaces the incompatible pickled model
"""

import pickle
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.datasets import make_classification
import os

def create_mock_model():
    """Create a simple mock model for testing"""
    
    # Create synthetic data similar to phishing detection features
    X, y = make_classification(
        n_samples=1000,
        n_features=30,
        n_informative=20,
        n_redundant=5,
        n_clusters_per_class=1,
        random_state=42
    )
    
    # Convert labels to match original model format (-1 for phishing, 1 for safe)
    y = np.where(y == 0, -1, 1)
    
    # Create and train a simple Gradient Boosting model
    model = GradientBoostingClassifier(
        n_estimators=50,
        learning_rate=0.1,
        max_depth=6,
        random_state=42
    )
    
    model.fit(X, y)
    
    return model

if __name__ == "__main__":
    # Create the mock model
    print("Creating mock model for testing...")
    mock_model = create_mock_model()
    
    # Ensure pickle directory exists
    os.makedirs("pickle", exist_ok=True)
    
    # Save the model
    with open("pickle/model.pkl", "wb") as f:
        pickle.dump(mock_model, f)
    
    print("Mock model created and saved successfully!")
    print("Model accuracy on synthetic data: {:.2f}%".format(mock_model.score(
        *make_classification(n_samples=200, n_features=30, n_informative=20, n_redundant=5, random_state=123)
    ) * 100))