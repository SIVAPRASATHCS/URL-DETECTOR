"""
Advanced Machine Learning Model for Phishing Detection
Implements ensemble methods, feature importance analysis, and model explainability
"""

import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    RandomForestClassifier, 
    GradientBoostingClassifier, 
    VotingClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
import joblib
import logging
import shap
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class AdvancedPhishingModel:
    """Advanced ensemble model for phishing detection with explainability"""
    
    def __init__(self):
        self.ensemble_model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'using_ip', 'long_url', 'short_url', 'symbol', 'redirecting',
            'prefix_suffix', 'sub_domains', 'https', 'domain_reg_len', 'favicon',
            'non_std_port', 'https_domain_url', 'request_url', 'anchor_url',
            'links_in_script_tags', 'server_form_handler', 'info_email',
            'abnormal_url', 'website_forwarding', 'status_bar_cust',
            'disable_right_click', 'using_popup_window', 'iframe_redirection',
            'age_of_domain', 'dns_recording', 'website_traffic', 'page_rank',
            'google_index', 'links_pointing_to_page', 'stats_report'
        ]
        self.explainer = None
        
    def create_ensemble_model(self) -> VotingClassifier:
        """Create an ensemble model combining multiple algorithms"""
        
        # Individual models
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        
        svm_model = SVC(
            kernel='rbf',
            probability=True,
            random_state=42
        )
        
        lr_model = LogisticRegression(
            random_state=42,
            max_iter=1000
        )
        
        # Create ensemble
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('gb', gb_model),
                ('svm', svm_model),
                ('lr', lr_model)
            ],
            voting='soft'  # Use probability-based voting
        )
        
        return ensemble
    
    def train_model(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train the ensemble model and return performance metrics"""
        
        logger.info("Starting advanced model training...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Create and train ensemble model
        self.ensemble_model = self.create_ensemble_model()
        self.ensemble_model.fit(X_train_scaled, y_train)
        
        # Make predictions
        y_pred = self.ensemble_model.predict(X_test_scaled)
        y_pred_proba = self.ensemble_model.predict_proba(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        # Cross-validation score
        cv_scores = cross_val_score(
            self.ensemble_model, X_train_scaled, y_train, cv=5
        )
        
        # Feature importance (using Random Forest from ensemble)
        feature_importance = self.get_feature_importance()
        
        # Create SHAP explainer
        try:
            self.explainer = shap.TreeExplainer(
                self.ensemble_model.named_estimators_['rf']
            )
        except Exception as e:
            logger.warning(f"Could not create SHAP explainer: {e}")
        
        results = {
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'classification_report': classification_report(y_test, y_pred),
            'feature_importance': feature_importance,
            'predictions': y_pred,
            'probabilities': y_pred_proba
        }
        
        logger.info(f"Model training completed. Accuracy: {accuracy:.4f}")
        return results
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions with confidence scores"""
        if self.ensemble_model is None:
            raise ValueError("Model not trained yet")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.ensemble_model.predict(X_scaled)
        probabilities = self.ensemble_model.predict_proba(X_scaled)
        
        return predictions, probabilities
    
    def explain_prediction(self, X: np.ndarray, sample_idx: int = 0) -> Dict[str, Any]:
        """Explain a specific prediction using SHAP"""
        if self.explainer is None:
            return {"error": "SHAP explainer not available"}
        
        try:
            X_scaled = self.scaler.transform(X)
            shap_values = self.explainer.shap_values(X_scaled[sample_idx:sample_idx+1])
            
            # Get feature contributions
            feature_contributions = {}
            for i, feature in enumerate(self.feature_names):
                if isinstance(shap_values, list):
                    # Binary classification
                    contribution = shap_values[1][0][i] if len(shap_values) > 1 else shap_values[0][0][i]
                else:
                    contribution = shap_values[0][i]
                feature_contributions[feature] = float(contribution)
            
            # Sort by absolute contribution
            sorted_contributions = sorted(
                feature_contributions.items(), 
                key=lambda x: abs(x[1]), 
                reverse=True
            )
            
            return {
                "feature_contributions": dict(sorted_contributions[:10]),  # Top 10
                "prediction_confidence": "High" if max(self.predict(X[sample_idx:sample_idx+1])[1][0]) > 0.8 else "Medium"
            }
            
        except Exception as e:
            logger.error(f"Error explaining prediction: {e}")
            return {"error": str(e)}
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from Random Forest in ensemble"""
        if self.ensemble_model is None:
            return {}
        
        try:
            rf_model = self.ensemble_model.named_estimators_['rf']
            importance_dict = {}
            
            for i, feature in enumerate(self.feature_names):
                importance_dict[feature] = float(rf_model.feature_importances_[i])
            
            # Sort by importance
            sorted_importance = sorted(
                importance_dict.items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            
            return dict(sorted_importance)
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
            return {}
    
    def save_model(self, filepath: str):
        """Save the trained model and scaler"""
        model_data = {
            'ensemble_model': self.ensemble_model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load a trained model and scaler"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.ensemble_model = model_data['ensemble_model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data.get('feature_names', self.feature_names)
            
            # Recreate SHAP explainer if possible
            try:
                self.explainer = shap.TreeExplainer(
                    self.ensemble_model.named_estimators_['rf']
                )
            except Exception as e:
                logger.warning(f"Could not recreate SHAP explainer: {e}")
            
            logger.info(f"Model loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False

def create_advanced_model():
    """Create and train an advanced phishing detection model"""
    from sklearn.datasets import make_classification
    
    logger.info("Creating advanced phishing detection model...")
    
    # Generate synthetic data (in production, use real phishing dataset)
    X, y = make_classification(
        n_samples=5000,
        n_features=30,
        n_informative=25,
        n_redundant=3,
        n_clusters_per_class=2,
        class_sep=0.8,
        random_state=42
    )
    
    # Convert labels to match original format (-1 for phishing, 1 for safe)
    y = np.where(y == 0, -1, 1)
    
    # Create and train model
    model = AdvancedPhishingModel()
    results = model.train_model(X, y)
    
    # Save the model
    import os
    os.makedirs("pickle", exist_ok=True)
    model.save_model("pickle/advanced_model.pkl")
    
    print("Advanced Model Training Results:")
    print(f"Accuracy: {results['accuracy']:.4f}")
    print(f"Cross-validation Score: {results['cv_mean']:.4f} (+/- {results['cv_std']*2:.4f})")
    print("\nTop 10 Most Important Features:")
    for i, (feature, importance) in enumerate(list(results['feature_importance'].items())[:10]):
        print(f"{i+1:2d}. {feature:25s}: {importance:.4f}")
    
    return model, results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_advanced_model()