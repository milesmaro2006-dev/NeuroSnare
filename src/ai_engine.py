import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
from src.config import Config
from src.logger import logger

class AIEngine:
    def __init__(self):
        self.model = None; self.scaler = StandardScaler(); self.is_trained = False; self.load_model()
    def train_model(self, data_path='data/training_data.csv', force=False):
        try:
            data = pd.read_csv(data_path); X = data.iloc[:, :25]; X_scaled = self.scaler.fit_transform(X)
            self.model = IsolationForest(contamination=Config.CONTAMINATION, random_state=Config.RANDOM_STATE, n_estimators=100)
            self.model.fit(X_scaled); self.is_trained = True; self.save_model(); return True
        except Exception as e: logger.log_error('TRAINING', str(e)); return False
    def predict(self, features):
        if not self.is_trained or self.model is None: return self._default_detection(features)
        try:
            arr = np.array(features).reshape(1, -1)
            if arr.shape[1] < 25: arr = np.hstack([arr, np.zeros((1, 25 - arr.shape[1]))])
            elif arr.shape[1] > 25: arr = arr[:, :25]
            scaled = self.scaler.transform(arr); score = self.model.decision_function(scaled)[0]; pred = self.model.predict(scaled)[0]
            is_attack = (pred == -1); confidence = 1 / (1 + np.exp(-score))
            return {'is_attack': is_attack, 'confidence': float(confidence), 'prediction': 'Malicious' if is_attack else 'Normal'}
        except Exception as e: logger.log_error('PREDICT', str(e)); return self._default_detection(features)
    def _default_detection(self, features):
        size = features[0] if len(features) > 0 else 0; port = features[1] if len(features) > 1 else 0
        is_attack = (size > Config.PACKET_SIZE_THRESHOLD) or (port in [22,23,21,3389,3306])
        return {'is_attack': is_attack, 'confidence': 0.7 if is_attack else 0.1, 'prediction': 'Malicious' if is_attack else 'Normal'}
    def save_model(self): Path('models').mkdir(exist_ok=True); joblib.dump({'model': self.model, 'scaler': self.scaler, 'is_trained': self.is_trained}, Config.MODEL_PATH)
    def load_model(self):
        if Path(Config.MODEL_PATH).exists():
            data = joblib.load(Config.MODEL_PATH); self.model = data['model']; self.scaler = data['scaler']; self.is_trained = data['is_trained']; return True
        return False
ai_engine = AIEngine()
