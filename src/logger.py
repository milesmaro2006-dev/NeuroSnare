import logging
import logging.handlers
import json
from datetime import datetime
from pathlib import Path
from src.config import Config

class CustomLogger:
    def __init__(self):
        self.setup_logging()

    def setup_logging(self):
        Path('logs').mkdir(exist_ok=True)
        self.logger = logging.getLogger('NeuroSnare')
        self.logger.setLevel(getattr(logging, Config.LOG_LEVEL))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh = logging.handlers.RotatingFileHandler(Config.LOG_FILE, maxBytes=10_485_760, backupCount=5)
        fh.setFormatter(formatter); self.logger.addHandler(fh)
        ah = logging.handlers.RotatingFileHandler(Config.ATTACK_LOG, maxBytes=5_242_880, backupCount=3)
        ah.setFormatter(formatter); self.logger.addHandler(ah)
        ch = logging.StreamHandler(); ch.setFormatter(formatter); self.logger.addHandler(ch)

    def log_attack(self, attacker_ip, target_port, attack_type, details=None):
        self.logger.warning(json.dumps({'timestamp': datetime.now().isoformat(), 'attacker_ip': attacker_ip, 'target_port': target_port, 'attack_type': attack_type, 'details': details}))

    def log_system_event(self, event_type, message):
        self.logger.info(json.dumps({'timestamp': datetime.now().isoformat(), 'event_type': event_type, 'message': message}))

    def log_error(self, error_type, error_message):
        self.logger.error(json.dumps({'timestamp': datetime.now().isoformat(), 'error_type': error_type, 'error_message': error_message}))

    def log_honeypot_activity(self, activity_type, details):
        self.logger.info(f"HONEYPOT: {json.dumps({'timestamp': datetime.now().isoformat(), 'activity_type': activity_type, 'details': details})}")

logger = CustomLogger()
