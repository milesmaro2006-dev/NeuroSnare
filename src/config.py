import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'eth0')
    REAL_SERVER_IP = os.getenv('REAL_SERVER_IP', '192.168.1.10')

    HONEYPOT_IPS = {
        'ssh': os.getenv('HONEYPOT_IP_SSH', '192.168.1.101'),
        'web': os.getenv('HONEYPOT_IP_WEB', '192.168.1.102'),
        'ftp': os.getenv('HONEYPOT_IP_FTP', '192.168.1.103'),
        'smb': os.getenv('HONEYPOT_IP_SMB', '192.168.1.104'),
    }

    MODEL_PATH = 'models/ai_model.pkl'
    CONTAMINATION = 0.05
    RANDOM_STATE = 42

    IPTABLES_CHAIN = 'NEUROSNARE'
    IPTABLES_TABLE = 'nat'

    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/system.log'
    ATTACK_LOG = 'logs/attacks.log'
    HONEYPOT_LOG = 'logs/honeypot_activity.log'

    PACKET_SIZE_THRESHOLD = 1500
    CONNECTION_RATE_THRESHOLD = 100
    PORT_SCAN_THRESHOLD = 20
    ATTACK_COOLDOWN = 60

    DB_FILE = 'neurosnare.db'

    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    OTX_API_KEY = os.getenv('OTX_API_KEY')

    DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', 5000))
