import requests
from src.config import Config
from src.logger import logger

class ThreatIntel:
    def __init__(self):
        self.abuse_key = Config.ABUSEIPDB_API_KEY
        self.vt_key = Config.VIRUSTOTAL_API_KEY
        self.otx_key = Config.OTX_API_KEY

    def check_ip(self, ip):
        result = {'sources': {}}
        if self.abuse_key:
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'
                resp = requests.get(url, headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip, 'maxAgeInDays': 30}, timeout=5)
                if resp.status_code == 200:
                    data = resp.json().get('data', {})
                    result['sources']['abuseipdb'] = {'score': data.get('abuseConfidenceScore', 0), 'country': data.get('countryCode', '')}
            except Exception as e: logger.log_error('ABUSEIPDB', str(e))
        if self.vt_key:
            try:
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
                resp = requests.get(url, headers={'x-apikey': self.vt_key}, timeout=5)
                if resp.status_code == 200:
                    stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    result['sources']['virustotal'] = {'malicious': stats.get('malicious', 0), 'harmless': stats.get('harmless', 0)}
            except Exception as e: logger.log_error('VT', str(e))
        if self.otx_key:
            try:
                url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
                resp = requests.get(url, headers={'X-OTX-API-KEY': self.otx_key}, timeout=5)
                if resp.status_code == 200:
                    result['sources']['otx'] = {'pulse_count': resp.json().get('pulse_info', {}).get('count', 0)}
            except Exception as e: logger.log_error('OTX', str(e))
        return result
