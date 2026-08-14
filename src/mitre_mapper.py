import json
from src.logger import logger

class MITREMapper:
    def __init__(self, mapping_file='data/mitre_attack.json'):
        try:
            with open(mapping_file, 'r') as f: self.mapping = json.load(f)
        except: self.mapping = {}
    def get_mitre_id(self, attack_type): return self.mapping.get(attack_type, 'T0000')
