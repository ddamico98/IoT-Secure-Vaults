from typing import Dict, Tuple, List
import sqlite3
from src.security.secure_vault import SecureVault
from src.security.auth_protocol import AuthenticationMessage, AuthState
import secrets

class IoTServer:
    def __init__(self):
        self.active_sessions: Dict[str, dict] = {}
        self.devices: Dict[str, SecureVault] = {}
        self.db = self._init_database()
        
    def _init_database(self):
        db = sqlite3.connect(':memory:')
        cur = db.cursor()
        cur.execute('''
            CREATE TABLE devices
            (device_id TEXT PRIMARY KEY, vault_data BLOB)
        ''')
        return db
    
    def _generate_challenge(self) -> Tuple[List[int], bytes]:
        indices = [secrets.randbelow(10) for _ in range(3)]  # usando n=10 come default
        random_number = secrets.token_bytes(16)
        return indices, random_number
        
    def handle_auth_phase1(self, msg: AuthenticationMessage) -> AuthenticationMessage:
        if msg.device_id not in self.devices:
            raise ValueError("Dispositivo non autorizzato")
        
        challenge_indices, random_number = self._generate_challenge()
        session_data = {
            'device_id': msg.device_id,
            'state': AuthState.CHALLENGE_SENT,
            'challenge': challenge_indices,
            'random_number': random_number
        }
        self.active_sessions[msg.session_id] = session_data
        
        return AuthenticationMessage(
            session_id=msg.session_id,
            device_id=msg.device_id,
            challenge=challenge_indices,
            random_number=random_number
        )

    def handle_auth_request(self, device_id: str, 
                           message: AuthenticationMessage) -> AuthenticationMessage:
        if device_id not in self.devices:
            raise ValueError("Dispositivo non autorizzato")
            
        vault = self.devices[device_id]
        challenge_indices, random_number = self._generate_challenge()
        
        self.active_sessions[message.session_id] = {
            'device_id': device_id,
            'challenge': challenge_indices,
            'random_number': random_number
        }
        
        return AuthenticationMessage(
            session_id=message.session_id,
            challenge=challenge_indices,
            random_number=random_number
        ) 