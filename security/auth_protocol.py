import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple
import hmac
import hashlib
from enum import Enum
from src.security.secure_vault import SecureVault

class AuthState(Enum):
    INIT = 0
    CHALLENGE_SENT = 1
    AUTHENTICATED = 2
    FAILED = 3
    AUTH_STARTED = 4

@dataclass
class AuthenticationMessage:
    session_id: str
    device_id: Optional[str] = None
    challenge: Optional[List[int]] = None
    random_number: Optional[bytes] = None
    response: Optional[bytes] = None

class DeviceAuthenticator:
    def __init__(self, vault: SecureVault):
        self.vault = vault
        self.state = AuthState.INIT
        self.current_session = None
        self.challenge_response = None
        self.device_id = None

    def set_device_id(self, device_id: str):
        self.device_id = device_id

    def initiate_auth(self) -> AuthenticationMessage:
        if not self.device_id:
            raise ValueError("Device ID not set")
            
        self.state = AuthState.AUTH_STARTED
        self.current_session = secrets.token_hex(16)
        return AuthenticationMessage(
            session_id=self.current_session,
            device_id=self.device_id
        )

    def handle_challenge(self, message: AuthenticationMessage) -> AuthenticationMessage:
        if self.state != AuthState.AUTH_STARTED:
            raise ValueError("Invalid authentication state")
            
        self.state = AuthState.CHALLENGE_SENT
        response = self.vault.generate_response(message.challenge)
        
        return AuthenticationMessage(
            session_id=self.current_session,
            device_id=self.device_id,
            response=response,
            random_number=secrets.token_bytes(32)
        )

class AuthenticationProtocol:
    def __init__(self, secure_vault):
        self.vault = secure_vault
        self.session_key = None
        
    def generate_challenge(self) -> Tuple[List[int], bytes]:
        indices = [secrets.randbelow(self.vault.n) for _ in range(3)]
        random_number = secrets.token_bytes(16)
        return indices, random_number
    
    def compute_response(self, challenge_indices: List[int], 
                        random_number: bytes) -> bytes:
        selected_keys = self.vault.get_keys_by_indices(challenge_indices)
        combined_key = b''.join(selected_keys)
        return hmac.new(combined_key, random_number, hashlib.sha256).digest() 