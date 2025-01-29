import secrets
import hmac
import hashlib
from typing import List, Tuple
from cryptography.fernet import Fernet
import base64

class SecureVault:
    def __init__(self, n: int = 10, m: int = 128):
        self.n = n  # numero di chiavi
        self.m = m  # dimensione chiave in bit
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.keys = self._generate_and_encrypt_keys()
    
    def _generate_and_encrypt_keys(self) -> List[bytes]:
        raw_keys = [secrets.token_bytes(self.m // 8) for _ in range(self.n)]
        return [self.fernet.encrypt(key) for key in raw_keys]
    
    def decrypt_key(self, encrypted_key: bytes) -> bytes:
        return self.fernet.decrypt(encrypted_key)
    
    def get_keys_by_indices(self, indices: List[int]) -> List[bytes]:
        return [self.decrypt_key(self.keys[i]) for i in indices]
    
    def generate_response(self, challenge: List[int]) -> bytes:
        # Ottiene le chiavi decifrate per gli indici della sfida
        challenge_keys = self.get_keys_by_indices(challenge)
        
        # Combina le chiavi usando XOR
        response = challenge_keys[0]
        for key in challenge_keys[1:]:
            response = bytes(a ^ b for a, b in zip(response, key))
            
        # Genera HMAC della risposta
        h = hmac.new(self.encryption_key, response, hashlib.sha256)
        return h.digest()
    
    def update_vault(self, session_data: bytes):
        # Genera HMAC dei dati di sessione
        h = hmac.new(self.encryption_key, session_data, hashlib.sha256)
        hmac_value = h.digest()
        
        # Aggiorna le chiavi usando XOR con HMAC
        for i in range(self.n):
            decrypted_key = self.decrypt_key(self.keys[i])
            start = (i * len(hmac_value)) % len(hmac_value)
            updated_key = bytes(a ^ b for a, b in zip(decrypted_key, 
                              hmac_value[start:start + len(decrypted_key)]))
            self.keys[i] = self.fernet.encrypt(updated_key) 