import time
import random

class SimulatedChannel:
    def __init__(self, latency_ms: float = 50, jitter_ms: float = 10):
        self.latency = latency_ms
        self.jitter = jitter_ms
        
    def transmit(self, data: bytes) -> bytes:
        # Simula latenza di rete
        delay = self.latency + random.uniform(-self.jitter, self.jitter)
        time.sleep(delay / 1000)
        return data 