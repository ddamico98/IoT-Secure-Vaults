from dataclasses import dataclass
from typing import List, Dict

@dataclass
class SimulationMetrics:
    auth_time_ms: List[float] = None
    power_consumption_mwh: List[float] = None
    memory_usage_kb: List[float] = None
    
    def __post_init__(self):
        self.auth_time_ms = []
        self.power_consumption_mwh = []
        self.memory_usage_kb = []
        
    def add_measurement(self, auth_time: float, power: float, memory: float):
        self.auth_time_ms.append(auth_time)
        self.power_consumption_mwh.append(power)
        self.memory_usage_kb.append(memory) 