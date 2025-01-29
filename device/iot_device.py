import secrets
from dataclasses import dataclass
from src.security.auth_protocol import DeviceAuthenticator
from src.security.secure_vault import SecureVault

@dataclass
class DeviceSpecs:
    memory_kb: int = 32
    cpu_mhz: float = 16.0
    voltage_v: float = 3.3
    base_current_ma: float = 5.0
    peak_current_ma: float = 20.0

class SimulatedIoTDevice:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.specs = DeviceSpecs()
        # Inizializza prima il vault
        vault = SecureVault()
        # Poi crea l'authenticator passando il vault e device_id
        self.authenticator = DeviceAuthenticator(vault)
        self.authenticator.set_device_id(device_id)
        # Infine assegna il vault all'istanza
        self.vault = vault
        
        # Metriche di monitoraggio
        self.power_consumption = 0.0
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        self.auth_attempts = 0

    def simulate_power_consumption(self, operation_time_ms: float):
        # Calcolo corrente effettiva basata su CPU usage e operazione
        current_ma = (
            self.specs.base_current_ma + 
            (self.specs.peak_current_ma - self.specs.base_current_ma) * self.cpu_usage
        )
        
        # Calcolo energia in mWh
        energy_mwh = (
            self.specs.voltage_v * 
            current_ma * 
            operation_time_ms / 
            (3600.0)  # conversione da ms a h
        )
        
        # Aggiorna consumi
        self.power_consumption += energy_mwh
        
        # Simula l'aumento dell'utilizzo CPU
        self.cpu_usage = min(1.0, self.cpu_usage + 0.2)
        
        # Simula l'utilizzo della memoria
        self.memory_usage = min(
            self.specs.memory_kb,
            self.memory_usage + (operation_time_ms * 0.1)  # 0.1 KB/ms
        )

    def reset_metrics(self):
        """Resetta le metriche del dispositivo dopo l'autenticazione"""
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        # Non resettiamo power_consumption qui
        self.auth_attempts += 1

    def get_power_profile(self) -> dict:
        """Restituisce il profilo energetico del dispositivo"""
        current_ma = (self.specs.base_current_ma + 
                     (self.specs.peak_current_ma - self.specs.base_current_ma) * self.cpu_usage)
        
        return {
            'voltage_v': self.specs.voltage_v,
            'current_ma': current_ma,
            'power_mw': self.specs.voltage_v * current_ma,
            'total_energy_mwh': self.power_consumption
        } 