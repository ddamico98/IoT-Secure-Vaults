from typing import List
import time
from src.device.iot_device import SimulatedIoTDevice
from src.server.iot_server import IoTServer
from src.network.channel import SimulatedChannel
from src.simulation.metrics import SimulationMetrics
from src.security.attack_simulator import SecurityTestSuite

class SimulationRunner:
    def __init__(self, num_devices: int):
        self.devices = [SimulatedIoTDevice(f"dev_{i}") 
                       for i in range(num_devices)]
        self.server = IoTServer()
        self.channel = SimulatedChannel()
        self.metrics = SimulationMetrics()
        
        # Registra i dispositivi nel server
        for device in self.devices:
            self.server.devices[device.device_id] = device.vault
        
    def run_full_simulation(self):
        # Test di sicurezza
        security_suite = SecurityTestSuite(self.devices[0], self.server)
        attack_results = security_suite.run_all_attacks()
        security_report = security_suite.generate_security_report()
        print("\n" + security_report)
        
        # Simulazione normale
        for device in self.devices:
            start_time = time.time()
            self._run_authentication(device)
            auth_time = (time.time() - start_time) * 1000
            
            # Ottieni il profilo energetico completo prima del reset
            power_profile = device.get_power_profile()
            
            self.metrics.add_measurement(
                auth_time=auth_time,
                power=power_profile['total_energy_mwh'],
                memory=device.memory_usage
            )
            
            # Reset delle metriche dopo aver salvato le misurazioni
            device.reset_metrics()
            
    def _run_authentication(self, device: SimulatedIoTDevice):
        # Fase 1: Inizializzazione
        msg1 = device.authenticator.initiate_auth()
        msg1 = self.channel.transmit(msg1)
        device.simulate_power_consumption(20.0)  # Inizializzazione
        
        # Fase 2: Challenge del server
        msg2 = self.server.handle_auth_phase1(msg1)
        msg2 = self.channel.transmit(msg2)
        device.simulate_power_consumption(30.0)  # Elaborazione challenge
        
        # Fase 3: Risposta del device
        msg3 = device.authenticator.handle_challenge(msg2)
        msg3 = self.channel.transmit(msg3)
        device.simulate_power_consumption(40.0)  # Generazione risposta
        
        # Fase 4: Verifica finale e aggiornamento vault
        device.vault.update_vault(msg3.session_id.encode())
        device.simulate_power_consumption(25.0)  # Aggiornamento vault
        
        # Reset CPU usage per la prossima autenticazione
        device.reset_metrics() 