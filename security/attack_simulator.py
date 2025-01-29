import time
import secrets
import numpy as np
from dataclasses import dataclass
from typing import List, Dict
from src.device.iot_device import SimulatedIoTDevice
from src.server.iot_server import IoTServer
from src.network.channel import SimulatedChannel
import random

@dataclass
class AttackResult:
    attack_type: str
    details: str  # Contiene il rapporto attacchi rilevati/totali
    time_to_detect_ms: float

class SecurityTestSuite:
    def __init__(self, device: SimulatedIoTDevice, server: IoTServer):
        self.device = device
        self.server = server
        self.channel = SimulatedChannel()
        self.results: List[AttackResult] = []
        self.attack_history = []
        
    def run_all_attacks(self) -> List[AttackResult]:
        self.test_mitm_attack()
        self.test_side_channel_attack()
        self.test_password_prediction()
        self.test_dos_attack()
        return self.results
        
    def try_intercept_and_modify(self, message) -> Dict:
        # Simula un tentativo di modifica del messaggio
        try:
            # Tenta di modificare il messaggio
            modified = bytearray(message.response if message.response else message.random_number)
            modified[0] ^= 0xFF  # Inverte i bit del primo byte
            
            return {
                'modified': True,
                'original': message,
                'modified_data': bytes(modified)
            }
        except (AttributeError, TypeError):
            return {'modified': False, 'original': message}
            
    def test_mitm_attack(self):
        start_time = time.time()
        detected_attacks = 0
        total_attempts = 100
        
        for _ in range(total_attempts):
            # Inizia una nuova sessione di autenticazione
            msg1 = self.device.authenticator.initiate_auth()
            if random.random() < 0.3:  # 30% probabilità di tentare l'intercettazione
                try:
                    # Modifica il messaggio
                    intercepted = self.try_intercept_and_modify(msg1)
                    if intercepted['modified']:
                        # Tenta di completare l'autenticazione con il messaggio modificato
                        try:
                            msg2 = self.server.handle_auth_phase1(intercepted['modified_data'])
                            detected_attacks += 1
                        except (ValueError, TypeError):
                            pass
                except Exception:
                    continue
        
        self.results.append(AttackResult(
            attack_type="MITM",
            details=f"Attacchi rilevati: {detected_attacks}/{total_attempts}",
            time_to_detect_ms=(time.time() - start_time) * 1000
        ))

    def test_side_channel_attack(self):
        start_time = time.time()
        detected_patterns = 0
        total_patterns = 50
        
        # Raccoglie tracce di potenza durante multiple autenticazioni
        for _ in range(total_patterns):
            trace = []
            initial_power = self.device.power_consumption
            
            # Registra il consumo durante l'intera autenticazione
            msg1 = self.device.authenticator.initiate_auth()
            trace.append(self.device.power_consumption - initial_power)
            
            msg2 = self.server.handle_auth_phase1(msg1)
            trace.append(self.device.power_consumption - initial_power)
            
            msg3 = self.device.authenticator.handle_challenge(msg2)
            trace.append(self.device.power_consumption - initial_power)
            
            # Aggiungi rumore realistico (3-5% del segnale)
            noise_factor = random.uniform(0.03, 0.05)
            # Evita valori nulli aggiungendo un offset minimo
            trace = [max(p, 1e-6) for p in trace]  # Assicura valori positivi
            noisy_trace = [p * (1 + random.gauss(0, noise_factor)) for p in trace]
            
            # Analisi delle tracce per pattern ricorrenti
            if len(noisy_trace) >= 2:
                # Calcola correlazione solo se le tracce hanno varianza non nulla
                trace1 = np.array(noisy_trace[-1])
                trace2 = np.array(noisy_trace[-2])
                
                if np.std(trace1) > 1e-6 and np.std(trace2) > 1e-6:
                    correlation = np.corrcoef(trace1, trace2)[0,1]
                    if correlation > 0.85:  # Alta correlazione potrebbe indicare una vulnerabilità
                        detected_patterns += 1
        
        self.results.append(AttackResult(
            attack_type="Side-Channel",
            details=f"Attacchi rilevati: {detected_patterns}/{total_patterns}",
            time_to_detect_ms=(time.time() - start_time) * 1000
        ))

    def test_password_prediction(self):
        start_time = time.time()
        detected_attempts = 0
        total_attempts = 30
        observed_responses = []  # Inizializzazione della lista mancante
        
        # Raccoglie risposte per analisi
        for _ in range(total_attempts):
            msg1 = self.device.authenticator.initiate_auth()
            msg2 = self.server.handle_auth_phase1(msg1)
            msg3 = self.device.authenticator.handle_challenge(msg2)
            
            if msg3.response:
                observed_responses.append(msg3.response)
        
        # Analizza pattern nelle risposte
        if len(observed_responses) >= 2:
            for i in range(len(observed_responses)-1):
                # Cerca pattern ripetuti nelle risposte
                if observed_responses[i] == observed_responses[i+1]:
                    detected_attempts += 1
                # Cerca pattern prevedibili (es. incrementali)
                elif observed_responses[i] < observed_responses[i+1]:
                    detected_attempts += 0.5
        
        self.results.append(AttackResult(
            attack_type="Password-Prediction",
            details=f"Attacchi rilevati: {detected_attempts}/{total_attempts}",
            time_to_detect_ms=(time.time() - start_time) * 1000
        ))

    def test_dos_attack(self):
        start_time = time.time()
        MAX_REQUESTS = 1000
        WINDOW_SIZE = 100  # ms
        request_times = []  # Inizializzazione della lista mancante
        detected_requests = 0
        
        for _ in range(MAX_REQUESTS):
            current_time = time.time() * 1000
            
            # Rimuovi richieste vecchie dalla finestra
            request_times = [t for t in request_times if current_time - t < WINDOW_SIZE]
            
            # Se troppe richieste nella finestra, blocca
            if len(request_times) > 50:  # Max 50 richieste per finestra
                detected_requests += 1
                time.sleep(0.01)  # Simula backoff
                continue
                
            try:
                self.device.authenticator.initiate_auth()
                request_times.append(current_time)
            except Exception:
                detected_requests += 1
        
        self.results.append(AttackResult(
            attack_type="DoS",
            details=f"Attacchi rilevati: {detected_requests}/{MAX_REQUESTS}",
            time_to_detect_ms=(time.time() - start_time) * 1000
        ))

    def generate_security_report(self) -> str:
        if not self.results:
            return "Nessun risultato di sicurezza disponibile"
            
        report = ["=== Report Sicurezza Secure Vault ===\n"]
        for result in self.results:
            report.append(f"\nAttacco: {result.attack_type}")
            report.append(f"Dettagli: {result.details}")
            report.append(f"Tempo rilevamento: {result.time_to_detect_ms:.2f}ms")
        
        return "\n".join(report)