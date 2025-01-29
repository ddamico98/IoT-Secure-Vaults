class SecuritySimulator:
    def __init__(self, channel):
        self.channel = channel
    
    def simulate_mitm_attack(self, message: bytes) -> bool:
        # Simula un attacco man-in-the-middle
        intercepted_message = message
        modified_message = self._try_modify_message(intercepted_message)
        return modified_message != message
    
    def simulate_side_channel_attack(self, device) -> dict:
        # Simula un attacco side-channel monitorando il consumo energetico
        power_traces = []
        for _ in range(100):
            initial_power = device.power_consumption
            device.simulate_authentication()
            power_traces.append(device.power_consumption - initial_power)
        return {'power_traces': power_traces} 