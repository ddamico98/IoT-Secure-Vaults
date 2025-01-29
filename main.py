from src.simulation.runner import SimulationRunner
from src.analysis.performance import PerformanceAnalyzer

def main():
    # Configurazione solo per 1000 dispositivi
    n = 1000
    runner = SimulationRunner(n)
    runner.run_full_simulation()
    
    analyzer = PerformanceAnalyzer()
    performance_metrics = analyzer.analyze_authentication_performance(runner.metrics)
    
    # Stampa risultati
    print(f"\nRisultati per {n} dispositivi:")
    print(f"Tempo medio auth: {performance_metrics['avg_auth_time_ms']:.2f} ms")
    print(f"Consumo medio: {performance_metrics['avg_power_mwh']:.2f} mWh")
    print(f"Tasso di successo: {performance_metrics['success_rate']*100:.1f}%")

if __name__ == "__main__":
    main() 