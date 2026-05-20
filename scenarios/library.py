"""Pre-built scenarios for CLI / notebook use."""
from __future__ import annotations

import random
from typing import Dict, List

from agents.attacker import NotPetyaAttacker
from agents.defender import BaselineDefender, HybridDefender, QuaticDefender
from core.topology import build_maersk_like_topology
from engine.simulation import RunResult, SimulationEngine


def scenario_maersk_counterfactual(n_endpoints=400, horizon=720, seed=42) -> Dict[str, RunResult]:
    results = {}
    topo_a = build_maersk_like_topology(n_endpoints=n_endpoints, n_zones=1,
        patch_coverage=0.55, wdigest_on=True, backup_online=True, seed=seed)
    results["baseline_nist_iso"] = SimulationEngine(
        topo_a, NotPetyaAttacker(topo_a, seed=seed),
        BaselineDefender(topo_a, seed=seed), horizon, "baseline_nist_iso").run()

    topo_b = build_maersk_like_topology(n_endpoints=n_endpoints, n_zones=6,
        patch_coverage=0.55, wdigest_on=False, backup_online=False, seed=seed)
    results["quatic_full"] = SimulationEngine(
        topo_b, NotPetyaAttacker(topo_b, seed=seed),
        QuaticDefender(topo_b, seed=seed), horizon, "quatic_full").run()

    topo_c = build_maersk_like_topology(n_endpoints=n_endpoints, n_zones=3,
        patch_coverage=0.55, wdigest_on=True, backup_online=True, seed=seed)
    results["hybrid_phase2_ica_only"] = SimulationEngine(
        topo_c, NotPetyaAttacker(topo_c, seed=seed),
        HybridDefender(topo_c, phase=2, seed=seed), horizon, "hybrid_phase2_ica_only").run()
    return results


def scenario_phase_ablation(n_endpoints=300, horizon=720, seed=42) -> Dict[str, RunResult]:
    results = {}
    for phase in range(7):
        topo = build_maersk_like_topology(
            n_endpoints=n_endpoints,
            n_zones=(1 if phase < 2 else (3 if phase < 5 else 6)),
            patch_coverage=0.55 + 0.05 * phase,
            wdigest_on=(phase < 3), backup_online=(phase < 4), seed=seed)
        results[f"phase_{phase}"] = SimulationEngine(
            topo, NotPetyaAttacker(topo, seed=seed),
            HybridDefender(topo, phase=phase, seed=seed), horizon, f"phase_{phase}").run()
    return results


def scenario_monte_carlo(defender_profile="quatic_full", n_runs=30,
                         n_endpoints=200, horizon=600, base_seed=0) -> List[RunResult]:
    rng = random.Random(base_seed)
    out = []
    for i in range(n_runs):
        seed = base_seed * 1000 + i
        if defender_profile == "baseline":
            topo = build_maersk_like_topology(n_endpoints=n_endpoints, n_zones=1,
                patch_coverage=0.55, wdigest_on=True, backup_online=True, seed=seed)
            atk = NotPetyaAttacker(topo, seed=seed,
                propagation_rate=rng.randint(4, 14),
                encryption_delay_ticks=rng.randint(15, 60))
            dfd = BaselineDefender(topo, seed=seed)
        else:
            topo = build_maersk_like_topology(n_endpoints=n_endpoints,
                n_zones=rng.randint(3, 8),
                patch_coverage=0.55, wdigest_on=False, backup_online=False, seed=seed)
            atk = NotPetyaAttacker(topo, seed=seed,
                propagation_rate=rng.randint(4, 14),
                encryption_delay_ticks=rng.randint(15, 60))
            dfd = QuaticDefender(topo, seed=seed)
        out.append(SimulationEngine(topo, atk, dfd, horizon,
                                     f"{defender_profile}_run_{i}").run())
    return out
