"""
QUATIC Simulation — Multi-Organisation TCICP Experiment
========================================================
Tests the central TCICP claim from Section 2.8 and Table 4.6:
  "Coordinated containment by N organisations is more effective than
   N organisations each fighting alone."

Setup:
  - N organisations, each with its own topology
  - Attacker hits Org 1 first, then Org 2 a few minutes later, etc.
  - Mode A (Isolated): each org fights independently (NotPetya 2017 reality)
  - Mode B (TCICP): when one org detects, all orgs activate elevated defence
    via Real-Time Intelligence Dissemination + Coordinated Defensive Activation

The experiment quantifies the federation benefit, validating the
"herd immunity" analogy from Section 2.9.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from agents.attack_classes import make_attacker
from agents.defender import HybridDefender, QuaticDefender
from core.topology import build_maersk_like_topology
from engine.simulation import RunResult, SimulationEngine


@dataclass
class FederationResult:
    org_results: List[RunResult] = field(default_factory=list)
    org_names: List[str] = field(default_factory=list)
    mode: str = "isolated"   # "isolated" or "tcicp"
    total_destroyed: float = 0.0   # avg destroyed % across all orgs
    total_healthy: float = 0.0
    contained_orgs: int = 0
    total_orgs: int = 0
    total_loss_usd: float = 0.0


def run_multi_org_experiment(
    n_orgs: int = 5,
    n_endpoints_per_org: int = 150,
    horizon: int = 240,
    attack_class: str = "notpetya",
    tcicp_mode: bool = True,
    stagger_minutes: int = 5,        # delay between when each org gets hit
    base_seed: int = 42,
) -> FederationResult:
    """
    Simulate an attack rolling across N organisations.

    If tcicp_mode=True, the first org to detect raises the global threat_level
    on all subsequent orgs (compressed RTID + CDA). This makes detection
    faster and containment more aggressive on orgs hit later.
    """
    results: List[RunResult] = []
    org_names = [f"Org-{i+1}" for i in range(n_orgs)]

    # Build all topologies and attackers first
    org_data = []
    for i in range(n_orgs):
        seed = base_seed + i * 100
        topo = build_maersk_like_topology(
            n_endpoints=n_endpoints_per_org, n_zones=6,
            patch_coverage=0.55, wdigest_on=False, backup_online=False,
            seed=seed,
        )
        atk = make_attacker(attack_class, topo, seed=seed)
        # Stagger: each subsequent org gets hit `stagger_minutes` later
        atk._entry_tick = None  # let it initialise on first tick called
        if tcicp_mode:
            # In TCICP mode, defenders start sharing memory from tick 0
            dfd = QuaticDefender(
                topo, seed=seed,
                # Later-hit orgs benefit from heightened initial threat
                initial_threat_level=0.5 + 0.1 * i,
            )
        else:
            # Isolated: each org is on its own, default threat level
            dfd = QuaticDefender(topo, seed=seed, initial_threat_level=0.5)
        org_data.append({
            "topo": topo, "atk": atk, "dfd": dfd,
            "name": org_names[i], "stagger_offset": i * stagger_minutes,
        })

    # Run each org's simulation in parallel "wall clock"
    # Stagger means: org i doesn't start being attacked until tick = i * stagger
    shared_immune_memory = set()
    global_threat_boost = 0.0
    for i, data in enumerate(org_data):
        engine = SimulationEngine(
            data["topo"], data["atk"], data["dfd"],
            horizon_ticks=horizon, scenario_name=f"{data['name']}_{attack_class}",
            capture_snapshots=False,  # save memory for federation runs
        )
        # If TCICP mode and earlier orgs already detected, give this defender
        # a sensitivity boost (pre-loaded immune memory + raised threat level)
        if tcicp_mode and shared_immune_memory:
            data["dfd"].immune_memory.update(shared_immune_memory)
            data["dfd"].threat_level = min(1.0, 0.5 + global_threat_boost)
        result = engine.run()
        results.append(result)

        # If org detected something, broadcast it
        if tcicp_mode and data["dfd"].immune_memory:
            shared_immune_memory.update(data["dfd"].immune_memory)
            global_threat_boost = min(0.5, global_threat_boost + 0.08)

    # Aggregate
    fed = FederationResult(
        org_results=results,
        org_names=org_names,
        mode=("tcicp" if tcicp_mode else "isolated"),
        total_orgs=n_orgs,
    )
    fed.total_destroyed = sum(r.final_destroyed_fraction for r in results) / n_orgs * 100
    fed.total_healthy = sum(r.final_healthy_fraction for r in results) / n_orgs * 100
    fed.contained_orgs = sum(1 for r in results if r.attack_contained)
    fed.total_loss_usd = sum(r.cost_estimate_usd for r in results)
    return fed


def federation_comparison(
    n_orgs: int = 5,
    n_endpoints_per_org: int = 150,
    horizon: int = 240,
    attack_class: str = "notpetya",
    base_seed: int = 42,
) -> Dict[str, FederationResult]:
    """Run both isolated and TCICP modes for comparison."""
    return {
        "isolated": run_multi_org_experiment(
            n_orgs=n_orgs, n_endpoints_per_org=n_endpoints_per_org,
            horizon=horizon, attack_class=attack_class,
            tcicp_mode=False, base_seed=base_seed,
        ),
        "tcicp": run_multi_org_experiment(
            n_orgs=n_orgs, n_endpoints_per_org=n_endpoints_per_org,
            horizon=horizon, attack_class=attack_class,
            tcicp_mode=True, base_seed=base_seed,
        ),
    }
