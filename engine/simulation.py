"""QUATIC Simulation — Discrete-event engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agents.attacker import AttackEvent, NotPetyaAttacker
from agents.defender import (
    BaselineDefender, DefenderAction, HybridDefender, QuaticDefender,
)
from core.topology import NodeState, Topology


@dataclass
class TickRecord:
    tick: int
    healthy_fraction: float
    destroyed_fraction: float
    compromised_fraction: float
    quarantined_fraction: float
    dcs_alive: int
    attack_events: int
    defender_actions: int
    node_states: Dict[str, str] = field(default_factory=dict)
    zones_isolated: List[str] = field(default_factory=list)


@dataclass
class RunResult:
    scenario_name: str
    ticks: List[TickRecord] = field(default_factory=list)
    attack_events: List[AttackEvent] = field(default_factory=list)
    defender_actions: List[DefenderAction] = field(default_factory=list)

    time_to_detection: Optional[int] = None
    time_to_containment: Optional[int] = None
    final_destroyed_fraction: float = 0.0
    final_healthy_fraction: float = 0.0
    final_dcs_alive: int = 0
    attack_contained: bool = False
    zones_breached: int = 0
    cross_zone_attempts_blocked: int = 0
    cost_estimate_usd: float = 0.0

    def summary(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario_name,
            "final_healthy_pct": round(100 * self.final_healthy_fraction, 2),
            "final_destroyed_pct": round(100 * self.final_destroyed_fraction, 2),
            "time_to_detection_min": self.time_to_detection,
            "time_to_containment_min": self.time_to_containment,
            "dcs_alive": self.final_dcs_alive,
            "zones_breached": self.zones_breached,
            "cross_zone_blocks": self.cross_zone_attempts_blocked,
            "contained": self.attack_contained,
            "estimated_loss_usd": round(self.cost_estimate_usd, 0),
        }


def estimate_cost(topo: Topology, downtime_ticks: int) -> float:
    per_node_per_tick = 0.35
    destroyed = sum(
        1 for n in topo.nodes.values()
        if n.state in (NodeState.ENCRYPTED, NodeState.DESTROYED)
    )
    rebuild_cost_per_destroyed = 1800.0
    return destroyed * rebuild_cost_per_destroyed + \
           destroyed * per_node_per_tick * max(1, downtime_ticks)


class SimulationEngine:
    def __init__(
        self,
        topo: Topology,
        attacker: NotPetyaAttacker,
        defender: Any,
        horizon_ticks: int = 720,
        scenario_name: str = "unnamed",
        capture_snapshots: bool = True,
    ):
        self.topo = topo
        self.attacker = attacker
        self.defender = defender
        self.horizon = horizon_ticks
        self.scenario_name = scenario_name
        self.capture_snapshots = capture_snapshots
        self.result = RunResult(scenario_name=scenario_name)

    def run(self) -> RunResult:
        for t in range(self.horizon):
            events = self.attacker.tick(t)
            self.defender.tick(events, t)

            hf = self.topo.healthy_fraction()
            df = self.topo.destroyed_fraction()
            cf = sum(1 for n in self.topo.nodes.values()
                     if n.state == NodeState.COMPROMISED) / max(1, len(self.topo.nodes))
            qf = sum(1 for n in self.topo.nodes.values()
                     if n.state == NodeState.QUARANTINED) / max(1, len(self.topo.nodes))

            record = TickRecord(
                tick=t, healthy_fraction=hf, destroyed_fraction=df,
                compromised_fraction=cf, quarantined_fraction=qf,
                dcs_alive=self.topo.domain_controllers_alive(),
                attack_events=len(events),
                defender_actions=len(getattr(self.defender, "actions", [])),
            )
            if self.capture_snapshots:
                record.node_states = self.topo.snapshot_states()
                record.zones_isolated = [zid for zid, z in self.topo.zones.items() if z.isolated]
            self.result.ticks.append(record)

            if hf < 0.02 and df > 0.9:
                break
            no_live_compromise = cf == 0.0 and self.attacker._fired_payload
            if no_live_compromise and t > self.attacker.encryption_delay_ticks + 10:
                break

        self.result.attack_events = list(self.attacker.events)
        self.result.defender_actions = list(getattr(self.defender, "actions", []))
        self.result.final_destroyed_fraction = self.topo.destroyed_fraction()
        self.result.final_healthy_fraction = self.topo.healthy_fraction()
        self.result.final_dcs_alive = self.topo.domain_controllers_alive()
        self.result.zones_breached = sum(
            1 for z in self.topo.zones.values()
            if any(
                self.topo.nodes[nid].state in (
                    NodeState.COMPROMISED, NodeState.ENCRYPTED, NodeState.DESTROYED
                )
                for nid in z.nodes
            )
        )
        self.result.cross_zone_attempts_blocked = sum(
            1 for e in self.attacker.events
            if e.stage == "lateral_movement_blocked"
        )

        if self.result.defender_actions:
            self.result.time_to_detection = self.result.defender_actions[0].tick
            contain_actions = [
                a for a in self.result.defender_actions
                if a.action in ("autonomous_quarantine", "zone_isolation", "manual_quarantine")
            ]
            if contain_actions:
                self.result.time_to_containment = contain_actions[0].tick

        self.result.attack_contained = (
            self.result.final_healthy_fraction > 0.80
            and self.result.final_destroyed_fraction < 0.05
        )

        self.result.cost_estimate_usd = estimate_cost(
            self.topo,
            downtime_ticks=(
                (self.result.time_to_containment or self.horizon)
                - (self.result.time_to_detection or 0)
            ),
        )
        return self.result
