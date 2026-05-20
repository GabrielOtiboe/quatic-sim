"""QUATIC Simulation — Defenders (Baseline NIST/ISO, QUATIC full, Hybrid)."""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Optional, Set

from agents.attacker import AttackEvent
from core.topology import (
    Node, NodeState, ProcessBehaviour, Topology,
)


@dataclass
class DefenderAction:
    tick: int
    action: str
    target: str
    rationale: str


def entropy_signal(node: Node) -> float:
    return node.observable_entropy_spike()


def auth_signal(node: Node) -> float:
    return node.observable_auth_spike()


def has_behaviour(node: Node, b: ProcessBehaviour) -> bool:
    return b in node.running_processes


class BaselineDefender:
    """NIST CSF / ISO 27001 — reactive, signature-based, human-speed."""

    def __init__(
        self,
        topo: Topology,
        seed: int = 7,
        signature_hit_prob: float = 0.0,
        human_response_ticks_mean: float = 180,
        human_response_ticks_sigma: float = 60,
        has_edr: bool = True,
        has_segmentation: bool = False,
    ):
        self.topo = topo
        self.rng = random.Random(seed)
        self.signature_hit_prob = signature_hit_prob
        self.mu = human_response_ticks_mean
        self.sigma = human_response_ticks_sigma
        self.has_edr = has_edr
        self.has_segmentation = has_segmentation
        self.actions: List[DefenderAction] = []
        self._alerted_tick: Optional[int] = None

    def detect(self, events: List[AttackEvent], tick: int) -> bool:
        for e in events:
            if e.behaviour == ProcessBehaviour.HIGH_ENTROPY_WRITE:
                if self.has_edr and self.rng.random() < 0.6:
                    if self._alerted_tick is None:
                        self._alerted_tick = tick
                        return True
            if self.rng.random() < self.signature_hit_prob:
                if self._alerted_tick is None:
                    self._alerted_tick = tick
                    return True
        return False

    def respond(self, tick: int) -> None:
        if self._alerted_tick is None:
            return
        sampled_lag = max(1, int(self.rng.gauss(self.mu, self.sigma)))
        if tick < self._alerted_tick + sampled_lag:
            return
        for nid, node in self.topo.nodes.items():
            if node.state == NodeState.COMPROMISED:
                node.state = NodeState.QUARANTINED
                self.actions.append(DefenderAction(
                    tick=tick, action="manual_quarantine", target=nid,
                    rationale="SOC analyst isolated host after human triage.",
                ))

    def tick(self, events: List[AttackEvent], t: int) -> None:
        self.detect(events, t)
        self.respond(t)


class QuaticDefender:
    """Full ICA + QES + TCICP."""

    def __init__(
        self,
        topo: Topology,
        seed: int = 11,
        ica_enabled: bool = True,
        dia_detection_threshold: float = 0.15,
        dia_response_latency_ticks: int = 1,
        qes_layer1: bool = True,
        qes_layer2: bool = True,
        qes_layer3: bool = True,
        qes_layer4: bool = True,
        qes_layer5: bool = True,
        tcicp_enabled: bool = True,
        initial_threat_level: float = 0.5,
        false_negative_rate: float = 0.12,
        false_positive_rate: float = 0.03,
    ):
        self.topo = topo
        self.rng = random.Random(seed)
        self.ica_enabled = ica_enabled
        self.threshold = dia_detection_threshold
        self.response_latency = dia_response_latency_ticks
        self.qes = {1: qes_layer1, 2: qes_layer2, 3: qes_layer3,
                    4: qes_layer4, 5: qes_layer5}
        self.tcicp_enabled = tcicp_enabled
        self.threat_level = initial_threat_level
        self.fn_rate = false_negative_rate
        self.fp_rate = false_positive_rate
        self.actions: List[DefenderAction] = []
        self.immune_memory: Set[str] = set()

        if self.qes[5]:
            self._apply_pqc_sessions()

    def _apply_pqc_sessions(self) -> None:
        for node in self.topo.nodes.values():
            for c in node.credentials:
                if c.privilege >= 1:
                    c.quantum_session = True
                    c.in_memory_plaintext = False

    def _qes_detects(self, node: Node, event: AttackEvent) -> Optional[str]:
        if self.rng.random() < self.fn_rate * (1.0 - self.threat_level * 0.5):
            return None
        sens = self.threshold * (1.0 - 0.4 * self.threat_level)

        if self.qes[1] and (
            entropy_signal(node) > sens or
            has_behaviour(node, ProcessBehaviour.HIGH_ENTROPY_WRITE) or
            has_behaviour(node, ProcessBehaviour.MBR_WRITE)
        ):
            return "QES-L1-FileEntropy"
        if self.qes[2] and event.cross_zone and has_behaviour(node, ProcessBehaviour.C2_BEACON):
            return "QES-L2-NetEntropy"
        if self.qes[3] and (
            auth_signal(node) > sens or
            has_behaviour(node, ProcessBehaviour.CREDENTIAL_DUMP) or
            has_behaviour(node, ProcessBehaviour.AUTH_BURST)
        ):
            return "QES-L3-AuthEntropy"
        if self.qes[4] and has_behaviour(node, ProcessBehaviour.SMB_SCAN):
            return "QES-L4-TopologyRandomisation"
        return None

    def _dia_quarantine_node(self, tick: int, nid: str, reason: str) -> None:
        node = self.topo.nodes[nid]
        if node.state in (NodeState.COMPROMISED, NodeState.HEALTHY):
            node.state = NodeState.QUARANTINED
        self.actions.append(DefenderAction(
            tick=tick, action="autonomous_quarantine", target=nid,
            rationale=f"ICA DIA micro-segmented host on {reason}.",
        ))

    def _dia_revoke_credentials(self, tick: int, nid: str) -> None:
        node = self.topo.nodes[nid]
        for c in node.credentials:
            c.in_memory_plaintext = False
        self.actions.append(DefenderAction(
            tick=tick, action="credential_revocation", target=nid,
            rationale="ICA DIA revoked session credentials post-anomaly.",
        ))

    def _isolate_zone(self, tick: int, zone_id: str, reason: str) -> None:
        z = self.topo.zones.get(zone_id)
        if z and not z.isolated:
            z.isolated = True
            self.actions.append(DefenderAction(
                tick=tick, action="zone_isolation", target=zone_id,
                rationale=f"ICA sealed immune zone ({reason}).",
            ))

    def _tcicp_share(self, fingerprint: str, tick: int) -> None:
        if not self.tcicp_enabled:
            return
        if fingerprint in self.immune_memory:
            return
        self.immune_memory.add(fingerprint)
        self.threat_level = min(1.0, self.threat_level + 0.1)
        self.actions.append(DefenderAction(
            tick=tick, action="tcicp_memory_update", target="global",
            rationale=f"TCICP shared fingerprint {fingerprint}.",
        ))

    def tick(self, events: List[AttackEvent], t: int) -> None:
        zones_to_isolate: Set[str] = set()
        for e in events:
            node = self.topo.nodes[e.node_id]
            layer = self._qes_detects(node, e)
            if layer is None:
                continue
            fingerprint = f"{e.stage}:{e.behaviour.value}"
            self._tcicp_share(fingerprint, t)
            if self.ica_enabled:
                self._dia_quarantine_node(t, e.node_id, layer)
                self._dia_revoke_credentials(t, e.node_id)
                zones_to_isolate.add(node.zone_id)
            else:
                self._dia_quarantine_node(t, e.node_id, layer + " (sensor-only)")

        if self.ica_enabled:
            for zid in zones_to_isolate:
                count = sum(
                    1 for nid in self.topo.zones[zid].nodes
                    if self.topo.nodes[nid].state == NodeState.QUARANTINED
                )
                if count >= 2:
                    self._isolate_zone(t, zid, reason="cluster of anomalies")


class HybridDefender(QuaticDefender):
    PHASE_PROFILES = {
        0: dict(ica_enabled=False, qes_layer1=False, qes_layer2=False,
                qes_layer3=False, qes_layer4=False, qes_layer5=False,
                tcicp_enabled=False),
        1: dict(ica_enabled=False, qes_layer1=True, qes_layer2=True,
                qes_layer3=True, qes_layer4=False, qes_layer5=False,
                tcicp_enabled=False),
        2: dict(ica_enabled=True, qes_layer1=True, qes_layer2=True,
                qes_layer3=True, qes_layer4=False, qes_layer5=False,
                tcicp_enabled=False),
        3: dict(ica_enabled=True, qes_layer1=True, qes_layer2=True,
                qes_layer3=True, qes_layer4=False, qes_layer5=True,
                tcicp_enabled=False),
        4: dict(ica_enabled=True, qes_layer1=True, qes_layer2=True,
                qes_layer3=True, qes_layer4=False, qes_layer5=True,
                tcicp_enabled=False),
        5: dict(ica_enabled=True, qes_layer1=True, qes_layer2=True,
                qes_layer3=True, qes_layer4=True, qes_layer5=True,
                tcicp_enabled=True),
        6: dict(ica_enabled=True, qes_layer1=True, qes_layer2=True,
                qes_layer3=True, qes_layer4=True, qes_layer5=True,
                tcicp_enabled=True),
    }

    def __init__(self, topo: Topology, phase: int = 0, seed: int = 11):
        profile = self.PHASE_PROFILES[phase]
        super().__init__(topo, seed=seed, **profile)
        self.phase = phase
