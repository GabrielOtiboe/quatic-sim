"""QUATIC Simulation — Attacker (NotPetya-class TTP chain)."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional, Set

from core.topology import (
    Credential, Node, NodeState, ProcessBehaviour, Topology,
)


@dataclass
class AttackerKnowledge:
    harvested_credentials: List[Credential] = field(default_factory=list)
    known_nodes: Set[str] = field(default_factory=set)
    foothold_nodes: Set[str] = field(default_factory=set)
    encrypted_nodes: Set[str] = field(default_factory=set)
    destroyed_dcs: Set[str] = field(default_factory=set)


@dataclass
class AttackEvent:
    tick: int
    stage: str
    node_id: str
    behaviour: ProcessBehaviour
    entropy_delta: float = 0.0
    auth_delta: float = 0.0
    cross_zone: bool = False
    description: str = ""


class NotPetyaAttacker:
    def __init__(
        self,
        topo: Topology,
        seed: int = 1337,
        supply_chain_entry_node: Optional[str] = None,
        propagation_rate: int = 8,
        encryption_delay_ticks: int = 30,
        destroy_dcs: bool = True,
        fake_ransom: bool = True,
        stealth: float = 0.0,
    ):
        self.topo = topo
        self.rng = random.Random(seed)
        self.knowledge = AttackerKnowledge()
        self.propagation_rate = propagation_rate
        self.encryption_delay_ticks = encryption_delay_ticks
        self.destroy_dcs = destroy_dcs
        self.fake_ransom = fake_ransom
        self.stealth = max(0.0, min(1.0, stealth))
        self.events: List[AttackEvent] = []
        self.stage = "dormant"
        self._fired_payload = False
        self._entry_tick: Optional[int] = None
        self._entry_node = supply_chain_entry_node

    def initial_access(self, tick: int) -> None:
        if self._entry_node is None:
            eligible = [nid for nid, n in self.topo.nodes.items()
                        if n.role == "endpoint"]
            self._entry_node = self.rng.choice(eligible)

        node = self.topo.nodes[self._entry_node]
        node.state = NodeState.COMPROMISED
        node.compromised_tick = tick
        if self.stealth < 0.5:
            node.running_processes.append(ProcessBehaviour.C2_BEACON)
        self.knowledge.foothold_nodes.add(self._entry_node)
        self.knowledge.known_nodes.add(self._entry_node)
        self._entry_tick = tick
        self.stage = "execution"

        self.events.append(AttackEvent(
            tick=tick, stage="initial_access",
            node_id=self._entry_node,
            behaviour=ProcessBehaviour.C2_BEACON,
            description="Poisoned vendor update executed on patient-zero endpoint.",
        ))

    def harvest_credentials(self, tick: int) -> None:
        new_creds: List[Credential] = []
        for nid in list(self.knowledge.foothold_nodes):
            node = self.topo.nodes[nid]
            if node.state != NodeState.COMPROMISED:
                continue
            for c in node.credentials:
                if c.quantum_session:
                    continue
                if c.in_memory_plaintext and c not in self.knowledge.harvested_credentials:
                    new_creds.append(c)

            if self.stealth > 0.7:
                new_creds = new_creds[:max(1, len(new_creds) // 4)]
                node.current_auth_rate = node.auth_baseline_rate * 1.4
                self.events.append(AttackEvent(
                    tick=tick, stage="privilege_escalation",
                    node_id=nid, behaviour=ProcessBehaviour.NORMAL,
                    auth_delta=node.observable_auth_spike(),
                    description="Stealth credential harvest (LOLBAS).",
                ))
            else:
                node.running_processes.append(ProcessBehaviour.CREDENTIAL_DUMP)
                burst_multiplier = 12 * (1.0 - 0.85 * self.stealth)
                node.current_auth_rate = node.auth_baseline_rate * max(1.1, burst_multiplier)
                self.events.append(AttackEvent(
                    tick=tick, stage="privilege_escalation",
                    node_id=nid, behaviour=ProcessBehaviour.CREDENTIAL_DUMP,
                    auth_delta=node.observable_auth_spike(),
                    description=f"Mimikatz-style dump harvested {len(new_creds)} credentials.",
                ))

        self.knowledge.harvested_credentials.extend(new_creds)

    def propagate(self, tick: int) -> None:
        frontier = list(self.knowledge.foothold_nodes)
        if not frontier:
            return

        attempts = 0
        max_attempts = self.propagation_rate
        self.rng.shuffle(frontier)

        have_admin = any(c.privilege >= 1 for c in self.knowledge.harvested_credentials)

        for src in frontier:
            if attempts >= max_attempts:
                break
            src_node = self.topo.nodes[src]
            for dst in self.topo.neighbours(src):
                if attempts >= max_attempts:
                    break
                dst_node = self.topo.nodes[dst]
                if dst_node.state != NodeState.HEALTHY:
                    continue

                if src_node.zone_id != dst_node.zone_id:
                    if not self.topo.cross_zone_allowed(src_node.zone_id, dst_node.zone_id):
                        self.events.append(AttackEvent(
                            tick=tick, stage="lateral_movement_blocked",
                            node_id=dst, behaviour=ProcessBehaviour.SMB_SCAN,
                            cross_zone=True,
                            description="SMB probe blocked at immune-zone boundary.",
                        ))
                        continue

                infected = False
                if not dst_node.os_patched:
                    infected = True; method = "eternalblue"
                elif have_admin:
                    infected = True; method = "pth"
                else:
                    method = "failed"

                if self.stealth > 0.7:
                    src_node.current_auth_rate = src_node.auth_baseline_rate * 1.2
                    behaviour_signal = ProcessBehaviour.NORMAL
                else:
                    src_node.running_processes.append(ProcessBehaviour.SMB_SCAN)
                    src_node.current_auth_rate = src_node.auth_baseline_rate * 8
                    behaviour_signal = (ProcessBehaviour.AUTH_BURST if method == "pth"
                                       else ProcessBehaviour.SMB_SCAN)

                self.events.append(AttackEvent(
                    tick=tick, stage="lateral_movement",
                    node_id=dst, behaviour=behaviour_signal,
                    auth_delta=src_node.observable_auth_spike(),
                    cross_zone=(src_node.zone_id != dst_node.zone_id),
                    description=f"Lateral movement via {method} on {dst}.",
                ))

                if infected:
                    dst_node.state = NodeState.COMPROMISED
                    dst_node.compromised_tick = tick
                    dst_node.running_processes.append(ProcessBehaviour.C2_BEACON)
                    self.knowledge.foothold_nodes.add(dst)
                    attempts += 1

    def fire_payload(self, tick: int) -> None:
        for nid in list(self.knowledge.foothold_nodes):
            node = self.topo.nodes[nid]
            if node.state == NodeState.COMPROMISED:
                node.current_entropy = 0.98
                node.running_processes.extend([
                    ProcessBehaviour.MASS_FILE_WRITE,
                    ProcessBehaviour.HIGH_ENTROPY_WRITE,
                    ProcessBehaviour.MBR_WRITE,
                ])
                self.events.append(AttackEvent(
                    tick=tick, stage="encrypt", node_id=nid,
                    behaviour=ProcessBehaviour.HIGH_ENTROPY_WRITE,
                    entropy_delta=node.observable_entropy_spike(),
                    description="MFT encryption + MBR overwrite.",
                ))
                node.state = NodeState.ENCRYPTED
                if node.has_backup and node.backup_online:
                    node.state = NodeState.DESTROYED
                self.knowledge.encrypted_nodes.add(nid)

        if self.destroy_dcs:
            for dc_id in self.topo.domain_controllers:
                if dc_id in self.knowledge.foothold_nodes:
                    self.topo.nodes[dc_id].state = NodeState.DESTROYED
                    self.knowledge.destroyed_dcs.add(dc_id)

        self._fired_payload = True
        self.stage = "post_impact"

    def tick(self, t: int) -> List[AttackEvent]:
        before = len(self.events)

        if self.stealth > 0.6 and self.stage == "spreading":
            if self.rng.random() < (self.stealth - 0.5):
                return []

        if self.stage == "dormant":
            self.initial_access(t)
        elif self.stage in ("execution", "spreading"):
            self.harvest_credentials(t)
            self.propagate(t)
            self.stage = "spreading"
            if self._entry_tick is not None and \
               (t - self._entry_tick) >= self.encryption_delay_ticks and \
               not self._fired_payload:
                self.fire_payload(t)
        return self.events[before:]
