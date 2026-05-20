"""QUATIC Simulation — Core topology (nodes, zones, links, credentials)."""
from __future__ import annotations

import enum
import random
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


class NodeState(enum.Enum):
    HEALTHY = "healthy"
    RECONNOITRED = "reconnoitred"
    COMPROMISED = "compromised"
    ENCRYPTED = "encrypted"
    QUARANTINED = "quarantined"
    RECOVERED = "recovered"
    DESTROYED = "destroyed"


class ProcessBehaviour(enum.Enum):
    NORMAL = "normal"
    MASS_FILE_WRITE = "mass_file_write"
    HIGH_ENTROPY_WRITE = "high_entropy_write"
    CREDENTIAL_DUMP = "credential_dump"
    SMB_SCAN = "smb_scan"
    AUTH_BURST = "auth_burst"
    MBR_WRITE = "mbr_write"
    C2_BEACON = "c2_beacon"


@dataclass
class Credential:
    cred_id: str
    user: str
    privilege: int
    in_memory_plaintext: bool = True
    quantum_session: bool = False


@dataclass
class Node:
    node_id: str
    zone_id: str
    role: str
    os_patched: bool = True
    state: NodeState = NodeState.HEALTHY
    credentials: List[Credential] = field(default_factory=list)
    running_processes: List[ProcessBehaviour] = field(default_factory=list)
    baseline_entropy: float = 0.45
    current_entropy: float = 0.45
    auth_baseline_rate: float = 1.0
    current_auth_rate: float = 1.0
    baseline_noise_amplitude: float = 0.25
    has_backup: bool = False
    backup_online: bool = True
    compromised_tick: Optional[int] = None
    grid_x: int = 0
    grid_y: int = 0

    def observable_entropy_spike(self) -> float:
        return max(0.0, self.current_entropy - self.baseline_entropy)

    def observable_auth_spike(self) -> float:
        raw = max(0.0, self.current_auth_rate - self.auth_baseline_rate)
        return max(0.0, raw - self.baseline_noise_amplitude * self.auth_baseline_rate)


@dataclass
class ImmuneZone:
    zone_id: str
    name: str
    nodes: List[str] = field(default_factory=list)
    trusted_zones: Set[str] = field(default_factory=set)
    isolated: bool = False
    dia_sensitivity: float = 0.5


@dataclass
class Link:
    src: str
    dst: str
    smb_allowed: bool = True
    cross_zone: bool = False
    inspected: bool = False


@dataclass
class Topology:
    nodes: Dict[str, Node] = field(default_factory=dict)
    zones: Dict[str, ImmuneZone] = field(default_factory=dict)
    links: List[Link] = field(default_factory=list)
    domain_controllers: List[str] = field(default_factory=list)

    def add_zone(self, zone: ImmuneZone) -> None:
        self.zones[zone.zone_id] = zone

    def add_node(self, node: Node) -> None:
        self.nodes[node.node_id] = node
        if node.zone_id in self.zones:
            self.zones[node.zone_id].nodes.append(node.node_id)
        if node.role == "domain_controller":
            self.domain_controllers.append(node.node_id)

    def connect(self, src: str, dst: str, smb: bool = True) -> None:
        cross = self.nodes[src].zone_id != self.nodes[dst].zone_id
        self.links.append(Link(src, dst, smb_allowed=smb, cross_zone=cross))

    def neighbours(self, node_id: str) -> List[str]:
        out = []
        for l in self.links:
            if l.src == node_id:
                out.append(l.dst)
            elif l.dst == node_id:
                out.append(l.src)
        return out

    def cross_zone_allowed(self, src_zone: str, dst_zone: str) -> bool:
        if src_zone == dst_zone:
            return True
        src = self.zones.get(src_zone)
        if src is None or src.isolated:
            return False
        dst = self.zones.get(dst_zone)
        if dst is None or dst.isolated:
            return False
        return dst_zone in src.trusted_zones

    def healthy_fraction(self) -> float:
        if not self.nodes:
            return 0.0
        return sum(
            1 for n in self.nodes.values()
            if n.state in (NodeState.HEALTHY, NodeState.RECOVERED, NodeState.QUARANTINED)
        ) / len(self.nodes)

    def destroyed_fraction(self) -> float:
        if not self.nodes:
            return 0.0
        return sum(
            1 for n in self.nodes.values()
            if n.state in (NodeState.ENCRYPTED, NodeState.DESTROYED)
        ) / len(self.nodes)

    def domain_controllers_alive(self) -> int:
        return sum(
            1 for nid in self.domain_controllers
            if self.nodes[nid].state not in (NodeState.ENCRYPTED, NodeState.DESTROYED)
        )

    def snapshot_states(self) -> Dict[str, str]:
        """Return {node_id: state_value} for visualization."""
        return {nid: n.state.value for nid, n in self.nodes.items()}


def build_maersk_like_topology(
    n_endpoints: int = 200,
    n_servers: int = 20,
    n_domain_controllers: int = 6,
    n_zones: int = 1,
    smb_everywhere: bool = True,
    patch_coverage: float = 0.55,
    wdigest_on: bool = True,
    backup_online: bool = True,
    trust_all_zones: bool = False,
    seed: int = 42,
) -> Topology:
    rng = random.Random(seed)
    topo = Topology()

    zone_ids = [f"Z{i}" for i in range(n_zones)]
    for zid in zone_ids:
        topo.add_zone(ImmuneZone(zone_id=zid, name=f"Immune Zone {zid}"))

    if trust_all_zones:
        for z in topo.zones.values():
            z.trusted_zones = set(zid for zid in zone_ids if zid != z.zone_id)

    def pick_zone(i: int) -> str:
        return zone_ids[i % n_zones]

    all_nodes = []
    for i in range(n_domain_controllers):
        nid = f"DC-{i:02d}"
        dc = Node(
            node_id=nid, zone_id=pick_zone(i), role="domain_controller",
            os_patched=True,
            credentials=[Credential(
                cred_id=str(uuid.uuid4())[:8], user=f"admin-{i}",
                privilege=2, in_memory_plaintext=wdigest_on,
            )],
            has_backup=True, backup_online=backup_online,
        )
        topo.add_node(dc); all_nodes.append(nid)

    for i in range(n_servers):
        nid = f"SRV-{i:03d}"
        srv = Node(
            node_id=nid, zone_id=pick_zone(i + 100), role="server",
            os_patched=rng.random() < patch_coverage,
            credentials=[Credential(
                cred_id=str(uuid.uuid4())[:8], user=f"svc-{i}",
                privilege=1, in_memory_plaintext=wdigest_on,
            )],
            has_backup=True, backup_online=backup_online,
        )
        topo.add_node(srv); all_nodes.append(nid)

    for i in range(n_endpoints):
        nid = f"EP-{i:04d}"
        ep = Node(
            node_id=nid, zone_id=pick_zone(i + 1000), role="endpoint",
            os_patched=rng.random() < patch_coverage,
            credentials=[Credential(
                cred_id=str(uuid.uuid4())[:8], user=f"user-{i}",
                privilege=0, in_memory_plaintext=wdigest_on,
            )],
        )
        if rng.random() < 0.40:
            ep.credentials.append(Credential(
                cred_id=str(uuid.uuid4())[:8], user=f"admin-shared",
                privilege=2, in_memory_plaintext=wdigest_on,
            ))
        topo.add_node(ep); all_nodes.append(nid)

    # Grid positions for visualization
    import math
    total = len(all_nodes)
    cols = max(1, int(math.ceil(math.sqrt(total))))
    for idx, nid in enumerate(all_nodes):
        topo.nodes[nid].grid_x = idx % cols
        topo.nodes[nid].grid_y = idx // cols

    # Wire links
    by_zone: Dict[str, List[str]] = {zid: [] for zid in zone_ids}
    for nid, node in topo.nodes.items():
        by_zone[node.zone_id].append(nid)

    for zid, nids in by_zone.items():
        for src in nids:
            peers = rng.sample(nids, min(5, len(nids)))
            for dst in peers:
                if dst != src:
                    topo.connect(src, dst, smb=smb_everywhere)

    for i in range(len(zone_ids) - 1):
        a = by_zone[zone_ids[i]][0]
        b = by_zone[zone_ids[i + 1]][0]
        topo.connect(a, b, smb=smb_everywhere)

    return topo
