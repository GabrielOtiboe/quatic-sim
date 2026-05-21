"""
QUATIC Simulation — Attack Class Library
=========================================
Models the six attack classes the thesis demands the framework defend against:

  1. NotPetya-class           (Section 2.2 — worm + wiper)
  2. AI-Driven Ransomware     (Section 2.6 — GAN-evading, ML target selection)
  3. Stealth APT              (Section 2.6 — Sandworm-class, long dwell)
  4. Supply Chain Compromise  (Section 2.2 — M.E.Doc style)
  5. Quantum HNDL             (Section 2.10 — harvest now, decrypt later)
  6. Multi-Org Coordinated    (Section 2.8 — single attack across N orgs)

Each class is a configured NotPetyaAttacker with thesis-justified parameters.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from agents.attacker import NotPetyaAttacker
from core.topology import Topology


ATTACK_CLASSES: Dict[str, Dict] = {
    "notpetya": {
        "display": "🦠 NotPetya (worm + wiper)",
        "thesis_ref": "Section 2.2; Table 4.1",
        "description": (
            "The 2017 Maersk catastrophe. Self-replicating worm using "
            "EternalBlue (SMBv1 exploit) + Mimikatz (credential dump) "
            "delivered via poisoned M.E.Doc supply-chain update. "
            "Encrypts MFT, wipes MBR, destroys 100% of estate in <10 min."
        ),
        "params": dict(
            propagation_rate=8, encryption_delay_ticks=30,
            destroy_dcs=True, fake_ransom=True, stealth=0.0,
        ),
        "expected_baseline": "Catastrophic — ~75-100% destroyed",
        "expected_quatic": "Contained at minute 1-2 by QES L3 (auth entropy)",
    },
    "ai_ransomware": {
        "display": "🤖 AI-Driven Ransomware (GAN-evading)",
        "thesis_ref": "Section 2.6; Brundage et al. 2021; Hu and Tan 2020",
        "description": (
            "Next-generation ransomware using Generative Adversarial Networks "
            "to morph signatures dynamically, and ML to identify highest-value "
            "targets. 2× faster propagation than NotPetya. No signature-based "
            "detection possible. The thesis argues NIST/ISO are obsolete here."
        ),
        "params": dict(
            propagation_rate=14, encryption_delay_ticks=12,
            destroy_dcs=True, fake_ransom=False, stealth=0.3,
        ),
        "expected_baseline": "Total failure — signature detection useless",
        "expected_quatic": "Contained by QES Layer 1 (entropy) at minute 1-3",
    },
    "stealth_apt": {
        "display": "🥷 Stealth APT (Sandworm-class)",
        "thesis_ref": "Section 2.6, 2.11; Valeriano et al. 2021",
        "description": (
            "Long-dwell nation-state attacker. Uses living-off-the-land "
            "(LOLBAS) instead of Mimikatz. No SMB scanning — uses WMI/WinRM. "
            "Goes dormant between actions to hide in benign activity. "
            "Hardest case for any defender."
        ),
        "params": dict(
            propagation_rate=4, encryption_delay_ticks=90,
            destroy_dcs=True, fake_ransom=False, stealth=0.90,
        ),
        "expected_baseline": "Never detected — silent infiltration",
        "expected_quatic": "Detected late (min 30-60) with 5-8% pre-detection loss",
    },
    "supply_chain": {
        "display": "📦 Supply Chain Compromise (M.E.Doc-style)",
        "thesis_ref": "Section 2.2; Table 4.5; Peisert et al. 2021",
        "description": (
            "Trusted vendor delivers poisoned update. Bypasses application "
            "whitelisting, code signing, and behavioural sandboxes because "
            "the update is signed with legitimate vendor certificate. "
            "Tests QUATIC ICA Principle 2 (sandboxed update execution)."
        ),
        "params": dict(
            propagation_rate=6, encryption_delay_ticks=45,
            destroy_dcs=True, fake_ransom=True, stealth=0.2,
        ),
        "expected_baseline": "Bypasses all preventive controls",
        "expected_quatic": "ICA sandboxed execution + QES L1 catches at minute 1-2",
    },
    "quantum_hndl": {
        "display": "⚛️ Quantum HNDL (harvest-now, decrypt-later)",
        "thesis_ref": "Section 2.10; NIST 2022; Pirandola et al. 2020",
        "description": (
            "Adversary exfiltrates encrypted data today, intending to "
            "decrypt it years from now once Cryptographically Relevant "
            "Quantum Computers (CRQCs) arrive. Sub-clinical exfiltration "
            "campaign. Tests QES Layer 5 (post-quantum cryptography)."
        ),
        "params": dict(
            propagation_rate=2, encryption_delay_ticks=200,
            destroy_dcs=False, fake_ransom=False, stealth=0.85,
        ),
        "expected_baseline": "Undetected; data captured will be readable in 5-20 yrs",
        "expected_quatic": "QES L5 PQC ensures harvested data stays unreadable",
    },
    "multi_org_coordinated": {
        "display": "🌐 Multi-Org Coordinated Attack",
        "thesis_ref": "Section 2.8; Schmitt 2021; Table 4.6",
        "description": (
            "Single threat actor attacks N organisations simultaneously "
            "via shared supply chain. Tests TCICP — does cooperation help? "
            "Compared against isolated baseline response (the actual NotPetya "
            "international response)."
        ),
        "params": dict(
            propagation_rate=10, encryption_delay_ticks=20,
            destroy_dcs=True, fake_ransom=True, stealth=0.1,
        ),
        "expected_baseline": "Each org fights alone; attack succeeds against all",
        "expected_quatic": "TCICP RTID + CDA: first detection immunises all",
    },
}


def make_attacker(class_id: str, topo: Topology, seed: int = 1337) -> NotPetyaAttacker:
    """Build an attacker configured for a specific attack class."""
    spec = ATTACK_CLASSES[class_id]
    return NotPetyaAttacker(topo, seed=seed, **spec["params"])


def attack_class_options() -> List[tuple]:
    """Return (id, display_name) tuples for UI selection."""
    return [(k, v["display"]) for k, v in ATTACK_CLASSES.items()]
