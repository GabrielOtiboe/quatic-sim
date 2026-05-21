"""
QUATIC Simulation — Framework Capability Scoring (Tables 4.3 and 4.4)
======================================================================
Implements the 12-dimension comparative scoring system the thesis uses
to derive the 13.9% (NIST/ISO) vs 94.4% (QUATIC) capability claim.

Scoring:
  3 = Adequate
  1 = Partial
  0 = Insufficient

Total possible = 36.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


CAPABILITY_DIMENSIONS = [
    {
        "id": "supply_chain_integrity",
        "name": "Supply chain integrity verification",
        "threat_example": "M.E.Doc poisoned update",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "ICA Principle 2: cryptographically verified, sandboxed update execution",
    },
    {
        "id": "worm_containment",
        "name": "Self-replicating worm containment",
        "threat_example": "EternalBlue + Mimikatz propagation",
        "nist": 1, "iso": 1, "quatic": 3,
        "quatic_justification": "ICA DIAs perform machine-speed micro-segmentation in milliseconds",
    },
    {
        "id": "credential_memory",
        "name": "Credential memory protection",
        "threat_example": "Mimikatz WDigest exploitation",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "QES Layer 5: PQC-sealed sessions; no plaintext credentials in memory",
    },
    {
        "id": "post_quantum_crypto",
        "name": "Quantum-resilient cryptography",
        "threat_example": "Future CRQC-enabled decryption (HNDL)",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "QES Layer 5: CRYSTALS-Kyber + CRYSTALS-Dilithium (NIST PQC standards)",
    },
    {
        "id": "ai_malware_evasion",
        "name": "AI-enhanced malware evasion",
        "threat_example": "GAN-based signature evasion",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "QES is signature-independent; entropy-based detection unaffected by GAN morphing",
    },
    {
        "id": "zero_day_defence",
        "name": "Zero-day exploit defence",
        "threat_example": "EternalBlue before patching",
        "nist": 1, "iso": 1, "quatic": 3,
        "quatic_justification": "Pre-pathogenic detection via behavioural anomaly, not signatures",
    },
    {
        "id": "transnational_coord",
        "name": "Transnational threat coordination",
        "threat_example": "GRU targeting Ukrainian supply chain",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "TCICP RTID + CDA: real-time cross-jurisdiction defensive coordination",
    },
    {
        "id": "multi_node_recovery",
        "name": "Simultaneous multi-node failure recovery",
        "threat_example": "All DCs destroyed simultaneously",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "ICA Principle 5: structural diversity prevents correlated DC failure",
    },
    {
        "id": "machine_speed_response",
        "name": "Machine-speed automated response",
        "threat_example": "Sub-10-minute global propagation",
        "nist": 0, "iso": 0, "quatic": 3,
        "quatic_justification": "ICA Principle 4: autonomous DIA containment within milliseconds",
    },
    {
        "id": "behavioural_detection",
        "name": "Behavioural anomaly detection (novel threats)",
        "threat_example": "Novel NotPetya signature undetectable at T+0",
        "nist": 1, "iso": 1, "quatic": 3,
        "quatic_justification": "ICA DIA negative selection + QES multi-layer entropy monitoring",
    },
    {
        "id": "immutable_backup",
        "name": "Immutable offline backup architecture",
        "threat_example": "Online backup encryption by ransomware",
        "nist": 1, "iso": 1, "quatic": 3,
        "quatic_justification": "Phase 4 mandates air-gapped, immutable backup architecture per Table 5.5",
    },
    {
        "id": "distributed_resilience",
        "name": "Distributed network resilience",
        "threat_example": "Single flat network enabling global propagation",
        "nist": 1, "iso": 1, "quatic": 1,
        "quatic_justification": "ICA Immune Zones provide architectural mandate; full distributed resilience requires implementation specifics outside framework scope",
    },
]


@dataclass
class FrameworkScore:
    framework_name: str
    adequate_count: int     # number of dimensions scored 3
    partial_count: int      # number of dimensions scored 1
    insufficient_count: int # number of dimensions scored 0
    total: int              # sum
    max_possible: int = 36

    @property
    def capability_percent(self) -> float:
        return 100.0 * self.total / self.max_possible


def score_framework(framework: str) -> FrameworkScore:
    """Compute the capability score for one framework across all 12 dimensions."""
    adequate = partial = insufficient = total = 0
    for dim in CAPABILITY_DIMENSIONS:
        score = dim[framework]
        total += score
        if score == 3:
            adequate += 1
        elif score == 1:
            partial += 1
        else:
            insufficient += 1
    return FrameworkScore(
        framework_name=framework,
        adequate_count=adequate,
        partial_count=partial,
        insufficient_count=insufficient,
        total=total,
    )


def all_scores() -> Dict[str, FrameworkScore]:
    return {
        "NIST CSF": score_framework("nist"),
        "ISO 27001": score_framework("iso"),
        "QUATIC System": score_framework("quatic"),
    }


# ---------------------------------------------------------------------------
# Geopolitical Bystander Risk Typology (Table 4.7)
# ---------------------------------------------------------------------------
GEOPOLITICAL_RISKS = [
    {
        "id": "supply_chain_contamination",
        "name": "Supply Chain Contamination Risk",
        "definition": "Exposure through shared commercial software/hardware supply chains connecting to targeted entities",
        "notpetya_exemplification": "M.E.Doc used by Maersk for Ukrainian tax compliance; poisoned update reached Maersk machines",
        "affected_industries": "All industries using local commercial software in targeted jurisdictions",
        "quatic_mitigation": "ICA Principle 2 (sandboxed update execution) + supply chain integrity monitoring",
    },
    {
        "id": "network_topology",
        "name": "Network Topology Risk",
        "definition": "Exposure through network interconnections with targeted entities (partners, subsidiaries)",
        "notpetya_exemplification": "NotPetya traversed flat networks connecting Ukrainian operations to global Maersk systems",
        "affected_industries": "Multinationals with operations in geopolitically contested regions",
        "quatic_mitigation": "ICA Principle 1: Immune Zones isolate regional operations with zero-trust segmentation",
    },
    {
        "id": "regulatory_dependency",
        "name": "Regulatory Compliance Dependency Risk",
        "definition": "Mandatory use of local software/services that create exposure to geopolitical cyber operations",
        "notpetya_exemplification": "Maersk legally required to use M.E.Doc for Ukrainian tax filing",
        "affected_industries": "All organisations with regulated operations in targeted jurisdictions",
        "quatic_mitigation": "TCICP JNLF: jurisdiction-neutral framework + isolated compliance environments",
    },
    {
        "id": "ecosystem_disruption",
        "name": "Ecosystem Disruption Risk",
        "definition": "Indirect operational losses through disruption of critical commercial ecosystem partners",
        "notpetya_exemplification": "Trucking, logistics partners, cargo owners suffered losses from Maersk disruption",
        "affected_industries": "Industries dependent on disrupted entities (logistics, healthcare, energy)",
        "quatic_mitigation": "TCICP MAP: mutual assistance + diversified supplier networks",
    },
    {
        "id": "collateral_intelligence",
        "name": "Collateral Intelligence Exposure Risk",
        "definition": "Exposure of sensitive data to attackers targeting other entities on shared infrastructure",
        "notpetya_exemplification": "Not directly applicable in NotPetya (wiperware) — relevant in espionage scenarios",
        "affected_industries": "Cloud service users; shared infrastructure tenants",
        "quatic_mitigation": "QES Layer 5 PQC + data isolation; TCICP intelligence sharing",
    },
    {
        "id": "attribution_contamination",
        "name": "Attribution Contamination Risk",
        "definition": "Secondary exposure through false-flag operations designed to implicate bystander organisations",
        "notpetya_exemplification": "Not directly applicable — relevant in false-flag scenarios",
        "affected_industries": "Organisations in politically sensitive positions",
        "quatic_mitigation": "TCICP CAM: collective attribution intelligence + forensic capability",
    },
]


# ---------------------------------------------------------------------------
# Quality Attribute Failure Matrix (Table 4.2 — ISO/IEC 25010)
# ---------------------------------------------------------------------------
QUALITY_ATTRIBUTES = [
    {"attr": "Security", "sub": "Confidentiality",
     "ideal": "Encrypted credentials; no plaintext in memory",
     "maersk": "WDigest stored decryptable credential material in memory",
     "exploit": "Mimikatz harvested credentials from memory",
     "severity": "Critical",
     "quatic_layer": "QES Layer 5 (PQC sessions)"},
    {"attr": "Security", "sub": "Integrity",
     "ideal": "Verified software update integrity pre-execution",
     "maersk": "No integrity verification of M.E.Doc updates",
     "exploit": "Poisoned update executed without verification",
     "severity": "Critical",
     "quatic_layer": "ICA Principle 2 (sandboxed update execution)"},
    {"attr": "Security", "sub": "Authenticity",
     "ideal": "Hardware-backed multi-factor authentication",
     "maersk": "Password-only authentication on most systems",
     "exploit": "Harvested credentials authenticated as legitimate users",
     "severity": "Critical",
     "quatic_layer": "QES Layer 5 (quantum-randomised session tokens)"},
    {"attr": "Security", "sub": "Vulnerability mgmt",
     "ideal": "Patched within 30 days of critical CVE disclosure",
     "maersk": "Windows 2000 deployed; patches years overdue",
     "exploit": "EternalBlue SMBv1 exploit succeeded on unpatched machines",
     "severity": "Critical",
     "quatic_layer": "ICA Principle 1 (Immune Zones limit blast radius)"},
    {"attr": "Reliability", "sub": "Fault tolerance",
     "ideal": "Graceful degradation under component failure",
     "maersk": "Cascading failure upon domain controller destruction",
     "exploit": "All DCs destroyed simultaneously; no fallback",
     "severity": "Critical",
     "quatic_layer": "ICA Principle 5 (Structural Diversity)"},
    {"attr": "Reliability", "sub": "Recoverability",
     "ideal": "Defined RTO from tested backup procedures",
     "maersk": "No validated recovery procedure for total DC failure",
     "exploit": "10-day rebuild; 2-month full recovery",
     "severity": "Critical",
     "quatic_layer": "Phase 4 (Air-gapped backup architecture)"},
    {"attr": "Reliability", "sub": "Availability",
     "ideal": "99.9%+ availability for critical shipping operations",
     "maersk": "Effectively 0% availability for 17 ports during peak disruption",
     "exploit": "Total operational paralysis of global port operations",
     "severity": "Critical",
     "quatic_layer": "ICA Immune Zones maintain availability per zone"},
    {"attr": "Maintainability", "sub": "Modularity",
     "ideal": "Isolated network zones limiting lateral movement",
     "maersk": "Flat global network with unrestricted internal access",
     "exploit": "Unrestricted propagation across all global operations",
     "severity": "Critical",
     "quatic_layer": "ICA Principle 1 (Immune Zone Architecture)"},
    {"attr": "Performance", "sub": "Time behaviour",
     "ideal": "Detection within propagation window",
     "maersk": "Detection only upon system shutdown",
     "exploit": "Propagation complete before detection occurred",
     "severity": "Critical",
     "quatic_layer": "QES Layers 1-3 (sub-second entropy detection)"},
]
