"""
QUATIC Cyber-Resilience Simulator — Complete Thesis Validation Platform
========================================================================

Comprehensive interactive validation of the QUATIC framework
(Owusu Sekyere, KNUST MSc Forensic Science, 2025).

Eight thesis-aligned dashboards:
  1. 🏠 Home — Framework overview and thesis abstract
  2. 🦠 Attack Lab — Run any of 6 attack classes vs any defender
  3. 📊 Framework Scoring — Table 4.3/4.4 capability comparison (13.9% vs 94.4%)
  4. 🛡️ QUATIC Components — Explore ICA, QES, TCICP in depth
  5. 🌐 Multi-Org TCICP — Federation experiment (Section 2.8)
  6. 📈 Phased Rollout — Implementation roadmap Phases 0-6 (Table 5.5)
  7. 🎯 Quality Attributes — ISO/IEC 25010 failure matrix (Table 4.2)
  8. 🌍 Geopolitical Risks — Bystander risk typology (Table 4.7)
"""
from __future__ import annotations

import os
import sys
import time
from typing import Dict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.attack_classes import ATTACK_CLASSES, make_attacker
from agents.capability_scoring import (
    CAPABILITY_DIMENSIONS, GEOPOLITICAL_RISKS, QUALITY_ATTRIBUTES,
    all_scores,
)
from agents.defender import BaselineDefender, HybridDefender, QuaticDefender
from agents.federation import federation_comparison
from core.topology import build_maersk_like_topology
from engine.simulation import SimulationEngine


st.set_page_config(
    page_title="QUATIC Cyber-Resilience Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main > div { padding-top: 0.5rem; }
    .big-title { font-size: 2.3rem; font-weight: 700; margin-bottom: 0; color: #1a1a1a; }
    .subtitle { color: #555; font-size: 1rem; margin-top: 0.1rem; }
    .stMetric { background: #f8f9fa; padding: 1rem; border-radius: 8px;
                border-left: 4px solid #2b8c3e; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
    h2 { margin-top: 1.5rem; color: #1a1a1a; }
    h3 { color: #2b3e50; }
    .verdict-good { background: linear-gradient(90deg, #d4edda, #c3e6cb);
                    padding: 1.3rem; border-radius: 10px; border-left: 5px solid #28a745; }
    .verdict-bad { background: linear-gradient(90deg, #f8d7da, #f5c6cb);
                   padding: 1.3rem; border-radius: 10px; border-left: 5px solid #dc3545; }
    .verdict-warn { background: linear-gradient(90deg, #fff3cd, #ffeaa7);
                    padding: 1.3rem; border-radius: 10px; border-left: 5px solid #ffc107; }
    .info-card { background: #f0f4f8; padding: 1rem; border-radius: 8px;
                 border-left: 3px solid #4a90e2; margin: 0.5rem 0; }
    .thesis-ref { color: #666; font-size: 0.85rem; font-style: italic; }
</style>
""", unsafe_allow_html=True)


with st.sidebar:
    st.markdown("# 🛡️ QUATIC")
    st.caption("Thesis Validation Platform")
    st.markdown("---")

    tab = st.radio(
        "📋 Dashboards",
        [
            "🏠 Home",
            "🦠 Attack Laboratory",
            "📊 Framework Scoring",
            "🛡️ QUATIC Components",
            "🌐 Multi-Org TCICP",
            "📈 Phased Rollout",
            "🎯 Quality Attributes",
            "🌍 Geopolitical Risks",
        ],
        index=0,
    )

    st.markdown("---")
    st.caption(
        "Built on **Owusu Sekyere's** 2025 MSc thesis at KNUST. "
        "Implements all 12 capability dimensions (Table 4.3), 6 attack classes "
        "(Sections 2.2-2.10), and the full ICA/QES/TCICP framework (Chapter 5)."
    )


STATE_COLOURS = {
    "healthy": "#2b8c3e",
    "compromised": "#e6692b",
    "encrypted": "#8b1a1a",
    "destroyed": "#1a1a1a",
    "quarantined": "#f0b030",
    "reconnoitred": "#d0572b",
    "recovered": "#5cb85c",
}


def render_network_grid(node_states, topo_positions, title=""):
    if not topo_positions:
        return None
    xs, ys, colors = [], [], []
    for nid, state in node_states.items():
        if nid in topo_positions:
            xs.append(topo_positions[nid][0])
            ys.append(topo_positions[nid][1])
            colors.append(STATE_COLOURS.get(state, "#ccc"))
    if not xs:
        return None
    fig, ax = plt.subplots(figsize=(9, 6), dpi=80)
    ax.scatter(xs, ys, c=colors, s=70, edgecolors="white", linewidths=0.5)
    ax.set_aspect("equal")
    ax.invert_yaxis()
    ax.set_xticks([]); ax.set_yticks([])
    ax.set_title(title, fontsize=11, pad=8)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")
    fig.tight_layout(pad=0.3)
    return fig


def plot_timeline(result, title=""):
    ticks = [r.tick for r in result.ticks]
    healthy = [r.healthy_fraction * 100 for r in result.ticks]
    destroyed = [r.destroyed_fraction * 100 for r in result.ticks]
    compromised = [r.compromised_fraction * 100 for r in result.ticks]
    quarantined = [r.quarantined_fraction * 100 for r in result.ticks]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.fill_between(ticks, 0, healthy, alpha=0.85, color="#2b8c3e", label="Healthy")
    ax.fill_between(ticks, healthy, [h+q for h,q in zip(healthy, quarantined)],
                    alpha=0.7, color="#f0b030", label="Quarantined")
    ax.fill_between(ticks, [h+q for h,q in zip(healthy, quarantined)],
                    [h+q+c for h,q,c in zip(healthy, quarantined, compromised)],
                    alpha=0.7, color="#e6692b", label="Infected")
    ax.fill_between(ticks, [h+q+c for h,q,c in zip(healthy, quarantined, compromised)],
                    [100]*len(ticks), alpha=0.7, color="#1a1a1a", label="Destroyed")
    if result.time_to_detection is not None:
        ax.axvline(result.time_to_detection, linestyle="--", color="navy",
                   alpha=0.7, label=f"Detected @ min {result.time_to_detection}")
    ax.set_xlabel("Minutes")
    ax.set_ylabel("% of estate")
    ax.set_ylim(0, 100)
    ax.set_title(title)
    ax.legend(loc="center right", framealpha=0.95, fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    return fig


def render_legend():
    cols = st.columns(5)
    items = [("🟢 Healthy", "#2b8c3e"), ("🟡 Quarantined", "#f0b030"),
             ("🟠 Infected", "#e6692b"), ("🔴 Encrypted", "#8b1a1a"),
             ("⚫ Destroyed", "#1a1a1a")]
    for col, (label, _) in zip(cols, items):
        col.markdown(f"**{label}**")


# ============================================================================
# TAB 1 — HOME
# ============================================================================
if tab == "🏠 Home":
    st.markdown('<p class="big-title">🛡️ QUATIC Cyber-Resilience Simulator</p>',
                unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Empirical validation platform for the '
                'Quantum-Resilient, Autonomous, Transnational Immuno-Cyber System</p>',
                unsafe_allow_html=True)
    st.markdown("---")

    col1, col2 = st.columns([3, 2])
    with col1:
        st.markdown("""
### 📜 What this is

This is a working empirical validation platform for the QUATIC framework
proposed in **Owusu Sekyere's 2025 MSc Forensic Science thesis** at the
Kwame Nkrumah University of Science and Technology.

The thesis argues that current cybersecurity frameworks (NIST CSF, ISO 27001)
score only **13.9%** on a 12-dimension capability test against advanced
threats, while the proposed QUATIC system reaches **94.4%**. This simulator
lets you reproduce that claim — and stress-test it against six different
attack classes.

### 🎯 What you can test

The simulator covers **all four research questions** from the thesis:

1. **RQ1 — NotPetya blind spots:** Run the Maersk counterfactual.
   See the actual catastrophe and the QUATIC alternative side-by-side.
   → *Attack Laboratory tab*

2. **RQ2 — NIST/ISO inadequacy:** Score the frameworks against
   AI-ransomware, stealth APTs, quantum HNDL, and supply chain attacks.
   → *Framework Scoring + Attack Laboratory*

3. **RQ3 — Structural vulnerabilities:** Test the centralised-architecture
   problem and run the multi-organisation cooperation experiment.
   → *Multi-Org TCICP tab*

4. **RQ4 — QUATIC fills the voids:** Explore each component (ICA, QES,
   TCICP) and trace exactly which one catches which attack stage.
   → *QUATIC Components tab*
""")

    with col2:
        st.markdown("### 📊 Headline numbers")
        st.metric("Capability — NIST CSF", "13.9%", delta="-80.5pp vs ideal",
                  delta_color="inverse")
        st.metric("Capability — ISO 27001", "13.9%", delta="-80.5pp vs ideal",
                  delta_color="inverse")
        st.metric("Capability — QUATIC", "94.4%", delta="+80.5pp vs baseline")
        st.metric("Attack classes tested", "6")
        st.metric("Quality dimensions scored", "12")

    st.markdown("---")
    st.markdown("### 📚 Thesis structure mapped to dashboards")

    mapping = [
        ["Chapter 1 — Introduction", "🏠 Home"],
        ["Chapter 2.2-2.6 — Attack mechanisms", "🦠 Attack Laboratory"],
        ["Chapter 2.7 — Centralised architecture risks", "🌐 Multi-Org TCICP"],
        ["Chapter 2.8 — Transnational cooperation gap", "🌐 Multi-Org TCICP"],
        ["Chapter 4.2 — Attack stage analysis (Table 4.1)", "🦠 Attack Laboratory"],
        ["Chapter 4.2 — Quality failure matrix (Table 4.2)", "🎯 Quality Attributes"],
        ["Chapter 4.3 — Framework capability score (Tables 4.3, 4.4)", "📊 Framework Scoring"],
        ["Chapter 4.4 — Geopolitical bystander risks (Table 4.7)", "🌍 Geopolitical Risks"],
        ["Chapter 5.2 — ICA / QES / TCICP components", "🛡️ QUATIC Components"],
        ["Chapter 5.2.6 — NotPetya counterfactual (Table 5.4)", "🦠 Attack Laboratory"],
        ["Chapter 5.3 — Phased rollout (Table 5.5)", "📈 Phased Rollout"],
    ]
    st.table({"Thesis section": [r[0] for r in mapping],
              "Dashboard": [r[1] for r in mapping]})

    st.markdown("---")
    st.info(
        "**👈 Pick a dashboard from the sidebar to start.** "
        "If you're new, start with **🦠 Attack Laboratory** — it's the most "
        "visual and shows the central claim of the thesis in action."
    )


# ============================================================================
# TAB 2 — ATTACK LABORATORY
# ============================================================================
elif tab == "🦠 Attack Laboratory":
    st.markdown("## 🦠 Attack Laboratory")
    st.markdown(
        "Pit any of **six attack classes** against any of **three defender profiles**. "
        "Live network visualisation; minute-by-minute timeline; plain-English findings."
    )

    col_a, col_b = st.columns([1, 2])

    with col_a:
        st.markdown("### Choose attack")
        attack_id = st.selectbox(
            "Attack class",
            options=list(ATTACK_CLASSES.keys()),
            format_func=lambda k: ATTACK_CLASSES[k]["display"],
            index=0,
            label_visibility="collapsed",
        )

        st.markdown("### Choose defender")
        defender_choice = st.radio(
            "Defender",
            ["🛡️ QUATIC (full)",
             "📋 Baseline (NIST/ISO)",
             "🔧 Hybrid (phased rollout)"],
            index=0,
            label_visibility="collapsed",
        )
        phase = 2
        if defender_choice.startswith("🔧"):
            phase = st.slider("Hybrid phase", 0, 6, 2)

        st.markdown("### Parameters")
        n_endpoints = st.slider("Network size (computers)", 50, 800, 200, 50)
        n_zones = st.slider("Number of immune zones", 1, 12, 6)
        horizon = st.slider("Simulation length (min)", 60, 480, 240, 30)
        seed = st.number_input("Random seed", value=42, step=1)
        animate = st.checkbox("🎬 Live animation", value=True)

        run_btn = st.button("▶️ RUN", type="primary", use_container_width=True)

    with col_b:
        attack_spec = ATTACK_CLASSES[attack_id]
        st.markdown(f"### {attack_spec['display']}")
        st.markdown(f"<span class='thesis-ref'>📖 {attack_spec['thesis_ref']}</span>",
                    unsafe_allow_html=True)
        st.markdown(f"<div class='info-card'>{attack_spec['description']}</div>",
                    unsafe_allow_html=True)

        col_x, col_y = st.columns(2)
        col_x.markdown(f"**Expected vs Baseline:** {attack_spec['expected_baseline']}")
        col_y.markdown(f"**Expected vs QUATIC:** {attack_spec['expected_quatic']}")

    if run_btn:
        with st.spinner(f"Running {attack_spec['display']} vs {defender_choice}..."):
            hardened = defender_choice.startswith("🛡️")
            topo = build_maersk_like_topology(
                n_endpoints=n_endpoints,
                n_zones=(n_zones if hardened else 1),
                patch_coverage=0.55,
                wdigest_on=(not hardened),
                backup_online=(not hardened),
                seed=seed,
            )
            atk = make_attacker(attack_id, topo, seed=seed)
            if defender_choice.startswith("🛡️"):
                dfd = QuaticDefender(topo, seed=seed)
                name = "QUATIC (full)"
            elif defender_choice.startswith("📋"):
                dfd = BaselineDefender(topo, seed=seed)
                name = "Baseline (NIST/ISO)"
            else:
                dfd = HybridDefender(topo, phase=phase, seed=seed)
                name = f"Hybrid (Phase {phase})"
            t0 = time.time()
            result = SimulationEngine(topo, atk, dfd, horizon, name).run()
            elapsed = time.time() - t0

        s = result.summary()
        healthy = s["final_healthy_pct"]
        destroyed = s["final_destroyed_pct"]
        ttd = s["time_to_detection_min"]
        ttd_text = f"minute {ttd}" if ttd is not None else "never"

        if s["contained"]:
            v_cls = "verdict-good"; v_icon = "✅"; v_msg = "ATTACK CONTAINED"
        elif healthy > 50:
            v_cls = "verdict-warn"; v_icon = "⚠️"; v_msg = "PARTIAL CONTAINMENT"
        else:
            v_cls = "verdict-bad"; v_icon = "❌"; v_msg = "CATASTROPHIC FAILURE"

        st.markdown(
            f'<div class="{v_cls}"><strong>{v_icon} {v_msg}</strong><br/>'
            f'{name} detected the {attack_spec["display"]} at <strong>{ttd_text}</strong>. '
            f'<strong>{healthy:.1f}%</strong> healthy, <strong>{destroyed:.1f}%</strong> destroyed, '
            f'{s["dcs_alive"]}/6 domain controllers alive. '
            f'Estimated loss: <strong>${s["estimated_loss_usd"]:,.0f}</strong>.</div>',
            unsafe_allow_html=True,
        )
        st.caption(f"⏱️ Simulation ran in {elapsed:.2f} seconds")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Healthy", f"{healthy:.1f}%")
        c2.metric("Destroyed", f"{destroyed:.1f}%")
        c3.metric("Domain controllers", f"{s['dcs_alive']}/6")
        c4.metric("Loss", f"${s['estimated_loss_usd']:,.0f}")

        if animate and result.ticks and result.ticks[0].node_states:
            st.markdown("### 🎬 Live network view")
            render_legend()
            positions = {nid: (n.grid_x, n.grid_y) for nid, n in topo.nodes.items()}
            total_frames = len(result.ticks)
            stride = max(1, total_frames // 40)
            indices = list(range(0, total_frames, stride))
            if indices[-1] != total_frames - 1:
                indices.append(total_frames - 1)
            slot = st.empty()
            for idx in indices:
                tr = result.ticks[idx]
                fig = render_network_grid(
                    tr.node_states, positions,
                    title=f"Minute {tr.tick} — {name} vs {attack_spec['display']}\n"
                          f"{tr.healthy_fraction*100:.0f}% healthy, "
                          f"{tr.destroyed_fraction*100:.0f}% destroyed",
                )
                if fig:
                    slot.pyplot(fig); plt.close(fig)
                time.sleep(0.08)

        st.markdown("### 📈 Timeline")
        fig = plot_timeline(result, f"{name} vs {attack_spec['display']}")
        st.pyplot(fig); plt.close(fig)

        with st.expander(f"🔍 Attack events ({len(result.attack_events)} total — first 30)"):
            for e in result.attack_events[:30]:
                icon = {"initial_access": "🎯", "privilege_escalation": "🔑",
                        "lateral_movement": "➡️", "lateral_movement_blocked": "🛑",
                        "encrypt": "💣"}.get(e.stage, "•")
                st.text(f"Min {e.tick:>3}  {icon}  {e.stage:<28s}  on {e.node_id}")

        with st.expander(f"🛡️ Defender actions ({len(result.defender_actions)} total — first 30)"):
            if not result.defender_actions:
                st.warning("⚠️ The defender never reacted. No actions taken.")
            else:
                for a in result.defender_actions[:30]:
                    st.text(f"Min {a.tick:>3}  ⚡  {a.action:<24s}  on {a.target}")
                    st.caption(f"      ↳ {a.rationale}")


# ============================================================================
# TAB 3 — FRAMEWORK SCORING (Tables 4.3 and 4.4)
# ============================================================================
elif tab == "📊 Framework Scoring":
    st.markdown("## 📊 Framework Capability Scoring")
    st.markdown(
        "<span class='thesis-ref'>📖 Tables 4.3 and 4.4 — the central quantitative "
        "claim of the thesis</span>", unsafe_allow_html=True)
    st.markdown("""
The thesis assesses NIST CSF, ISO 27001, and QUATIC against **twelve advanced
threat capability dimensions**. Scoring: **3 = Adequate**, **1 = Partial**,
**0 = Insufficient**. Maximum 36 points = 100% capability.
""")

    scores = all_scores()

    c1, c2, c3 = st.columns(3)
    c1.metric("📋 NIST CSF",
              f"{scores['NIST CSF'].capability_percent:.1f}%",
              delta=f"{scores['NIST CSF'].total}/36 points",
              delta_color="inverse")
    c2.metric("📋 ISO 27001",
              f"{scores['ISO 27001'].capability_percent:.1f}%",
              delta=f"{scores['ISO 27001'].total}/36 points",
              delta_color="inverse")
    c3.metric("🛡️ QUATIC System",
              f"{scores['QUATIC System'].capability_percent:.1f}%",
              delta=f"{scores['QUATIC System'].total}/36 points")

    fig, ax = plt.subplots(figsize=(10, 4.5))
    names = list(scores.keys())
    pcts = [scores[n].capability_percent for n in names]
    colors = ["#c0392b", "#c0392b", "#2b8c3e"]
    bars = ax.bar(names, pcts, color=colors, alpha=0.85, edgecolor="white")
    for bar, pct in zip(bars, pcts):
        ax.text(bar.get_x() + bar.get_width()/2, pct + 1.5,
                f"{pct:.1f}%", ha="center", fontweight="bold", fontsize=12)
    ax.set_ylim(0, 105)
    ax.set_ylabel("Capability Score (%)", fontsize=11)
    ax.set_title("Framework Capability Comparison — 12 Advanced Threat Dimensions",
                 fontsize=12)
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    st.pyplot(fig); plt.close(fig)

    st.markdown("### 🔬 Dimension-by-dimension breakdown")
    rows = []
    for dim in CAPABILITY_DIMENSIONS:
        def label(score):
            if score == 3: return "✅ Adequate"
            elif score == 1: return "⚠️ Partial"
            else: return "❌ Insufficient"
        rows.append({
            "Capability": dim["name"],
            "Threat example": dim["threat_example"],
            "NIST CSF": label(dim["nist"]),
            "ISO 27001": label(dim["iso"]),
            "QUATIC": label(dim["quatic"]),
            "How QUATIC addresses it": dim["quatic_justification"],
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.success("""
**The 80.5-percentage-point gap is real and structural.** Both NIST CSF and
ISO 27001 score **0 (Insufficient)** on 7 of 12 critical dimensions: supply
chain integrity, credential memory protection, quantum cryptography,
AI-malware evasion, transnational coordination, multi-node recovery, and
machine-speed response. These are exactly the capabilities that nation-state-
class attackers (Sandworm/GRU) specifically target. QUATIC addresses 10 of 12
adequately through ICA + QES + TCICP.
""")


# ============================================================================
# TAB 4 — QUATIC COMPONENTS
# ============================================================================
elif tab == "🛡️ QUATIC Components":
    st.markdown("## 🛡️ QUATIC Components — Deep Dive")
    st.markdown(
        "<span class='thesis-ref'>📖 Chapter 5.2 — full framework specification</span>",
        unsafe_allow_html=True)

    component_tab = st.tabs([
        "🦠 ICA — Immuno-Cyber Architecture",
        "⚛️ QES — Quantum Entropy Sentinel",
        "🌐 TCICP — Transnational Cooperation",
    ])

    with component_tab[0]:
        st.markdown("### 🦠 Immuno-Cyber Architecture (ICA)")
        st.caption("Biological-immune-system-inspired distributed defence")
        st.markdown("""
**Theoretical foundation:** Drawn from immunology (Forrest et al. 1994;
Dasgupta et al. 2020; Aickelin and Cayzer 2020). Mimics self/non-self
discrimination, distributed autonomous response, immunological memory,
and herd immunity.

The ICA has **six original design principles**:
""")
        principles = [
            ("Principle 1 — Immune Zone Architecture",
             "Network divided into autonomous Resource Immune Zones (RIZs) "
             "with cryptographic barriers and zero-trust between zones.",
             "Prevents flat-network catastrophes like Maersk 2017."),
            ("Principle 2 — Distributed Immune Agents (DIAs)",
             "Each zone has autonomous software agents (analogous to T-cells/B-cells) "
             "performing continuous behavioural profiling.",
             "Catches novel threats without signatures."),
            ("Principle 3 — Immunological Memory",
             "Detected threats are profiled and shared across zones via TCICP, "
             "lowering future detection thresholds.",
             "Variants of NotPetya/WannaCry caught faster."),
            ("Principle 4 — Autonomous Containment Response",
             "DIAs perform pre-authorised containment in milliseconds: "
             "micro-segmentation, session termination, privilege revocation.",
             "Outpaces machine-speed propagation."),
            ("Principle 5 — Structural Diversity",
             "Core identity systems, backups, management routed through "
             "≥3 structurally diverse domains with no shared dependencies.",
             "Maersk's correlated DC failure would be impossible."),
            ("Principle 6 — Adaptive Calibration",
             "Detection thresholds dynamically adjust based on global threat "
             "level fed in from TCICP.",
             "Accepts higher false-positive rate during active campaigns."),
        ]
        for title, desc, benefit in principles:
            st.markdown(f"**{title}**")
            st.markdown(f"<div class='info-card'>{desc}<br/>"
                        f"<strong>Resilience benefit:</strong> {benefit}</div>",
                        unsafe_allow_html=True)

    with component_tab[1]:
        st.markdown("### ⚛️ Quantum Entropy Sentinel (QES)")
        st.caption("Pre-pathogenic threat detection via entropy + post-quantum cryptography")
        st.markdown("""
**Theoretical foundation:** Quantum information theory (Pirandola et al.
2020; NIST PQC standards 2022). Detects malware activity *before* it
delivers payload by monitoring statistical entropy signatures.

The QES has **five monitoring layers** (Table 5.2):
""")
        layers = [
            ("Layer 1 — File System Entropy",
             "Lightweight sensors flag file writes producing encrypted-output entropy signatures.",
             "**Detects:** ransomware/wiperware encryption — **Latency: 2-10 seconds**"),
            ("Layer 2 — Network Traffic Entropy",
             "Inter-zone packet flow analysis identifies covert C2 channels.",
             "**Detects:** C2 communication, data exfiltration — **Latency: sub-second**"),
            ("Layer 3 — Authentication Entropy",
             "Statistical deviation analysis on auth event logs.",
             "**Detects:** Mimikatz pass-the-hash, credential bursts — **Latency: 10-60s**"),
            ("Layer 4 — Quantum Topology Randomisation",
             "QRNG-based moving-target defence: IPs and routes periodically randomised.",
             "**Detects/prevents:** Reconnaissance, lateral movement planning — **Ongoing**"),
            ("Layer 5 — Post-Quantum Cryptography",
             "CRYSTALS-Kyber (KEM) + CRYSTALS-Dilithium (signatures) for "
             "all critical authentication and backups.",
             "**Defeats:** HNDL attacks, future CRQC decryption — **Continuous**"),
        ]
        for title, desc, detect in layers:
            st.markdown(f"**{title}**")
            st.markdown(f"<div class='info-card'>{desc}<br/>{detect}</div>",
                        unsafe_allow_html=True)

    with component_tab[2]:
        st.markdown("### 🌐 Transnational Cyber-Immune Cooperation Protocol (TCICP)")
        st.caption("Jurisdiction-neutral collective defence")
        st.markdown("""
**Theoretical foundation:** Herd immunity (Linkov and Trump 2019) +
cooperative governance theory (Ostrom 1990; Schmitt 2021).

NotPetya hit 64 countries in <10 minutes. The international response was
balkanised — each org fought alone, took 6 months to attribute. TCICP
solves this with **five protocol mechanisms** (Table 5.3):
""")
        mechanisms = [
            ("RTID — Real-Time Threat Intelligence Dissemination",
             "Behavioural threat profiles shared across all participants in <60s.",
             "Biological analogy: **Cytokine signalling**"),
            ("CDA — Coordinated Defensive Activation",
             "First detection by any participant triggers elevated posture across all.",
             "Biological analogy: **Systemic inflammatory response**"),
            ("MAP — Mutual Assistance Protocol",
             "Pre-negotiated obligations: recovery personnel, backup DCs, hosting.",
             "Biological analogy: **T-cell recruitment**"),
            ("CAM — Collective Attribution Mechanism",
             "Shared forensic evidence database compresses attribution from months to hours.",
             "Biological analogy: **Antibody generation**"),
            ("JNLF — Jurisdiction-Neutral Legal Framework",
             "Multilateral treaty (analogous to ICAO) provides legal cover for "
             "cross-border defensive operations without ad-hoc diplomacy.",
             "Biological analogy: **Constitutional immune system**"),
        ]
        for title, desc, analogy in mechanisms:
            st.markdown(f"**{title}**")
            st.markdown(f"<div class='info-card'>{desc}<br/>{analogy}</div>",
                        unsafe_allow_html=True)

        st.info("👉 To see TCICP **in action**, go to the **🌐 Multi-Org TCICP** tab and run the federation experiment.")


# ============================================================================
# TAB 5 — MULTI-ORG TCICP
# ============================================================================
elif tab == "🌐 Multi-Org TCICP":
    st.markdown("## 🌐 Multi-Organisation TCICP Experiment")
    st.markdown(
        "<span class='thesis-ref'>📖 Section 2.8; Table 4.6 — international "
        "cooperation gap analysis</span>", unsafe_allow_html=True)
    st.markdown("""
This experiment validates the **TCICP herd-immunity hypothesis**.

**Setup:** An attacker hits N organisations in sequence. We run twice:
- **Isolated** — each org fights alone (actual NotPetya 2017 reality)
- **TCICP** — first org's detection triggers RTID + CDA across all

Does cooperation actually reduce systemic damage?
""")

    col1, col2, col3 = st.columns(3)
    with col1:
        n_orgs = st.slider("Number of organisations", 2, 8, 5)
    with col2:
        n_endpoints_each = st.slider("Computers per organisation", 50, 300, 100, 25)
    with col3:
        fed_attack = st.selectbox(
            "Attack class",
            options=list(ATTACK_CLASSES.keys()),
            format_func=lambda k: ATTACK_CLASSES[k]["display"],
            index=0,
        )

    if st.button("⚖️ RUN FEDERATION EXPERIMENT", type="primary",
                  use_container_width=True):
        with st.spinner("Running both isolated and TCICP scenarios..."):
            results = federation_comparison(
                n_orgs=n_orgs, n_endpoints_per_org=n_endpoints_each,
                horizon=240, attack_class=fed_attack, base_seed=42,
            )

        iso = results["isolated"]
        tci = results["tcicp"]

        st.markdown("### 📋 Federation results")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### 🔴 Isolated (no cooperation)")
            st.metric("Orgs contained", f"{iso.contained_orgs}/{iso.total_orgs}")
            st.metric("Avg healthy", f"{iso.total_healthy:.1f}%")
            st.metric("Avg destroyed", f"{iso.total_destroyed:.1f}%")
            st.metric("Total federation loss", f"${iso.total_loss_usd:,.0f}")
        with c2:
            st.markdown("#### 🟢 TCICP (cooperation)")
            st.metric("Orgs contained", f"{tci.contained_orgs}/{tci.total_orgs}",
                      delta=f"+{tci.contained_orgs - iso.contained_orgs} more")
            st.metric("Avg healthy", f"{tci.total_healthy:.1f}%",
                      delta=f"+{tci.total_healthy - iso.total_healthy:.1f}pp")
            st.metric("Avg destroyed", f"{tci.total_destroyed:.1f}%",
                      delta=f"{tci.total_destroyed - iso.total_destroyed:+.1f}pp",
                      delta_color="inverse")
            st.metric("Total federation loss", f"${tci.total_loss_usd:,.0f}",
                      delta=f"${tci.total_loss_usd - iso.total_loss_usd:+,.0f}",
                      delta_color="inverse")

        savings = iso.total_loss_usd - tci.total_loss_usd
        if savings > 0:
            st.success(
                f"📈 **TCICP cooperation saved ${savings:,.0f}** across the federation. "
                f"Isolated: {iso.contained_orgs}/{n_orgs} orgs contained. "
                f"TCICP: {tci.contained_orgs}/{n_orgs} orgs contained. "
                f"This empirically validates the **herd immunity hypothesis** of Section 2.9."
            )
        else:
            st.info("For this attack class and parameters, cooperation did not "
                    "meaningfully change the outcome. Try a different attack or more orgs.")

        st.markdown("### 🏢 Per-organisation outcomes")
        rows = []
        for i, name in enumerate(iso.org_names):
            rows.append({
                "Organisation": name,
                "Isolated — Healthy": f"{iso.org_results[i].final_healthy_fraction*100:.1f}%",
                "Isolated — Destroyed": f"{iso.org_results[i].final_destroyed_fraction*100:.1f}%",
                "Isolated — Detected": iso.org_results[i].time_to_detection or "Never",
                "TCICP — Healthy": f"{tci.org_results[i].final_healthy_fraction*100:.1f}%",
                "TCICP — Destroyed": f"{tci.org_results[i].final_destroyed_fraction*100:.1f}%",
                "TCICP — Detected": tci.org_results[i].time_to_detection or "Never",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)


# ============================================================================
# TAB 6 — PHASED ROLLOUT
# ============================================================================
elif tab == "📈 Phased Rollout":
    st.markdown("## 📈 QUATIC Phased Implementation Roadmap")
    st.markdown(
        "<span class='thesis-ref'>📖 Table 5.5 — 36-month roadmap with KPIs</span>",
        unsafe_allow_html=True)
    st.markdown("""
Organisations can't deploy QUATIC overnight. The thesis specifies a **7-phase
rollout over 36 months**. This dashboard runs the same attack against each
phase's defensive maturity and shows containment improving cumulatively.
""")

    phase_attack = st.selectbox(
        "Test attack against each phase:",
        options=list(ATTACK_CLASSES.keys()),
        format_func=lambda k: ATTACK_CLASSES[k]["display"],
    )

    if st.button("▶️ RUN PHASE ABLATION", type="primary", use_container_width=True):
        with st.spinner("Running 7 phases (Phase 0 → Phase 6)..."):
            phase_results = {}
            for phase in range(7):
                topo = build_maersk_like_topology(
                    n_endpoints=200,
                    n_zones=(1 if phase < 2 else (3 if phase < 5 else 6)),
                    patch_coverage=0.55 + 0.05 * phase,
                    wdigest_on=(phase < 3), backup_online=(phase < 4),
                    seed=42,
                )
                atk = make_attacker(phase_attack, topo, seed=42)
                dfd = HybridDefender(topo, phase=phase, seed=42)
                result = SimulationEngine(topo, atk, dfd, 300, f"phase_{phase}").run()
                phase_results[phase] = result

        st.markdown("### 📊 Phase-by-phase outcomes")
        phase_descriptions = [
            "Phase 0 — Foundation (no active defence)",
            "Phase 1 — QES Layers 1-3 (entropy sensors on flat network)",
            "Phase 2 — ICA Immune Zones (KEY inflection point)",
            "Phase 3 — Post-Quantum Crypto added",
            "Phase 4 — Air-Gapped Backups",
            "Phase 5 — TCICP Federation",
            "Phase 6 — Full Integration",
        ]

        rows = []
        for phase in range(7):
            s = phase_results[phase].summary()
            rows.append({
                "Phase": phase_descriptions[phase],
                "Healthy %": f"{s['final_healthy_pct']:.1f}%",
                "Destroyed %": f"{s['final_destroyed_pct']:.1f}%",
                "DCs alive": f"{s['dcs_alive']}/6",
                "Detected at": f"min {s['time_to_detection_min']}" if s["time_to_detection_min"] else "Never",
                "Contained": "✅" if s["contained"] else "❌",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

        fig, ax = plt.subplots(figsize=(11, 5))
        phases = [f"Phase {i}" for i in range(7)]
        healthy = [phase_results[i].summary()["final_healthy_pct"] for i in range(7)]
        destroyed = [phase_results[i].summary()["final_destroyed_pct"] for i in range(7)]
        x = np.arange(len(phases))
        ax.bar(x - 0.2, healthy, 0.4, label="Healthy %", color="#2b8c3e", alpha=0.85)
        ax.bar(x + 0.2, destroyed, 0.4, label="Destroyed %", color="#c0392b", alpha=0.85)
        ax.set_xticks(x); ax.set_xticklabels(phases)
        ax.set_ylim(0, 110)
        ax.set_ylabel("% of estate")
        ax.set_title(f"QUATIC Phase Ablation vs {ATTACK_CLASSES[phase_attack]['display']}")
        ax.legend()
        ax.grid(True, axis="y", alpha=0.3)
        for i in range(7):
            mark = "✓" if phase_results[i].attack_contained else "✗"
            colr = "#2b8c3e" if phase_results[i].attack_contained else "#c0392b"
            ax.text(i, 105, mark, ha="center", color=colr,
                    fontsize=16, fontweight="bold")
        fig.tight_layout()
        st.pyplot(fig); plt.close(fig)

        first_contained = next(
            (p for p in range(7) if phase_results[p].attack_contained), None)
        if first_contained is not None:
            st.success(
                f"🎯 **Inflection point: Phase {first_contained}** is the minimum "
                f"deployment that contains this attack. For maximum ROI on "
                f"cybersecurity investment, prioritise reaching at least Phase {first_contained}."
            )


# ============================================================================
# TAB 7 — QUALITY ATTRIBUTES (Table 4.2)
# ============================================================================
elif tab == "🎯 Quality Attributes":
    st.markdown("## 🎯 Quality Attribute Failure Matrix")
    st.markdown(
        "<span class='thesis-ref'>📖 Table 4.2 — ISO/IEC 25010 quality attribute "
        "analysis of Maersk vs NotPetya</span>", unsafe_allow_html=True)
    st.markdown("""
The thesis uses the **ISO/IEC 25010 software quality model** to diagnose
every dimension on which Maersk's security architecture failed. For each
quality attribute: what Maersk had vs. what was needed, how NotPetya
exploited the gap, and which QUATIC component addresses it.
""")

    rows = []
    for q in QUALITY_ATTRIBUTES:
        rows.append({
            "Attribute": q["attr"],
            "Sub-characteristic": q["sub"],
            "Ideal state": q["ideal"],
            "Maersk actual": q["maersk"],
            "How NotPetya exploited it": q["exploit"],
            "Severity": q["severity"],
            "QUATIC layer that addresses": q["quatic_layer"],
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("### 📊 Severity distribution")
    crit = sum(1 for q in QUALITY_ATTRIBUTES if q["severity"] == "Critical")
    high = sum(1 for q in QUALITY_ATTRIBUTES if q["severity"] == "High")
    med = sum(1 for q in QUALITY_ATTRIBUTES if q["severity"] == "Medium")
    c1, c2, c3 = st.columns(3)
    c1.metric("🔴 Critical failures", crit)
    c2.metric("🟠 High failures", high)
    c3.metric("🟡 Medium failures", med)

    st.error(
        f"**Maersk had {crit} CRITICAL quality failures** — each one alone "
        "would have been a serious vulnerability. The combination is what "
        "produced catastrophic outcome. Every single critical failure has "
        "a matching QUATIC component designed to address it."
    )


# ============================================================================
# TAB 8 — GEOPOLITICAL RISKS (Table 4.7)
# ============================================================================
elif tab == "🌍 Geopolitical Risks":
    st.markdown("## 🌍 Geopolitical Bystander Risk Typology")
    st.markdown(
        "<span class='thesis-ref'>📖 Table 4.7 — original typology of cyber "
        "conflict bystander risks</span>", unsafe_allow_html=True)
    st.markdown("""
One of the thesis's **original conceptual contributions** is this typology
of six ways non-targeted commercial organisations get caught in state-sponsored
cyber operations.

Maersk was not the intended target of NotPetya — Ukraine was. But Maersk
suffered the second-largest commercial loss from a cyber attack in history.
The typology explains why this collateral damage is structural, not
accidental, and how QUATIC mitigates each risk type.
""")

    for risk in GEOPOLITICAL_RISKS:
        with st.expander(f"**{risk['name']}**"):
            st.markdown(f"**Definition:** {risk['definition']}")
            st.markdown(f"**NotPetya example:** {risk['notpetya_exemplification']}")
            st.markdown(f"**Affected industries:** {risk['affected_industries']}")
            st.markdown(f"**🛡️ QUATIC mitigation:** {risk['quatic_mitigation']}")

    st.markdown("---")
    st.info("""
**Why this matters for the thesis:** Most cybersecurity literature treats
companies as primary attack targets. The thesis argues — empirically grounded
in NotPetya — that **commercial bystander damage is now the dominant pattern
in nation-state cyber operations**. Defensive strategies that ignore this
(NIST/ISO) are conceptually misaligned with the actual threat model.
""")
