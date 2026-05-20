"""
QUATIC Cyber-Resilience Simulator — Live Dashboard
==================================================
Run locally:  streamlit run app.py
Deploy:       https://share.streamlit.io  (free, public)
"""
from __future__ import annotations

import math
import os
import sys
import time
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.attacker import NotPetyaAttacker
from agents.defender import BaselineDefender, HybridDefender, QuaticDefender
from core.topology import NodeState, build_maersk_like_topology
from engine.simulation import SimulationEngine


# ============================================================================
# Page config and styling
# ============================================================================
st.set_page_config(
    page_title="QUATIC Cyber-Resilience Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main > div { padding-top: 1rem; }
    .stMetric { background: #f8f9fa; padding: 1rem; border-radius: 8px;
                border-left: 4px solid #2b8c3e; }
    .big-title { font-size: 2.5rem; font-weight: 700; margin-bottom: 0; }
    .subtitle { color: #666; font-size: 1.1rem; margin-top: 0; }
    div[data-testid="stMetricValue"] { font-size: 2rem; }
    .stAlert { border-radius: 8px; }
    h2 { margin-top: 2rem; }
    .verdict-good { background: linear-gradient(90deg, #d4edda, #c3e6cb);
                    padding: 1.5rem; border-radius: 12px; border-left: 6px solid #28a745;
                    font-size: 1.1rem; }
    .verdict-bad { background: linear-gradient(90deg, #f8d7da, #f5c6cb);
                   padding: 1.5rem; border-radius: 12px; border-left: 6px solid #dc3545;
                   font-size: 1.1rem; }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# Header
# ============================================================================
col_logo, col_title = st.columns([1, 9])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown('<p class="big-title">QUATIC Cyber-Resilience Simulator</p>',
                unsafe_allow_html=True)
    st.markdown(
        '<p class="subtitle">Interactive validation of the Quantum-Augmented Trans-Immune Cyber framework — Owusu Sekyere (KNUST, 2025)</p>',
        unsafe_allow_html=True)

st.markdown("---")

# ============================================================================
# Sidebar controls
# ============================================================================
with st.sidebar:
    st.header("⚙️ Simulation Controls")

    st.subheader("🏢 Network")
    n_endpoints = st.slider("Number of computers (endpoints)",
                            50, 1000, 200, 50,
                            help="Maersk had ~45,000 across global ops")
    n_zones = st.slider("Number of immune zones", 1, 12, 6,
                        help="1 = flat (Maersk 2017). More = better isolation.")
    patch_coverage = st.slider("Patch coverage %", 0, 100, 55,
                               help="% of computers up-to-date with security patches") / 100.0

    st.subheader("⚔️ Attacker")
    propagation_rate = st.slider("Virus spread speed (computers/min)",
                                  1, 30, 8)
    encryption_delay = st.slider("Dwell time before payload (min)",
                                  5, 120, 30,
                                  help="How long the virus hides before destroying data")
    stealth = st.slider("Attacker stealth level", 0.0, 1.0, 0.0, 0.1,
                        help="0 = loud NotPetya. 1 = silent nation-state APT.")

    st.subheader("🛡️ Defender")
    defender_choice = st.radio(
        "Defence strategy",
        ["🛡️ QUATIC (full)", "📋 Baseline (NIST/ISO)", "🔧 Hybrid (phased rollout)"],
        index=0,
    )
    phase = 2
    if defender_choice.startswith("🔧"):
        phase = st.slider("Implementation phase", 0, 6, 2,
                          help="Phase 0 = nothing, Phase 2 = Immune Zones, Phase 6 = full QUATIC")

    st.subheader("⏱️ Time")
    horizon = st.slider("Simulation length (minutes)",
                        60, 1440, 240, 60)
    seed = st.number_input("Random seed", value=42, step=1,
                           help="Change to run the attack with different random choices")

    st.markdown("---")
    animate = st.checkbox("🎬 Show live animation", value=True,
                         help="Watch the attack unfold node-by-node on the network grid")

    run_button = st.button("▶️ RUN SIMULATION", type="primary",
                            use_container_width=True)
    compare_button = st.button("⚖️ COMPARE ALL DEFENDERS",
                                use_container_width=True)

    st.markdown("---")
    st.caption("💡 Tip: drag any slider, then click **Run** to see the effect.")


# ============================================================================
# Helper functions
# ============================================================================
STATE_COLOURS = {
    "healthy": "#2b8c3e",
    "compromised": "#e6692b",
    "encrypted": "#8b1a1a",
    "destroyed": "#1a1a1a",
    "quarantined": "#f0b030",
    "reconnoitred": "#d0572b",
    "recovered": "#5cb85c",
}


def build_defender(name, topo, seed, phase=2):
    if name.startswith("🛡️"):
        return QuaticDefender(topo, seed=seed), "QUATIC (full)"
    elif name.startswith("📋"):
        return BaselineDefender(topo, seed=seed), "Baseline (NIST/ISO)"
    else:
        return HybridDefender(topo, phase=phase, seed=seed), f"Hybrid (Phase {phase})"


def run_simulation(defender_choice, **kw):
    hardened = defender_choice.startswith("🛡️")
    topo = build_maersk_like_topology(
        n_endpoints=kw["n_endpoints"],
        n_zones=kw["n_zones"],
        patch_coverage=kw["patch_coverage"],
        wdigest_on=(not hardened),
        backup_online=(not hardened),
        seed=kw["seed"],
    )
    atk = NotPetyaAttacker(
        topo, seed=kw["seed"],
        propagation_rate=kw["propagation_rate"],
        encryption_delay_ticks=kw["encryption_delay"],
        stealth=kw["stealth"],
    )
    defender, defender_name = build_defender(
        defender_choice, topo, kw["seed"], kw.get("phase", 2),
    )
    engine = SimulationEngine(topo, atk, defender, kw["horizon"], defender_name)
    result = engine.run()
    return result, defender_name, topo


def render_network_grid(node_states: Dict[str, str], topo_positions: Dict[str, tuple],
                         title: str = "Network state"):
    """Render the network as a coloured grid of dots."""
    if not topo_positions:
        return None
    xs = [topo_positions[nid][0] for nid in node_states.keys() if nid in topo_positions]
    ys = [topo_positions[nid][1] for nid in node_states.keys() if nid in topo_positions]
    colors = [STATE_COLOURS.get(state, "#ccc") for nid, state in node_states.items()
              if nid in topo_positions]

    if not xs:
        return None

    fig, ax = plt.subplots(figsize=(9, 6), dpi=80)
    ax.scatter(xs, ys, c=colors, s=70, edgecolors="white", linewidths=0.5)
    ax.set_aspect("equal")
    ax.invert_yaxis()
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_title(title, fontsize=11, pad=8)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")
    fig.tight_layout(pad=0.3)
    return fig


def render_legend():
    cols = st.columns(5)
    legend_items = [
        ("🟢", "Healthy", "#2b8c3e"),
        ("🟡", "Quarantined", "#f0b030"),
        ("🟠", "Infected", "#e6692b"),
        ("🔴", "Encrypted", "#8b1a1a"),
        ("⚫", "Destroyed", "#1a1a1a"),
    ]
    for col, (icon, label, _) in zip(cols, legend_items):
        col.markdown(f"**{icon} {label}**")


def plot_timeline_curve(result, title="Infection timeline"):
    ticks = [r.tick for r in result.ticks]
    healthy = [r.healthy_fraction * 100 for r in result.ticks]
    destroyed = [r.destroyed_fraction * 100 for r in result.ticks]
    compromised = [r.compromised_fraction * 100 for r in result.ticks]
    quarantined = [r.quarantined_fraction * 100 for r in result.ticks]

    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.fill_between(ticks, 0, healthy, alpha=0.85, label="Healthy", color="#2b8c3e")
    ax.fill_between(ticks, healthy,
                    [h + q for h, q in zip(healthy, quarantined)],
                    alpha=0.7, label="Quarantined", color="#f0b030")
    ax.fill_between(ticks,
                    [h + q for h, q in zip(healthy, quarantined)],
                    [h + q + c for h, q, c in zip(healthy, quarantined, compromised)],
                    alpha=0.7, label="Infected", color="#e6692b")
    ax.fill_between(ticks,
                    [h + q + c for h, q, c in zip(healthy, quarantined, compromised)],
                    [100] * len(ticks),
                    alpha=0.7, label="Destroyed", color="#1a1a1a")
    if result.time_to_detection is not None:
        ax.axvline(result.time_to_detection, linestyle="--", color="navy", alpha=0.7,
                   label=f"Detected @ min {result.time_to_detection}")
    ax.set_xlabel("Minutes since attack started")
    ax.set_ylabel("% of estate")
    ax.set_ylim(0, 100)
    ax.set_title(title)
    ax.legend(loc="center right", framealpha=0.95, fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    return fig


def write_findings(result, defender_name, baseline_compare=None):
    s = result.summary()
    healthy = s["final_healthy_pct"]
    destroyed = s["final_destroyed_pct"]
    ttd = s["time_to_detection_min"]
    ttd_text = f"minute {ttd}" if ttd is not None else "never (no detection at all)"

    if s["contained"]:
        verdict = "✅ Attack contained."
        story = (
            f"{defender_name} detected the threat at {ttd_text} and contained it "
            f"before serious damage. {healthy:.1f}% of computers stayed operational. "
            f"All {s['dcs_alive']} domain controllers survived — staff can still log in. "
            f"Estimated business loss: <strong>${s['estimated_loss_usd']:,.0f}</strong>."
        )
    elif healthy > 50:
        verdict = "⚠️ Attack partially contained."
        story = (
            f"{defender_name} {('eventually noticed the attack at ' + ttd_text) if ttd else 'never noticed the attack'}, "
            f"and by then {destroyed:.1f}% of computers were already destroyed. "
            f"Only {s['dcs_alive']} of 6 domain controllers survived. "
            f"Estimated loss: <strong>${s['estimated_loss_usd']:,.0f}</strong>."
        )
    else:
        verdict = "❌ Catastrophic failure."
        if ttd is None:
            story = (
                f"{defender_name} <strong>never detected the attack.</strong> "
                f"The virus moved through the network silently and destroyed "
                f"{destroyed:.1f}% of computers. Only {s['dcs_alive']} of 6 domain "
                f"controllers survived. <strong>This is the Maersk 2017 scenario.</strong> "
                f"Estimated loss: <strong>${s['estimated_loss_usd']:,.0f}</strong> "
                f"(real Maersk loss: $250–300 million on a 45,000-computer estate)."
            )
        else:
            story = (
                f"{defender_name} detected the attack at {ttd_text}, but by then "
                f"it was too late. {destroyed:.1f}% of computers were destroyed. "
                f"Estimated loss: <strong>${s['estimated_loss_usd']:,.0f}</strong>."
            )
    return verdict, story


# ============================================================================
# Main: single-defender run
# ============================================================================
if run_button:
    params = dict(
        n_endpoints=n_endpoints, n_zones=n_zones, patch_coverage=patch_coverage,
        propagation_rate=propagation_rate, encryption_delay=encryption_delay,
        stealth=stealth, horizon=horizon, seed=seed, phase=phase,
    )

    progress = st.empty()
    progress.info("🔄 Running simulation...")
    t_start = time.time()
    result, defender_name, topo = run_simulation(defender_choice, **params)
    elapsed = time.time() - t_start
    progress.empty()

    # ---- Verdict ----
    verdict, story = write_findings(result, defender_name)
    s = result.summary()
    if s["contained"]:
        st.markdown(f'<div class="verdict-good"><strong>{verdict}</strong><br/><br/>{story}</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="verdict-bad"><strong>{verdict}</strong><br/><br/>{story}</div>',
                    unsafe_allow_html=True)

    st.caption(f"⏱️ Simulation completed in {elapsed:.2f} seconds")

    # ---- Metrics ----
    st.markdown("## 📊 Key Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Computers still working", f"{s['final_healthy_pct']:.1f}%",
              delta=None)
    c2.metric("Computers destroyed", f"{s['final_destroyed_pct']:.1f}%",
              delta=None)
    c3.metric("Domain controllers alive", f"{s['dcs_alive']}/6")
    c4.metric("Estimated financial loss", f"${s['estimated_loss_usd']:,.0f}")

    # ---- Live animation ----
    if animate and result.ticks and result.ticks[0].node_states:
        st.markdown("## 🎬 Live network view")
        st.caption("Watch the attack unfold across every computer in real time:")
        render_legend()

        positions = {nid: (n.grid_x, n.grid_y) for nid, n in topo.nodes.items()}

        # Decide how many frames to show
        total_frames = len(result.ticks)
        if total_frames > 60:
            stride = max(1, total_frames // 50)
        else:
            stride = 1
        frame_indices = list(range(0, total_frames, stride))
        if frame_indices[-1] != total_frames - 1:
            frame_indices.append(total_frames - 1)

        slot = st.empty()
        for i, idx in enumerate(frame_indices):
            tr = result.ticks[idx]
            fig = render_network_grid(
                tr.node_states, positions,
                title=f"Minute {tr.tick} — {defender_name} — "
                      f"{tr.healthy_fraction*100:.0f}% healthy, "
                      f"{tr.destroyed_fraction*100:.0f}% destroyed"
            )
            if fig:
                slot.pyplot(fig)
                plt.close(fig)
            time.sleep(0.08)

    # ---- Static timeline ----
    st.markdown("## 📈 Timeline chart")
    fig = plot_timeline_curve(result, f"{defender_name} — Attack timeline")
    st.pyplot(fig)
    plt.close(fig)

    # ---- Event details ----
    with st.expander("🔍 Detailed attacker events (first 30)"):
        for e in result.attack_events[:30]:
            icon = {"initial_access": "🎯", "privilege_escalation": "🔑",
                    "lateral_movement": "➡️", "lateral_movement_blocked": "🛑",
                    "encrypt": "💣"}.get(e.stage, "•")
            st.text(f"Min {e.tick:>3}  {icon}  {e.stage:<28s}  on {e.node_id}")

    with st.expander("🛡️ Defender actions (first 30)"):
        if not result.defender_actions:
            st.info("⚠️ The defender never reacted. No actions were taken.")
        else:
            for a in result.defender_actions[:30]:
                st.text(f"Min {a.tick:>3}  ⚡  {a.action:<24s}  on {a.target}")
                st.caption(f"      ↳ {a.rationale}")


# ============================================================================
# Compare-all-defenders mode
# ============================================================================
if compare_button:
    st.markdown("## ⚖️ Side-by-side comparison")
    st.caption("The same attack against three different defences:")

    params = dict(
        n_endpoints=n_endpoints, n_zones=n_zones, patch_coverage=patch_coverage,
        propagation_rate=propagation_rate, encryption_delay=encryption_delay,
        stealth=stealth, horizon=horizon, seed=seed, phase=2,
    )

    results = {}
    names = {}
    topos = {}
    progress = st.progress(0.0)
    for i, (key, choice) in enumerate([
        ("baseline", "📋 Baseline (NIST/ISO)"),
        ("hybrid", "🔧 Hybrid (phased rollout)"),
        ("quatic", "🛡️ QUATIC (full)"),
    ]):
        progress.progress((i + 0.5) / 3, text=f"Running {choice}...")
        res, name, topo = run_simulation(choice, **params)
        results[key] = res
        names[key] = name
        topos[key] = topo
    progress.empty()

    # Summary table
    st.subheader("📋 Results table")
    rows = []
    for key in ["baseline", "hybrid", "quatic"]:
        s = results[key].summary()
        rows.append({
            "Defender": names[key],
            "Healthy %": f"{s['final_healthy_pct']:.1f}%",
            "Destroyed %": f"{s['final_destroyed_pct']:.1f}%",
            "Detected at": f"min {s['time_to_detection_min']}" if s['time_to_detection_min'] else "Never",
            "DCs alive": f"{s['dcs_alive']}/6",
            "Contained": "✅" if s["contained"] else "❌",
            "Estimated loss": f"${s['estimated_loss_usd']:,.0f}",
        })
    st.table(rows)

    # Highlight delta
    bs = results["baseline"].summary()
    qs = results["quatic"].summary()
    saved = bs["estimated_loss_usd"] - qs["estimated_loss_usd"]
    healthy_diff = qs["final_healthy_pct"] - bs["final_healthy_pct"]
    st.success(
        f"📈 **QUATIC saved ${saved:,.0f}** vs baseline, "
        f"keeping **{healthy_diff:+.1f} percentage points** more of the estate healthy."
    )

    # Three timeline charts
    st.subheader("📈 Side-by-side timelines")
    for key in ["baseline", "hybrid", "quatic"]:
        fig = plot_timeline_curve(results[key], names[key])
        st.pyplot(fig)
        plt.close(fig)

    # Animated comparison
    if animate:
        st.subheader("🎬 Side-by-side animated network views")
        st.caption("Same attack, three defences, simultaneously:")
        render_legend()
        cols = st.columns(3)
        slots = [c.empty() for c in cols]

        max_ticks = min(len(results[k].ticks) for k in ["baseline", "hybrid", "quatic"])
        stride = max(1, max_ticks // 40)
        frame_indices = list(range(0, max_ticks, stride))
        if frame_indices[-1] != max_ticks - 1:
            frame_indices.append(max_ticks - 1)

        positions_per = {
            k: {nid: (n.grid_x, n.grid_y) for nid, n in topos[k].nodes.items()}
            for k in ["baseline", "hybrid", "quatic"]
        }

        for idx in frame_indices:
            for slot, key in zip(slots, ["baseline", "hybrid", "quatic"]):
                tr = results[key].ticks[idx]
                fig = render_network_grid(
                    tr.node_states, positions_per[key],
                    title=f"Min {tr.tick} — {names[key]}\n"
                          f"{tr.healthy_fraction*100:.0f}% healthy"
                )
                if fig:
                    slot.pyplot(fig)
                    plt.close(fig)
            time.sleep(0.12)


# ============================================================================
# Default state: explainer panel
# ============================================================================
if not run_button and not compare_button:
    st.markdown("## 👋 Welcome!")
    st.markdown("""
This simulator lets you test the **QUATIC cyber-resilience framework**
against a NotPetya-class attack — the same kind that destroyed shipping
company Maersk's entire global IT network in 2017, costing $250–300 million.

### What you can do here:

1. **Adjust the sliders** on the left to change the company size, attacker behaviour, and defender configuration.
2. **Click "▶️ RUN SIMULATION"** to see how that scenario plays out.
3. **Click "⚖️ COMPARE ALL DEFENDERS"** to run the same attack against three different defences side by side.
4. **Watch the live animation** to see every computer in the company turn from green (healthy) to orange (infected) to black (destroyed), or stay green if QUATIC blocks the attack.

### What you'll learn:

- **Baseline (NIST/ISO)** frameworks fail catastrophically against zero-day attacks like NotPetya.
- **QUATIC** contains the attack in 1–2 minutes by detecting credential dumping, lateral movement, and network anomalies in real time.
- **Phase-by-phase rollout** is possible — even partial QUATIC (Phase 2 with Immune Zones) saves the network.

### Quick demo:
👉 Just click **▶️ RUN SIMULATION** in the sidebar now to see QUATIC in action.
Then change the defender to **📋 Baseline** and click Run again to see the difference.
""")

    st.markdown("---")
    st.caption(
        "Built on Owusu Sekyere's 2025 MSc thesis at Kwame Nkrumah University of Science and Technology. "
        "Simulation engine: discrete-event tick-based model. Code: Python + Streamlit + Matplotlib. "
        "Open-source under the simulator's research-prototype license."
    )
