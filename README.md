# 🛡️ QUATIC Cyber-Resilience Simulator

**Interactive validation of the Quantum-Augmented Trans-Immune Cyber (QUATIC) framework**
Owusu Sekyere — KNUST MSc Forensic Science, 2025

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)

---

## 🌐 Live Demo

👉 **[Open the live dashboard](https://YOUR-DEPLOY-URL.streamlit.app)** (loads in your browser, no install needed)

## 🎯 What is this?

A discrete-event simulator that pits a **NotPetya-class cyber attack** against three different defences:

1. **Baseline (NIST CSF / ISO 27001)** — reactive, signature-based, human-speed.
2. **QUATIC (full)** — the proposed framework: Immune Zones + Quantum Entropy Sentinel + Transnational Cyber-Immune Cooperation.
3. **Hybrid (phased rollout)** — staged deployment across Phases 0–6.

The simulator answers the question:

> *Would QUATIC have prevented the 2017 Maersk catastrophe — and if so, by how much?*

## 📊 Key Findings

| Defender | Healthy % | Destroyed % | TTD (min) | DCs alive | Contained |
|---|---|---|---|---|---|
| Baseline (NIST/ISO) | 27% | 73% | Never | 1/6 | ❌ |
| QUATIC (full) | 100% | 0% | 2 | 6/6 | ✅ |
| Hybrid Phase 2 | 99% | 1% | 2 | 4/6 | ✅ |

Across 20 Monte Carlo runs with randomized attacker parameters:
- Baseline: **0/20 contained**, mean loss $335,426
- QUATIC: **20/20 contained**, mean loss $0

## 🎮 Try it yourself

### Online (recommended)
Visit the [live dashboard](https://YOUR-DEPLOY-URL.streamlit.app), drag the sliders, click Run.

### Locally
```bash
git clone https://github.com/GabrielOtiboe/quatic-sim.git
cd quatic-sim
pip install -r requirements.txt
streamlit run app.py
```
Then open http://localhost:8501 in your browser.

## 🧪 Six built-in scenarios

| # | Scenario | Maps to |
|---|---|---|
| 1 | Maersk counterfactual | Table 5.4 of thesis |
| 2 | Phase-by-phase ablation | Table 5.5 roadmap |
| 3 | Monte Carlo (30 runs) | Sensitivity analysis |
| 4 | AI-ransomware variant | Section 2.6 |
| 5 | Stealth APT sweep | Adversarial stress test |
| 6 | TCICP federation on/off | Section 3.3 |

## 🏗️ Architecture

```
app.py                  # Streamlit dashboard (live UI)
core/topology.py        # Nodes, zones, links, credentials
agents/attacker.py      # NotPetya kill-chain
agents/defender.py      # Baseline / QUATIC / Hybrid defenders
engine/simulation.py    # Tick-based discrete-event engine
scenarios/library.py    # Pre-built experiments
```

## 📚 Citation

If you reference this simulator in academic work:

> Owusu Sekyere, K. (2025). *QUATIC: A Quantum-Augmented Trans-Immune
> Cyber Framework for Pre-Pathogenic Threat Containment.* MSc dissertation,
> Kwame Nkrumah University of Science and Technology.

## 🛠️ Tech stack

- **Python 3.10+**
- **Streamlit** — interactive web UI
- **Matplotlib** — visualizations
- **NumPy** — numerics
- Pure-Python discrete-event simulation engine (no external dependencies)

## 📄 License

Research prototype — free for academic use.
