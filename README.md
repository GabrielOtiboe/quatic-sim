# 🛡️ QUATIC Cyber-Resilience Simulator

**Comprehensive empirical validation platform for the Quantum-Resilient, Autonomous, Transnational Immuno-Cyber System**
Owusu Sekyere — KNUST MSc Forensic Science, 2025

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)

---

## 🌐 Live Demo

👉 **[Open the live dashboard](https://quatic-sim.streamlit.app)** (loads in your browser, no install needed)

## 🎯 What this is

A comprehensive **8-dashboard interactive validation platform** for every claim in the QUATIC thesis. Not just a NotPetya demo — a full empirical reproduction of:

- **Table 4.1** — NotPetya attack stage analysis
- **Table 4.2** — ISO/IEC 25010 quality attribute failure matrix
- **Tables 4.3 + 4.4** — Framework capability scoring (13.9% vs 94.4%)
- **Table 4.5** — Centralised architecture risk analysis
- **Table 4.6** — International cooperation gap analysis
- **Table 4.7** — Geopolitical bystander risk typology
- **Chapter 5.2** — Full ICA + QES + TCICP component specification
- **Table 5.4** — QUATIC counterfactual analysis
- **Table 5.5** — 36-month phased implementation roadmap

## 📊 Headline reproduction

The thesis claims NIST CSF and ISO 27001 score **13.9%** while QUATIC reaches **94.4%** on a 12-dimension capability test. This simulator **reproduces those exact numbers computationally**.

## 🎮 Eight thesis-aligned dashboards

| Tab | What it does | Thesis ref |
|-----|--------------|------------|
| 🏠 **Home** | Framework overview, headline metrics, dashboard map | Chapter 1 |
| 🦠 **Attack Laboratory** | 6 attack classes × 3 defenders × tunable parameters | Sections 2.2-2.10; Table 4.1 |
| 📊 **Framework Scoring** | 12-dimension capability comparison: 13.9% vs 94.4% | Tables 4.3, 4.4 |
| 🛡️ **QUATIC Components** | Deep dive into ICA (6 principles), QES (5 layers), TCICP (5 mechanisms) | Chapter 5.2 |
| 🌐 **Multi-Org TCICP** | Federation experiment: cooperation vs isolation | Section 2.8; Table 4.6 |
| 📈 **Phased Rollout** | Test any attack against each of 7 implementation phases | Table 5.5 |
| 🎯 **Quality Attributes** | ISO/IEC 25010 failure matrix with QUATIC mappings | Table 4.2 |
| 🌍 **Geopolitical Risks** | Bystander risk typology with QUATIC mitigations | Table 4.7 |

## 🦠 Six attack classes tested

1. **🦠 NotPetya** (worm + wiper) — the Maersk 2017 catastrophe
2. **🤖 AI-Driven Ransomware** (GAN-evading, ML target selection) — Section 2.6
3. **🥷 Stealth APT** (Sandworm-class, LOLBAS, dormancy) — Section 2.6
4. **📦 Supply Chain Compromise** (M.E.Doc-style poisoned update) — Section 2.2
5. **⚛️ Quantum HNDL** (harvest-now-decrypt-later) — Section 2.10
6. **🌐 Multi-Org Coordinated** (single attack across N organisations) — Section 2.8

## 🛡️ Three defender profiles

1. **📋 Baseline** — NIST CSF / ISO 27001 (reactive, signature-based, human-speed)
2. **🛡️ QUATIC** — Full ICA + QES + TCICP (pre-pathogenic, machine-speed, federated)
3. **🔧 Hybrid** — Phased rollout (Phase 0 through Phase 6 per Table 5.5)

## 🎮 Try it yourself

### Online (recommended)
Visit the [live dashboard](https://quatic-sim.streamlit.app) — drag sliders, click Run, watch the results.

### Locally
```bash
git clone https://github.com/GabrielOtiboe/quatic-sim.git
cd quatic-sim
pip install -r requirements.txt
streamlit run app.py
```
Then open http://localhost:8501 in your browser.

## 🏗️ Architecture

```
app.py                         # 8-tab Streamlit dashboard (~700 lines)
core/topology.py               # Nodes, zones, links, credentials
agents/
  attacker.py                  # NotPetya kill-chain engine
  attack_classes.py            # 6 thesis-justified attack class configurations
  defender.py                  # Baseline / QUATIC / Hybrid defenders
  federation.py                # Multi-org TCICP experiment harness
  capability_scoring.py        # Tables 4.3, 4.7, ISO/IEC 25010 data
engine/simulation.py           # Tick-based discrete-event engine
scenarios/library.py           # CLI-accessible pre-built scenarios
```

## 📚 Citation

> Owusu Sekyere, K. (2025). *Cyber Threats, Operational Disruption, and the Future of Resilience: Lessons from NotPetya and the QUATIC System.* MSc dissertation, Kwame Nkrumah University of Science and Technology.

## 🛠️ Tech stack

- **Python 3.10+**
- **Streamlit** — interactive multi-tab web UI
- **Matplotlib** — publication-quality visualisations
- **NumPy** — numerics
- Pure-Python discrete-event simulation engine

## 📄 License

Research prototype — free for academic use.
