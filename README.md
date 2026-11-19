# 🛡️ Cybersecurity Threat Analytics Dashboard

**Exploring attack-labelled network traffic with Python, SQL, and Streamlit**

A data analytics portfolio project that investigates patterns in labelled network flows: common attack categories, protocols, services, traffic rates, and data quality. It converts a cybersecurity benchmark dataset into summary tables, charts, and an interactive dashboard to support exploratory security analysis.

> **Scope:** This is a **descriptive analytics project**, not a real-time intrusion detection system (IDS) or a trained attack classifier. A network flow labelled as an attack is **not** the same as a confirmed security incident.

## 📊 Dashboard preview

The following images were generated using **synthetic demonstration data**, not actual UNSW-NB15 records.

![Distribution of simulated attack-labelled flows](reports/attack_mix.png)

![Simulated attack-labelled flow share by protocol](reports/protocol_exposure.png)

## 🎯 Project objectives

- Compare normal and attack-labelled network flows.
- Identify frequent attack categories in the analysed dataset.
- Explore how attack-labelled flow shares differ across network protocols and services.
- Summarise flow duration, data transfer volume, and traffic rate.
- Validate records and report data-quality issues before analysis.
- Communicate findings through a Streamlit dashboard, CSV reports, SQL queries, and charts.

## 🛠️ Technology stack

| Technology | Purpose |
| --- | --- |
| Python | Data processing and analysis |
| Pandas / NumPy | Cleaning, transformation, and aggregation |
| Matplotlib | Exportable charts |
| Plotly / Streamlit | Interactive dashboard |
| SQL | Reusable queries for attack categories, protocols, and services |
| Pytest | Automated testing |

## 📁 Project structure

```text
02-cybersecurity-threat-analytics/
├── app.py                 # Interactive Streamlit dashboard
├── pipeline.py            # Data processing and report generation
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
├── data/
│   └── demo_flows.csv     # Synthetic data for demonstration
├── outputs/               # Generated cleaned data and summary tables
├── reports/               # Generated PNG charts
├── sql/
│   └── analysis.sql       # SQL analysis queries
└── tests/
    └── test_pipeline.py   # Pipeline tests
```

## 🚀 Getting started

**Requirements:** Python 3.10+ recommended and a terminal (PowerShell on Windows works).

### 1. Clone or download the repository

```powershell
git clone https://github.com/YOUR-USERNAME/02-cybersecurity-threat-analytics.git
cd 02-cybersecurity-threat-analytics
```

Replace `YOUR-USERNAME` with your GitHub username, or open the folder after extracting the ZIP.

### 2. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 3. Run the demo analysis

```powershell
python pipeline.py --demo
```

This generates cleaned data, summary tables, and charts from **fictional network-flow data**.

### 4. Open the dashboard

```powershell
python -m streamlit run app.py
```

Use the sidebar to filter by protocol and service. You can also upload an official UNSW-NB15 training or testing CSV in the dashboard.

### 5. Run tests

```powershell
python -m pytest -q
```

## 🧾 Working with a real dataset

The project supports the publicly documented [UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset), a research benchmark containing normal traffic and simulated attacks in a controlled environment.

1. Download the official **UNSW_NB15_training-set.csv** from the dataset provider.
2. Save it inside the `data` folder.
3. Run:

```powershell
python pipeline.py --input data/UNSW_NB15_training-set.csv
```

The output tables and charts will then be based on the CSV you provided. The dashboard analyses uploaded data separately; upload the same CSV there to view it interactively.

**Dataset citation:** Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems*. MilCIS 2015. Refer to the [official source](https://research.unsw.edu.au/projects/unsw-nb15-dataset) for dataset access and citation details.

## 📈 Analysis outputs

Running the pipeline writes the following files:

| Output | Description |
| --- | --- |
| `outputs/cleaned_flows.csv` | Validated flow records and derived fields |
| `outputs/kpis.csv` | Overall flow counts, attack-labelled share, and categories |
| `outputs/attack_categories.csv` | Attack categories and counts |
| `outputs/protocol_risk.csv` | Protocol-level flow and label summaries |
| `outputs/service_risk.csv` | Service-level flow and label summaries |
| `outputs/traffic_profile.csv` | Duration, rate, and traffic-volume summaries |
| `outputs/data_quality.csv` | Data-cleaning and quality checks |
| `reports/attack_mix.png` | Attack-category chart |
| `reports/protocol_exposure.png` | Protocol comparison chart |

Additional outputs include connection-state summaries and SQL queries in `sql/analysis.sql`.

## 🔍 Questions this project helps explore

- Which attack categories appear most frequently in the selected dataset?
- How does the proportion of attack-labelled flows vary by protocol?
- Which services account for the largest flow volumes?
- How do traffic rates and transferred bytes differ between labelled normal and attack traffic?
- What data-quality limitations should be considered before interpreting results?

## ⚠️ Limitations and responsible interpretation

- **Demo data is synthetic.** Demo graphs and numbers are not empirical findings from a production network.
- **The real dataset is a benchmark**, not a live security operations centre feed.
- **Flow counts are not incident counts.** Multiple flows may relate to a single event, and labels do not independently confirm an incident.
- **Attack-labelled percentages depend on dataset sampling and class balance.** They must not be interpreted as the probability that an arbitrary real-world connection is malicious.
- **Official training/testing splits do not provide timestamps** suitable for claims about trends over time.
- **This app does not inspect packets, attribute attackers, or block threats.**

## 💡 Skills demonstrated

Data cleaning · Exploratory data analysis · Cybersecurity fundamentals · Network-flow interpretation · Python · SQL · Interactive dashboards · Reproducible analysis · Data-quality validation · Technical documentation

## 🔭 Future improvements

- Add an exploratory notebook with deeper statistical analysis.
- Compare results between the official training and testing datasets.
- Add configurable report exports and enhanced dashboard filters.
- Introduce separate, properly validated intrusion-detection modelling as a future project phase.

---

**Portfolio project:** Built to demonstrate practical cybersecurity data analysis and clear communication of security-related findings.
