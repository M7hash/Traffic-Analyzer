# Traffic Analyzer (Scapy-Based)

A simple and lightweight network traffic analyzer built using **Scapy**.  
Compatible with Python 3.11+ (including Python 3.13).

This tool reads `.pcap` / `.pcapng` files and provides basic traffic statistics and visualization.

---

## 📌 Features

-  Reads PCAP / PCAPNG files
-  Counts total packets
-  Detects TCP and UDP packets
-  Identifies top source IP addresses
-  Displays traffic distribution graph
-  Fast and compatible with modern Python versions

---

##  Technologies Used

- Python 3
- Scapy
- Matplotlib

---

##  Installation

### 1️ Clone the repository

```bash
git clone https://github.com/M7hash/traffic-analyzer.git
cd traffic-analyzer
```
## 2️ Create a virtual environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3️ Install dependencies

```bash
pip install scapy matplotlib
```

## 4 Usage

```bash
python traffic_analyzer.py <pcap_file>
```

## Example:

```bash
python traffic_analyzer.py sample.pcapng
```
