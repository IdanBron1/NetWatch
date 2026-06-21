# NetWatch 🛡️
**Machine Learning-Powered Network Traffic Analyzer & Sniffer**

NetWatch is an advanced, real-time packet sniffer and network analysis tool. It not only captures and visualizes network flows but also leverages a trained **Random Forest Machine Learning model** to classify traffic types dynamically.

## 🚀 Features
* **Real-Time Packet Sniffing:** Captures network packets and groups them into bi-directional flows using `Scapy`.
* **Traffic Classification (ML):** Analyzes flow statistics (packet sizes, arrival times) to predict traffic types (e.g., VPN, Streaming, Browsing) dynamically.
* **Geographic IP Resolution:** Maps external IP addresses to physical locations using MaxMind's GeoLite2 DB.
* **Modern GUI:** A dark-themed, responsive dashboard built with `CustomTkinter` displaying live statistics and geographic mapping.
* **PDF Reporting:** Automatically generates summary reports of network activity.

## 📸 Dashboard
*(Place a screenshot of your working CustomTkinter GUI here - e.g., `![NetWatch GUI](docs/screenshot.png)`)*

## 🧠 The Machine Learning Pipeline
The repository includes the full Data Science pipeline used to train the model in the `model_training/` directory. The data was sourced from MIT and UNB research datasets.
Models evaluated include:
* Artificial Neural Networks (ANN) - Peak validation accuracy: 86.62%
* 1D Convolutional Neural Networks (1D CNN) - Peak validation accuracy: 82.77%
* XGBoost - 92.73%
* **Random Forest (Selected Champion)** - 92.74%

## ⚙️ Installation & Setup

**1. Clone the repository:**
`git clone https://github.com/IdanBron1/NetWatch.git`
`cd NetWatch`

**2. Install dependencies:**
`pip install -r requirements.txt`

**3. Download Required Resources:**
Due to size and licensing, the trained models and GeoIP databases are not included in this repository. You must place them in the `resources/` directory before running the app:
* `random_forest_model.pkl` & `label_encoder.pkl`
* `GeoLite2-City.mmdb` (Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data))

**4. Run the Application:**
*Run as Administrator (Windows) or with `sudo` (Linux) for packet sniffing permissions.*
`python src/main.py`

## ⚖️ License & Credits
* Traffic data sourced from [MIT](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat) and the [University of New Brunswick (UNB)](https://www.unb.ca//cic/datasets/vpn.html).
* This project is open-source under the MIT License.