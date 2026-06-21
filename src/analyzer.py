import pandas as pd
import joblib
import os
import geoip2.database
import numpy as np

# --- CONFIGURATION ---
MODEL_FILE = "random_forest_model.pkl"
ENCODER_FILE = "label_encoder.pkl"
GEO_DB_FILE = "GeoLite2-City.mmdb"

class TrafficAnalyzer:
    def __init__(self):
        self.model = None
        self.encoder = None
        self.geo_reader = None
        self.load_resources()

    def load_resources(self):
        if os.path.exists(MODEL_FILE) and os.path.exists(ENCODER_FILE):
            try:
                self.model = joblib.load(MODEL_FILE)
                self.encoder = joblib.load(ENCODER_FILE)
                print(f">> ANALYZER: Loaded {MODEL_FILE}")
            except:
                pass

        if os.path.exists(GEO_DB_FILE):
            try:
                self.geo_reader = geoip2.database.Reader(GEO_DB_FILE)
            except:
                pass

    def get_geoip(self, ip):
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Local Network", "LAN", "🏠"

        if not self.geo_reader: return "Unknown", "--", "❓"

        try:
            response = self.geo_reader.city(ip)
            country = response.country.name
            city = response.city.name
            iso = response.country.iso_code

            if city:
                full_location = f"{city}, {country}"
            else:
                full_location = country

            return full_location, iso, self.get_flag_emoji(iso)
        except:
            return "Unknown", "--", "🌐"

    def get_flag_emoji(self, iso_code):
        if not iso_code: return "🏳️"
        flags = {"US": "🇺🇸", "IL": "🇮🇱", "GB": "🇬🇧", "RU": "🇷🇺", "CN": "🇨🇳", "DE": "🇩🇪", "FR": "🇫🇷"}
        return flags.get(iso_code, "🏳️")

    def analyze_flows(self, active_flows_list):
        if not active_flows_list: return pd.DataFrame()

        df = pd.DataFrame(active_flows_list)

        # 1. Feature Engineering (MATCHING THE TRAINING NOTEBOOK EXACTLY)
        df['duration'] = df['last_seen'] - df['start_time']
        df['duration'] = df['duration'].replace(0, 0.001)

        # Speeds - Naming MUST match the Random Forest training data
        df['avg_bytes_per_sec'] = (df['fwd_bytes'] + df['bwd_bytes']) / df['duration']
        df['avg_pkts_per_sec'] = (df['fwd_pkts'] + df['bwd_pkts']) / df['duration']

        # Packet Sizes - The Random Forest relies heavily on these!
        df['avg_pkt_size'] = (df['fwd_bytes'] + df['bwd_bytes']) / (df['fwd_pkts'] + df['bwd_pkts']).replace(0, 1)
        df['avg_fwd_pkt_size'] = df['fwd_bytes'] / df['fwd_pkts'].replace(0, 1)
        df['avg_bwd_pkt_size'] = df['bwd_bytes'] / df['bwd_pkts'].replace(0, 1)

        # Ratios
        df['pkt_ratio'] = df['fwd_pkts'] / df['bwd_pkts'].replace(0, 1)

        # 2. AI Prediction
        if self.model:
            try:
                expected_cols = self.model.feature_names_in_
                # Fill missing columns securely without throwing warnings
                for col in expected_cols:
                    if col not in df.columns:
                        df[col] = 0.0

                X = df[expected_cols].fillna(0)
                predictions = self.model.predict(X)
                df['PREDICTED_CLASS'] = self.encoder.inverse_transform(predictions)
            except Exception as e:
                print(f"ML Error: {e}")
                df['PREDICTED_CLASS'] = "N/A"
        else:
            df['PREDICTED_CLASS'] = "N/A"

        # 3. LOGIC OVERRIDES (The Fixes)
        if 'avg_bytes_per_sec' in df.columns:
            mask_slow = (df['PREDICTED_CLASS'] == 'File_Transfer') & (df['avg_bytes_per_sec'] < 2000)
            df.loc[mask_slow, 'PREDICTED_CLASS'] = 'Infrastructure'

        if 'dst_port' in df.columns:
            infra_mask = df['dst_port'].isin([53, 123, 1900, 5353, 137, 445])
            df.loc[infra_mask, 'PREDICTED_CLASS'] = 'Infrastructure'

        return df