from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
import threading
import time
import datetime

conf.use_pcap = True

class PacketSniffer:
    def __init__(self, output_queue):
        self.queue = output_queue
        self.sniffing = False
        self.packet_count = 0
        self.flows = {}
        self.thread = None

    def start(self):
        if self.sniffing: return
        self.sniffing = True
        self.packet_count = 0
        self.flows = {}
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.sniffing = False

    def _sniff_loop(self):
        try:
            # store=0 is CRITICAL for performance
            sniff(prn=self._process_packet, stop_filter=lambda x: not self.sniffing, store=0)
        except Exception as e:
            print(f">> SNIFFER ERROR: {e}")
            self.stop()

    def _process_packet(self, pkt):
        if not self.sniffing: return

        try:
            # 1. LIGHTWEIGHT PARSING
            ts = time.time()
            length = len(pkt)

            proto_str = "OTHER"
            src = "0.0.0.0"
            dst = "0.0.0.0"
            sport = 0
            dport = 0
            p_num = 0
            is_heavy_udp = False

            # 2. IP Layer Parsing
            if pkt.haslayer(IP):
                ip = pkt[IP]
                src = ip.src
                dst = ip.dst
                p_num = ip.proto

                if pkt.haslayer(TCP):
                    proto_str = "TCP"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto_str = "UDP"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    is_heavy_udp = True
                elif pkt.haslayer(ICMP):
                    proto_str = "ICMP"
                else:
                    proto_str = str(p_num)

            # 3. ARP Layer Parsing
            elif pkt.haslayer(ARP):
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
                proto_str = "ARP"
                p_num = 2054
            else:
                return

            # --- FLOW LOGIC ---
            if src < dst:
                key = (src, sport, dst, dport, p_num)
                direction = 'fwd'
            else:
                key = (dst, dport, src, sport, p_num)
                direction = 'bwd'

            if key not in self.flows:
                self.flows[key] = {
                    'start_time': ts, 'last_seen': ts,
                    'fwd_pkts': 0, 'bwd_pkts': 0,
                    'fwd_bytes': 0, 'bwd_bytes': 0,
                    'fwd_iat_max': 0.0, 'bwd_iat_max': 0.0,
                    'dst_port': dport if direction == 'fwd' else sport,
                    'protocol': p_num,
                    'src_ip': src, 'dst_ip': dst,
                    'PREDICTED_CLASS': 'Analyzing...'
                }

            f = self.flows[key]
            iat = ts - f['last_seen']
            f['last_seen'] = ts

            if direction == 'fwd':
                f['fwd_pkts'] += 1
                f['fwd_bytes'] += length
                f['fwd_iat_max'] = max(f['fwd_iat_max'], iat)
            else:
                f['bwd_pkts'] += 1
                f['bwd_bytes'] += length
                f['bwd_iat_max'] = max(f['bwd_iat_max'], iat)

            # --- Calculate Derived Features in Real-Time ---
            duration = ts - f['start_time']
            if duration <= 0:
                duration = 0.000001

            f['duration'] = duration
            f['tot_pkts'] = f['fwd_pkts'] + f['bwd_pkts']
            f['tot_bytes'] = f['fwd_bytes'] + f['bwd_bytes']

            f['avg_bytes_per_sec'] = f['tot_bytes'] / duration
            f['avg_pkts_per_sec'] = f['tot_pkts'] / duration
            f['flow_byts_s'] = f['avg_bytes_per_sec']

            if f['bwd_pkts'] > 0:
                f['pkt_ratio'] = f['fwd_pkts'] / f['bwd_pkts']
            else:
                f['pkt_ratio'] = float(f['fwd_pkts'])

            f['fwd_iat_mean'] = 0 if f['fwd_pkts'] <= 1 else (ts - f['start_time']) / (f['fwd_pkts'] - 1)
            f['bwd_iat_mean'] = 0 if f['bwd_pkts'] <= 1 else (ts - f['start_time']) / (f['bwd_pkts'] - 1)

            self.packet_count += 1
            should_update_gui = False

            # Let the flow mature before updating GUI
            if f['tot_pkts'] > 15 and f['duration'] > 0.5:
                if is_heavy_udp:
                    if self.packet_count % 20 == 0:
                        should_update_gui = True
                else:
                    should_update_gui = True

            if should_update_gui:
                time_str = datetime.datetime.now().strftime("%H:%M:%S")
                row_data = (self.packet_count, time_str, proto_str, src, dst, length, sport, dport)
                self.queue.put(row_data)

        except:
            pass