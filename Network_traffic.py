import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.backends.backend_pdf import PdfPages
from datetime import datetime
packet_list = []
packet_lock = threading.Lock()
def process_packet(packet):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        if TCP in packet:
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            protocol_name = 'TCP'
        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            protocol_name = 'UDP'
        elif ICMP in packet:
            source_port = None
            destination_port = None
            protocol_name = 'ICMP'
        else:
            source_port = None
            destination_port = None
            protocol_name = 'Other'
        packet_info = {
            'Time': timestamp,
            'Source IP': source_ip,
            'Destination IP': destination_ip,
            'Protocol': protocol_name,
            'Length': length,
            'Source Port': source_port,
            'Destination Port': destination_port
        }
        with packet_lock:
            packet_list.append(packet_info)
        print(f"Captured packet: {packet_info}")

def capture_packets():
    sniff(prn=process_packet, stop_filter=lambda x: stop_sniffing.is_set())

def stop_capture():
    input("Press Enter to stop capturing...\n")
    stop_sniffing.set()

def update_plots(i):
    with packet_lock:
        if packet_list:
            df = pd.DataFrame(packet_list)
            if not df.empty and 'Source IP' in df.columns and 'Protocol' in df.columns:
                source_ip_protocol_counts = df.groupby(['Source IP', 'Protocol']).size().unstack(fill_value=0)
                destination_ip_protocol_counts = df.groupby(['Destination IP', 'Protocol']).size().unstack(fill_value=0)
                protocol_colors = {'TCP': 'red', 'UDP': 'blue', 'ICMP': 'green', 'Other': 'gray'}
                ax1.clear()
                ax2.clear()
                if not source_ip_protocol_counts.empty:
                    source_ip_protocol_counts.plot(kind='bar', stacked=True, ax=ax1, color=[protocol_colors.get(p, 'black') for p in source_ip_protocol_counts.columns])
                    ax1.set_title('Source IP vs Packet Count by Protocol')
                    ax1.set_xlabel('Source IP')
                    ax1.set_ylabel('Packet Count')
                    ax1.legend(title='Protocol')
                    ax1.tick_params(axis='x', rotation=45)
                if not destination_ip_protocol_counts.empty:
                    destination_ip_protocol_counts.plot(kind='bar', stacked=True, ax=ax2, color=[protocol_colors.get(p, 'black') for p in destination_ip_protocol_counts.columns])
                    ax2.set_title('Destination IP vs Packet Count by Protocol')
                    ax2.set_xlabel('Destination IP')
                    ax2.set_ylabel('Packet Count')
                    ax2.legend(title='Protocol')
                    ax2.tick_params(axis='x', rotation=45)

stop_sniffing = threading.Event()
capture_thread = threading.Thread(target=capture_packets)
capture_thread.start()
stop_capture()

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 14))
ani = FuncAnimation(fig, update_plots, interval=2000)
plt.show()

capture_thread.join()

df = pd.DataFrame(packet_list)

if not df.empty and 'Source IP' in df.columns and 'Protocol' in df.columns:
    source_ip_protocol_counts = df.groupby(['Source IP', 'Protocol']).size().unstack(fill_value=0)
    destination_ip_protocol_counts = df.groupby(['Destination IP', 'Protocol']).size().unstack(fill_value=0)

    with open("captured.txt", "w") as file:
        for packet_info in packet_list:
            file.write(f"{packet_info}\n")

    with PdfPages('visualizations.pdf') as pdf:
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 14))
        protocol_colors = {'TCP': 'red', 'UDP': 'blue', 'ICMP': 'green', 'Other': 'gray'}
        if not source_ip_protocol_counts.empty:
            source_ip_protocol_counts.plot(kind='bar', stacked=True, ax=ax1, color=[protocol_colors.get(p, 'black') for p in source_ip_protocol_counts.columns])
            ax1.set_title('Source IP vs Packet Count by Protocol')
            ax1.set_xlabel('Source IP')
            ax1.set_ylabel('Packet Count')
            ax1.legend(title='Protocol')
            ax1.tick_params(axis='x', rotation=45)
        if not destination_ip_protocol_counts.empty:
            destination_ip_protocol_counts.plot(kind='bar', stacked=True, ax=ax2, color=[protocol_colors.get(p, 'black') for p in destination_ip_protocol_counts.columns])
            ax2.set_title('Destination IP vs Packet Count by Protocol')
            ax2.set_xlabel('Destination IP')
            ax2.set_ylabel('Packet Count')
            ax2.legend(title='Protocol')
            ax2.tick_params(axis='x', rotation=45)
        plt.tight_layout()
        pdf.savefig(fig)
        plt.close()
