import dpkt
import matplotlib.pyplot as plt
from datetime import datetime
import os
import sys


def main (filename):
    timestamps = []
    ftp_attempts = 0

    with open(filename, 'rb') as file:
        pcap = dpkt.pcap.Reader(file)
        for ts, buf in pcap:
            # Check if the packet is an FTP packet
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                ip = eth.data
                tcp = ip.data
                if tcp.dport == 21 or tcp.sport == 21:
                    # Increment the FTP attempt count
                    ftp_attempts += 1
                    # Convert the timestamp to a human-readable format
                    timestamp = datetime.fromtimestamp(ts)
                    timestamps.append(timestamp)

    fig = plt.figure(figsize=(10, 6))  # Set the figure size to width=10 inches, height=6 inches
    plt.plot(timestamps, range(ftp_attempts), label='FTP Brute Force Attempts')
    plt.xlabel('Timestamp')
    plt.ylabel('Number of Attempts')
    plt.title('FTP Brute Force Attempts Over Time')
    plt.legend()
    plt.xticks(rotation=45)  # Rotate x-axis labels for better readability
    plt.show()

main(sys.argv[1])