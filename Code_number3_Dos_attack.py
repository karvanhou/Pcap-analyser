
import os
import sys
import dpkt
import matplotlib.pyplot as plt
from datetime import datetime




def main (filename):
    timestamps = []
    dos_flags = 0
    # Open file
    # Packet processing loop

    for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):
        
        # timestamps.append(datetime.fromtimestamp(ts))

        # Parse ethernet packet
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data

        # Check if IP packet
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # Check if TCP packet
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                # Check if TCP packet has SYN and ACK flags unset (potential DoS attack)
                if ip.p == dpkt.ip.IP_PROTO_TCP and (ip.data.flags & dpkt.tcp.TH_SYN) and not (ip.data.flags & dpkt.tcp.TH_ACK):
                    dos_flags += 1
                    # Convert the timestamp to a human-readable format
                    timestamps.append(datetime.fromtimestamp(ts))
                    
    # Plot the data
    fig = plt.figure(figsize=(10, 6))
    x=timestamps
    y=range((dos_flags))
    plt.scatter(x, y, label='DoS Flags')
    plt.xlabel('Timestamp')
    plt.ylabel('DoS Flags')
    plt.title('DoS Flags Over Time')
    plt.legend()
    plt.xticks(rotation=45)  # Rotate x-axis labels for better readability
    plt.show()


main(sys.argv[1])