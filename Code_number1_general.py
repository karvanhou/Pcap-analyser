import dpkt
import matplotlib.pyplot as plt
import socket
import os
import sys



def main (filename):
    if __name__ == "__main__":

        # Packet Counters
        counter = 0
        ipcounter = 0
        tcpcounter = 0
        udpcounter = 0
        httpcounter = 0
        httpscounter = 0
        ipv4counter = 0
        ftpcounter = 0
        arpcounter = 0 
        tcpcounter_No_ack = 0
        icmpfloodcounter = 0

        # Subnet Dictionary
        subnets = {}

        # Open file

        # Packet processing loop
        for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):
            counter += 1

            # Parse ethernet packet
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data

            # Check if IP packet or non-ip packet
            if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                ipcounter += 1

            # IPV4 packets
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ipv4counter += 1

                dst_ip = socket.inet_ntoa(ip.dst)

                # Extract destination
                string = socket.inet_ntoa(ip.dst)
                address = '.'.join(string.split(".")[:])
                if address in subnets:  # Increase count in dict
                    subnets[address] = subnets[address] + 1
                else:  # Insert key, value in dict
                    subnets[address] = 1

                # TCP packets
                if ip.p == dpkt.ip.IP_PROTO_TCP:  # ip.p == 6:
                    tcpcounter += 1
                    tcp = ip.data

                    # HTTP uses port 80
                    if tcp.dport == 80 or tcp.sport == 80:
                        httpcounter += 1

                    if ip.p == dpkt.ip.IP_PROTO_TCP and (ip.data.flags & dpkt.tcp.TH_SYN) and not (ip.data.flags & dpkt.tcp.TH_ACK):
                        tcpcounter_No_ack += 1
                        tcp = ip.data

                    # HTTPS uses port 443
                    elif tcp.dport == 443 or tcp.sport == 443:
                        httpscounter += 1

                    # FTP uses port 21
                    elif tcp.dport == 21 or tcp.sport == 21:
                        ftpcounter += 1    

                # UDP packets
                elif ip.p == dpkt.ip.IP_PROTO_UDP:  # ip.p == 17:
                    udpcounter += 1
                    udp = ip.data
                # ICMP packets
                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmpfloodcounter += 1    

            # ARP packets
            elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                arpcounter += 1


    if __name__ == "__main__":

        # Create labels and data for packet statistics bar chart
        packet_stats_labels = ["ETHERNET(total)","TCP","TCP_SYN_No_ACK", "HTTP", "HTTPS","FTP","ICMP Flood", "UDP", "IPv4", "ARP"]
        packet_stats_data = [counter,tcpcounter,tcpcounter_No_ack, httpcounter,httpscounter,ftpcounter,icmpfloodcounter, udpcounter, ipv4counter, arpcounter]

        # Create labels and data for IP address occurrences bar chart
        ip_occurrences_labels = list(subnets.keys())
        ip_occurrences_data = list(subnets.values())

        # Create figure and axes
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 6))

        # Create packet statistics bar chart
        bars = ax1.bar(packet_stats_labels, packet_stats_data)
        ax1.set_xlabel("Packet Type")
        ax1.set_ylabel("Count")
        ax1.set_title("Packet Statistics")

        # Create IP address occurrences bar chart
        bars1 = ax2.bar(ip_occurrences_labels, ip_occurrences_data)
        ax2.set_xlabel("IP Addresses")
        ax2.set_ylabel("Occurrences")
        ax2.set_title("IP Address Occurrences")
        ax2.set_xticklabels(ip_occurrences_labels, rotation=360)  # Rotate x-axis labels if needed
        # Create packet statistics bar chart
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2, height, str(height), ha='center', va='bottom')
        for bar in bars1:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2, height, str(height), ha='center', va='bottom')    


        # Adjust spacing between subplots
        plt.subplots_adjust(hspace=0.5)
        # Show the plot
        plt.show()


main(sys.argv[1])    