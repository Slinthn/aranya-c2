from scapy.all import *
# import scapy

load_contrib("quic")
ls(QUIC)

ls()

# scapy.layers.quic.QUIC

# pcap = rdpcap("graph-sync.pcapng")

# for pkt in pcap:
#     for layer in pkt.layers():
#         print(scapy.layers.can.CAN(layer))
#     # if layer.layer_name == "quic":


# # print(pcap.filter(lambda x: x.show()))

import pyshark

cap = pyshark.FileCapture("graph-sync.pcapng")



i = 0
for pkt in cap:
    if 'QUIC' in pkt:
        print(pkt.quic)
        i += 1
        if i == 3:
            break