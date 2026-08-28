# Supported protocol and packet formats

 * `pcap` PCAP format, only the older format, versions 2.3 and 2.4 in either octet order.
   Other versions are rejected, as are PCAPNG files.
   Ethernet (LinkType 1), Raw IP (LinkType 101) and IEEE 802.11 (LinkType 105) captures
 * `wifi` IEEE 802.11 MAC frames, the Data, QoS Data, Null, ACK and BlockAck frames.
   Management frames, the fourth address, HT Control, A-MSDU and FCS are not covered.
   The body of a protected, i.e. encrypted, frame is left as raw data
 * `llc` IEEE 802.2 LLC, only the SNAP form which carries IP
 * `ip` IPv4 and IPv6, with fragmentation but excluding other options
 * `tcp` TCP
 * `udp` UDP
 * `dns` DNS over TCP and UDP
