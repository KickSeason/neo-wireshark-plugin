# neo-wireshark-plugin
a neo p2p protocol lua plugin for wireshark

Frame 2679: 1508 bytes on wire (12064 bits), 1508 bytes captured (12064 bits)
Linux cooked capture
Internet Protocol Version 4, Src: 192.168.130.171, Dst: 47.90.28.83
Transmission Control Protocol, Src Port: 36415, Dst Port: 53333, Seq: 26885, Ack: 1006423, Len: 1440
Neo P2P Protocol, PrivNet
    MAGIC: PrivNet (630401)
    COMMAND: getdata
    LENGTH: 16004
    CHECKSUM: 837608805
[Dissector bug, protocol TCP: /build/wireshark-rjGTDh/wireshark-2.6.3/epan/dissectors/packet-tcp.c:5591: failed assertion "save_desegment_offset == pinfo->desegment_offset && save_desegment_len == pinfo->desegment_len"]
    [Expert Info (Error/Malformed): /build/wireshark-rjGTDh/wireshark-2.6.3/epan/dissectors/packet-tcp.c:5591: failed assertion "save_desegment_offset == pinfo->desegment_offset && save_desegment_len == pinfo->desegment_len"]
        [/build/wireshark-rjGTDh/wireshark-2.6.3/epan/dissectors/packet-tcp.c:5591: failed assertion "save_desegment_offset == pinfo->desegment_offset && save_desegment_len == pinfo->desegment_len"]
        [Severity level: Error]
        [Group: Malformed]




