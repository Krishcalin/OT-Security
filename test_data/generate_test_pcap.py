#!/usr/bin/env python3
"""
Generate a synthetic PCAP file containing OT/ICS protocol traffic
that will trigger findings in the OT Passive Scanner.

Protocols included:
  - Modbus/TCP (port 502) with MEI response for device identification
  - S7comm (port 102) with COTP CR/CC and S7 data transfer
  - EtherNet/IP (port 44818) with ListIdentity response
  - DNP3 (port 20000) with control commands (no auth), direct operate, cold restart
  - IEC 60870-5-104 (port 2404) with interrogation and control
  - OPC-UA (port 4840) without security
  - MQTT (port 1883) without TLS
  - BACnet/IP (port 47808)

Uses dpkt for PCAP construction (no scapy dependency needed).
"""
import struct
import time
import os

# Try dpkt first, then scapy
try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, Raw, wrpcap, RandMAC
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def build_modbus_request(transaction_id, unit_id, fc, data=b""):
    """Build a Modbus/TCP MBAP + PDU request."""
    pdu = bytes([fc]) + data
    length = len(pdu) + 1  # +1 for unit_id
    mbap = struct.pack(">HHH", transaction_id, 0x0000, length) + bytes([unit_id])
    return mbap + pdu


def build_modbus_response(transaction_id, unit_id, fc, data=b""):
    """Build a Modbus/TCP response."""
    pdu = bytes([fc]) + data
    length = len(pdu) + 1
    mbap = struct.pack(">HHH", transaction_id, 0x0000, length) + bytes([unit_id])
    return mbap + pdu


def build_modbus_mei_response(transaction_id, unit_id):
    """Build a Modbus MEI (FC 43) Read Device Identification response."""
    # MEI response: FC=0x2B, MEI type=0x0E
    objects = [
        (0x00, b"Schneider Electric"),      # vendor_name
        (0x01, b"Modicon M580"),            # product_code
        (0x02, b"3.20"),                     # firmware_version
        (0x04, b"M580 ePAC Controller"),    # product_name
        (0x05, b"BMEP585040"),              # model_name
    ]
    obj_data = b""
    for obj_id, value in objects:
        obj_data += bytes([obj_id, len(value)]) + value

    mei_data = bytes([
        0x0E,  # MEI type = Read Device ID
        0x01,  # Read Device ID code (basic)
        0x01,  # Conformity level
        0x00,  # More follows = No
        0x00,  # Next object ID
        len(objects),  # Number of objects
    ]) + obj_data

    return build_modbus_response(transaction_id, unit_id, 0x2B, mei_data)


def build_s7_cotp_cr():
    """Build an S7comm COTP Connection Request (CR) packet."""
    # TPKT header: version=3, reserved=0, length=22
    # COTP CR: LI=17, PDU type=0xE0, dst_ref=0x0000, src_ref=0x0001, class=0
    # Parameters: src-tsap (0xC1), dst-tsap (0xC2)
    cotp_params = (
        bytes([0xC1, 0x02, 0x01, 0x00])  # src TSAP = 0x0100
        + bytes([0xC2, 0x02, 0x01, 0x02])  # dst TSAP = 0x0102 (rack=0, slot=2)
        + bytes([0xC0, 0x01, 0x0A])  # TPDU size = 1024
    )
    cotp_header = bytes([
        len(cotp_params) + 6,  # Length indicator
        0xE0,  # CR PDU type
        0x00, 0x00,  # DST reference
        0x00, 0x01,  # SRC reference
        0x00,  # Class / option
    ]) + cotp_params

    tpkt_len = 4 + len(cotp_header)
    tpkt = struct.pack(">BBH", 0x03, 0x00, tpkt_len)
    return tpkt + cotp_header


def build_s7_cotp_cc():
    """Build S7comm COTP Connection Confirm (CC) packet."""
    cotp_params = (
        bytes([0xC1, 0x02, 0x01, 0x00])
        + bytes([0xC2, 0x02, 0x01, 0x02])
        + bytes([0xC0, 0x01, 0x0A])
    )
    cotp_header = bytes([
        len(cotp_params) + 6,
        0xD0,  # CC PDU type
        0x00, 0x01,  # DST reference
        0x00, 0x01,  # SRC reference
        0x00,
    ]) + cotp_params

    tpkt_len = 4 + len(cotp_header)
    tpkt = struct.pack(">BBH", 0x03, 0x00, tpkt_len)
    return tpkt + cotp_header


def build_s7_data():
    """Build an S7comm data transfer (COTP DT + S7 Job Read)."""
    # S7 PDU: proto_id=0x32, ROSCTR=JOB(0x01), ... Read request
    s7_pdu = bytes([
        0x32,  # S7 protocol ID
        0x01,  # ROSCTR = Job
        0x00, 0x00,  # Redundancy ID
        0x00, 0x01,  # PDU reference
        0x00, 0x0E,  # Parameter length = 14
        0x00, 0x00,  # Data length = 0
        # Parameter: Function=Read (0x04), item count=1
        0x04, 0x01,
        # Item: syntax=S7ANY(0x10), transport=BYTE(0x02), length=100, DB=1, area=0x84, addr
        0x12, 0x0A, 0x10, 0x02, 0x00, 0x64, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
    ])

    # COTP DT header
    cotp_dt = bytes([0x02, 0xF0, 0x80])  # LI=2, DT PDU, EOT=1
    payload = cotp_dt + s7_pdu

    tpkt_len = 4 + len(payload)
    tpkt = struct.pack(">BBH", 0x03, 0x00, tpkt_len)
    return tpkt + payload


def build_eip_list_identity_response():
    """Build an EtherNet/IP ListIdentity response with CIP identity item."""
    # CIP Identity item data (embedded inside ListIdentity item)
    product_name = b"1756-L71/B ControlLogix5571"
    identity = struct.pack("<H", 1)  # Encap protocol version
    # Socket address: sin_family(2) + sin_port(2) + sin_addr(4) + sin_zero(8) = 16 bytes
    identity += struct.pack(">HH4s8s", 2, 44818, bytes([10, 10, 1, 100]), b"\x00" * 8)
    # Vendor ID = 0x0001 (Rockwell)
    identity += struct.pack("<H", 0x0001)
    # Device Type = 0x10 (PLC)
    identity += struct.pack("<H", 0x0010)
    # Product Code = 55
    identity += struct.pack("<H", 55)
    # Revision: Major=30, Minor=11
    identity += bytes([30, 11])
    # Status = 0x0000
    identity += struct.pack("<H", 0x0000)
    # Serial = 0xDEADBEEF
    identity += struct.pack("<I", 0xDEADBEEF)
    # Product Name length + name
    identity += bytes([len(product_name)])
    identity += product_name
    # State
    identity += bytes([0x03])

    # Wrap in ListIdentity item
    item = struct.pack("<HH", 0x000C, len(identity)) + identity  # type=ListIdentity, len
    body = struct.pack("<H", 1) + item  # item_count=1

    # EIP header: cmd=0x0063, length, session=0, status=0, sender_context, options
    eip_header = struct.pack("<HH", 0x0063, len(body))
    eip_header += struct.pack("<I", 0x00000000)  # session handle
    eip_header += struct.pack("<I", 0x00000000)  # status
    eip_header += b"\x00" * 8  # sender context
    eip_header += struct.pack("<I", 0x00000000)  # options

    return eip_header + body


def build_eip_register_session():
    """Build EtherNet/IP RegisterSession request."""
    body = struct.pack("<HH", 0x0001, 0x0000)  # protocol_version=1, options=0
    eip_header = struct.pack("<HH", 0x0065, len(body))
    eip_header += struct.pack("<I", 0x00000000)
    eip_header += struct.pack("<I", 0x00000000)
    eip_header += b"\x00" * 8
    eip_header += struct.pack("<I", 0x00000000)
    return eip_header + body


def build_dnp3_frame(ctrl, dest_addr, src_addr, app_fc=None, app_data=b""):
    """Build a DNP3 data link + transport + application frame."""
    # Data link header: 0x0564, length, control, dest, src
    # Then transport byte + application layer
    app_layer = b""
    if app_fc is not None:
        # Transport: FIR=1, FIN=1, seq=0 -> 0xC0
        transport_byte = 0xC0
        # App control: FIR=1, FIN=1, CON=0, UNS=0, seq=0 -> 0xC0
        app_control = 0xC0
        app_layer = bytes([transport_byte, app_control, app_fc]) + app_data

    # DL length = 5 (min: ctrl+dest+src) + len(user_data)
    dl_length = 5 + len(app_layer)
    frame = bytes([0x05, 0x64, dl_length, ctrl])
    frame += struct.pack("<H", dest_addr)
    frame += struct.pack("<H", src_addr)
    # CRC would go here in real DNP3 -- scanner doesn't validate CRC
    frame += app_layer
    return frame


def build_iec104_startdt():
    """Build IEC 60870-5-104 STARTDT act U-frame."""
    # APCI: start=0x68, length=4, control fields for STARTDT act
    return bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])


def build_iec104_interrogation():
    """Build IEC 60870-5-104 interrogation command I-frame."""
    # APCI: start=0x68, length varies, I-format
    # ASDU: type=100 (C_IC_NA_1), num=1, cause=6(activation), OA=0, CASDU=1
    asdu = bytes([
        100,        # Type ID: C_IC_NA_1 (interrogation)
        0x01,       # SQ=0, num=1
        0x06, 0x00, # Cause of transmission: activation, OA=0
        0x01, 0x00, # Common ASDU address = 1
        0x00, 0x00, 0x00,  # IOA = 0
        0x14,       # QOI = 20 (station interrogation)
    ])
    apci = bytes([0x68, len(asdu) + 4, 0x00, 0x00, 0x00, 0x00])
    return apci + asdu


def build_opcua_hello():
    """Build OPC-UA Hello message (no security)."""
    # OPC-UA Hello: MessageType="HEL", chunk='F'
    endpoint_url = b"opc.tcp://10.10.2.50:4840/OPCUA/SimulationServer"
    body = struct.pack("<I", 0)  # protocol version
    body += struct.pack("<I", 65536)  # receive buffer size
    body += struct.pack("<I", 65536)  # send buffer size
    body += struct.pack("<I", 0)  # max message size
    body += struct.pack("<I", 0)  # max chunk count
    body += struct.pack("<I", len(endpoint_url))
    body += endpoint_url

    header = b"HELF"
    header += struct.pack("<I", 8 + len(body))  # message size
    return header + body


def build_opcua_open_channel_none():
    """Build OPC-UA OpenSecureChannel with SecurityPolicy=None."""
    # This is a simplified version that the scanner detects as OPC-UA on port 4840
    # with no security policy
    sec_policy = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    body = struct.pack("<I", len(sec_policy))
    body += sec_policy
    body += b"\x00" * 20  # placeholder for certificate, nonce, etc.

    header = b"OPNF"
    header += struct.pack("<I", 8 + len(body))
    return header + body


def build_mqtt_connect(client_id=b"ot_sensor_01", username=None):
    """Build MQTT CONNECT packet (no TLS, optionally no auth)."""
    # Variable header
    protocol_name = b"\x00\x04MQTT"
    protocol_level = bytes([0x04])  # MQTT 3.1.1
    connect_flags = 0x02  # Clean session, no auth
    if username:
        connect_flags |= 0x80  # username flag
    connect_flags_byte = bytes([connect_flags])
    keep_alive = struct.pack(">H", 60)

    var_header = protocol_name + protocol_level + connect_flags_byte + keep_alive

    # Payload: client ID
    payload = struct.pack(">H", len(client_id)) + client_id
    if username:
        payload += struct.pack(">H", len(username)) + username

    remaining_length = len(var_header) + len(payload)
    # Fixed header: CONNECT = 0x10
    fixed_header = bytes([0x10])
    # Encode remaining length (simple, <128)
    fixed_header += bytes([remaining_length])

    return fixed_header + var_header + payload


def build_mqtt_publish(topic=b"ot/plc/status", message=b'{"temp":85.2,"pressure":120.5}'):
    """Build MQTT PUBLISH packet."""
    var_header = struct.pack(">H", len(topic)) + topic
    remaining_length = len(var_header) + len(message)
    fixed_header = bytes([0x30])  # PUBLISH, QoS 0
    fixed_header += bytes([remaining_length])
    return fixed_header + var_header + message


def build_bacnet_whois():
    """Build BACnet/IP Who-Is broadcast."""
    # BVLC header: type=0x81, function=0x0B(original-broadcast-NPDU), length=12
    # NPDU: version=1, control=0x20 (expecting reply)
    # APDU: PDU-type=unconfirmed-request(0x10), service=who-is(0x08)
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])  # version, control, dnet, dlen, hop
    apdu = bytes([0x10, 0x08])  # unconfirmed req, who-is
    payload = npdu + apdu
    bvlc = bytes([0x81, 0x0B]) + struct.pack(">H", 4 + len(payload))
    return bvlc + payload


def generate_pcap_with_dpkt(output_path):
    """Generate test PCAP using dpkt."""
    import dpkt

    writer = dpkt.pcap.Writer(open(output_path, "wb"))
    ts = time.time()

    def make_tcp_pkt(src_ip, dst_ip, src_mac, dst_mac, sport, dport, payload, flags=0x18):
        """Create Ethernet/IP/TCP packet with payload."""
        tcp_pkt = dpkt.tcp.TCP(
            sport=sport, dport=dport, seq=1000, ack=1000,
            off=5, flags=flags, win=65535, data=payload
        )
        ip_pkt = dpkt.ip.IP(
            src=bytes(int(x) for x in src_ip.split(".")),
            dst=bytes(int(x) for x in dst_ip.split(".")),
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp_pkt, len=20 + len(tcp_pkt)
        )
        eth = dpkt.ethernet.Ethernet(
            src=bytes.fromhex(src_mac.replace(":", "")),
            dst=bytes.fromhex(dst_mac.replace(":", "")),
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_pkt
        )
        return bytes(eth)

    def make_udp_pkt(src_ip, dst_ip, src_mac, dst_mac, sport, dport, payload):
        """Create Ethernet/IP/UDP packet with payload."""
        udp_pkt = dpkt.udp.UDP(
            sport=sport, dport=dport,
            ulen=8 + len(payload), data=payload
        )
        ip_pkt = dpkt.ip.IP(
            src=bytes(int(x) for x in src_ip.split(".")),
            dst=bytes(int(x) for x in dst_ip.split(".")),
            p=dpkt.ip.IP_PROTO_UDP,
            data=udp_pkt, len=20 + len(udp_pkt)
        )
        eth = dpkt.ethernet.Ethernet(
            src=bytes.fromhex(src_mac.replace(":", "")),
            dst=bytes.fromhex(dst_mac.replace(":", "")),
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_pkt
        )
        return bytes(eth)

    # ====================================================================
    # Network topology:
    #   10.10.1.10  = SCADA Master / HMI       (MAC 00:1A:2B:00:01:10)
    #   10.10.1.20  = Engineering Workstation   (MAC 00:1A:2B:00:01:20)
    #   10.10.1.100 = Schneider Modbus PLC      (MAC 00:80:F4:00:01:64)
    #   10.10.1.101 = Siemens S7 PLC            (MAC 00:0E:8C:00:01:65)
    #   10.10.1.102 = Rockwell EtherNet/IP PLC  (MAC 00:00:BC:00:01:66)
    #   10.10.2.10  = DNP3 Master Station       (MAC 00:1A:2B:00:02:0A)
    #   10.10.2.50  = DNP3 RTU / Outstation     (MAC 00:1A:2B:00:02:32)
    #   10.10.2.51  = IEC 104 RTU               (MAC 00:1A:2B:00:02:33)
    #   10.10.2.60  = OPC-UA Server             (MAC 00:1A:2B:00:02:3C)
    #   10.10.3.10  = MQTT Broker               (MAC 00:1A:2B:00:03:0A)
    #   10.10.3.20  = BACnet Controller         (MAC 00:1A:2B:00:03:14)
    # ====================================================================

    # --- Modbus traffic (10.10.1.10 -> 10.10.1.100) ---
    # Request: Read Holding Registers (FC 0x03)
    for i in range(5):
        payload = build_modbus_request(i + 1, 1, 0x03, struct.pack(">HH", 0, 10))
        pkt = make_tcp_pkt("10.10.1.10", "10.10.1.100",
                           "00:1A:2B:00:01:10", "00:80:F4:00:01:64",
                           50000 + i, 502, payload)
        writer.writepkt(pkt, ts + i * 0.1)

    # Response: Read Holding Registers
    for i in range(5):
        resp_data = bytes([20]) + b"\x00\x01" * 10  # 10 registers
        payload = build_modbus_response(i + 1, 1, 0x03, resp_data)
        pkt = make_tcp_pkt("10.10.1.100", "10.10.1.10",
                           "00:80:F4:00:01:64", "00:1A:2B:00:01:10",
                           502, 50000 + i, payload)
        writer.writepkt(pkt, ts + i * 0.1 + 0.05)

    # Modbus Write Single Coil (FC 0x05) - write operations
    for i in range(3):
        payload = build_modbus_request(10 + i, 1, 0x05, struct.pack(">HH", i, 0xFF00))
        pkt = make_tcp_pkt("10.10.1.10", "10.10.1.100",
                           "00:1A:2B:00:01:10", "00:80:F4:00:01:64",
                           51000 + i, 502, payload)
        writer.writepkt(pkt, ts + 1.0 + i * 0.1)

    # Modbus MEI response (device identification)
    mei_payload = build_modbus_mei_response(20, 1)
    pkt = make_tcp_pkt("10.10.1.100", "10.10.1.10",
                       "00:80:F4:00:01:64", "00:1A:2B:00:01:10",
                       502, 50010, mei_payload)
    writer.writepkt(pkt, ts + 2.0)

    # --- S7comm traffic (10.10.1.20 -> 10.10.1.101) ---
    # COTP Connection Request
    cr_payload = build_s7_cotp_cr()
    pkt = make_tcp_pkt("10.10.1.20", "10.10.1.101",
                       "00:1A:2B:00:01:20", "00:0E:8C:00:01:65",
                       52000, 102, cr_payload)
    writer.writepkt(pkt, ts + 3.0)

    # COTP Connection Confirm
    cc_payload = build_s7_cotp_cc()
    pkt = make_tcp_pkt("10.10.1.101", "10.10.1.20",
                       "00:0E:8C:00:01:65", "00:1A:2B:00:01:20",
                       102, 52000, cc_payload)
    writer.writepkt(pkt, ts + 3.1)

    # S7 Data Transfer (multiple reads)
    for i in range(5):
        s7_payload = build_s7_data()
        pkt = make_tcp_pkt("10.10.1.20", "10.10.1.101",
                           "00:1A:2B:00:01:20", "00:0E:8C:00:01:65",
                           52000, 102, s7_payload)
        writer.writepkt(pkt, ts + 3.2 + i * 0.1)

    # --- EtherNet/IP traffic (10.10.1.10 -> 10.10.1.102) ---
    # RegisterSession request
    reg_payload = build_eip_register_session()
    pkt = make_tcp_pkt("10.10.1.10", "10.10.1.102",
                       "00:1A:2B:00:01:10", "00:00:BC:00:01:66",
                       53000, 44818, reg_payload)
    writer.writepkt(pkt, ts + 5.0)

    # ListIdentity response
    for i in range(3):
        li_payload = build_eip_list_identity_response()
        pkt = make_tcp_pkt("10.10.1.102", "10.10.1.10",
                           "00:00:BC:00:01:66", "00:1A:2B:00:01:10",
                           44818, 53000, li_payload)
        writer.writepkt(pkt, ts + 5.1 + i * 0.2)

    # --- DNP3 traffic (10.10.2.10 -> 10.10.2.50) ---
    # Multiple packets to establish session state
    # Read request (FC 0x01) from master
    for i in range(3):
        dnp3_payload = build_dnp3_frame(
            ctrl=0xC4,  # DIR=1, PRM=1, FC=4(unconfirmed user data)
            dest_addr=10, src_addr=1,
            app_fc=0x01  # Read
        )
        pkt = make_tcp_pkt("10.10.2.10", "10.10.2.50",
                           "00:1A:2B:00:02:0A", "00:1A:2B:00:02:32",
                           54000, 20000, dnp3_payload)
        writer.writepkt(pkt, ts + 7.0 + i * 0.2)

    # Response from outstation
    for i in range(3):
        dnp3_payload = build_dnp3_frame(
            ctrl=0x44,  # DIR=0, PRM=1, FC=0
            dest_addr=1, src_addr=10,
            app_fc=0x81  # Response
        )
        pkt = make_tcp_pkt("10.10.2.50", "10.10.2.10",
                           "00:1A:2B:00:02:32", "00:1A:2B:00:02:0A",
                           20000, 54000, dnp3_payload)
        writer.writepkt(pkt, ts + 7.1 + i * 0.2)

    # Direct Operate (FC 0x05) -- bypasses SBO, triggers vulnerability
    for i in range(2):
        dnp3_payload = build_dnp3_frame(
            ctrl=0xC4, dest_addr=10, src_addr=1,
            app_fc=0x05  # Direct Operate
        )
        pkt = make_tcp_pkt("10.10.2.10", "10.10.2.50",
                           "00:1A:2B:00:02:0A", "00:1A:2B:00:02:32",
                           54001, 20000, dnp3_payload)
        writer.writepkt(pkt, ts + 8.0 + i * 0.2)

    # Cold Restart (FC 0x0D) -- dangerous command
    dnp3_payload = build_dnp3_frame(
        ctrl=0xC4, dest_addr=10, src_addr=1,
        app_fc=0x0D  # Cold Restart
    )
    pkt = make_tcp_pkt("10.10.2.10", "10.10.2.50",
                       "00:1A:2B:00:02:0A", "00:1A:2B:00:02:32",
                       54002, 20000, dnp3_payload)
    writer.writepkt(pkt, ts + 9.0)

    # File Open (FC 0x19) -- file injection vector
    dnp3_payload = build_dnp3_frame(
        ctrl=0xC4, dest_addr=10, src_addr=1,
        app_fc=0x19  # Open File
    )
    pkt = make_tcp_pkt("10.10.2.10", "10.10.2.50",
                       "00:1A:2B:00:02:0A", "00:1A:2B:00:02:32",
                       54003, 20000, dnp3_payload)
    writer.writepkt(pkt, ts + 9.5)

    # DNP3 over UDP (stateless, harder to secure)
    dnp3_udp_payload = build_dnp3_frame(
        ctrl=0xC4, dest_addr=10, src_addr=1,
        app_fc=0x01  # Read
    )
    pkt = make_udp_pkt("10.10.2.10", "10.10.2.50",
                       "00:1A:2B:00:02:0A", "00:1A:2B:00:02:32",
                       54010, 20000, dnp3_udp_payload)
    writer.writepkt(pkt, ts + 10.0)

    # --- IEC 60870-5-104 traffic (10.10.1.10 -> 10.10.2.51) ---
    # STARTDT
    iec104_startdt = build_iec104_startdt()
    pkt = make_tcp_pkt("10.10.1.10", "10.10.2.51",
                       "00:1A:2B:00:01:10", "00:1A:2B:00:02:33",
                       55000, 2404, iec104_startdt)
    writer.writepkt(pkt, ts + 11.0)

    # Interrogation command
    for i in range(3):
        iec104_interrog = build_iec104_interrogation()
        pkt = make_tcp_pkt("10.10.1.10", "10.10.2.51",
                           "00:1A:2B:00:01:10", "00:1A:2B:00:02:33",
                           55000, 2404, iec104_interrog)
        writer.writepkt(pkt, ts + 11.1 + i * 0.1)

    # --- OPC-UA traffic (10.10.1.20 -> 10.10.2.60) ---
    # Hello (no security)
    opcua_hello = build_opcua_hello()
    pkt = make_tcp_pkt("10.10.1.20", "10.10.2.60",
                       "00:1A:2B:00:01:20", "00:1A:2B:00:02:3C",
                       56000, 4840, opcua_hello)
    writer.writepkt(pkt, ts + 13.0)

    # OpenSecureChannel with SecurityPolicy#None
    for i in range(3):
        opcua_open = build_opcua_open_channel_none()
        pkt = make_tcp_pkt("10.10.1.20", "10.10.2.60",
                           "00:1A:2B:00:01:20", "00:1A:2B:00:02:3C",
                           56000, 4840, opcua_open)
        writer.writepkt(pkt, ts + 13.1 + i * 0.2)

    # --- MQTT traffic (10.10.1.20 -> 10.10.3.10) ---
    # CONNECT without auth, no TLS (port 1883)
    mqtt_connect = build_mqtt_connect(client_id=b"ot_sensor_01")
    pkt = make_tcp_pkt("10.10.1.20", "10.10.3.10",
                       "00:1A:2B:00:01:20", "00:1A:2B:00:03:0A",
                       57000, 1883, mqtt_connect)
    writer.writepkt(pkt, ts + 15.0)

    # PUBLISH messages
    for i in range(5):
        mqtt_pub = build_mqtt_publish(
            topic=b"ot/plc/telemetry",
            message=f'{{"sensor_id":{i},"value":{65.0+i*2.5}}}'.encode()
        )
        pkt = make_tcp_pkt("10.10.1.20", "10.10.3.10",
                           "00:1A:2B:00:01:20", "00:1A:2B:00:03:0A",
                           57000, 1883, mqtt_pub)
        writer.writepkt(pkt, ts + 15.1 + i * 0.5)

    # --- BACnet/IP traffic (10.10.1.10 -> 10.10.3.20) ---
    bacnet_whois = build_bacnet_whois()
    for i in range(3):
        pkt = make_udp_pkt("10.10.1.10", "10.10.3.20",
                           "00:1A:2B:00:01:10", "00:1A:2B:00:03:14",
                           47808, 47808, bacnet_whois)
        writer.writepkt(pkt, ts + 17.0 + i * 0.3)

    # --- Cross-zone traffic (IT->OT) to trigger segmentation violations ---
    # HTTP from OT device (10.10.1.100) to external-looking IP
    http_req = b"GET /firmware/update HTTP/1.1\r\nHost: updates.vendor.com\r\n\r\n"
    pkt = make_tcp_pkt("10.10.1.100", "192.168.1.50",
                       "00:80:F4:00:01:64", "00:1A:2B:FF:FF:01",
                       60000, 80, http_req)
    writer.writepkt(pkt, ts + 19.0)

    # Telnet to OT device (deeply insecure)
    telnet_data = b"\xff\xfb\x01\xff\xfb\x03"  # Telnet negotiation
    pkt = make_tcp_pkt("10.10.1.20", "10.10.1.100",
                       "00:1A:2B:00:01:20", "00:80:F4:00:01:64",
                       60100, 23, telnet_data)
    writer.writepkt(pkt, ts + 19.5)

    # Add more Modbus packets from engineering workstation to same PLC
    # (triggers multiple master stations finding)
    for i in range(3):
        payload = build_modbus_request(30 + i, 1, 0x03, struct.pack(">HH", 100, 10))
        pkt = make_tcp_pkt("10.10.1.20", "10.10.1.100",
                           "00:1A:2B:00:01:20", "00:80:F4:00:01:64",
                           52100 + i, 502, payload)
        writer.writepkt(pkt, ts + 20.0 + i * 0.1)

    writer.close()
    print(f"[OK] Generated PCAP: {output_path}")
    print(f"     Packets: ~60+ across 11 devices")
    print(f"     Protocols: Modbus, S7comm, EtherNet/IP, DNP3, IEC-104, OPC-UA, MQTT, BACnet")


def generate_pcap_with_scapy(output_path):
    """Generate test PCAP using scapy."""
    packets = []
    ts = time.time()

    def tcp_pkt(src_ip, dst_ip, sport, dport, payload, t):
        pkt = (Ether() / IP(src=src_ip, dst=dst_ip) /
               TCP(sport=sport, dport=dport, flags="PA", seq=1000, ack=1000) /
               Raw(load=payload))
        pkt.time = t
        return pkt

    def udp_pkt(src_ip, dst_ip, sport, dport, payload, t):
        pkt = (Ether() / IP(src=src_ip, dst=dst_ip) /
               UDP(sport=sport, dport=dport) /
               Raw(load=payload))
        pkt.time = t
        return pkt

    # --- Modbus ---
    for i in range(5):
        payload = build_modbus_request(i + 1, 1, 0x03, struct.pack(">HH", 0, 10))
        packets.append(tcp_pkt("10.10.1.10", "10.10.1.100", 50000 + i, 502, payload, ts + i * 0.1))
        resp_data = bytes([20]) + b"\x00\x01" * 10
        resp = build_modbus_response(i + 1, 1, 0x03, resp_data)
        packets.append(tcp_pkt("10.10.1.100", "10.10.1.10", 502, 50000 + i, resp, ts + i * 0.1 + 0.05))

    for i in range(3):
        payload = build_modbus_request(10 + i, 1, 0x05, struct.pack(">HH", i, 0xFF00))
        packets.append(tcp_pkt("10.10.1.10", "10.10.1.100", 51000 + i, 502, payload, ts + 1.0 + i * 0.1))

    packets.append(tcp_pkt("10.10.1.100", "10.10.1.10", 502, 50010,
                           build_modbus_mei_response(20, 1), ts + 2.0))

    # --- S7comm ---
    packets.append(tcp_pkt("10.10.1.20", "10.10.1.101", 52000, 102, build_s7_cotp_cr(), ts + 3.0))
    packets.append(tcp_pkt("10.10.1.101", "10.10.1.20", 102, 52000, build_s7_cotp_cc(), ts + 3.1))
    for i in range(5):
        packets.append(tcp_pkt("10.10.1.20", "10.10.1.101", 52000, 102, build_s7_data(), ts + 3.2 + i * 0.1))

    # --- EtherNet/IP ---
    packets.append(tcp_pkt("10.10.1.10", "10.10.1.102", 53000, 44818, build_eip_register_session(), ts + 5.0))
    for i in range(3):
        packets.append(tcp_pkt("10.10.1.102", "10.10.1.10", 44818, 53000,
                               build_eip_list_identity_response(), ts + 5.1 + i * 0.2))

    # --- DNP3 ---
    for i in range(3):
        packets.append(tcp_pkt("10.10.2.10", "10.10.2.50", 54000, 20000,
                               build_dnp3_frame(0xC4, 10, 1, 0x01), ts + 7.0 + i * 0.2))
        packets.append(tcp_pkt("10.10.2.50", "10.10.2.10", 20000, 54000,
                               build_dnp3_frame(0x44, 1, 10, 0x81), ts + 7.1 + i * 0.2))
    for i in range(2):
        packets.append(tcp_pkt("10.10.2.10", "10.10.2.50", 54001, 20000,
                               build_dnp3_frame(0xC4, 10, 1, 0x05), ts + 8.0 + i * 0.2))
    packets.append(tcp_pkt("10.10.2.10", "10.10.2.50", 54002, 20000,
                           build_dnp3_frame(0xC4, 10, 1, 0x0D), ts + 9.0))
    packets.append(tcp_pkt("10.10.2.10", "10.10.2.50", 54003, 20000,
                           build_dnp3_frame(0xC4, 10, 1, 0x19), ts + 9.5))
    packets.append(udp_pkt("10.10.2.10", "10.10.2.50", 54010, 20000,
                           build_dnp3_frame(0xC4, 10, 1, 0x01), ts + 10.0))

    # --- IEC-104 ---
    packets.append(tcp_pkt("10.10.1.10", "10.10.2.51", 55000, 2404,
                           build_iec104_startdt(), ts + 11.0))
    for i in range(3):
        packets.append(tcp_pkt("10.10.1.10", "10.10.2.51", 55000, 2404,
                               build_iec104_interrogation(), ts + 11.1 + i * 0.1))

    # --- OPC-UA ---
    packets.append(tcp_pkt("10.10.1.20", "10.10.2.60", 56000, 4840,
                           build_opcua_hello(), ts + 13.0))
    for i in range(3):
        packets.append(tcp_pkt("10.10.1.20", "10.10.2.60", 56000, 4840,
                               build_opcua_open_channel_none(), ts + 13.1 + i * 0.2))

    # --- MQTT ---
    packets.append(tcp_pkt("10.10.1.20", "10.10.3.10", 57000, 1883,
                           build_mqtt_connect(b"ot_sensor_01"), ts + 15.0))
    for i in range(5):
        packets.append(tcp_pkt("10.10.1.20", "10.10.3.10", 57000, 1883,
                               build_mqtt_publish(b"ot/plc/telemetry",
                                                  f'{{"sensor_id":{i},"value":{65.0+i*2.5}}}'.encode()),
                               ts + 15.1 + i * 0.5))

    # --- BACnet ---
    for i in range(3):
        packets.append(udp_pkt("10.10.1.10", "10.10.3.20", 47808, 47808,
                               build_bacnet_whois(), ts + 17.0 + i * 0.3))

    # --- Cross-zone ---
    packets.append(tcp_pkt("10.10.1.100", "192.168.1.50", 60000, 80,
                           b"GET /firmware/update HTTP/1.1\r\nHost: updates.vendor.com\r\n\r\n",
                           ts + 19.0))
    packets.append(tcp_pkt("10.10.1.20", "10.10.1.100", 60100, 23,
                           b"\xff\xfb\x01\xff\xfb\x03", ts + 19.5))
    for i in range(3):
        payload = build_modbus_request(30 + i, 1, 0x03, struct.pack(">HH", 100, 10))
        packets.append(tcp_pkt("10.10.1.20", "10.10.1.100", 52100 + i, 502, payload, ts + 20.0 + i * 0.1))

    wrpcap(output_path, packets)
    print(f"[OK] Generated PCAP: {output_path}")
    print(f"     Packets: {len(packets)}")
    print(f"     Protocols: Modbus, S7comm, EtherNet/IP, DNP3, IEC-104, OPC-UA, MQTT, BACnet")


if __name__ == "__main__":
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ot_test_traffic.pcap")

    if HAS_DPKT:
        print("[*] Using dpkt to generate PCAP ...")
        generate_pcap_with_dpkt(output)
    elif HAS_SCAPY:
        print("[*] Using scapy to generate PCAP ...")
        generate_pcap_with_scapy(output)
    else:
        print("[ERROR] Neither dpkt nor scapy is installed.")
        print("  pip install dpkt")
        print("  pip install scapy")
        exit(1)
