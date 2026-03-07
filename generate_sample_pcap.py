#!/usr/bin/env python3
"""
Sample PCAP Generator for OT Security Scanner
Creates synthetic ICS/SCADA network traffic with deliberate security issues.
"""
import struct, random, time, os

def _eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload, flags=0x18):
    """Build Ethernet+IP+TCP frame."""
    src_mac = b'\x00\x0c\x29\x01\x02\x03'
    dst_mac = b'\x00\x0c\x29\x04\x05\x06'
    eth = dst_mac + src_mac + b'\x08\x00'
    ip_src = bytes(int(x) for x in src_ip.split('.'))
    ip_dst = bytes(int(x) for x in dst_ip.split('.'))
    tcp_hdr_len = 20
    ip_total = 20 + tcp_hdr_len + len(payload)
    ip_hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, ip_total, random.randint(1,65535),
                        0x4000, 64, 6, 0, ip_src, ip_dst)
    tcp_hdr = struct.pack('>HHIIBBHHH', src_port, dst_port,
                         random.randint(1,0xFFFFFFFF), random.randint(1,0xFFFFFFFF),
                         0x50, flags, 65535, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload

def _eth_ip_udp(src_ip, dst_ip, src_port, dst_port, payload):
    """Build Ethernet+IP+UDP frame."""
    src_mac = b'\x00\x0c\x29\x01\x02\x03'
    dst_mac = b'\x00\x0c\x29\x04\x05\x06'
    eth = dst_mac + src_mac + b'\x08\x00'
    ip_src = bytes(int(x) for x in src_ip.split('.'))
    ip_dst = bytes(int(x) for x in dst_ip.split('.'))
    udp_len = 8 + len(payload)
    ip_total = 20 + udp_len
    ip_hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, ip_total, random.randint(1,65535),
                        0x4000, 64, 17, 0, ip_src, ip_dst)
    udp_hdr = struct.pack('>HHHH', src_port, dst_port, udp_len, 0)
    return eth + ip_hdr + udp_hdr + payload

def _modbus_req(tid, uid, fc, data=b''):
    length = 2 + len(data)
    return struct.pack('>HHHBB', tid, 0, length, uid, fc) + data

def _write_pcap(filename, frames):
    with open(filename, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        ts = int(time.time()) - 3600
        for frame in frames:
            ts += random.uniform(0.001, 0.5)
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1000000)
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)

def generate():
    frames = []
    # ── Modbus traffic ──
    plc1 = "192.168.1.10"
    scada = "192.168.1.100"
    hmi = "192.168.1.50"
    attacker = "10.0.0.99"

    # Normal reads
    for i in range(20):
        frames.append(_eth_ip_tcp(scada, plc1, random.randint(40000,60000), 502,
                     _modbus_req(i+1, 1, 3, struct.pack('>HH', 0, 10))))
    # Write single coil (dangerous)
    for i in range(5):
        frames.append(_eth_ip_tcp(hmi, plc1, random.randint(40000,60000), 502,
                     _modbus_req(100+i, 1, 5, struct.pack('>HH', i, 0xFF00))))
    # Write multiple registers
    frames.append(_eth_ip_tcp(attacker, plc1, 45000, 502,
                 _modbus_req(200, 1, 16, struct.pack('>HHB', 100, 5, 10) + b'\x00'*10)))
    # Diagnostics — Force Listen Only (DoS)
    frames.append(_eth_ip_tcp(attacker, plc1, 45001, 502,
                 _modbus_req(300, 1, 8, struct.pack('>HH', 4, 0))))
    # Device ID read (reconnaissance)
    frames.append(_eth_ip_tcp(attacker, plc1, 45002, 502,
                 _modbus_req(400, 1, 43, b'\x0e\x01\x00')))
    # Exception responses
    for i in range(15):
        frames.append(_eth_ip_tcp(plc1, attacker, 502, 45003+i,
                     _modbus_req(500+i, 1, 0x83, b'\x02')))

    # ── S7comm traffic ──
    plc_s7 = "192.168.2.10"
    eng_ws = "192.168.2.50"
    # TPKT + COTP + S7 setup
    tpkt = b'\x03\x00\x00\x19'
    cotp_dt = b'\x02\xf0\x80'
    s7_job = b'\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x00\xf0'
    frames.append(_eth_ip_tcp(eng_ws, plc_s7, 50000, 102, tpkt + cotp_dt + s7_job))
    # CPU STOP
    cpu_stop_payload = tpkt + cotp_dt + b'\x32\x01\x00\x00\x00\x00\x00\x10\x00\x00' + \
                      b'\x29\x00\x00\x00\x00\x00\x09' + b'P_PROGRAM'
    frames.append(_eth_ip_tcp(attacker, plc_s7, 50001, 102, cpu_stop_payload))
    # S7 Write Variable
    s7_write = tpkt + cotp_dt + b'\x32\x01\x00\x00\x00\x00\x00\x0e\x00\x00\x05' + b'\x00'*10
    for i in range(8):
        frames.append(_eth_ip_tcp(eng_ws, plc_s7, 50010+i, 102, s7_write))

    # ── DNP3 traffic ──
    rtu = "192.168.3.10"
    master = "192.168.3.100"
    dnp3_hdr = b'\x05\x64\x05\xc0\x01\x00\x00\x00'
    # Cold restart
    frames.append(_eth_ip_tcp(attacker, rtu, 45000, 20000,
                 dnp3_hdr + b'\xc0\x0d' + b'\x00'*5))
    # Direct operate
    for i in range(5):
        frames.append(_eth_ip_tcp(master, rtu, 45100+i, 20000,
                     dnp3_hdr + b'\xc0\x05' + b'\x0c\x01'*3))
    # Normal reads
    for i in range(15):
        frames.append(_eth_ip_tcp(master, rtu, 45200+i, 20000,
                     dnp3_hdr + b'\xc0\x01' + b'\x00'*4))

    # ── BACnet/IP traffic ──
    bac_ctrl = "192.168.4.10"
    bms = "192.168.4.100"
    bvlc = b'\x81\x0a\x00\x11'
    npdu = b'\x01\x04'
    # Who-Is scanning (excessive)
    for i in range(25):
        apdu_whois = b'\x10\x08'
        frames.append(_eth_ip_udp(attacker, "192.168.4.255", 47808, 47808,
                     bvlc + npdu + apdu_whois))
    # WriteProperty
    apdu_write = b'\x00\x04\x01\x0f'
    frames.append(_eth_ip_udp(bms, bac_ctrl, 47808, 47808, bvlc + npdu + apdu_write + b'\x00'*10))
    # ReinitializeDevice
    apdu_reinit = b'\x00\x04\x01\x14'
    frames.append(_eth_ip_udp(attacker, bac_ctrl, 47808, 47808, bvlc + npdu + apdu_reinit))
    # DeviceCommunicationControl
    apdu_dcc = b'\x00\x04\x01\x11'
    frames.append(_eth_ip_udp(attacker, bac_ctrl, 47808, 47808, bvlc + npdu + apdu_dcc))

    # ── OPC UA traffic ──
    opcua_srv = "192.168.5.10"
    opcua_client = "192.168.5.50"
    for i in range(10):
        frames.append(_eth_ip_tcp(opcua_client, opcua_srv, 50000+i, 4840,
                     b'OPN\x00' + b'\x00\x00\x00\x01' * 10 + b'None' + b'SecurityMode'))
    frames.append(_eth_ip_tcp(opcua_client, opcua_srv, 50020, 4840,
                 b'\x01\x00\xd3\x01' + b'ActivateSession' + b'Anonymous' + b'\x00'*20))

    # ── EtherNet/IP traffic ──
    ab_plc = "192.168.6.10"
    frames.append(_eth_ip_tcp(eng_ws, ab_plc, 50000, 44818, b'\x00'*24 + b'\x4b' + b'\x00'*20))
    frames.append(_eth_ip_tcp(eng_ws, ab_plc, 50001, 44818, b'\x00'*24 + b'\x52' + b'\x00'*20))

    # ── IEC 104 traffic ──
    iec_rtu = "192.168.7.10"
    iec_master = "192.168.7.100"
    for i in range(10):
        frames.append(_eth_ip_tcp(iec_master, iec_rtu, 50000+i, 2404,
                     b'\x68\x0e\x00\x00\x00\x00\x2d\x01\x06\x00\x00\x00\x00\x00\x00\x00'))
    # General interrogation
    for i in range(8):
        frames.append(_eth_ip_tcp(iec_master, iec_rtu, 50100+i, 2404,
                     b'\x68\x0e\x00\x00\x00\x00\x64\x01\x06\x00\x01\x00\x00\x00\x14\x00'))

    # ── MQTT traffic ──
    mqtt_broker = "192.168.8.10"
    # Anonymous CONNECT
    mqtt_connect = b'\x10\x0e\x00\x04MQTT\x04\x00\x00\x3c\x00\x02go'
    frames.append(_eth_ip_tcp("192.168.8.50", mqtt_broker, 50000, 1883, mqtt_connect))
    # Wildcard subscribe
    mqtt_sub = b'\x82\x08\x00\x01\x00\x01#\x00'
    frames.append(_eth_ip_tcp("192.168.8.50", mqtt_broker, 50001, 1883, mqtt_sub))
    # Publish with OT topic
    mqtt_pub = b'\x30\x1a\x00\x10plc/control/setpointvalue=42'
    frames.append(_eth_ip_tcp("192.168.8.50", mqtt_broker, 50002, 1883, mqtt_pub))

    # ── IT protocols on OT network (insecure) ──
    frames.append(_eth_ip_tcp(attacker, plc1, 50000, 23, b'admin\r\n'))  # Telnet
    frames.append(_eth_ip_tcp(attacker, plc_s7, 50001, 80, b'GET / HTTP/1.1\r\n'))  # HTTP
    frames.append(_eth_ip_tcp(attacker, rtu, 50002, 21, b'USER anonymous\r\n'))  # FTP
    frames.append(_eth_ip_tcp("192.168.1.200", plc1, 50003, 3389, b'\x03\x00'))  # RDP

    # ── PROFINET ──
    frames.append(_eth_ip_udp("192.168.9.50", "192.168.9.10", 49000, 34964,
                 b'\xfe\xfe\x00\x00' + b'DCP' + b'NameOfStation' + b'\x00'*10))

    random.shuffle(frames)  # Mix protocols for realism
    return frames

if __name__ == "__main__":
    os.makedirs("sample_pcaps", exist_ok=True)
    frames = generate()
    _write_pcap("sample_pcaps/ot_network_capture.pcap", frames)
    print(f"Generated sample_pcaps/ot_network_capture.pcap with {len(frames)} frames")
