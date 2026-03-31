"""Generate a test PCAP file using only Python stdlib (struct module).
No external dependencies needed - writes raw PCAP binary format directly."""
import struct, os, time

def write_pcap_header(f):
    # Global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

def write_packet(f, data, ts):
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1e6)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
    f.write(data)

def ip_checksum(header):
    if len(header) % 2: header += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(header)//2), header))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def make_eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    eth = bytes.fromhex(dst_mac.replace(":","")) + bytes.fromhex(src_mac.replace(":","")) + b'\x08\x00'
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+20+len(payload), 0x1234, 0x4000, 64, 6, 0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")))
    csum = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", csum) + ip_hdr[12:]
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 1000, 1000, 0x50, 0x18, 65535, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload

def make_eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    eth = bytes.fromhex(dst_mac.replace(":","")) + bytes.fromhex(src_mac.replace(":","")) + b'\x08\x00'
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+8+len(payload), 0x1234, 0x4000, 64, 17, 0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")))
    csum = ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", csum) + ip_hdr[12:]
    udp_hdr = struct.pack("!HHHH", sport, dport, 8+len(payload), 0)
    return eth + ip_hdr + udp_hdr + payload

def modbus_req(tid, uid, fc, data=b""):
    pdu = bytes([fc]) + data
    return struct.pack(">HHH", tid, 0, len(pdu)+1) + bytes([uid]) + pdu

def modbus_resp(tid, uid, fc, data=b""):
    pdu = bytes([fc]) + data
    return struct.pack(">HHH", tid, 0, len(pdu)+1) + bytes([uid]) + pdu

def modbus_mei_resp(tid, uid):
    objs = [(0,b"Schneider Electric"),(1,b"Modicon M580"),(2,b"3.20"),(4,b"M580 ePAC Controller"),(5,b"BMEP585040")]
    od = b""
    for oid, val in objs:
        od += bytes([oid, len(val)]) + val
    mei = bytes([0x0E, 0x01, 0x01, 0x00, 0x00, len(objs)]) + od
    return modbus_resp(tid, uid, 0x2B, mei)

def s7_cotp_cr():
    params = bytes([0xC1,0x02,0x01,0x00, 0xC2,0x02,0x01,0x02, 0xC0,0x01,0x0A])
    cotp = bytes([len(params)+6, 0xE0, 0,0, 0,1, 0]) + params
    return struct.pack(">BBH", 3, 0, 4+len(cotp)) + cotp

def s7_cotp_cc():
    params = bytes([0xC1,0x02,0x01,0x00, 0xC2,0x02,0x01,0x02, 0xC0,0x01,0x0A])
    cotp = bytes([len(params)+6, 0xD0, 0,1, 0,1, 0]) + params
    return struct.pack(">BBH", 3, 0, 4+len(cotp)) + cotp

def s7_data():
    s7 = bytes([0x32,0x01,0,0,0,1,0,14,0,0, 0x04,0x01, 0x12,0x0A,0x10,0x02,0,100,0,1,0x84,0,0,0])
    cotp_dt = bytes([2, 0xF0, 0x80])
    p = cotp_dt + s7
    return struct.pack(">BBH", 3, 0, 4+len(p)) + p

def eip_list_identity():
    pname = b"1756-L71/B ControlLogix5571"
    ident = struct.pack("<H", 1)
    ident += struct.pack(">HH4s8s", 2, 44818, bytes([10,10,1,102]), b"\x00"*8)
    ident += struct.pack("<H", 1)       # vendor=Rockwell
    ident += struct.pack("<H", 0x10)    # device type=PLC
    ident += struct.pack("<H", 55)      # product code
    ident += bytes([30, 11])            # revision
    ident += struct.pack("<H", 0)       # status
    ident += struct.pack("<I", 0xDEADBEEF)
    ident += bytes([len(pname)]) + pname + bytes([3])
    item = struct.pack("<HH", 0x000C, len(ident)) + ident
    body = struct.pack("<H", 1) + item
    hdr = struct.pack("<HHII", 0x0063, len(body), 0, 0) + b"\x00"*8 + struct.pack("<I", 0)
    return hdr + body

def eip_register():
    body = struct.pack("<HH", 1, 0)
    return struct.pack("<HHII", 0x0065, len(body), 0, 0) + b"\x00"*8 + struct.pack("<I", 0) + body

def dnp3_frame(ctrl, dest, src, app_fc=None):
    app = b""
    if app_fc is not None:
        app = bytes([0xC0, 0xC0, app_fc])
    return bytes([0x05, 0x64, 5+len(app), ctrl]) + struct.pack("<HH", dest, src) + app

def iec104_startdt():
    return bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])

def iec104_interrog():
    asdu = bytes([100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14])
    return bytes([0x68, len(asdu)+4, 0,0,0,0]) + asdu

def opcua_hello():
    url = b"opc.tcp://10.10.2.60:4840/OPCUA/SimServer"
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<I", len(url)) + url
    return b"HELF" + struct.pack("<I", 8+len(body)) + body

def opcua_open_none():
    sp = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    body = struct.pack("<I", len(sp)) + sp + b"\x00"*20
    return b"OPNF" + struct.pack("<I", 8+len(body)) + body

def mqtt_connect(cid=b"ot_sensor_01"):
    vh = b"\x00\x04MQTT" + bytes([0x04, 0x02]) + struct.pack(">H", 60)
    pl = struct.pack(">H", len(cid)) + cid
    return bytes([0x10, len(vh)+len(pl)]) + vh + pl

def mqtt_publish(topic=b"ot/plc/data", msg=b'{"temp":85.2}'):
    vh = struct.pack(">H", len(topic)) + topic
    return bytes([0x30, len(vh)+len(msg)]) + vh + msg

def bacnet_whois():
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])
    apdu = bytes([0x10, 0x08])
    p = npdu + apdu
    return bytes([0x81, 0x0B]) + struct.pack(">H", 4+len(p)) + p

def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ot_test_traffic.pcap")
    ts = time.time()
    M = "00:1A:2B:00:01:10"; EW = "00:1A:2B:00:01:20"
    P1 = "00:80:F4:00:01:64"; P2 = "00:0E:8C:00:01:65"; P3 = "00:00:BC:00:01:66"
    DM = "00:1A:2B:00:02:0A"; DR = "00:1A:2B:00:02:32"; IR = "00:1A:2B:00:02:33"
    OU = "00:1A:2B:00:02:3C"; MQ = "00:1A:2B:00:03:0A"; BA = "00:1A:2B:00:03:14"

    with open(out, "wb") as f:
        write_pcap_header(f)
        # Modbus read requests + responses
        for i in range(5):
            write_packet(f, make_eth_ip_tcp(M,P1,"10.10.1.10","10.10.1.100",50000+i,502,
                modbus_req(i+1,1,0x03,struct.pack(">HH",0,10))), ts+i*0.1)
            write_packet(f, make_eth_ip_tcp(P1,M,"10.10.1.100","10.10.1.10",502,50000+i,
                modbus_resp(i+1,1,0x03,bytes([20])+b"\x00\x01"*10)), ts+i*0.1+0.05)
        # Modbus write coils
        for i in range(3):
            write_packet(f, make_eth_ip_tcp(M,P1,"10.10.1.10","10.10.1.100",51000+i,502,
                modbus_req(10+i,1,0x05,struct.pack(">HH",i,0xFF00))), ts+1+i*0.1)
        # Modbus MEI
        write_packet(f, make_eth_ip_tcp(P1,M,"10.10.1.100","10.10.1.10",502,50010,
            modbus_mei_resp(20,1)), ts+2)
        # S7comm CR/CC/Data
        write_packet(f, make_eth_ip_tcp(EW,P2,"10.10.1.20","10.10.1.101",52000,102,s7_cotp_cr()), ts+3)
        write_packet(f, make_eth_ip_tcp(P2,EW,"10.10.1.101","10.10.1.20",102,52000,s7_cotp_cc()), ts+3.1)
        for i in range(5):
            write_packet(f, make_eth_ip_tcp(EW,P2,"10.10.1.20","10.10.1.101",52000,102,s7_data()), ts+3.2+i*0.1)
        # EtherNet/IP
        write_packet(f, make_eth_ip_tcp(M,P3,"10.10.1.10","10.10.1.102",53000,44818,eip_register()), ts+5)
        for i in range(3):
            write_packet(f, make_eth_ip_tcp(P3,M,"10.10.1.102","10.10.1.10",44818,53000,eip_list_identity()), ts+5.1+i*0.2)
        # DNP3 reads
        for i in range(3):
            write_packet(f, make_eth_ip_tcp(DM,DR,"10.10.2.10","10.10.2.50",54000,20000,
                dnp3_frame(0xC4,10,1,0x01)), ts+7+i*0.2)
            write_packet(f, make_eth_ip_tcp(DR,DM,"10.10.2.50","10.10.2.10",20000,54000,
                dnp3_frame(0x44,1,10,0x81)), ts+7.1+i*0.2)
        # DNP3 Direct Operate (bypasses SBO)
        for i in range(2):
            write_packet(f, make_eth_ip_tcp(DM,DR,"10.10.2.10","10.10.2.50",54001,20000,
                dnp3_frame(0xC4,10,1,0x05)), ts+8+i*0.2)
        # DNP3 Cold Restart
        write_packet(f, make_eth_ip_tcp(DM,DR,"10.10.2.10","10.10.2.50",54002,20000,
            dnp3_frame(0xC4,10,1,0x0D)), ts+9)
        # DNP3 File Open
        write_packet(f, make_eth_ip_tcp(DM,DR,"10.10.2.10","10.10.2.50",54003,20000,
            dnp3_frame(0xC4,10,1,0x19)), ts+9.5)
        # DNP3 over UDP
        write_packet(f, make_eth_ip_udp(DM,DR,"10.10.2.10","10.10.2.50",54010,20000,
            dnp3_frame(0xC4,10,1,0x01)), ts+10)
        # IEC-104
        write_packet(f, make_eth_ip_tcp(M,IR,"10.10.1.10","10.10.2.51",55000,2404,iec104_startdt()), ts+11)
        for i in range(3):
            write_packet(f, make_eth_ip_tcp(M,IR,"10.10.1.10","10.10.2.51",55000,2404,iec104_interrog()), ts+11.1+i*0.1)
        # OPC-UA
        write_packet(f, make_eth_ip_tcp(EW,OU,"10.10.1.20","10.10.2.60",56000,4840,opcua_hello()), ts+13)
        for i in range(3):
            write_packet(f, make_eth_ip_tcp(EW,OU,"10.10.1.20","10.10.2.60",56000,4840,opcua_open_none()), ts+13.1+i*0.2)
        # MQTT (no TLS, no auth)
        write_packet(f, make_eth_ip_tcp(EW,MQ,"10.10.1.20","10.10.3.10",57000,1883,mqtt_connect()), ts+15)
        for i in range(5):
            write_packet(f, make_eth_ip_tcp(EW,MQ,"10.10.1.20","10.10.3.10",57000,1883,
                mqtt_publish(b"ot/plc/telemetry",f'{{"s":{i},"v":{65+i*2.5}}}'.encode())), ts+15.1+i*0.5)
        # BACnet/IP
        for i in range(3):
            write_packet(f, make_eth_ip_udp(M,BA,"10.10.1.10","10.10.3.20",47808,47808,bacnet_whois()), ts+17+i*0.3)
        # Cross-zone: HTTP from PLC to external
        write_packet(f, make_eth_ip_tcp(P1,"00:1A:2B:FF:FF:01","10.10.1.100","192.168.1.50",60000,80,
            b"GET /update HTTP/1.1\r\nHost: vendor.com\r\n\r\n"), ts+19)
        # Telnet to OT device
        write_packet(f, make_eth_ip_tcp(EW,P1,"10.10.1.20","10.10.1.100",60100,23,
            b"\xff\xfb\x01\xff\xfb\x03"), ts+19.5)
        # Extra Modbus from different master (EW -> PLC)
        for i in range(3):
            write_packet(f, make_eth_ip_tcp(EW,P1,"10.10.1.20","10.10.1.100",52100+i,502,
                modbus_req(30+i,1,0x03,struct.pack(">HH",100,10))), ts+20+i*0.1)

    print(f"Generated: {out}")
    print(f"Size: {os.path.getsize(out)} bytes")

if __name__ == "__main__":
    main()
