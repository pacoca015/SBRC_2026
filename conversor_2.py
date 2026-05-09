import csv
from collections import defaultdict, Counter, deque
from scapy.all import PcapReader, raw
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

input_pcap = r"C:/Users/gusta/PycharmProjects/transformador/capturaUDP_Novo_teste.pcap"
output_csv = r"C:/Users/gusta/PycharmProjects/Versao_Dataset_pcap/capturaUDP_Novo_.csv"

BATCH_SIZE = 10000
REPORT_EVERY = 100_000

# Rótulo: somente pacotes cuja ORIGEM está aqui são BENIGN (0)
# Rótulos
BENIGN_IPS = {"192.168.1.5","192.168.1.2","192.168.1.7","192.168.2.7","192.168.2.8","192.168.2.10" }              # label 0
ATTACK_IPS = {"192.168.1.11","192.168.1.3","192.168.1.4","192.168.1.6","192.168.1.8", "192.168.2.11","192.168.2.4","192.168.2.5","192.168.2.6","192.168.2.9", "192.168.3.2","192.168.3.11","192.168.3.3","192.168.3.5","192.168.3.8","192.168.3.10","192.168.4.6","192.168.4.8","192.168.5.4","192.168.5.5","192.168.5.7","192.168.5.8","192.168.1.9","192.168.5.9"} # label 1

# Se STRICT=True: se o src_ip não estiver em nenhuma lista,  IGNORA o pacote (não vai pro CSV)
# Se STRICT=False: aplica DEFAULT_LABEL para desconhecidos
STRICT_LABELING = False
DEFAULT_LABEL = 0  # 1 = ataque, 0 = benigno



def tcp_option_value(opts, key):
    for k, v in (opts or []):
        if k == key:
            if key == "Timestamp":
                try:
                    return int(v[0]), int(v[1])
                except Exception:
                    return 0, 0
            try:
                return int(v)
            except Exception:
                return 1
    return 0 if key != "Timestamp" else (0, 0)

def prune_deque(dq, now_ts, window=1.0):
    while dq and now_ts - dq[0][0] > window:
        dq.popleft()


header = [

    "ts","delta_time",
    "src_ip","dst_ip","ip_proto","ip_len","ip_ttl","ip_id",
    "ip_flags_df","ip_flags_mf","ip_frag_off",
    "src_port","dst_port",
    "tcp_seq","tcp_ack","tcp_flags",
    "tcp_syn","tcp_ack_flag","tcp_rst","tcp_fin","tcp_psh",
    "tcp_urg","tcp_ece","tcp_cwr",
    "tcp_window","tcp_dataofs","tcp_payload_len",
    "tcp_mss","tcp_wscale","tcp_sackok","tcp_tsval","tcp_tsecr",
    "udp_len","udp_checksum","udp_payload_len",
    "icmp_type","icmp_code","icmp_id","icmp_seq","icmp_payload_len",
    "iat_src","src_pkts_1s","src_bytes_1s",
    "label",
]

with open(output_csv, "w", newline="") as csvfile:
    w = csv.writer(csvfile); w.writerow(header)

    pkt_reader = PcapReader(input_pcap)


    total_pkts = 0
    ipv4_pkts = ipv6_pkts = arp_pkts = non_ip_pkts = 0
    ipv4_tcp = ipv4_udp = ipv4_icmp = 0


    csv_rows = 0
    benign_count = attack_count = 0

    tcp_src_counter = Counter()
    udp_src_counter = Counter()
    icmp_src_counter = Counter()
    last_ts_by_src = {}
    q_by_src = defaultdict(deque)
    prev_ts = None

    batch = []

    for pkt in pkt_reader:
        total_pkts += 1


        if ARP in pkt:
            arp_pkts += 1
        elif IPv6 in pkt:
            ipv6_pkts += 1
        elif IP in pkt:

            ip = pkt[IP]
            proto = int(getattr(ip, "proto", 0) or 0)
            is_tcp = (TCP in pkt and proto == 6)
            is_udp = (UDP in pkt and proto == 17)
            is_icmp = (ICMP in pkt and proto == 1)

            ipv4_pkts += 1
            if is_tcp:
                ipv4_tcp += 1
            elif is_udp:
                ipv4_udp += 1
            elif is_icmp:
                ipv4_icmp += 1

        elif is_icmp:
            ic = pkt[ICMP]
            try:
                icmp_type = int(getattr(ic, "type", 0) or 0)
                icmp_code = int(getattr(ic, "code", 0) or 0)
            except Exception:
                icmp_type = icmp_code = 0


            icmp_id = int(getattr(ic, "id", 0) or 0)
            icmp_seq = int(getattr(ic, "seq", 0) or 0)
            try:
                icmp_payload_len = len(raw(ic.payload)) if ic.payload else 0
            except Exception:
                icmp_payload_len = 0



            icmp_src_counter[src_ip] += 1

        else:
            non_ip_pkts += 1


        if not IP in pkt:
            if total_pkts % REPORT_EVERY == 0:
                print(f"[diag] lidos={total_pkts} | ipv4={ipv4_pkts} (tcp={ipv4_tcp}, udp={ipv4_udp}, icmp={ipv4_icmp}) "
                      f"| ipv6={ipv6_pkts} | arp={arp_pkts} | non_ip={non_ip_pkts} | CSV_rows={csv_rows} "
                      f"| benign={benign_count} | attack={attack_count}")
            continue

        ip = pkt[IP]
        is_tcp = TCP in pkt and int(getattr(ip, "proto", 0) or 0) == 6
        is_udp = UDP in pkt and int(getattr(ip, "proto", 0) or 0) == 17
        is_icmp = ICMP in pkt and int(getattr(ip, "proto", 0) or 0) == 1
        if not (is_tcp or is_udp  or is_icmp):
            if total_pkts % REPORT_EVERY == 0:
                print(f"[diag] lidos={total_pkts} | ipv4={ipv4_pkts} (tcp={ipv4_tcp}, udp={ipv4_udp}, icmp={ipv4_icmp}) "
                      f"| ipv6={ipv6_pkts} | arp={arp_pkts} | non_ip={non_ip_pkts} | CSV_rows={csv_rows} "
                      f"| benign={benign_count} | attack={attack_count}")
            continue

        ts = float(getattr(pkt, "time", 0.0) or 0.0)
        delta_time = 0.0 if prev_ts is None else (ts - prev_ts)
        prev_ts = ts

        src_ip = str(ip.src).strip()
        dst_ip = str(ip.dst).strip()
        ip_len = int(getattr(ip, "len", 0) or 0)
        ip_ttl = int(getattr(ip, "ttl", 0) or 0)
        ip_id  = int(getattr(ip, "id", 0) or 0)
        ip_proto = int(getattr(ip, "proto", 0) or 0)

        ip_flags = getattr(ip, "flags", 0)
        try:
            ip_flags_df = 1 if int(ip_flags) & 0x2 else 0
            ip_flags_mf = 1 if int(ip_flags) & 0x1 else 0
        except Exception:
            ip_flags_df = ip_flags_mf = 0
        ip_frag_off = int(getattr(ip, "frag", 0) or 0)

        src_port = dst_port = 0

        tcp_seq = tcp_ack = tcp_flags_val = 0
        tcp_syn = tcp_ack_flag = tcp_rst = tcp_fin = tcp_psh = 0
        tcp_urg = tcp_ece = tcp_cwr = 0
        tcp_window = tcp_dataofs = tcp_payload_len = 0
        tcp_mss = tcp_wscale = tcp_sackok = tcp_tsval = tcp_tsecr = 0

        udp_len = udp_checksum = udp_payload_len = 0

        icmp_type = icmp_code = icmp_id = icmp_seq = icmp_payload_len = 0

        if is_tcp:
            t = pkt[TCP]
            src_port = int(getattr(t, "sport", 0) or 0)
            dst_port = int(getattr(t, "dport", 0) or 0)

            tcp_seq = int(getattr(t, "seq", 0) or 0)
            tcp_ack = int(getattr(t, "ack", 0) or 0)
            try:
                tcp_flags_val = int(getattr(t, "flags", 0) or 0)
            except Exception:
                tcp_flags_val = 0

            try:
                f = int(t.flags)
                tcp_fin  = 1 if (f & 0x01) else 0
                tcp_syn  = 1 if (f & 0x02) else 0
                tcp_rst  = 1 if (f & 0x04) else 0
                tcp_psh  = 1 if (f & 0x08) else 0
                tcp_ack_flag = 1 if (f & 0x10) else 0
                tcp_urg  = 1 if (f & 0x20) else 0
                tcp_ece  = 1 if (f & 0x40) else 0
                tcp_cwr  = 1 if (f & 0x80) else 0
            except Exception:
                tcp_fin = tcp_syn = tcp_rst = tcp_psh = tcp_ack_flag = tcp_urg = tcp_ece = tcp_cwr = 0

            tcp_window  = int(getattr(t, "window", 0) or 0)
            tcp_dataofs = int(getattr(t, "dataofs", 0) or 0)
            try:
                tcp_payload_len = len(raw(t.payload)) if t.payload else 0
            except Exception:
                tcp_payload_len = 0

            opts = getattr(t, "options", []) or []
            tcp_mss    = tcp_option_value(opts, "MSS") or 0
            tcp_wscale = tcp_option_value(opts, "WScale") or 0
            tcp_sackok = 1 if tcp_option_value(opts, "SAckOK") else 0
            tcp_tsval, tcp_tsecr = tcp_option_value(opts, "Timestamp")

            tcp_src_counter[src_ip] += 1

        elif is_udp:
            u = pkt[UDP]
            src_port = int(getattr(u, "sport", 0) or 0)
            dst_port = int(getattr(u, "dport", 0) or 0)
            udp_len = int(getattr(u, "len", 0) or 0)
            chk = getattr(u, "chksum", 0)
            try:
                udp_checksum = int(chk)
            except Exception:
                udp_checksum = 0
            try:
                udp_payload_len = len(raw(u.payload)) if u.payload else 0
            except Exception:
                udp_payload_len = 0

            udp_src_counter[src_ip] += 1

        elif is_icmp:
            ic = pkt[ICMP]
            try:
                icmp_type = int(getattr(ic, "type", 0) or 0)
                icmp_code = int(getattr(ic, "code", 0) or 0)
            except Exception:
                icmp_type = icmp_code = 0


            icmp_id = int(getattr(ic, "id", 0) or 0)
            icmp_seq = int(getattr(ic, "seq", 0) or 0)
            try:
                icmp_payload_len = len(raw(ic.payload)) if ic.payload else 0
            except Exception:
                icmp_payload_len = 0


        last_src_ts = last_ts_by_src.get(src_ip)
        iat_src = 0.0 if last_src_ts is None else (ts - last_src_ts)
        last_ts_by_src[src_ip] = ts

        size_bytes = ip_len if ip_len > 0 else len(raw(pkt)) if pkt is not None else 0
        dq = q_by_src[src_ip]; dq.append((ts, size_bytes)); prune_deque(dq, ts, window=1.0)
        src_pkts_1s  = len(dq)
        src_bytes_1s = sum(sz for _, sz in dq)

        if src_ip in BENIGN_IPS:
            label = 0
            benign_count += 1
        elif src_ip in ATTACK_IPS:
            label = 1
            attack_count += 1
        else:
            if STRICT_LABELING:

                continue
            label = DEFAULT_LABEL
            if label == 0:
                benign_count += 1
            else:
                attack_count += 1

        batch.append([
            ts, delta_time,
            src_ip, dst_ip, ip_proto, ip_len, ip_ttl, ip_id,
            ip_flags_df, ip_flags_mf, ip_frag_off,
            src_port, dst_port,
            tcp_seq, tcp_ack, tcp_flags_val,
            tcp_syn, tcp_ack_flag, tcp_rst, tcp_fin, tcp_psh,
            tcp_urg, tcp_ece, tcp_cwr,
            tcp_window, tcp_dataofs, tcp_payload_len,
            tcp_mss, tcp_wscale, tcp_sackok, tcp_tsval, tcp_tsecr,
            udp_len, udp_checksum, udp_payload_len,
            icmp_type, icmp_code, icmp_id, icmp_seq, icmp_payload_len,
            iat_src, src_pkts_1s, src_bytes_1s,
            label,
        ])

        csv_rows += 1

        if csv_rows % BATCH_SIZE == 0:
            w.writerows(batch); batch.clear()

        if total_pkts % REPORT_EVERY == 0:
            print(f"[diag] lidos={total_pkts} | ipv4={ipv4_pkts} (tcp={ipv4_tcp}, udp={ipv4_udp}, icmp={ipv4_icmp}) "
                  f"| ipv6={ipv6_pkts} | arp={arp_pkts} | non_ip={non_ip_pkts} | CSV_rows={csv_rows} "
                  f"| benign={benign_count} | attack={attack_count}")
            print("       top TCP src:", tcp_src_counter.most_common(10))
            print("       top UDP src:", udp_src_counter.most_common(10))
            print("       top ICMP src:", icmp_src_counter.most_common(10))

    if batch:
        w.writerows(batch)

print("\n[FINAL]")
print(f"total lidos={total_pkts}")
print(f"ipv4={ipv4_pkts} (tcp={ipv4_tcp}, udp={ipv4_udp}, icmp={ipv4_icmp}) | ipv6={ipv6_pkts} | arp={arp_pkts} | non_ip={non_ip_pkts}")
print(f"CSV_rows={csv_rows} | benign={benign_count} | attack={attack_count}")
print("top 20 TCP src:", tcp_src_counter.most_common(20))
print("top 20 UDP src:", udp_src_counter.most_common(20))
print("top 20 ICMP src:", icmp_src_counter.most_common(20))

print(f"[+] CSV: {output_csv}")
