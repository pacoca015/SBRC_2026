import os
import re
import time
import torch
import joblib
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from torch import nn, optim
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from x_transformers import Encoder
import contextlib
import subprocess
import math
import shutil
from typing import List, Tuple, Dict, Any

# =========================
# Modo: "train" | "test" | "monitor"
# =========================
MODE = ("monitor")
CKPT_DIR = r"C:/Users/gusta/PycharmProjects/Versao_Dataset_pcap/ckpt_ddos_UDP"

# =========================
# Hiperparâmetros
# =========================
PCAP_IDLE_TIMEOUT = 10.0   # segundos sem crescer -> encerra
PCAP_GROWTH_POLL  = 10.0    # checa a cada x segundos

USE_TORCH_COMPILE = False
AMP_DTYPE   = torch.float16
EARLY_BREAK_ON_ATTACK = True
CHUNK_BATCH = 50
AMP_ENABLED = True

NUM_EPOCHS    = 5
BATCH_SIZE    = 50
LEARNING_RATE = 1e-5
SEQ_LEN       = 120
THRESHOLD_P   = 0.90
POLL_SECONDS   = 1.0
WAIT_FOREVER   = True
IDLE_MAX_POLLS = None

# ============== Estratégia de chunking/aggregação da janela =================
CHUNK_MODE       = "non_overlap"
CHUNK_STRIDE     = 10
AGGREGATE        = "max"
MIN_COVERED_FRAC = 1.0
VOTE_FRACTION    = 0.2
# ==================================================================================

# =========================
# Caminhos de dados
# =========================
TRAIN_CSV = r'C:\Users\gusta\PycharmProjects\Versao_Dataset_pcap\capturaUDP_Novo_.csv'
TEST_WINDOWS_CSV = None

# =========================
# Colunas
# =========================
FEATURES = ["ip_proto","ip_len","ip_ttl","ip_id","ip_flags_df","ip_flags_mf","ip_frag_off","src_port","dst_port","tcp_seq","tcp_ack","tcp_flags","tcp_syn","tcp_ack_flag","tcp_rst","tcp_fin","tcp_psh","tcp_urg","tcp_ece","tcp_cwr","tcp_window","tcp_dataofs","tcp_payload_len","tcp_mss","tcp_wscale","tcp_sackok","tcp_tsval","tcp_tsecr","udp_len","udp_checksum","udp_payload_len","iat_src","src_pkts_1s","src_bytes_1s","label"]
FEATURE_DIM = 34

# =========================
# Métricas
# =========================
class _Metrics:
    def __init__(self):
        self.y_true = []
        self.y_pred = []
        self.lat_ms = []
        self.rows = []
        self.win_idx = []

    def add(self, y_true, y_pred, lat_ms, rows, win_idx):
        self.y_true.append(int(y_true))
        self.y_pred.append(int(y_pred))
        self.lat_ms.append(float(lat_ms))
        self.rows.append(int(rows))
        self.win_idx.append(int(win_idx))

    def finalize_and_print(self, title="Avaliação Final por Arquivo (janela=5s)"):
        if not self.y_true:
            print("[MÉTRICAS] nada para consolidar.")
            return

        y_true = np.array(self.y_true, dtype=int)
        y_pred = np.array(self.y_pred, dtype=int)
        lat = np.array(self.lat_ms, dtype=float)

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=1)
        rec = recall_score(y_true, y_pred, zero_division=1)
        f1 = f1_score(y_true, y_pred, zero_division=1)
        cm = confusion_matrix(y_true, y_pred, labels=[0,1])

        print("\n===== " + title + " =====")
        print(f"Arquivos avaliados: {len(y_true)}")
        print(f"Acurácia:  {acc:.4f}")
        print(f"Precisão:  {prec:.4f}")
        print(f"Recall:    {rec:.4f}")
        print(f"F1-Score:  {f1:.4f}")
        print("Matriz de Confusão (labels=[0,1]):")
        print(cm)
        print(f"[LATÊNCIA] média={lat.mean():.1f} ms | min={lat.min():.1f} ms | max={lat.max():.1f} ms | arquivos={len(lat)}")

        try:
            plt.figure()
            plt.hist(lat, bins=min(30, max(5, len(lat)//2)))
            plt.xlabel("latência por janela (ms)")
            plt.ylabel("contagem de janelas")
            plt.title("Histograma de latência")
            plt.tight_layout()
            plt.savefig("latency_hist.png", dpi=120)
            plt.close()

            plt.figure()
            im = plt.imshow(cm, interpolation="nearest")
            plt.colorbar(im)
            plt.xticks([0,1], ["Pred 0","Pred 1"])
            plt.yticks([0,1], ["True 0","True 1"])
            for i in range(cm.shape[0]):
                for j in range(cm.shape[1]):
                    plt.text(j, i, str(cm[i, j]), ha="center", va="center")
            plt.title("Matriz de Confusão")
            plt.tight_layout()
            plt.savefig("confusion_matrix.png", dpi=120)
            plt.close()

            print("Arquivos gerados: latency_hist.png, confusion_matrix.png")
        except Exception as e:
            print(f"[MÉTRICAS] falha ao plotar: {e}")

# =========================
# Monitor (PCAP -> TShark -> Modelo)
# =========================

WINDOW_SECONDS = 5.0
TSHARK_BIN = r"C:\Program Files\Wireshark\tshark.exe"# <-------------altere o caminho para o tshark (windos, nao sei como funciona no linux)

PCAP_PATH = r"C:\Users\gusta\PycharmProjects\transformador\capturaUDP__teste_novo.pcap"# <-------------altere o caminho do pcap

if not os.path.isfile(TSHARK_BIN):
    raise RuntimeError(f"TShark não encontrado em: {TSHARK_BIN}")

BENIGN_IPS = {"192.168.1.2", "192.168.1.3",}# <-------------altere os endereços benigno
ATTACK_IPS = {"192.168.5.11", "192.168.4.8","192.168.5.2","192.168.2.8","192.168.5.10"} # <-------------altere os endereços de ataque

LABEL_POLICY = "lenient"

def build_labels_from_ips(src_ip_arr: np.ndarray,
                          benign_ips: set,
                          attack_ips: set,
                          policy: str) -> np.ndarray:
    src_ip_arr = np.asarray(src_ip_arr, dtype=object)

    is_attack = np.isin(src_ip_arr, np.array(list(attack_ips), dtype=object)) if attack_ips else np.zeros(src_ip_arr.shape, bool)
    is_benign = np.isin(src_ip_arr, np.array(list(benign_ips), dtype=object)) if benign_ips else np.zeros(src_ip_arr.shape, bool)

    if policy == "conservative":
        labels = np.where(is_attack, 1,
                  np.where(is_benign, 0, 1))
    else:
        labels = np.where(is_attack, 1,
                  np.where(is_benign, 0, 0))
    return labels.astype(np.int32)

TS_FIELDS = [
    "frame.time_epoch",
    "ip.proto",
    "ip.len",
    "ip.ttl",
    "ip.id",
    "ip.flags.df",
    "ip.flags.mf",
    "ip.frag_offset",
    "ip.src",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.hdr_len",
    "tcp.len",
    "tcp.options.mss_val",
    "tcp.options.wscale.shift",
    "tcp.options.sack_perm",
    "tcp.options.timestamp.tsval",
    "tcp.options.timestamp.tsecr",
    "udp.length",
    "udp.checksum",
    "frame.len",
]

def build_tshark_cmd_from_pcap(pcap_path: str) -> List[str]:
    return [
        TSHARK_BIN,
        "-n",
        "-r", pcap_path,
        "-Y", "ip && (tcp || udp)",
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-o", "tcp.desegment_tcp_streams:false",
        "-o", "http.desegment_body:false",
        "-o", "tls.desegment_ssl_records:false",
        "-o", "tcp.try_heuristic_first:false",
    ] + sum([["-e", f] for f in TS_FIELDS], [])

def _to_int(x: str) -> int:
    try:
        return int(x)
    except Exception:
        return 0

def _to_float(x: str) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0

def _bool01(x: str) -> int:
    x = (x or "").strip().lower()
    return 1 if x in ("1", "true", "t", "yes") else 0

def compute_derivatives_numpy(ts: np.ndarray,
                              src_ip_arr: np.ndarray,
                              size_bytes: np.ndarray
                              ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    n = ts.shape[0]
    if n == 0:
        return (np.zeros(0, dtype=np.float32),
                np.zeros(0, dtype=np.int32),
                np.zeros(0, dtype=np.int32))

    uniq_ips, src_ids = np.unique(src_ip_arr, return_inverse=True)

    order = np.lexsort((ts, src_ids))
    ts_sorted = ts[order]
    id_sorted = src_ids[order]
    size_sorted = size_bytes[order]

    iat_sorted = np.empty_like(ts_sorted, dtype=np.float32)
    iat_sorted[:] = 0.0
    group_change = np.empty_like(id_sorted, dtype=bool)
    group_change[0] = True
    group_change[1:] = (id_sorted[1:] != id_sorted[:-1])

    diffs = np.empty_like(ts_sorted, dtype=np.float64)
    diffs[0] = 0.0
    diffs[1:] = ts_sorted[1:] - ts_sorted[:-1]
    diffs[group_change] = 0.0
    iat_sorted = diffs.astype(np.float32)

    pkts_sorted = np.empty_like(id_sorted, dtype=np.int32)
    bytes_sorted = np.empty_like(id_sorted, dtype=np.int32)

    start = 0
    sum_bytes = 0
    for i in range(n):
        if i == 0 or id_sorted[i] != id_sorted[i-1]:
            start = i
            sum_bytes = 0
        sum_bytes += int(size_sorted[i])
        while start <= i and (id_sorted[start] != id_sorted[i] or (ts_sorted[i] - ts_sorted[start]) > 1.0):
            sum_bytes -= int(size_sorted[start])
            start += 1
        pkts_sorted[i] = i - start + 1
        bytes_sorted[i] = sum_bytes

    inv_order = np.empty_like(order)
    inv_order[order] = np.arange(n)

    iat = iat_sorted[inv_order]
    src_pkts_1s = pkts_sorted[inv_order]
    src_bytes_1s = bytes_sorted[inv_order]

    return iat.astype(np.float32), src_pkts_1s.astype(np.int32), src_bytes_1s.astype(np.int32)

def build_features_from_raw_compat(window_raw,
                                   benign_ips=None,
                                   attack_ips=None):
    if benign_ips is None: benign_ips = BENIGN_IPS
    if attack_ips is None: attack_ips = ATTACK_IPS

    try:
        return build_features_from_raw(window_raw, benign_ips, attack_ips)
    except TypeError:
        pass

    try:
        return build_features_from_raw(window_raw, benign_ips)
    except TypeError:
        pass

    return build_features_from_raw(window_raw)

def build_features_from_raw(window_raw: Dict[str, np.ndarray],
                            benign_ips: set) -> np.ndarray:
    ts = window_raw["ts"]
    src_ip = window_raw["src_ip"]
    size_bytes = window_raw["size_bytes"]

    iat_src, src_pkts_1s, src_bytes_1s = compute_derivatives_numpy(ts, src_ip, size_bytes)

    tcp_sport = window_raw["tcp_sport"]
    tcp_dport = window_raw["tcp_dport"]
    udp_sport = window_raw["udp_sport"]
    udp_dport = window_raw["udp_dport"]

    src_port = np.where(tcp_sport != 0, tcp_sport, udp_sport).astype(np.int32)
    dst_port = np.where(tcp_dport != 0, tcp_dport, udp_dport).astype(np.int32)

    f = window_raw["tcp_flags"].astype(np.int32)
    tcp_fin = ((f & 0x01) != 0).astype(np.int32)
    tcp_syn = ((f & 0x02) != 0).astype(np.int32)
    tcp_rst = ((f & 0x04) != 0).astype(np.int32)
    tcp_psh = ((f & 0x08) != 0).astype(np.int32)
    tcp_ack_flag = ((f & 0x10) != 0).astype(np.int32)
    tcp_urg = ((f & 0x20) != 0).astype(np.int32)
    tcp_ece = ((f & 0x40) != 0).astype(np.int32)
    tcp_cwr = ((f & 0x80) != 0).astype(np.int32)

    tcp_dataofs = (window_raw["tcp_hdr_len"] // 4).astype(np.int32)

    udp_len = window_raw["udp_length"].astype(np.int32)
    udp_payload_len = np.maximum(udp_len - 8, 0).astype(np.int32)

    label = build_labels_from_ips(
        window_raw["src_ip"],
        BENIGN_IPS,
        ATTACK_IPS,
        LABEL_POLICY,
    )

    cols = [
        window_raw["ip_proto"].astype(np.int32),
        window_raw["ip_len"].astype(np.int32),
        window_raw["ip_ttl"].astype(np.int32),
        window_raw["ip_id"].astype(np.int32),
        window_raw["ip_flags_df"].astype(np.int32),
        window_raw["ip_flags_mf"].astype(np.int32),
        window_raw["ip_frag_off"].astype(np.int32),

        src_port, dst_port,

        window_raw["tcp_seq"].astype(np.int64),
        window_raw["tcp_ack"].astype(np.int64),
        window_raw["tcp_flags"].astype(np.int32),

        tcp_syn, tcp_ack_flag, tcp_rst, tcp_fin, tcp_psh,
        tcp_urg, tcp_ece, tcp_cwr,

        window_raw["tcp_window"].astype(np.int32),
        tcp_dataofs.astype(np.int32),
        window_raw["tcp_payload_len"].astype(np.int32),

        window_raw["tcp_mss"].astype(np.int32),
        window_raw["tcp_wscale"].astype(np.int32),
        window_raw["tcp_sackok"].astype(np.int32),
        window_raw["tcp_tsval"].astype(np.int64),
        window_raw["tcp_tsecr"].astype(np.int64),

        udp_len.astype(np.int32),
        window_raw["udp_checksum"].astype(np.int32),
        udp_payload_len.astype(np.int32),

        iat_src.astype(np.float32),
        src_pkts_1s.astype(np.int32),
        src_bytes_1s.astype(np.int32),

        label.astype(np.int32),
    ]
    X = np.column_stack(cols).astype(np.float32, copy=False)
   # print("debug 1",X)
    return X




def stream_pcap_offline_and_yield_windows(pcap_path: str, window_seconds: float = WINDOW_SECONDS):
    cmd_base = build_tshark_cmd_from_pcap(pcap_path)

    env = os.environ.copy()

    env["PATH"] = env.get("PATH", "") + r";C:\Program Files\Wireshark"
    print("printando cmd", env)
    buf = {
        "ts": [],
        "ip_proto": [], "ip_len": [], "ip_ttl": [], "ip_id": [],
        "ip_flags_df": [], "ip_flags_mf": [], "ip_frag_off": [],
        "src_ip": [],
        "tcp_sport": [], "tcp_dport": [], "udp_sport": [], "udp_dport": [],
        "tcp_seq": [], "tcp_ack": [], "tcp_flags": [],
        "tcp_window": [], "tcp_hdr_len": [], "tcp_payload_len": [],
        "tcp_mss": [], "tcp_wscale": [], "tcp_sackok": [], "tcp_tsval": [], "tcp_tsecr": [],
        "udp_length": [], "udp_checksum": [],
        "size_bytes": [],
    }

    base_ts = None
    processed_lines = 0

    last_size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    last_growth_time = time.monotonic()

    while True:

        proc = subprocess.Popen(
            cmd_base,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env
        )
        if proc.stdout is None:
            raise RuntimeError("Falha ao abrir stdout do TShark")

        line_idx = 0
        got_new = False

        for line in proc.stdout:
            #print("[TSHARK RAW]", line.rstrip("\r\n"))
            if processed_lines < 5:
                print("RAW:", repr(line))
                print("SPLIT:", line.rstrip("\r\n").split("\t"))

            line_idx += 1
            if line_idx <= processed_lines:
                continue

            processed_lines += 1
            got_new = True

            parts = line.rstrip("\r\n").split("\t")
            if len(parts) != len(TS_FIELDS):
                parts = line.rstrip("\r\n").split("\t")
                if len(parts) < len(TS_FIELDS):
                    parts += [""] * (len(TS_FIELDS) - len(parts))
                elif len(parts) > len(TS_FIELDS):
                    parts = parts[:len(TS_FIELDS)]
            ts = _to_float(parts[0])
            if math.isnan(ts) or ts <= 0:
                continue

            if base_ts is None:
                base_ts = ts

            if ts - base_ts >= window_seconds and len(buf["ts"]) > 0:
                yield _finalize_window(buf)
                for k in buf.keys():
                    buf[k].clear()
                base_ts = ts

            ip_proto    = _to_int(parts[1])
            ip_len      = _to_int(parts[2])
            ip_ttl      = _to_int(parts[3])
            ip_id       = _to_int(parts[4])
            ip_flags_df = _bool01(parts[5])
            ip_flags_mf = _bool01(parts[6])
            ip_frag     = _to_int(parts[7])
            src_ip      = parts[8]

            tcp_sport   = _to_int(parts[9]);  tcp_dport = _to_int(parts[10])
            udp_sport   = _to_int(parts[11]); udp_dport = _to_int(parts[12])

            tcp_seq     = _to_int(parts[13])
            tcp_ack     = _to_int(parts[14])
            tcp_flags   = _to_int(parts[15])
            tcp_window  = _to_int(parts[16])
            tcp_hdrlen  = _to_int(parts[17])
            tcp_pllen   = _to_int(parts[18])
            tcp_mss     = _to_int(parts[19])
            tcp_wscale  = _to_int(parts[20])
            tcp_sackok  = _bool01(parts[21])
            tcp_tsval   = _to_int(parts[22])
            tcp_tsecr   = _to_int(parts[23])

            udp_length  = _to_int(parts[24])
            udp_chk     = _to_int(parts[25])
            frame_len   = _to_int(parts[26])

            buf["ts"].append(ts)
            buf["ip_proto"].append(ip_proto)
            buf["ip_len"].append(ip_len)
            buf["ip_ttl"].append(ip_ttl)
            buf["ip_id"].append(ip_id)
            buf["ip_flags_df"].append(ip_flags_df)
            buf["ip_flags_mf"].append(ip_flags_mf)
            buf["ip_frag_off"].append(ip_frag)
            buf["src_ip"].append(src_ip)
            buf["tcp_sport"].append(tcp_sport)
            buf["tcp_dport"].append(tcp_dport)
            buf["udp_sport"].append(udp_sport)
            buf["udp_dport"].append(udp_dport)
            buf["tcp_seq"].append(tcp_seq)
            buf["tcp_ack"].append(tcp_ack)
            buf["tcp_flags"].append(tcp_flags)
            buf["tcp_window"].append(tcp_window)
            buf["tcp_hdr_len"].append(tcp_hdrlen)
            buf["tcp_payload_len"].append(tcp_pllen)
            buf["tcp_mss"].append(tcp_mss)
            buf["tcp_wscale"].append(tcp_wscale)
            buf["tcp_sackok"].append(tcp_sackok)
            buf["tcp_tsval"].append(tcp_tsval)
            buf["tcp_tsecr"].append(tcp_tsecr)
            buf["udp_length"].append(udp_length)
            buf["udp_checksum"].append(udp_chk)
            buf["size_bytes"].append(frame_len)

       
        try:
            proc.stdout.close()
        except:
            pass
        try:
            proc.wait(timeout=5)
        except:
            proc.kill()


        if len(buf["ts"]) > 0:
            yield _finalize_window(buf)
            for k in buf.keys():
                buf[k].clear()


        cur_size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
        if cur_size > last_size:
            last_size = cur_size
            last_growth_time = time.monotonic()
        else:
            idle = time.monotonic() - last_growth_time
            if idle >= PCAP_IDLE_TIMEOUT:
                print(f"[STREAM] PCAP sem crescimento por {PCAP_IDLE_TIMEOUT:.0f}s. Encerrando.")
                break


        if not got_new:
            time.sleep(PCAP_GROWTH_POLL)


def _finalize_window(buf_lists: Dict[str, Any]) -> Dict[str, np.ndarray]:
    out = {}
    for k, lst in buf_lists.items():
        if k in ("src_ip",):
            out[k] = np.array(lst, dtype=object)
        elif k in ("ts",):
            out[k] = np.array(lst, dtype=np.float64)
        else:
            out[k] = np.array(lst, dtype=np.int64)
    return out

def run_stream_offline_fast(model, scaler, train_medians, device, pcap_path: str):
    print(f"[STREAM_OFFLINE_FAST] tshark lendo: {pcap_path}")
    MET = _Metrics()
    total_rows = 0

    for win_idx, window_raw in enumerate(stream_pcap_offline_and_yield_windows(pcap_path, window_seconds=WINDOW_SECONDS)):
        t0 = time.perf_counter()

        atk_any = np.isin(window_raw["src_ip"], np.array(list(ATTACK_IPS), dtype=object)).any()
        y_true = 1 if atk_any else 0

        Xw = build_features_from_raw_compat(window_raw, BENIGN_IPS, ATTACK_IPS)
        n_rows = int(Xw.shape[0])
        total_rows += n_rows
        if n_rows == 0:
            continue
        #print(f"debug1 edefe")

        X_only = Xw[:, :-1].astype(np.float32, copy=False)
        print("Printando valores do x_only",X_only)
        print("[ANTES DO SCALER] X_only.shape =", X_only.shape)
        t_scale0 = time.perf_counter()
        X_scaled = scaler.transform(X_only)
        t_scale_ms = (time.perf_counter() - t_scale0) * 1000.0
        #print(f"debug2 ")
        p, det = predict_window_prob(
            model, device, X_scaled, SEQ_LEN, THRESHOLD_P,
            chunk_mode=CHUNK_MODE,
            chunk_stride=CHUNK_STRIDE,
            aggregate=AGGREGATE,
            min_covered_frac=MIN_COVERED_FRAC,
            vote_fraction=VOTE_FRACTION
        )
        #print(f"debug3 ")
        if AGGREGATE == "vote":
            y_pred = int(p >= 1.0)
            p_show = float(np.mean(np.array(det["chunk_probs"]) >= THRESHOLD_P)) if det["chunk_probs"] else 0.0
        else:
            y_pred = int(p >= THRESHOLD_P)
            p_show = p

        lat_total_ms = (time.perf_counter() - t0) * 1000.0
        MET.add(y_true=y_true, y_pred=y_pred,
                lat_ms=lat_total_ms, rows=n_rows, win_idx=win_idx)
        #print(f"debug4 ")
        early_tag = ""
        if det and det.get("early_break"):
            early_tag = f" | early=1 ({det.get('early_reason')}, chunk#{det.get('early_chunk_index')}, row~{det.get('early_at_row')})"

        print(
            f"[WIN {win_idx:06d}] rows={n_rows:5d} | chunks={det['n_chunks'] if det else 0:2d} | "
            f"cov={det['covered_frac'] if det else 0.0:.2f} | p_attack={p_show:.4f} | "
            f"y_true={y_true} | pred={y_pred} | "
            f"lat_total={lat_total_ms:.1f} ms (scale={t_scale_ms:.1f} ms, model={det['t_model_ms'] if det else 0.0:.1f} ms)"
            f"{early_tag}"
        )
        #print(f"debug6 ")
    print(f"[STREAM_OFFLINE_FAST] Total de linhas lidas: {total_rows}")
    MET.finalize_and_print(title="Avaliação Final por Arquivo (janela=5s)")
    print(f"[STREAM_OFFLINE_FAST] Total de linhas lidas: {total_rows}")

def make_autocast(device, dtype, enabled=True):
    if not enabled:
        return contextlib.nullcontext()
    if device.type != 'cuda':
        return contextlib.nullcontext()

    if hasattr(torch, "amp") and hasattr(torch.amp, "autocast"):
        return torch.amp.autocast("cuda", dtype=dtype)
    else:
        return torch.cuda.amp.autocast(dtype=dtype)

    # =========================
    # Dataset
    # =========================
class DDosDataset(Dataset):
    def __init__(self, data, seq_length):
        self.data = data
        self.seq_length = seq_length
    def __len__(self):
        return max(0, len(self.data) - self.seq_length)
    def __getitem__(self, idx):
        seq = self.data[idx:idx + self.seq_length]
        label = self.data[idx:idx+self.seq_length, -1].max()
        return torch.FloatTensor(seq[:, :-1]), torch.FloatTensor([label])

# =========================
# Modelo
# =========================
class DDoSDetector(nn.Module):
    def __init__(self, feature_dim=FEATURE_DIM, proj_dim=64, depth=2, heads=4, layer_dropout=0.1, use_scalenorm=True, pre_norm=False):
        super().__init__()
        self.projector = nn.Linear(feature_dim, proj_dim)
        self.encoder = Encoder(
            dim=proj_dim,
            depth=depth,
            heads=heads,
            layer_dropout=layer_dropout,
            use_scalenorm=use_scalenorm,
            pre_norm=pre_norm
        )
        self.classifier = nn.Linear(proj_dim, 1)

    def forward(self, x):
        x = self.projector(x)
        z = self.encoder(x)
        pooled = z.mean(dim=1)
        logits = self.classifier(pooled)
        return logits

# =========================
# Utils de pré-processamento
# =========================
def preprocess_dataframe(df: pd.DataFrame):
    X = df.drop(columns=["label"]).copy()
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    medianas = X.median(numeric_only=True)
    X = X.fillna(medianas).fillna(0.0)
    for c in X.columns:
        col = X[c].to_numpy()
        finite_mask = np.isfinite(col)
        if not finite_mask.any():
            X[c] = 0.0
            continue
        finite_min = col[finite_mask].min()
        finite_max = col[finite_mask].max()
        pos_inf_mask = np.isposinf(col)
        if pos_inf_mask.any(): col[pos_inf_mask] = finite_max
        neg_inf_mask = np.isneginf(col)
        if neg_inf_mask.any(): col[neg_inf_mask] = finite_min
        X[c] = col
    y = df["label"].values.reshape(-1, 1)
    return X, y, medianas

def transform_with_train_stats(X_df: pd.DataFrame, train_medians: pd.Series, scaler: MinMaxScaler):
    X_df = X_df.apply(pd.to_numeric, errors="coerce")
    X_df = X_df.replace([np.inf, -np.inf], np.nan)
    X_df = X_df.fillna(train_medians).fillna(0.0)
    return scaler.transform(X_df.values)

def pad_tail(chunk: np.ndarray, target_len: int) -> np.ndarray:
    L, D = chunk.shape
    if L >= target_len:
        return chunk[:target_len]
    out = np.zeros((target_len, D), dtype=chunk.dtype)
    if L > 0:
        out[:L] = chunk
        out[L:] = chunk[-1]
    return out

def chunk_window(Xw_scaled: np.ndarray, seq_len: int, mode: str, stride: int | None) -> list[tuple[np.ndarray, int, int]]:
    L = Xw_scaled.shape[0]
    chunks = []
    if L == 0:
        return chunks

    if mode == "overlap":
        s = stride if stride and stride > 0 else max(1, seq_len // 2)
        start = 0
        while start < L:
            end = min(start + seq_len, L)
            chunks.append((Xw_scaled[start:end], start, end))
            if end == L:
                break
            start += s
    else:
        start = 0
        while start < L:
            end = min(start + seq_len, L)
            chunks.append((Xw_scaled[start:end], start, end))
            start = end
    return chunks

def predict_window_prob(
    model: nn.Module,
    device: torch.device,
    Xw_scaled: np.ndarray,
    seq_len: int,
    threshold_p: float,
    chunk_mode: str = CHUNK_MODE,
    chunk_stride: int | None = CHUNK_STRIDE,
    aggregate: str = AGGREGATE,
    min_covered_frac: float = MIN_COVERED_FRAC,
    vote_fraction: float = VOTE_FRACTION
):
    L = Xw_scaled.shape[0]
    if L == 0:
        return 0.0, {
            "n_chunks": 0, "covered_frac": 0.0, "chunk_probs": [],
            "L_rows": 0, "t_total_ms": 0.0, "t_model_ms": 0.0,
            "chunk_times_ms": [], "early_break": False, "early_reason": None,
            "early_at_row": None, "early_chunk_index": None,
            "votes_seen": 0, "chunks_seen": 0
        }

    t_total0 = time.perf_counter()
    chunks = chunk_window(Xw_scaled, seq_len, chunk_mode, chunk_stride)

    p_list: list[float] = []
    covered = 0
    t_model = 0.0
    chunk_times = []

    votes = 0
    n_seen = 0

    early_break = False
    early_reason = None
    early_at_row = None
    early_chunk_index = None

    amp_enabled = (device.type == 'cuda') and AMP_ENABLED
    amp_dtype = AMP_DTYPE

    with torch.no_grad():
        k = 0
        while k < len(chunks):
            batch_items = []
            batch_meta = []
            for _ in range(CHUNK_BATCH):
                if k >= len(chunks):
                    break
                arr, start, end = chunks[k]
                batch_items.append(pad_tail(arr, seq_len))
                batch_meta.append((start, end))
                k += 1
            if not batch_items:
                break

            batch_np = np.stack(batch_items, axis=0)
            inp_t = torch.from_numpy(batch_np).float().to(device, non_blocking=True)

            t0 = time.perf_counter()
            with make_autocast(device, amp_dtype, enabled=amp_enabled):
                logits = model(inp_t)
                probs  = torch.sigmoid(logits)
            t1 = time.perf_counter()

            dt_ms = (t1 - t0) * 1000.0
            t_model += (t1 - t0)

            probs_np = probs.squeeze(1).detach().cpu().numpy().tolist()

            for j, p in enumerate(probs_np):
                start, end = batch_meta[j]
                p_list.append(p)
                covered = max(covered, end)

                n_seen += 1
                if p >= threshold_p:
                    votes += 1

                if EARLY_BREAK_ON_ATTACK:
                    if aggregate == "max" and p >= threshold_p:
                        early_break = True
                        early_reason = "p>=threshold (max)"
                        early_at_row = end
                        early_chunk_index = len(p_list) - 1
                        break
                    elif aggregate == "vote":
                        frac = votes / n_seen
                        if frac >= vote_fraction:
                            early_break = True
                            early_reason = f"vote frac {frac:.3f}>={vote_fraction:.3f}"
                            early_at_row = end
                            early_chunk_index = len(p_list) - 1
                            break

                if covered / float(L) >= min_covered_frac:
                    break

            per_chunk = dt_ms / max(1, len(probs_np))
            for _ in probs_np:
                if len(chunk_times) < 10:
                    chunk_times.append(per_chunk)

            if early_break or covered / float(L) >= min_covered_frac:
                break

    if not p_list:
        p_final = 0.0
    else:
        if aggregate == "max":
            p_final = float(np.max(p_list))
        elif aggregate == "vote":
            frac = votes / max(1, n_seen)
            p_final = 1.0 if frac >= vote_fraction else 0.0
        else:
            p_final = float(np.mean(p_list))

    t_total_ms = (time.perf_counter() - t_total0) * 1000.0
    details = {
        "n_chunks": len(p_list),
        "covered_frac": covered / float(L),
        "chunk_probs": p_list[:10],
        "L_rows": L,
        "t_total_ms": t_total_ms,
        "t_model_ms": t_model * 1000.0,
        "chunk_times_ms": chunk_times[:10],
        "early_break": early_break,
        "early_reason": early_reason,
        "early_at_row": early_at_row,
        "early_chunk_index": early_chunk_index,
        "votes_seen": votes,
        "chunks_seen": n_seen
    }
    return p_final, details

# ==================================================================================
# Save / Load artefatos
# ==================================================================================
def save_artifacts(model, scaler, train_medians, feature_names, seq_len, model_cfg, epoch=None):
    os.makedirs(CKPT_DIR, exist_ok=True)
    ckpt = {
        "model_state_dict": model.state_dict(),
        "model_cfg": model_cfg,
        "feature_names": feature_names,
        "seq_len": seq_len,
        "epoch": epoch,
    }
    torch.save(ckpt, os.path.join(CKPT_DIR, "model.pt"))
    torch.save(model.state_dict(), os.path.join(CKPT_DIR, "model_state_dict.pt"))
    torch.save(model, os.path.join(CKPT_DIR, "model_full.pt"))
    try:
        model_cpu = model.to("cpu").eval()
        dummy = torch.zeros(1, seq_len, len(feature_names), dtype=torch.float32)
        traced = torch.jit.trace(model_cpu, dummy)
        traced.save(os.path.join(CKPT_DIR, "model_scripted.ts"))
    except Exception as e:
        print(f"[AVISO] Não foi possível salvar TorchScript: {e}")
    joblib.dump(scaler,        os.path.join(CKPT_DIR, "scaler.joblib"))
    joblib.dump(train_medians, os.path.join(CKPT_DIR, "train_medians.joblib"))
    print("[OK] Artefatos salvos em", CKPT_DIR)

def load_artifacts():
    ckpt_path = os.path.join(CKPT_DIR, "model.pt")
    scaler_path = os.path.join(CKPT_DIR, "scaler.joblib")
    medians_path = os.path.join(CKPT_DIR, "train_medians.joblib")

    if os.path.isfile(scaler_path) and os.path.isfile(medians_path):
        scaler = joblib.load(scaler_path)
        train_medians = joblib.load(medians_path)
    else:
        ref_csv = TRAIN_CSV
        if not os.path.isfile(ref_csv):
            raise FileNotFoundError(
                "scaler.joblib/train_medians.joblib ausentes e TRAIN_CSV não encontrado para gerar fallback."
            )
        df_ref = pd.read_csv(ref_csv, usecols=FEATURES, low_memory=False)
        X_ref = df_ref.drop(columns=["label"]).apply(pd.to_numeric, errors="coerce")
        X_ref = X_ref.replace([np.inf, -np.inf], np.nan)
        train_medians = X_ref.median(numeric_only=True)
        X_ref = X_ref.fillna(train_medians).fillna(0.0)
        scaler = MinMaxScaler().fit(X_ref.values)
        os.makedirs(CKPT_DIR, exist_ok=True)
        joblib.dump(scaler, scaler_path)
        joblib.dump(train_medians, medians_path)
        print("[INFO] Fallback: scaler/medianas gerados a partir de", ref_csv)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True
    model = None
    seq_len = None
    feature_names = None
    if os.path.isfile(ckpt_path):
        obj = torch.load(ckpt_path, map_location="cpu")
        if isinstance(obj, dict) and "model_state_dict" in obj:
            cfg = obj.get("model_cfg", {})
            model = DDoSDetector(
                feature_dim=cfg.get("feature_dim", FEATURE_DIM),
                proj_dim=cfg.get("proj_dim", 64),
                depth=cfg.get("depth", 2),
                heads=cfg.get("heads", 4),
                layer_dropout=cfg.get("layer_dropout", 0.1),
                use_scalenorm=cfg.get("use_scalenorm", True),
                pre_norm=cfg.get("pre_norm", False),
            )
            model.load_state_dict(obj["model_state_dict"])
            model = model.to(device).eval()
            if USE_TORCH_COMPILE and device.type == 'cuda':
                try:
                    model = torch.compile(model)
                except Exception as e:
                    print(f"[AVISO] torch.compile indisponível/fracassou: {e}")

            seq_len = obj.get("seq_len", SEQ_LEN)
            feature_names = obj.get("feature_names", FEATURES[:-1])
        else:
            print("[AVISO] model.pt não está no formato esperado; tentando alternativas...")

    if model is None:
        sd_path = os.path.join(CKPT_DIR, "model_state_dict.pt")
        if os.path.isfile(sd_path):
            model = DDoSDetector()
            state = torch.load(sd_path, map_location="cpu")
            model.load_state_dict(state, strict=False)
            model.eval()
            seq_len = SEQ_LEN
            feature_names = FEATURES[:-1]
        else:
            full_path = os.path.join(CKPT_DIR, "model_full.pt")
            if os.path.isfile(full_path):
                model = torch.load(full_path, map_location="cpu")
                try: model.eval()
                except: pass
                seq_len = SEQ_LEN
                feature_names = FEATURES[:-1]
            else:
                raise FileNotFoundError("Nenhum checkpoint reconhecido em CKPT_DIR.")

    return model, scaler, train_medians, seq_len, feature_names

# =========================
# Validação extra por janelas de 5s
# =========================
def evaluate_on_5s_windows(csv_path: str, scaler: MinMaxScaler, train_medians: pd.Series, model: nn.Module, device: torch.device, window_seconds: float = 5.0):
    if not csv_path or not os.path.exists(csv_path):
        print(f"[AVISO] TEST_WINDOWS_CSV inválido ou não encontrado: {csv_path}")
        return
    df = _safe_read_table(csv_path, columns=None)
    req_cols = set(FEATURES + ["timestamp"])
    if not req_cols.issubset(set(df.columns)):
        print(f"[ERRO] CSV precisa ter colunas: {sorted(list(req_cols))}")
        return
    df = df.sort_values("timestamp").reset_index(drop=True)
    t0 = float(df["timestamp"].iloc[0])
    win_idx = np.floor((df["timestamp"].values - t0) / window_seconds).astype(int)
    df["win_idx"] = win_idx
    grp = df.groupby("win_idx", as_index=False).agg(
        win_label_bin=("label", "max"),
        n_rows=("label", "size")
    ).sort_values("win_idx")

    print(f"[INFO] Janelas totais: {len(grp)} | benignas: {int((grp['win_label_bin']==0).sum())} | ataque: {int((grp['win_label_bin']==1).sum())}")

    model.eval()
    probs = []
    details_all = []

    with torch.no_grad():
        for w in grp["win_idx"].tolist():
            dw = df[df["win_idx"] == w]
            Xw = dw[FEATURES[:-1]].copy()
            Xw = Xw.apply(pd.to_numeric, errors="coerce")
            Xw = Xw.replace([np.inf, -np.inf], np.nan)
            Xw = Xw.fillna(train_medians).fillna(0.0)
            Xw_scaled = scaler.transform(Xw.values)

            p, det = predict_window_prob(
                model, device, Xw_scaled, SEQ_LEN, THRESHOLD_P,
                chunk_mode=CHUNK_MODE,
                chunk_stride=CHUNK_STRIDE,
                aggregate=AGGREGATE,
                min_covered_frac=MIN_COVERED_FRAC,
                vote_fraction=VOTE_FRACTION
            )
            probs.append(p)
            details_all.append(det)

    probs = np.array(probs, dtype=float)
    y_true = grp["win_label_bin"].to_numpy().astype(int)
    if AGGREGATE == "vote":
        y_pred = (probs >= 1.0).astype(int)
    else:
        y_pred = (probs >= THRESHOLD_P).astype(int)

    print("\n[Val. 5s - BINÁRIO (qualquer ataque na janela = 1)]")
    print(f"Acurácia:  {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precisão:  {precision_score(y_true, y_pred, zero_division=1):.4f}")
    print(f"Recall:    {recall_score(y_true, y_pred, zero_division=1):.4f}")
    print(f"F1-Score:  {f1_score(y_true, y_pred, zero_division=1):.4f}")
    print("Matriz de Confusão (labels=[0,1]):")
    print(confusion_matrix(y_true, y_pred, labels=[0,1]))

    head_n = min(10, len(grp))
    print(f"\n[Amostra de {head_n} janelas]")
    sample = pd.DataFrame({
        "win_idx": grp["win_idx"].values[:head_n],
        "n_rows": grp["n_rows"].values[:head_n],
        "y_true": y_true[:head_n],
        "p_attack": probs[:head_n],
        "y_pred": y_pred[:head_n],
        "chunks": [d["n_chunks"] for d in details_all[:head_n]],
        "cov_frac": [round(d["covered_frac"],3) for d in details_all[:head_n]],
    })
    pd.set_option("display.float_format", lambda x: f"{x:.4f}")
    print(sample.to_string(index=False))

def read_window_once(path: str, columns=None):
    if path.endswith(".parquet"):
        return pd.read_parquet(path, columns=columns, engine="pyarrow")
    if columns is None:
        return pd.read_csv(path, low_memory=False)
    return pd.read_csv(path, usecols=columns, low_memory=False)

def _safe_read_table(path: str, columns=None, retries: int = 5, delay: float = 0.2):
    for _ in range(retries):
        try:
            return read_window_once(path, columns=columns)
        except Exception:
            time.sleep(delay)
    return read_window_once(path, columns=columns)

# =========================
# Treino + avaliação + monitor
# =========================
def main():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print("Debug")
    if device.type == 'cuda':
        print('Usando gpu')
        try:
            torch.set_float32_matmul_precision('high')
        except Exception:
            pass

    if device.type == 'cuda':
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.allow_tf32 = True

        print('Usando gpu')
    if MODE == "train":
        df = pd.read_csv(TRAIN_CSV, usecols=FEATURES, low_memory=False)
        print("[INFO] Amostra treino:", df.head(3))
        X, y, train_medians = preprocess_dataframe(df)
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X.values)
        data = np.hstack((X_scaled, y))
        train_data, test_data = train_test_split(data, test_size=0.2, shuffle=True)
        train_dataset = DDosDataset(train_data, SEQ_LEN)
        test_dataset  = DDosDataset(test_data,  SEQ_LEN)
        train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=False, num_workers=0)
        test_loader  = DataLoader(test_dataset,  batch_size=BATCH_SIZE, shuffle=False, num_workers=0)
        model = DDoSDetector().to(device)
        optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
        criterion = nn.BCEWithLogitsLoss()

        for epoch in range(NUM_EPOCHS):
            model.train()
            total_loss = 0.0
            for inputs, labels in tqdm(train_loader, desc=f'Epoch {epoch + 1}/{NUM_EPOCHS}'):
                inputs, labels = inputs.to(device), labels.to(device)
                optimizer.zero_grad()
                outputs = model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f'[Epoch {epoch+1}] Loss médio: {total_loss / max(1,len(train_loader)):.4f}')

        model.eval()
        all_preds, all_labels = [], []
        with torch.no_grad():
            for inputs, labels in test_loader:
                inputs, labels = inputs.to(device), labels.to(device)
                outputs = model(inputs)
                preds = torch.sigmoid(outputs)
                all_preds.extend(preds.cpu().numpy().flatten().tolist())
                all_labels.extend(labels.cpu().numpy().flatten().tolist())
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels).astype(int)
        all_preds_binary = (all_preds >= THRESHOLD_P).astype(int)
        print('\n' + '=' * 50)
        print('[Avaliação padrão - split por linhas]')
        print(f'Acurácia: {accuracy_score(all_labels, all_preds_binary):.4f}')
        print(f'Precisão: {precision_score(all_labels, all_preds_binary, zero_division=1):.4f}')
        print(f'Recall:   {recall_score(all_labels, all_preds_binary, zero_division=1):.4f}')
        print(f'F1-Score: {f1_score(all_labels, all_preds_binary, zero_division=1):.4f}')
        print('Matriz de Confusão:')
        print(confusion_matrix(all_labels, all_preds_binary, labels=[0,1]))

        model_cfg = {
            "feature_dim": FEATURE_DIM,
            "proj_dim": 64,
            "depth": 2,
            "heads": 4,
            "layer_dropout": 0.1,
            "use_scalenorm": True,
            "pre_norm": False,
        }
        save_artifacts(model, scaler, train_medians, FEATURES[:-1], SEQ_LEN, model_cfg, epoch=NUM_EPOCHS)

        if TEST_WINDOWS_CSV:
            print('\n' + '=' * 50)
            print('[Avaliação extra - janelas de 5s]')
            evaluate_on_5s_windows(TEST_WINDOWS_CSV, scaler, train_medians, model, device, window_seconds=5.0)

    elif MODE == "test":
        model, scaler, train_medians, seq_len_ckpt, feature_names = load_artifacts()
        assert seq_len_ckpt == SEQ_LEN, f"SEQ_LEN do código ({SEQ_LEN}) difere do checkpoint ({seq_len_ckpt})"
        assert feature_names == FEATURES[:-1], "FEATURES do código divergem do checkpoint."
        if TEST_WINDOWS_CSV:
            print('\n' + '=' * 50)
            print('[TEST MODE] Avaliação extra - janelas de 5s')
            evaluate_on_5s_windows(TEST_WINDOWS_CSV, scaler, train_medians, model.to(device), device, window_seconds=5.0)
        else:
            print("[TEST MODE] Nenhum TEST_WINDOWS_CSV fornecido.")

    elif MODE == "monitor":
        model, scaler, train_medians, seq_len_ckpt, feature_names = load_artifacts()
        assert seq_len_ckpt == SEQ_LEN, f"SEQ_LEN do código ({SEQ_LEN}) difere do checkpoint ({seq_len_ckpt})"
        assert feature_names == FEATURES[:-1], "FEATURES do código divergem do checkpoint."
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        if device.type == 'cuda':
            try:
                torch.set_float32_matmul_precision('high')
            except:
                pass
            torch.backends.cuda.matmul.allow_tf32 = True
            torch.backends.cudnn.allow_tf32 = True
        run_stream_offline_fast(model.to(device).eval(), scaler, train_medians, device, pcap_path=PCAP_PATH)

    else:
        raise ValueError("MODE deve ser 'train', 'test' ou 'monitor'.")

if __name__ == "__main__":
    main()
