"""
run.py — Interface interativa para o detector de DDoS (SBRC)
Execute: python run.py
"""

import os
import sys
import subprocess

# ─────────────────────────────────────────────────────────────
# Raiz do repositório  (pasta onde run.py está)
# Estrutura esperada:
#   <repo>/
#     main.py
#     conversor_2.py
#     run.py
#     Experimento 1/
#       ckpt_ddos_.../
#       <arquivo>.csv
#       <arquivo>.pcap
#     Experimento 2/  ...
#     Experimento 3/  ...
# ─────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))

def repo(*parts) -> str:
    """Monta um caminho relativo à raiz do repositório."""
    return os.path.join(ROOT, *parts)


# ─────────────────────────────────────────────────────────────
# Experimentos pré-definidos (artigo)
# ─────────────────────────────────────────────────────────────
EXPERIMENTOS = {
    "1": {
        "nome": "Experimento 1 — TCP SYN Flood (dataset_TCP-GU)",
        "train_csv": repo("Experimento 1", "capturaSYN_treino_novo_CORRETA.csv"),
        "pcap":      repo("Experimento 1", "captura_teste_SYN.pcap"),
        "ckpt_dir":  repo("Experimento 1", "ckpt_ddos_SYN_TREINO_NOVO_CERTO"),
        "benign_ips": {
            "192.168.1.5", "192.168.1.2", "192.168.1.7",
            "192.168.1.8", "192.168.1.9", "192.168.1.10",
        },
        "attack_ips": {
            "192.168.1.11", "192.168.1.3", "192.168.1.6",
            "192.168.2.2",  "192.168.2.11","192.168.2.3",
            "192.168.2.4",  "192.168.2.5", "192.168.2.8",
            "192.168.3.2",  "192.168.3.8", "192.168.3.3",
            "192.168.3.7",  "192.168.4.2", "192.168.4.3",
            "192.168.4.4",  "192.168.4.7", "192.168.4.8",
            "192.168.4.10", "192.168.4.9", "192.168.5.2",
            "192.168.5.3",  "192.168.5.4", "192.168.5.8",
        },
    },
    "2": {
        "nome": "Experimento 2 — UDP Flood",
        "train_csv": repo("Experimento 2", "capturaUDP_Novo_.csv"),
        "pcap":      repo("Experimento 2", "captura_udp_flood.pcap"),
        "ckpt_dir":  repo("Experimento 2", "ckpt_ddos_UDP_TREINO_NOVO_CERTO"),
        "benign_ips": {
            "192.168.1.5", "192.168.1.2", "192.168.1.7",
            "192.168.1.8", "192.168.1.9", "192.168.1.10",
        },
        "attack_ips": {
            "192.168.1.11", "192.168.1.3", "192.168.1.6",
            "192.168.2.2",  "192.168.2.11","192.168.2.3",
            "192.168.2.4",  "192.168.2.5", "192.168.2.8",
            "192.168.3.2",  "192.168.3.8", "192.168.3.3",
            "192.168.3.7",  "192.168.4.2", "192.168.4.3",
            "192.168.4.4",  "192.168.4.7", "192.168.4.8",
            "192.168.4.10", "192.168.4.9", "192.168.5.2",
            "192.168.5.3",  "192.168.5.4", "192.168.5.8",
        },
    },
    "3": {
        "nome": "Experimento 3 — Misto (TCP + UDP)",
        "train_csv": repo("Experimento 3", "capturaSYN_UDP_treino_novo.csv"),
        "pcap":      repo("Experimento 3", "captura_teste_novo_udp_syn2.pcap"),
        "ckpt_dir":  repo("Experimento 3", "ckpt_ddos_UDP_SYN_TREINO_NOVO_CERTO"),
        "benign_ips": {
            "192.168.1.5", "192.168.1.2", "192.168.1.7",
            "192.168.1.8", "192.168.1.9", "192.168.1.10",
        },
        "attack_ips": {
            "192.168.1.11", "192.168.1.3", "192.168.1.6",
            "192.168.2.2",  "192.168.2.11","192.168.2.3",
            "192.168.2.4",  "192.168.2.5", "192.168.2.8",
            "192.168.3.2",  "192.168.3.8", "192.168.3.3",
            "192.168.3.7",  "192.168.4.2", "192.168.4.3",
            "192.168.4.4",  "192.168.4.7", "192.168.4.8",
            "192.168.4.10", "192.168.4.9", "192.168.5.2",
            "192.168.5.3",  "192.168.5.4", "192.168.5.8",
        },
    },
}

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def banner():
    print()
    print("=" * 60)
    print("   Detector de DDoS com Transformer — SBRC")
    print("=" * 60)
    print()

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else default

def ask_float(prompt: str, default: float) -> float:
    while True:
        raw = ask(prompt, str(default))
        try:
            return float(raw)
        except ValueError:
            print(f"  x Digite um numero decimal (ex.: {default})")

def ask_int(prompt: str, default: int) -> int:
    while True:
        raw = ask(prompt, str(default))
        try:
            return int(raw)
        except ValueError:
            print(f"  x Digite um numero inteiro (ex.: {default})")

def ask_path(prompt: str, default: str = "", must_exist: bool = False) -> str:
    while True:
        val = ask(prompt, default)
        if not val:
            print("  x Caminho nao pode ser vazio.")
            continue
        if must_exist and not os.path.exists(val):
            print(f"  x Caminho nao encontrado: {val}")
            continue
        return val

def ask_choice(prompt: str, options: dict) -> str:
    print(f"\n{prompt}")
    for k, v in options.items():
        label = v if isinstance(v, str) else v.get("nome", v)
        print(f"  [{k}] {label}")
    keys = list(options.keys())
    while True:
        choice = input("  Sua escolha: ").strip()
        if choice in keys:
            return choice
        print(f"  x Opcao invalida. Escolha entre: {', '.join(keys)}")

def ask_ips(label: str, default_set: set) -> set:
    print(f"\n  IPs {label} atuais:")
    for ip in sorted(default_set):
        print(f"    - {ip}")
    manter = ask(f"  Manter esses IPs {label}? (s/n)", "s").lower()
    if manter == "s":
        return default_set
    print(f"  Digite os IPs {label} separados por virgula:")
    raw = input("  > ").strip()
    return {ip.strip() for ip in raw.split(",") if ip.strip()}

def ips_to_python_set_str(ips: set) -> str:
    quoted = ", ".join(f'"{ip}"' for ip in sorted(ips))
    return "{" + quoted + "}"

# ─────────────────────────────────────────────────────────────
# Hiperparâmetros
# ─────────────────────────────────────────────────────────────
DEFAULTS_ARTIGO = {
    "NUM_EPOCHS":        5,
    "BATCH_SIZE":        50,
    "LEARNING_RATE":     1e-5,
    "SEQ_LEN":           120,
    "THRESHOLD_P":       0.90,
    "CHUNK_BATCH":       50,
    "CHUNK_MODE":        "non_overlap",
    "CHUNK_STRIDE":      10,
    "AGGREGATE":         "max",
    "WINDOW_SECONDS":    5.0,
    "PCAP_IDLE_TIMEOUT": 10.0,
}

def coletar_hiperparametros(usar_artigo: bool) -> dict:
    if usar_artigo:
        print("\n  Usando configuracao exata do artigo.")
        return dict(DEFAULTS_ARTIGO)

    print("\n  Configure os hiperparametros (Enter = valor padrao do artigo):\n")
    hp = {}
    hp["NUM_EPOCHS"]        = ask_int  ("  Epocas de treino",                 DEFAULTS_ARTIGO["NUM_EPOCHS"])
    hp["BATCH_SIZE"]        = ask_int  ("  Batch size (sequencias por lote)",  DEFAULTS_ARTIGO["BATCH_SIZE"])
    hp["LEARNING_RATE"]     = ask_float("  Learning rate",                     DEFAULTS_ARTIGO["LEARNING_RATE"])
    hp["SEQ_LEN"]           = ask_int  ("  SEQ_LEN (linhas por chunk)",        DEFAULTS_ARTIGO["SEQ_LEN"])
    hp["THRESHOLD_P"]       = ask_float("  Threshold de decisao (0-1)",        DEFAULTS_ARTIGO["THRESHOLD_P"])
    hp["CHUNK_BATCH"]       = ask_int  ("  Chunks por lote de inferencia",     DEFAULTS_ARTIGO["CHUNK_BATCH"])
    hp["WINDOW_SECONDS"]    = ask_float("  Tamanho da janela de tempo (s)",    DEFAULTS_ARTIGO["WINDOW_SECONDS"])
    hp["PCAP_IDLE_TIMEOUT"] = ask_float("  Timeout de inatividade do PCAP (s)",DEFAULTS_ARTIGO["PCAP_IDLE_TIMEOUT"])

    chunk_mode = ask_choice("  Estrategia de chunking:", {
        "1": "non_overlap",
        "2": "overlap",
    })
    hp["CHUNK_MODE"] = "non_overlap" if chunk_mode == "1" else "overlap"
    hp["CHUNK_STRIDE"] = ask_int("  Stride do overlap", DEFAULTS_ARTIGO["CHUNK_STRIDE"]) \
        if hp["CHUNK_MODE"] == "overlap" else DEFAULTS_ARTIGO["CHUNK_STRIDE"]

    agg = ask_choice("  Agregacao de probabilidades:", {
        "1": "max  — prob. maxima entre os chunks",
        "2": "mean — media entre os chunks",
        "3": "vote — fracao de chunks acima do threshold",
    })
    hp["AGGREGATE"] = {"1": "max", "2": "mean", "3": "vote"}[agg]

    return hp

# ─────────────────────────────────────────────────────────────
# Coleta de experimento
# ─────────────────────────────────────────────────────────────

def coletar_experimento(modo: str) -> dict:
    opcoes = {k: v for k, v in EXPERIMENTOS.items()}
    opcoes["N"] = "Novo experimento (informar caminhos manualmente)"

    choice = ask_choice("Selecione o experimento:", opcoes)

    if choice != "N":
        exp = dict(EXPERIMENTOS[choice])
        print(f"\n  Experimento selecionado: {exp['nome']}")

        if modo == "monitor":
            trocar = ask("  Deseja usar um PCAP diferente? (s/n)", "n").lower()
            if trocar == "s":
                exp["pcap"] = ask_path("  Caminho do PCAP", exp["pcap"], must_exist=True)

        ajustar_ips = ask("  Deseja ajustar os IPs do experimento? (s/n)", "n").lower()
        if ajustar_ips == "s":
            exp["benign_ips"] = ask_ips("benignos", exp["benign_ips"])
            exp["attack_ips"] = ask_ips("de ataque", exp["attack_ips"])

        return exp

    # ── Novo experimento manual ──
    print("\n  Configure o novo experimento:\n")
    exp = {}
    exp["nome"] = ask("  Nome do experimento", "Novo Experimento")
    _exp_dir = repo(exp["nome"])

    exp["train_csv"] = ask_path(
        "  Caminho do CSV de treino (.csv)",
        os.path.join(_exp_dir, "dataset.csv"),
        must_exist=True,
    )

    if modo == "monitor":
        exp["pcap"] = ask_path(
            "  Caminho do PCAP (.pcap)",
            os.path.join(_exp_dir, "captura.pcap"),
            must_exist=True,
        )
    elif modo == "conversor":
        exp["pcap"] = ask_path(
            "  Caminho do PCAP a converter (.pcap)",
            os.path.join(_exp_dir, "captura.pcap"),
            must_exist=True,
        )
    else:
        exp["pcap"] = ""

    exp["ckpt_dir"] = ask(
        "  Diretorio para checkpoints",
        os.path.join(_exp_dir, "ckpt"),
    )

    print("\n  IPs benignos (separados por virgula):")
    raw_b = input("  > ").strip()
    exp["benign_ips"] = {ip.strip() for ip in raw_b.split(",") if ip.strip()}

    print("  IPs de ataque (separados por virgula):")
    raw_a = input("  > ").strip()
    exp["attack_ips"] = {ip.strip() for ip in raw_a.split(",") if ip.strip()}

    return exp

# ─────────────────────────────────────────────────────────────
# Gera main_configured.py
# ─────────────────────────────────────────────────────────────

MAIN_SCRIPT      = os.path.join(ROOT, "main.py")
CONVERSOR_SCRIPT = os.path.join(ROOT, "conversor_2.py")

def _re_sub_const(src: str, name: str, new_value: str) -> str:
    """Substitui o valor de uma constante via regex, preservando comentários."""
    import re
    pattern = rf'^({re.escape(name)}\s*=\s*).*?(\s*(?:#.*)?)$'
    replacement = rf'\g<1>{new_value}\g<2>'
    new_src, n = re.subn(pattern, replacement, src, count=1, flags=re.MULTILINE)
    if n == 0:
        print(f"  Aviso: constante '{name}' nao encontrada no script — verifique o arquivo.")
    return new_src

def gerar_script_configurado(
    modo: str,
    hp: dict,
    exp: dict,
    tshark_bin: str = "",
    output_path: str = "main_configured.py",
):
    import re

    with open(MAIN_SCRIPT, "r", encoding="utf-8") as f:
        src = f.read()

    src = _re_sub_const(src, "MODE",             f'("{modo}")')
    src = _re_sub_const(src, "NUM_EPOCHS",        str(hp["NUM_EPOCHS"]))
    src = _re_sub_const(src, "BATCH_SIZE",        str(hp["BATCH_SIZE"]))
    src = _re_sub_const(src, "LEARNING_RATE",     str(hp["LEARNING_RATE"]))
    src = _re_sub_const(src, "SEQ_LEN",           str(hp["SEQ_LEN"]))
    src = _re_sub_const(src, "THRESHOLD_P",       str(hp["THRESHOLD_P"]))
    src = _re_sub_const(src, "CHUNK_BATCH",       str(hp["CHUNK_BATCH"]))
    src = _re_sub_const(src, "CHUNK_MODE",        f'"{hp["CHUNK_MODE"]}"')
    src = _re_sub_const(src, "CHUNK_STRIDE",      str(hp["CHUNK_STRIDE"]))
    src = _re_sub_const(src, "AGGREGATE",         f'"{hp["AGGREGATE"]}"')
    src = _re_sub_const(src, "WINDOW_SECONDS",    str(hp["WINDOW_SECONDS"]))
    src = _re_sub_const(src, "PCAP_IDLE_TIMEOUT", str(hp["PCAP_IDLE_TIMEOUT"]))

    ckpt = exp["ckpt_dir"].replace("\\", "/")
    csv  = exp["train_csv"].replace("\\", "/")
    pcap = exp.get("pcap", "").replace("\\", "/")

    src = _re_sub_const(src, "CKPT_DIR",  f'r"{ckpt}"')
    src = _re_sub_const(src, "TRAIN_CSV", f'r"{csv}"')
    src = _re_sub_const(src, "PCAP_PATH", f'r"{pcap}"')

    if tshark_bin:
        src = _re_sub_const(src, "TSHARK_BIN", f'r"{tshark_bin.replace(chr(92), "/")}"')

    benign_str = ips_to_python_set_str(exp["benign_ips"])
    attack_str = ips_to_python_set_str(exp["attack_ips"])
    src = re.sub(r'BENIGN_IPS\s*=\s*\{[^}]*\}', f'BENIGN_IPS = {benign_str}',
                 src, flags=re.DOTALL)
    src = re.sub(r'ATTACK_IPS\s*=\s*\{[^}]*\}', f'ATTACK_IPS = {attack_str}',
                 src, flags=re.DOTALL)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(src)

    print(f"  Script principal salvo em: {output_path}")
    return output_path

# ─────────────────────────────────────────────────────────────
# Gera conversor_configured.py
# ─────────────────────────────────────────────────────────────

def gerar_conversor_configurado(exp: dict, output_path: str = "conversor_configured.py"):
    import re

    with open(CONVERSOR_SCRIPT, "r", encoding="utf-8") as f:
        src = f.read()

    pcap_in = exp.get("pcap", "").replace("\\", "/")
    exp_dir = os.path.dirname(exp["train_csv"]).replace("\\", "/")
    csv_out = exp_dir + "/captura_convertida.csv"

    src = re.sub(r'^input_pcap\s*=.*$', f'input_pcap = r"{pcap_in}"',
                 src, flags=re.MULTILINE)
    src = re.sub(r'^output_csv\s*=.*$', f'output_csv = r"{csv_out}"',
                 src, flags=re.MULTILINE)

    benign_str = ips_to_python_set_str(exp["benign_ips"])
    attack_str = ips_to_python_set_str(exp["attack_ips"])
    src = re.sub(r'BENIGN_IPS\s*=\s*\{[^}]*\}', f'BENIGN_IPS = {benign_str}',
                 src, flags=re.DOTALL)
    src = re.sub(r'ATTACK_IPS\s*=\s*\{[^}]*\}', f'ATTACK_IPS = {attack_str}',
                 src, flags=re.DOTALL)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(src)

    print(f"  Script conversor salvo em: {output_path}")
    return output_path

# ─────────────────────────────────────────────────────────────
# Resumo
# ─────────────────────────────────────────────────────────────

def imprimir_resumo(modo, hp, exp, tshark_bin=""):
    print()
    print("─" * 60)
    print("  RESUMO DA CONFIGURACAO")
    print("─" * 60)
    print(f"  Modo              : {modo.upper()}")
    print(f"  Experimento       : {exp['nome']}")
    print(f"  CSV de treino     : {exp['train_csv']}")
    if modo in ("monitor", "conversor"):
        print(f"  PCAP              : {exp.get('pcap', '—')}")
    if modo == "monitor":
        print(f"  TShark            : {tshark_bin}")
    print(f"  Checkpoint dir    : {exp['ckpt_dir']}")
    print(f"  IPs benignos      : {len(exp['benign_ips'])} enderecos")
    print(f"  IPs de ataque     : {len(exp['attack_ips'])} enderecos")
    if modo != "conversor":
        print()
        print(f"  Epocas            : {hp['NUM_EPOCHS']}")
        print(f"  Batch size        : {hp['BATCH_SIZE']}")
        print(f"  Learning rate     : {hp['LEARNING_RATE']}")
        print(f"  SEQ_LEN           : {hp['SEQ_LEN']}")
        print(f"  Threshold         : {hp['THRESHOLD_P']}")
        print(f"  Chunks/lote       : {hp['CHUNK_BATCH']}")
        print(f"  Janela (s)        : {hp['WINDOW_SECONDS']}")
        print(f"  Chunk mode        : {hp['CHUNK_MODE']}")
        print(f"  Agregacao         : {hp['AGGREGATE']}")
    print("─" * 60)
    print()

# ─────────────────────────────────────────────────────────────
# Fluxo principal
# ─────────────────────────────────────────────────────────────

def main():
    banner()

    # 1. Modo de operação
    modo_choice = ask_choice(
        "Modo de operacao:",
        {
            "1": "train     — treinar o modelo",
            "2": "monitor   — classificar fluxo em tempo real (PCAP)",
            "3": "conversor — converter PCAP em CSV para treino",
        },
    )
    modo_map = {"1": "train", "2": "monitor", "3": "conversor"}
    modo = modo_map[modo_choice]

    # 2. Hiperparâmetros (não pergunta para conversor)
    if modo != "conversor":
        cfg_choice = ask_choice(
            "Configuracao de hiperparametros:",
            {
                "1": "Configuracao do artigo (valores exatos do SBRC)",
                "2": "Nova configuracao (definir manualmente)",
            },
        )
        hp = coletar_hiperparametros(cfg_choice == "1")
    else:
        hp = dict(DEFAULTS_ARTIGO)

    # 3. TShark — só para monitor
    tshark_bin = ""
    if modo == "monitor":
        print()
        tshark_bin = ask_path(
            "  Caminho do executavel TShark",
            r"C:\Program Files\Wireshark\tshark.exe",
            must_exist=False,
        )

    # 4. Experimento
    print()
    exp = coletar_experimento(modo)

    # 5. Resumo + confirmação
    imprimir_resumo(modo, hp, exp, tshark_bin)
    confirmar = ask("  Confirmar e executar? (s/n)", "s").lower()
    if confirmar != "s":
        print("\n  Execucao cancelada.\n")
        sys.exit(0)

    # 6. Gera e executa
    if modo == "conversor":
        script_saida = "conversor_configured.py"
        gerar_conversor_configurado(exp, output_path=script_saida)
    else:
        script_saida = "main_configured.py"
        gerar_script_configurado(modo, hp, exp, tshark_bin, output_path=script_saida)

    print(f"\n  Executando: python {script_saida}\n")
    print("=" * 60)
    resultado = subprocess.run([sys.executable, script_saida], check=False)
    print("=" * 60)
    print(f"\n  Processo encerrado com codigo: {resultado.returncode}")
    if resultado.returncode != 0:
        print("  Aviso: o script retornou erro. Verifique as mensagens acima.")

if __name__ == "__main__":
    main()
