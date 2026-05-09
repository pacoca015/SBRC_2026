# Detecção de DDoS em Tempo Real com Transformer

Ferramenta de detecção de ataques DDoS baseada em modelo Transformer treinado sobre fluxos de rede. Suporta treinamento, monitoramento via PCAP e conversão de pcap para CSV (somente para novas capturas de tráfego).

---

## Selos Considerados

Os selos considerados são: D, F, S e R .

---

## Requisitos

### Hardware
- GPU NVIDIA com suporte a CUDA 12.4 (recomendado; CPU também funciona, porém mais lento)

### Software
- Python 3.12
- [Wireshark/TShark](https://www.wireshark.org/download.html) instalado e acessível no PATH (necessário apenas para o modo monitor)

### Estrutura esperada do repositório

```
/
  main.py
  conversor_2.py
  run.py
  Requirements.txt
  Experimento 1/
    capturaSYN_treino_novo_CORRETA.csv
    captura_teste_SYN.pcap
    ckpt_ddos_SYN_TREINO_NOVO_CERTO/
  Experimento 2/
    capturaUDP_Novo_.csv
    captura_udp_flood.pcap
    ckpt_ddos_UDP_TREINO_NOVO_CERTO/
  Experimento 3/
    capturaSYN_UDP_treino_novo.csv
    captura_teste_novo_udp_syn2.pcap
    ckpt_ddos_UDP_SYN_TREINO_NOVO_CERTO/
```

---

## Instalação

```bash
# 1. Criar e ativar ambiente virtual com Python 3.12
python3.12 -m venv .venv312

# Windows
.venv312\Scripts\Activate.ps1

# Linux/macOS
source .venv312/bin/activate

# 2. Instalar dependências gerais
pip install -r Requirements.txt

# 3. Instalar PyTorch com suporte a CUDA 12.4
pip install torch==2.6.0+cu124 torchvision==0.21.0+cu124 torchaudio==2.6.0+cu124 \
    --index-url https://download.pytorch.org/whl/cu124
```


---

## Execução Minima 

Toda a interação é feita pelo `run.py`, que guia o usuário por menus e gera automaticamente o script configurado para o experimento escolhido. Logo, esse script precisa ser executado sem erros e conectar aos outros 2 scripts, main e conversor. Para conferir o funcionamento, basta executar o treino em qualquer experimento e executar uma conversão em algum experimento.

```bash
python run.py
```

O menu principal oferece três modos:

```
[1] train     — treinar o modelo
[2] monitor   — classificar fluxo em tempo real (PCAP)
[3] conversor — converter PCAP em CSV para treino
```

---

## Exemplos de execução

### Exemplo 1 — Treino (Experimento 1: TCP SYN Flood)

```
python run.py

Modo de operacao:
  [1] train     — treinar o modelo
  Sua escolha: 1

Configuracao de hiperparametros:
  [1] Configuracao do artigo (valores exatos do SBRC)
  Sua escolha: 1

Selecione o experimento:
  [1] Experimento 1 — TCP SYN Flood (dataset_TCP-GU)
  Sua escolha: 1

  Confirmar e executar? (s/n) [s]: s
```

Ao final do treino os artefatos (`model.pt`, `scaler.joblib`, `train_medians.joblib`) são salvos automaticamente na pasta `ckpt` do experimento.

---

### Exemplo 2 — Monitoramento em tempo real (Experimento 1)

```
python run.py

Modo de operacao:
  [2] monitor   — classificar fluxo em tempo real (PCAP)
  Sua escolha: 2

Configuracao de hiperparametros:
  [1] Configuracao do artigo (valores exatos do SBRC)
  Sua escolha: 1

  Caminho do executavel TShark [C:\Program Files\Wireshark\tshark.exe]: 

Selecione o experimento:
  [1] Experimento 1 — TCP SYN Flood (dataset_TCP-GU)
  Sua escolha: 1

  Confirmar e executar? (s/n) [s]: s
```

A ferramenta processa o PCAP em janelas de 5 segundos e imprime para cada janela a probabilidade de ataque, a predição e a latência do modelo:

```
[WIN 000000] rows=  842 | chunks= 7 | cov=1.00 | p_attack=0.9823 | y_true=1 | pred=1 | lat_total=12.4 ms
[WIN 000001] rows=  613 | chunks= 6 | cov=1.00 | p_attack=0.0231 | y_true=0 | pred=0 | lat_total=9.1 ms
...
===== Avaliação Final por Arquivo (janela=5s) =====
Acurácia:  0.9700
Precisão:  0.9800
Recall:    0.9600
F1-Score:  0.9700
```

---

### Exemplo 3 — Conversão de PCAP para CSV

```
python run.py

Modo de operacao:
  [3] conversor — converter PCAP em CSV para treino
  Sua escolha: 3

Selecione o experimento:
  [1] Experimento 1 — TCP SYN Flood (dataset_TCP-GU)
  Sua escolha: 1

  Confirmar e executar? (s/n) [s]: s
```

O CSV resultante é salvo em `Experimento 1/captura_convertida.csv`, pronto para ser usado no treino.

---

## Hiperparâmetros principais

| Parâmetro | Valor (artigo) | Descrição |
|---|---|---|
| `SEQ_LEN` | 120 | Linhas por chunk de entrada |
| `THRESHOLD_P` | 0.90 | Limiar de decisão (ataque vs. benigno) |
| `WINDOW_SECONDS` | 5.0 | Tamanho da janela de análise (segundos) |
| `CHUNK_BATCH` | 50 | Chunks processados por lote na inferência |
| `LEARNING_RATE` | 1e-5 | Taxa de aprendizado |
| `NUM_EPOCHS` | 5 | Épocas de treinamento |

Todos os parâmetros podem ser alterados interativamente ao escolher a opção `[2] Nova configuracao` no menu de hiperparâmetros.


## LICENSE

Este projeto está licenciado sob a **MIT License**.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
