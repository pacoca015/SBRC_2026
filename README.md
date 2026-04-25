# Detecção de Ataques DDoS em Tempo Real com Transformers sobre Tráfego de Rede

Artefato referente ao artigo **"Detecção de Ataques DDoS em Tempo Real com Transformers sobre Tráfego de Rede"**, submetido ao SBRC 2025. O objetivo do artefato é permitir a reprodução dos experimentos de treinamento, teste e monitoramento de um modelo baseado em Transformer para detecção binária de ataques DDoS a partir de features extraídas de tráfego de rede.

---

## Estrutura do README

```
README.md
├── Título do projeto
├── Estrutura do README
├── Selos Considerados
├── Informações Básicas
├── Dependências
├── Preocupações com Segurança
├── Instalação
├── Teste Mínimo
├── Experimentos
│   ├── Reivindicação #1 – Treinamento do Modelo
│   ├── Reivindicação #2 – Avaliação por Janelas Temporais
│   └── Reivindicação #3 – Monitoramento em Tempo Real via PCAP
└── LICENSE
```

O repositório está organizado da seguinte forma:

```
/
├── Experimento 1/
│   ├── ckpt_ddos_SYN_TREINO_NOVO_CERTO/   # Artefatos do modelo treinado
│   ├── Dataset                             # Link/referência do dataset de treino ja convertido e para teste que não deve ser convertido, pois sera lido pelo pcap
│   ├── conversor 2.py                      # Conversor PCAP → CSV
│   └── transformer_espera.py               # Script principal
├── Experimento 2/
│   ├── ckpt_ddos_SYN_TREINO_NOVO_CERTO/
│   ├── Dataset
│   ├── conversor 2.py
│   └── transformer_espera.py
├── Experimento 3/
│   ├── ckpt_ddos_SYN_TREINO_NOVO_CERTO/
│   ├── Dataset
│   ├── conversor 2.py
│   └── transformer_espera.py
└── README.md
```

Cada pasta de experimento é autossuficiente e contém o script principal, o conversor de PCAP, que so dever ser usado para um treinamen com um arquivo diferente do que o provido no google drive e os artefatos do modelo já treinado (pesos, scaler e medianas de treino).

---

## Selos Considerados

Os selos considerados são: D, F, S e R .

---

## Informações Básicas

### Hardware

| Componente | Mínimo recomendado |
|---|---|
| CPU | Intel/AMD x86-64, 4 núcleos |
| RAM | 8 GB |
| Disco | 10 GB livres |
| GPU (opcional mas necessários para chegar nos tempos divulgados no artigo) | NVIDIA com CUDA 11.8+  |

Os experimentos foram originalmente executados em uma máquina com Windows 11, Python 3.10+ e GPU NVIDIA. O código é compatível com CPU, porém o treinamento será mais lento e os tempos de inferência na etapa monitor e teste serão consideravelmente maiores, porem os resultados das métricas irão se manter.

### Software

| Software | Versão testada |
|---|---|
| Python | 3.10 ou 3.11 |
| CUDA Toolkit (opcional) | 11.8 ou 12.1 |
| Wireshark / TShark | 4.x (Obrigatório somente modo `monitor`) |
| Sistema Operacional | Windows 10/11 ou Linux |

---

## Dependências

As bibliotecas Python necessárias são listadas abaixo com as versões testadas:

| Biblioteca | Versão |
|---|---|
| torch | 2.6.0+cu124 |
| torchaudio | 2.6.0+cu124 |
| torchvision | 0.21.0+cu124 |
| numpy | 2.4.3 |
| pandas | 3.0.1 |
| scikit-learn | 1.8.0 |
| joblib | 1.5.3 |
| matplotlib | 3.10.8 |
| tqdm | 4.67.3 |
| x-transformers | 2.17.9 |
| einops | 0.8.2 |
| einx | 0.4.2 |
| scipy | 1.17.1 |

Os datasets utilizados nos experimentos estão disponíveis no Google Drive:
Experimento 1: https://drive.google.com/drive/folders/1eaEFRe_bdD-kFphalQ7G8VDqKnHDMdEL?usp=sharing
Experimento 2: https://drive.google.com/drive/folders/1MijJX2FBqY7bXwlgqxWdPJxIg1aONqQX?usp=sharing (esta sem o arquivo pcap de teste por perca do arquivo por corrupção do arquivo)
Experimento 3: https://drive.google.com/drive/folders/1H6ON9OxvnJOcOfs-gF_h7U3-AClh7mna?usp=sharing
>   
> Os arquivos CSV (para treino/teste) e os arquivos PCAP (para monitoramento) estão organizados por experimento.

O TShark (Wireshark) é necessário **somente para o modo `monitor`**. Baixe em: https://www.wireshark.org/download.html

---

## Preocupações com Segurança

O artefato realiza leitura de arquivos PCAP de tráfego de rede previamente capturado, **não gerando nem transmitindo tráfego malicioso**. Nenhuma funcionalidade de ataque é implementada. Os arquivos PCAP fornecidos contêm tráfego sintético capturado em ambiente controlado e não representam risco para os avaliadores.

---

## Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/pacoca015/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO
```

### 2. Criar ambiente virtual (recomendado)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 3. Instalar dependências Python

```bash
pip install torch==2.6.0+cu124 torchvision==0.21.0+cu124 torchaudio==2.6.0+cu124 --index-url https://download.pytorch.org/whl/cu124
pip install numpy==2.4.3 pandas==3.0.1 scikit-learn==1.8.0 joblib==1.5.3 matplotlib==3.10.8 tqdm==4.67.3 x-transformers==2.17.9 einops==0.8.2 einx==0.4.2 scipy==1.17.1
Ou use o requirements.txt

```

> **Sem GPU:** substitua a linha do torch por:
> ```bash
> pip install torch torchvision torchaudio
> ```

### 4. Baixar os datasets

Acesse o link do Google Drive disponível na seção **Dependências** e baixe os arquivos para as pastas correspondentes de cada experimento (`Experimento 1/`, `Experimento 2/`, `Experimento 3/`).

### 5. (Somente modo monitor) Instalar TShark

Instale o Wireshark/TShark e anote o caminho do executável (ex: `C:\Program Files\Wireshark\tshark.exe`). Atualize a variável `TSHARK_BIN` no script antes de executar.

---

## Teste Mínimo

Este teste verifica que o ambiente está corretamente instalado carregando o modelo pré-treinado do **Experimento 1** e executando uma inferência de exemplo.

### Passo 1 – Configurar o script

Abra o arquivo `Experimento 1/transformer_espera.py` e verifique as seguintes variáveis:

```python
MODE     = "test"
CKPT_DIR = "./ckpt_ddos_SYN_TREINO_NOVO_CERTO"   # pasta com artefatos do modelo
TRAIN_CSV = "./Dataset/tt.csv"                     # CSV de referência para medianas
TEST_WINDOWS_CSV = None                            # deixe None para o teste mínimo
```

### Passo 2 – Executar

```bash
cd "Experimento 1"
python transformer_espera.py
```

### Resultado esperado

```
[TEST MODE] Nenhum TEST_WINDOWS_CSV fornecido.
```

Se essa mensagem aparecer sem erros, o modelo foi carregado com sucesso e o ambiente está funcional.

## Experimentos

### Reivindicação #1 – Treinamento do Modelo

**Descrição:** Treinar o modelo Transformer para detecção de DDoS a partir de um CSV de tráfego rotulado, reproduzindo os resultados de acurácia, precisão, recall e F1-score reportados no artigo.

**Arquivos:** `transformer_espera.py` (dentro da pasta do experimento desejado)

**Configuração:** Edite as variáveis no topo do script:

```python
MODE      = "train"
CKPT_DIR  = "./ckpt_ddos_SYN_TREINO_NOVO_CERTO"
TRAIN_CSV = "./Dataset/tt.csv"

NUM_EPOCHS    = 5
BATCH_SIZE    = 50
LEARNING_RATE = 1e-5
SEQ_LEN       = 120
THRESHOLD_P   = 0.90
```

**Execução:**

```bash
cd "Experimento 1"   # ou Experimento 2 / Experimento 3
python transformer_espera.py
```

**Resultado esperado:** Ao final do treinamento, o terminal exibirá métricas no conjunto de teste (split 80/20) e salvará os artefatos em `CKPT_DIR`:

```
[Avaliação padrão - split por linhas]
Acurácia:  ~0.99
Precisão:  ~0.99
Recall:    ~0.99
F1-Score:  ~0.99
Matriz de Confusão: [...]
[OK] Artefatos salvos em ./ckpt_ddos_SYN_TREINO_NOVO_CERTO caso treinado com outro arquivo é recomendado preencher outro caminho, caso contrario os arquivos salvos irão sobrescrever os antigos
```

Os artefatos gerados incluem: `model.pt`, `model_state_dict.pt`, `model_full.pt`, `model_scripted.ts`, `scaler.joblib` e `train_medians.joblib`.

---

### Reivindicação #2 – Avaliação por Janelas Temporais (Modo Test)

**Descrição:** Avaliar o modelo treinado sobre um CSV de teste organizado em janelas temporais de 5 segundos, verificando as métricas de detecção por janela reportadas no artigo.

**Pré-requisito:** Ter executado a Reivindicação #1 (ou usar o modelo pré-treinado disponível na pasta `ckpt_ddos_SYN_TREINO_NOVO_CERTO`).

**Configuração:**

```python
MODE             = "test"
CKPT_DIR         = "./ckpt_ddos_SYN_TREINO_NOVO_CERTO"
TRAIN_CSV        = "./Dataset/tt.csv"
TEST_WINDOWS_CSV = "./Dataset/test_windows.csv"   # CSV com colunas: features + label + timestamp

SEQ_LEN      = 120        # deve ser igual ao usado no treino
THRESHOLD_P  = 0.90
CHUNK_MODE   = "non_overlap"
AGGREGATE    = "max"
```

> O arquivo de teste precisa conter as mesmas features do treino, mais as colunas `label` e `timestamp`.

**Execução:**

```bash
cd "Experimento 1"
python transformer_espera.py
```


**Resultado esperado:**

```
[Val. 5s - BINÁRIO (qualquer ataque na janela = 1)]
Acurácia:  ~0.98
Precisão:  ~0.97
Recall:    ~0.99
F1-Score:  ~0.98
Matriz de Confusão (labels=[0,1]):
[[TN  FP]
 [FN  TP]]
```

---

### Reivindicação #3 – Monitoramento em Tempo Real via PCAP (Modo Monitor)

**Descrição:** Processar um arquivo PCAP usando TShark e executar inferência janela a janela (5 segundos), reproduzindo os resultados de latência e detecção em tempo real reportados no artigo.

**Pré-requisito:** TShark instalado e modelo treinado disponível em `CKPT_DIR` e arquivo csv usado não treino do atual experimento.

**Configuração:**

```python
MODE      = "monitor"
CKPT_DIR  = "./ckpt_ddos_SYN_TREINO_NOVO_CERTO"
TSHARK_BIN = r"C:\Program Files\Wireshark\tshark.exe"   # ajuste para seu sistema
PCAP_PATH  = "./Dataset/captura.pcap"                   # PCAP disponível no Drive

BENIGN_IPS = {"192.168.1.2", "192.168.1.5", ...}        # IPs legítimos do cenário para todos são os mesmo, não precisa alterar
ATTACK_IPS = {"192.168.1.11", "192.168.2.2", ...}       # IPs atacantes do cenário para todos são os mesmo, não precisa alterar, entretanto, caso novo teste é preciso alterar para fazer a classificação correta das janelas, porem essa etapa se consiste mais na medição do tempo pos agregamento das janelas, as etapas de verificação de métricas de acerto que foram levadas em consideração foi a avaliação unitárias de chunks pos treino

WINDOW_SECONDS = 5.0
THRESHOLD_P    = 0.90
CHUNK_BATCH    = 50
```


**Execução:**

```bash
cd "Experimento 1"
python transformer_espera.py
```



**Resultado esperado:** Para cada janela de 5 segundos, o terminal exibirá:

```
[WIN 000000] rows=  x | chunks=x | cov=1.00 | p_attack=x | y_true=x | pred=x | lat_total=x

...
===== Avaliação Final por Arquivo (janela=5s) =====
Acurácia: x
F1-Score:  x
Recall: x
Precisão: x
[LATÊNCIA] média= x | min= x | max= x

Adicionalmente, são gerados os arquivos `latency_hist.png` e `confusion_matrix.png` no diretório de execução.

---

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
