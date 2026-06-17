# 🛡️ Motor Antifraude com Property Graphs (GraphSec Engine)

Este projeto é uma **Proof of Concept (PoC)** de um motor de detecção de fraudes financeiras inspirado em arquiteturas utilizadas por instituições financeiras e empresas de tecnologia.

A solução utiliza **Property Graphs** em Python através da biblioteca **NetworkX** para identificar padrões complexos de comportamento malicioso, incluindo:

- Fraude em Anel (*Ring Fraud*)
- Sequestro de Conta (*Account Takeover - ATO*)
- Compartilhamento suspeito de infraestrutura
- Reutilização de dispositivos comprometidos

Diferentemente de abordagens tradicionais baseadas em bancos relacionais e consultas com múltiplos `JOINs`, este motor realiza travessias locais em memória, permitindo análises rápidas e tomadas de decisão em tempo real.

---

# 🧠 Arquitetura: Property Graph vs. RDF

A modelagem foi construída utilizando o paradigma **Property Graph**, escolhido por oferecer maior flexibilidade para cenários de detecção de fraude quando comparado ao modelo **RDF (Resource Description Framework)**.

## Principais vantagens adotadas

### Evita Explosão de Nós

Metadados contextuais, como:

- Device ID
- Horário de acesso
- Tipo de conexão
- Localização

são armazenados como propriedades e não como novos vértices da rede.

### Encapsulamento de Contexto nas Arestas

As informações relevantes para análise de comportamento ficam armazenadas diretamente nas conexões entre os nós.

Isso permite:

- Diferenciar tráfego legítimo de tráfego suspeito
- Reduzir complexidade estrutural
- Melhorar performance das consultas
- Facilitar implementação de regras antifraude

---

# 🎯 Regras de Negócio e Casos de Uso

O motor não bloqueia usuários apenas pelo compartilhamento de IP.

A tomada de decisão combina:

- Velocity Check
- Device Fingerprinting
- Histórico de comportamento
- Correlação temporal
- Blacklists de hardware

---

## 1️⃣ Ataque Automatizado em Anel (True Positive)

### Características detectadas

- Múltiplas contas criadas em curto intervalo de tempo (< 5 minutos)
- Mesmo dispositivo físico
- Utilização de VPN ou mascaramento de IP

### Ação

- Bloqueio automático
- Inclusão do dispositivo na blacklist

---

## 2️⃣ Sequestro de Conta (Account Takeover)

### Características detectadas

- Conta previamente legítima
- Login realizado através de hardware comprometido
- Mudança geográfica incompatível com o histórico do usuário

### Ação

- Bloqueio preventivo da conta
- Geração de alerta de segurança

---

## 3️⃣ Compartilhamento Familiar (False Positive Mitigado)

### Características detectadas

- Mesmo IP residencial
- Dispositivos diferentes
- Intervalos temporais normais

### Ação

- Acesso liberado
- Nenhuma penalização aplicada

---

## 4️⃣ Co-Location / Rede Pública (False Positive Mitigado)

### Características detectadas

- Grande volume de acessos no mesmo IP
- Ambiente público (faculdade, shopping, coworking etc.)
- Diversidade de dispositivos

### Ação

- Acesso liberado
- Classificação como comportamento orgânico

---

# ⚙️ Fluxo de Processamento

```text
JSON de Eventos
        │
        ▼
Construção do Grafo
        │
        ▼
Mapeamento de Usuários
IPs e Dispositivos
        │
        ▼
Aplicação das Regras
de Detecção
        │
        ▼
Análise de Fraude
        │
        ▼
Diagnóstico de Segurança
```

---

# 🛠️ Tecnologias Utilizadas

| Categoria | Tecnologia |
|------------|------------|
| Linguagem | Python 3.x |
| Estrutura de Grafos | NetworkX |
| Manipulação de Dados | JSON |
| Datas e Horários | datetime |

---

# 📂 Estrutura do Projeto

```text
graphsec-engine/
├── main.py
├── dados.json
├── README.md
└── requirements.txt
```

---

# 🚀 Como Executar o Projeto

## 1. Clone o repositório

```bash
git clone <URL_DO_REPOSITORIO>
cd graphsec-engine
```

---

## 2. Crie e ative um ambiente virtual (Opcional)

### Windows

```bash
python -m venv env
env\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv env
source env/bin/activate
```

---

## 3. Instale as dependências

```bash
pip install networkx
```

ou

```bash
pip install -r requirements.txt
```

---

## 4. Execute o motor antifraude

```bash
python fraude_graph_v2.py
```

---

# 📊 Saída Esperada

Durante a execução, o sistema:

1. Realiza a ingestão dos eventos contidos em `dados_v2.json`
2. Constrói a topologia da rede em memória
3. Executa as regras de correlação e detecção
4. Identifica comportamentos suspeitos
5. Exibe o diagnóstico de segurança no terminal

Exemplos de alertas:

```text
[ALERTA] Possível fraude em anel detectada

[ALERTA] Hardware comprometido reutilizado

[ALERTA] Possível Account Takeover identificado

[OK] Tráfego legítimo identificado
```

---

# 🔒 Conceitos Demonstrados

- Graph Analytics
- Fraud Detection
- Device Fingerprinting
- Velocity Checks
- Graph Traversal
- Cybersecurity
- Risk Analysis
- Behavioral Analysis
- Property Graph Modeling

---

# 🗺️ Possíveis Evoluções

- [ ] Persistência em Neo4j
- [ ] API REST para consulta em tempo real
- [ ] Dashboard de monitoramento
- [ ] Sistema de score de risco
- [ ] Machine Learning para classificação de eventos
- [ ] Integração com Kafka para processamento contínuo
- [ ] Visualização gráfica da rede de relacionamentos

---

# 👨‍💻 Desenvolvedor

**Wálisson Andrey Sales Dutra**

Computer Science • Backend Development • Data Engineering • Cybersecurity