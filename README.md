# 🛡️ FortiLog Monitor

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **SIEM Leve & Dashboard de Monitoramento Híbrido (FortiGate + Linux Server).**

O **FortiLog Monitor** é uma solução web desenvolvida em **Python (Flask)** para centralizar, visualizar e analisar logs de firewalls Fortigate e, simultaneamente, monitorar a saúde do servidor onde está hospedado.

Com uma interface moderna, responsiva e identidade visual profissional, ele transforma logs brutos em inteligência acionável para equipes de TI e Segurança (SOC/NOC).

---

## 📸 Visão Geral do Dashboard
![Dashboard Principal](screenshots/dashboardp1.png)
*(Visão unificada: Tráfego de Rede + Status de Hardware + Logs do Sistema Operacional)*

---

## 🚀 Funcionalidades Principais

### 📊 1. Monitoramento Híbrido
* **Tráfego de Rede:** Cards de total de conexões, permitidos e bloqueios (Firewall).
* **Hardware Server:** Monitoramento em tempo real de **CPU**, **RAM** e **Disco** do servidor da aplicação.
* **Logs do Sistema (Linux):** Leitura integrada do `/var/log/syslog` para auditoria de processos, CRON e serviços (Systemd).

### ⚡ 2. Análise em Tempo Real & Histórico
* **Feed ao Vivo:** Acompanhe o tráfego conforme ele acontece.
* **Filtros Avançados:** Pesquisa por Texto, IP, Usuário ou Ação (Bloqueado/Permitido).
* **Exportação Profissional:** Botões integrados para gerar relatórios em **PDF** e **CSV** instantaneamente.

### 🎨 3. Visualização de Dados
* **Gráficos Interativos:** Distribuição por Fabricantes (Polar Area) e Top Origens (Barras).
* **Identidade Visual:** Favicon personalizado e layout limpo com Bootstrap 5.

### ⚙️ 4. Gestão e Controle
* **Gestão de Dispositivos:** Mapeamento de MAC Address para nomes amigáveis.
* **Controle de Acesso:** Login seguro e níveis de permissão (Admin/Viewer).
* **Configuração de Alertas:** Definição de triggers para eventos críticos.

---

## 🖼️ Galeria de Telas

| Logs em Tempo Real (Com Exportação) | Relatórios Históricos |
|:---:|:---:|
| ![Logs Realtime](screenshots/logs.png) | ![Relatórios](screenshots/user.png) |

| Gestão de Dispositivos | Monitoramento de Sistema |
|:---:|:---:|
| ![Dispositivos](screenshots/mac.png) | ![Syslog](screenshots/alertas.png) |

---

## 🛠️ Tecnologias Utilizadas

* **Backend:** Python 3, Flask.
* **Frontend:** HTML5, CSS3, Bootstrap 5, Jinja2.
* **Dados & Gráficos:** Chart.js, Pandas (lógica interna).
* **Infraestrutura:** `psutil` (Hardware), `fpdf` (Relatórios PDF).
* **Automação:** Scripts de inicialização automática de JSONs.

---

## ⚙️ Instalação e Execução (Linux/WSL)

1. **Clone o repositório:**
   ```bash
   git clone [https://github.com/michaelwmarin/fortilog.git](https://github.com/michaelwmarin/fortilog.git)
   cd fortilog

```

2. **Crie o Ambiente Virtual (Recomendado):**
```bash
python3 -m venv venv
source venv/bin/activate

```


3. **Instale as dependências:**
```bash
pip install flask psutil python-dotenv fpdf

```


4. **Configuração (.env):**
Crie um arquivo `.env` na raiz:
```ini
SECRET_KEY=sua_chave_secreta
LOG_PATH=/opt/fortilog/logs/fortigate.log
# O sistema criará os JSONs de dados automaticamente na primeira execução

```


5. **Execute a aplicação:**
```bash
python3 app.py

```


6. **Acesse:**
Abra o navegador em `http://localhost:5000`

---

## 📄 Licença

Este projeto está sob a licença MIT. Sinta-se livre para contribuir!

<p align="center">
Desenvolvido com 💙 por <strong>Michael Marin</strong>
</p>
