# 🛡️ FortiLog Dashboard

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Dashboard inteligente para monitoramento e auditoria de tráfego em Firewalls FortiGate.

## 🚀 O Problema & A Solução
Analisar arquivos de logs de rede com milhões de linhas diretamente no Excel é lento e ineficiente. O **FortiLog** resolve isso processando os logs diretamente no servidor e entregando uma interface web leve e rápida, separando o tráfego em tempo real das buscas históricas.

## ✨ Principais Funcionalidades
* **⚡ Live View**: Monitoramento contínuo das últimas 24h de tráfego.
* **📂 Auditoria Histórica**: Filtros precisos por Data e Hora para encontrar incidentes específicos.
* **🧹 Smart Cleaning**: Remove automaticamente ruídos de infraestrutura (como tráfego de gerência de roteadores Huawei) para focar no tráfego dos usuários.
* **🔍 Identificação Amigável**: Traduz endereços MAC e IPs para nomes de funcionários e departamentos.

## 🛠️ Tecnologias Utilizadas
* **Backend**: Python com Flask (Processamento de Shell Scripts via subprocess).
* **Frontend**: HTML5, CSS3 (Bootstrap 5) e JavaScript (AJAX para Live Update).
* **Análise de Dados**: Regex avançado para parsing de logs do FortiOS.

## 📸 Demonstração do Dashboard

| ⚡ Monitoramento em Tempo Real | 📋 Relatórios Históricos |
|---|---|
| ![Tempo Real](screenshots/realtime.png) | ![Relatórios](screenshots/report.png) |

---

## 💻 Como Instalar e Rodar

1. **Clone o repositório:**
   ```bash
   git clone [https://github.com/michaelwmarin/fortilog.git](https://github.com/michaelwmarin/fortilog.git)
   cd fortilog

   ```

2. **Instale as dependências:**
   ```bash
   pip install -r requirements.txt

   ```


3. **Configure seus dados:**
* Vá na pasta `data/` e renomeie os arquivos `_sample.json` para `.json`.
* Adicione seus endereços MAC e nomes de servidores.


4. **Inicie o Dashboard:**
   ```bash
   python app.py

   ```


Acesse em: `http://localhost:5000`

---

🎨 *Projeto desenvolvido por [Michael Marin*](https://www.google.com/search?q=https://github.com/michaelwmarin)