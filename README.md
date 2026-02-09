# 🛡️ FortiLog Monitor v1.4.4

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3.0-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![Status](https://img.shields.io/badge/Status-Otimizado-brightgreen?style=for-the-badge)

> **SIEM Inteligente e Dashboard de Performance Híbrido.**
> Uma solução leve para centralizar logs de Firewalls **FortiGate** e monitorar a integridade de servidores **Linux** em tempo real.

---

## 🚀 O que há de novo na Versão Turbo?
Após o processamento de grandes volumes de dados (testado com sucesso em ambientes de **104 GB**), o FortiLog foi otimizado para oferecer:

* **⚡ Engine de Busca Otimizada:** Consultas ultra-rápidas que ignoram ruídos de rede (IPs ruidosos e câmeras) direto no banco de dados.
* **📊 Colunas de Precisão:** Correção completa na captura de **Data/Hora**, **MAC Address** e **ID da Política**, garantindo auditoria sem campos vazios.
* **🌡️ Telemetria de Hardware:** Monitoramento real de **CPU**, **Memória RAM (GB)** e **Ocupação de Disco** com indicadores visuais de consumo.

---

## 🛠️ Funcionalidades Principais

### 🔒 Segurança e Logs
* **Análise em Tempo Real:** Feed contínuo de eventos do FortiGate com parser inteligente.
* **Relatórios Históricos:** Filtros avançados por IP ou Nome Amigável com paginação de alta performance.
* **Exportação de Dados:** Gere arquivos **CSV** prontos para auditoria com um clique.

### 🖥️ Gestão de Ativos
* **Nomes Amigáveis:** Vínculo de MAC Address a nomes reais (ex: *DESKTOP-C5DVVFN*).
* **Mapeamento de Destinos:** Identificação de IPs externos e serviços conhecidos (ex: *Microsoft.Portal*).
* **Controle de Acesso:** Sistema de autenticação seguro para níveis de permissão ADM/User.

---

## 📸 Galeria de Telas

| Dashboard Limpo & Rápido | Auditoria de Logs (Fix Data/MAC/ID) |
|:---:|:---:|
| ![Dash](dashboardp1.png) | ![Logs](logs.png) |

---

## ⚙️ Instalação e Configuração

O FortiLog foi desenhado para rodar no diretório `/opt/fortilog`.

1.  **Estrutura de Pastas:**
    ```bash
    /opt/fortilog/
    ├── data/          # logs.db e configurações JSON
    ├── templates/     # Interface HTML (Jinja2)
    ├── static/        # CSS, Ícones e Imagens
    └── app.py         # Motor Principal (Flask)
    ```

2.  **Instalação das Dependências:**
    ```bash
    pip install flask psutil python-dotenv
    ```

3.  **Execução em Segundo Plano (Produção):**
    ```bash
    fuser -k 5000/tcp
    nohup python3 app.py > logs_site_final.txt 2>&1 &
    ```

---

## 🧹 Manutenção e Boas Práticas
Para manter a agilidade do sistema, o FortiLog v1.4.4 suporta rotação de dados. Em bancos de dados acima de **100 GB**, recomendamos o reset periódico ou backup das configurações (`.json`) seguido de um reset do banco para manter a fluidez do SQLite.

   ```bash
   # Backup Rápido de Configurações
   tar -czvf backup_fortilog_configs_$(date +%F).tar.gz /opt/fortilog/data/*.json /opt/fortilog/app.py
   ```

## 📄 Licença e Créditos

Este projeto está sob a licença MIT.

<p align="center">
<strong>Desenvolvido com foco em performance e segurança por Michael Marin 💙</strong>
</p>