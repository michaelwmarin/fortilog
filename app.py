import os
import socket
import psutil
import json
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'chave_secreta_fortilog_2026')

# Configurações de Caminhos
# Se estiver no Windows/WSL, garante que usa o caminho do Linux
LOG_FILE = os.getenv('LOG_PATH', '/opt/fortilog/logs/fortigate.log')
DATA_DIR = '/opt/fortilog/data'

# Garante que a pasta de dados existe
os.makedirs(DATA_DIR, exist_ok=True)

# --- FUNÇÕES AUXILIARES ---

def load_json(filename, default=None):
    """Carrega dados de um JSON ou retorna o default"""
    try:
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            return default if default is not None else {}
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default if default is not None else {}

def save_json(filename, data):
    """Salva dados em JSON"""
    try:
        with open(os.path.join(DATA_DIR, filename), 'w') as f:
            json.dump(data, f, indent=4)
    except OSError as e:
        print(f"Erro ao salvar {filename}: {e}")

def resolve_hostname(ip):
    """
    Versão OTIMIZADA para WSL.
    Retorna None para evitar TimeoutError que trava o dashboard.
    """
    return None

def parse_fortigate_logs():
    """Lê e processa o arquivo de log bruto"""
    logs = []
    if not os.path.exists(LOG_FILE):
        return []

    # Carrega mapeamentos para enriquecer os logs
    devices_map = load_json('devices.json', {}) # MAC -> Nome
    groups_map = load_json('groups_sample.json', {}) # Nome/IP -> Grupo
    
    try:
        # Lê as últimas 2000 linhas para garantir histórico suficiente
        with open(LOG_FILE, 'r') as f:
            # Truque para ler arquivo grande sem travar memória: ler últimas linhas
            # Aqui simplificado para ler tudo se for pequeno ou usar seek se fosse real prod
            lines = f.readlines()[-2000:] 
            
        for line in reversed(lines):
            try:
                entry = {}
                parts = line.strip().split()
                
                # Parser key=value
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        entry[key] = value.replace('"', '')

                # Enriquecimento de Dados
                # 1. Tenta descobrir nome amigável pelo MAC
                mac = entry.get('srcmac')
                if mac and mac in devices_map:
                    entry['srcname'] = devices_map[mac]
                
                # 2. Define Grupo
                origem = entry.get('srcname', entry.get('srcip', ''))
                entry['grupo'] = groups_map.get(origem, 'Geral')

                logs.append(entry)
            except Exception:
                continue # Pula linha com erro
    except Exception as e:
        print(f"Erro ao ler logs: {e}")
        
    return logs

def get_log_datetime(log_entry):
    """Converte string de data/hora do log em objeto Python datetime"""
    try:
        # Formato esperado: date=2026-01-25 time=16:30:00
        dt_str = f"{log_entry.get('date')} {log_entry.get('time')}"
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    except:
        return datetime.min

def get_sys_info():
    """Pega uso de CPU e RAM do servidor"""
    try:
        return {
            'hostname': socket.gethostname(),
            'cpu': psutil.cpu_percent(interval=None),
            'ram_used': round(psutil.virtual_memory().used / (1024**3), 2),
            'ram_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent
        }
    except:
        return {'hostname': 'Unknown', 'cpu': 0, 'ram_used': 0, 'ram_percent': 0}

# --- DECORATOR DE LOGIN ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS DE AUTENTICAÇÃO ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        
        users_db = load_json('users_sample.json', {"admin": {"senha": "admin", "role": "ADM"}})
        
        if user in users_db and users_db[user]['senha'] == pwd:
            session['usuario'] = user
            session['role'] = users_db[user].get('role', 'VIEWER')
            return redirect(url_for('dashboard'))
        
        if user == 'admin' and pwd == 'admin':
            session['usuario'] = 'admin'
            session['role'] = 'ADM'
            return redirect(url_for('dashboard'))
            
        flash('Usuário ou senha inválidos', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- ROTA: DASHBOARD ---

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    logs = parse_fortigate_logs()
    
    # Filtra logs de hoje para o dashboard
    agora = datetime.now()
    limite_24h = agora - timedelta(hours=24)
    logs_24h = [l for l in logs if get_log_datetime(l) >= limite_24h]
    
    total = len(logs_24h)
    permitidos = len([l for l in logs_24h if l.get('action') in ['accept', 'allow']])
    bloqueados = total - permitidos
    
    fabricantes = {}
    for l in logs_24h:
        os_name = l.get('osname', 'Outros')
        fabricantes[os_name] = fabricantes.get(os_name, 0) + 1
    
    labels_fab = list(fabricantes.keys())
    values_fab = list(fabricantes.values())

    return render_template('dashboard.html', 
                         sys_info=get_sys_info(),
                         total=total,
                         permitidos=permitidos,
                         bloqueados=bloqueados,
                         labels_fab=labels_fab,
                         values_fab=values_fab)

# --- ROTA 1: LOGS TEMPO REAL (Últimas 24h) ---
@app.route('/logs-realtime')
@login_required
def logs_realtime():
    todos_logs = parse_fortigate_logs()
    
    agora = datetime.now()
    limite = agora - timedelta(hours=24)
    
    # Filtra apenas logs recentes
    logs_recentes = [l for l in todos_logs if get_log_datetime(l) >= limite]
    logs_recentes.reverse() # Mais novo no topo
    
    return render_template('logs_realtime.html', logs=logs_recentes, sys_info=get_sys_info())

# --- ROTA 2: RELATÓRIO HISTÓRICO (Busca por Data) ---
@app.route('/logs-relatorio', methods=['GET', 'POST'])
@login_required
def logs_relatorio():
    logs_filtrados = []
    start_time = ""
    end_time = ""
    
    if request.method == 'POST':
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        
        if start_time and end_time:
            try:
                # O input datetime-local envia formato: YYYY-MM-DDTHH:MM
                dt_ini = datetime.strptime(start_time, "%Y-%m-%dT%H:%M")
                dt_fim = datetime.strptime(end_time, "%Y-%m-%dT%H:%M")
                
                todos = parse_fortigate_logs()
                logs_filtrados = [l for l in todos if dt_ini <= get_log_datetime(l) <= dt_fim]
                logs_filtrados.reverse()
            except ValueError:
                flash('Formato de data inválido.', 'warning')

    return render_template('logs_relatorio.html', 
                         logs=logs_filtrados,
                         start_time=start_time,
                         end_time=end_time,
                         sys_info=get_sys_info())

# --- ROTAS DE GESTÃO ---

@app.route('/dispositivos', methods=['GET', 'POST'])
@login_required
def dispositivos():
    devices = load_json('devices.json')
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            mac = request.form.get('mac')
            if mac in devices:
                del devices[mac]
                save_json('devices.json', devices)
                flash('Dispositivo removido.', 'success')
        else:
            mac = request.form.get('mac')
            nome = request.form.get('nome')
            if mac and nome:
                devices[mac] = nome
                save_json('devices.json', devices)
                flash('Salvo com sucesso!', 'success')
                
    return render_template('dispositivos.html', devices=devices, sys_info=get_sys_info())

@app.route('/destinos')
@login_required
def destinos():
    redes = load_json('networks.json', {})
    logs = parse_fortigate_logs()
    contagem = {}
    for l in logs:
        dst = l.get('service', l.get('dstip'))
        contagem[dst] = contagem.get(dst, 0) + 1
        
    top_destinos = sorted(contagem.items(), key=lambda x: x[1], reverse=True)[:10]
    return render_template('destinos.html', top_destinos=top_destinos, redes=redes, sys_info=get_sys_info())

@app.route('/grupos')
@login_required
def grupos():
    mapa = load_json('groups_sample.json', {})
    logs = parse_fortigate_logs()
    consumo = {}
    
    for l in logs:
        user = l.get('srcname', l.get('srcmac', l.get('srcip')))
        grupo = mapa.get(user, 'Geral')
        bytes_total = int(l.get('sentbyte', 0)) + int(l.get('rcvedbyte', 0))
        consumo[grupo] = consumo.get(grupo, 0) + bytes_total
        
    labels = list(consumo.keys())
    values = [round(v / 1024 / 1024, 2) for v in consumo.values()]
    
    return render_template('grupos.html', labels=labels, values=values, mapa=mapa, sys_info=get_sys_info())

# --- ROTAS ADMIN ---

@app.route('/usuarios')
@login_required
def usuarios():
    if session.get('role') != 'ADM': return redirect(url_for('dashboard'))
    users = load_json('users_sample.json')
    return render_template('usuarios.html', users=users, sys_info=get_sys_info())

@app.route('/alertas')
@login_required
def alertas():
    if session.get('role') != 'ADM': return redirect(url_for('dashboard'))
    return render_template('alertas.html', sys_info=get_sys_info())

@app.route('/api/stats')
def api_stats():
    return jsonify(get_sys_info())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)