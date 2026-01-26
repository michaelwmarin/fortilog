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

# --- CONFIGURAÇÕES DE CAMINHOS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOG_FILE = os.getenv('LOG_PATH', '/opt/fortilog/logs/fortigate.log')

# --- CONFIGURAÇÃO DOS ARQUIVOS JSON (Lendo do .env) ---
ENV_FILE_USERS    = os.getenv('FILE_USERS', 'users.json')
ENV_FILE_SERVERS  = os.getenv('FILE_SERVERS', 'servers.json')
ENV_FILE_MACS     = os.getenv('FILE_MACS', 'macs.json')
ENV_FILE_GROUPS   = os.getenv('FILE_GROUPS', 'groups.json')
ENV_FILE_NETWORKS = os.getenv('FILE_NETWORKS', 'networks.json')
ENV_FILE_ALERTS_CONFIG = os.getenv('FILE_ALERTS_CONFIG', 'alerts_config.json')
ENV_FILE_ALERTS_LOG    = os.getenv('FILE_ALERTS_LOG', 'alerts_log.json')
ENV_FILE_DEVICES  = os.getenv('FILE_DEVICES', 'devices.json') 

# --- INICIALIZAÇÃO DO SISTEMA ---
os.makedirs(DATA_DIR, exist_ok=True)

def init_files():
    """Cria arquivos inexistentes com dados padrão quando necessário."""
    arquivos_para_verificar = [
        ENV_FILE_USERS,
        ENV_FILE_SERVERS,
        ENV_FILE_MACS,
        ENV_FILE_GROUPS,
        ENV_FILE_NETWORKS,
        ENV_FILE_ALERTS_CONFIG,
        ENV_FILE_ALERTS_LOG,
        ENV_FILE_DEVICES
    ]

    print("--- Verificando integridade dos arquivos de dados ---")
    for filename in arquivos_para_verificar:
        path = os.path.join(DATA_DIR, filename)
        
        if not os.path.exists(path):
            try:
                data_to_write = {}
                
                # 1. REGRA DO USUÁRIO PADRÃO
                # Se o arquivo de usuários não existir, cria com o ADMIN padrão
                if filename == ENV_FILE_USERS:
                    data_to_write = {
                        "admin": {
                            "senha": "admin",
                            "role": "ADM",
                            "nome": "Administrador",
                            "email": "admin@fortilog.local",
                            "telegram": "",
                            "grupo_restricao": "Total",
                            "ativo": True
                        }
                    }
                    print(f"👤 Criando {filename} com usuário 'admin' padrão.")

                # 2. REGRA DOS DISPOSITIVOS (MACs)
                # Se for arquivo de MACs, tenta pegar do .env
                elif filename == ENV_FILE_MACS:
                    default_env = os.getenv('DEFAULT_DEVICES')
                    if default_env:
                        try:
                            data_to_write = json.loads(default_env)
                            print(f"⚠️ Criando {filename} usando DEFAULT_DEVICES do .env")
                        except json.JSONDecodeError:
                            print(f"❌ Erro de JSON na variável DEFAULT_DEVICES do .env")

                # Salva o arquivo (vazio, ou com os dados definidos acima)
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data_to_write, f, indent=4)
                
                if filename != ENV_FILE_USERS and filename != ENV_FILE_MACS:
                    print(f"✅ Arquivo criado (vazio): {filename}")
                
            except OSError as e:
                print(f"❌ Erro ao criar {filename}: {e}")
        else:
            print(f"🆗 Arquivo encontrado: {filename}")
    print("---------------------------------------------------")

# Executa a verificação ao iniciar
init_files()

# --- FUNÇÕES AUXILIARES ---

def load_json(filename, default=None):
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, FileNotFoundError):
        return default if default is not None else {}

def save_json(filename, data):
    try:
        path = os.path.join(DATA_DIR, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except OSError as e:
        print(f"Erro ao salvar {filename}: {e}")

def get_log_datetime(log_entry):
    try:
        dt_str = f"{log_entry.get('date')} {log_entry.get('time')}"
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    except:
        return datetime.min

def parse_fortigate_logs():
    logs = []
    if not os.path.exists(LOG_FILE):
        return []

    devices_map = load_json(ENV_FILE_MACS, {})
    groups_map = load_json(ENV_FILE_GROUPS, {})
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-2000:] 
            
        for line in reversed(lines):
            try:
                entry = {}
                parts = line.strip().split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        entry[key] = value.replace('"', '')

                mac = entry.get('srcmac')
                if mac and mac in devices_map:
                    entry['srcname'] = devices_map[mac]
                
                origem = entry.get('srcname', entry.get('srcip', ''))
                entry['grupo'] = groups_map.get(origem, 'Geral')

                logs.append(entry)
            except Exception:
                continue 
    except Exception as e:
        print(f"Erro ao ler logs: {e}")
    return logs

def get_sys_info():
    try:
        return {
            'hostname': socket.gethostname(),
            'cpu': psutil.cpu_percent(interval=None),
            'ram_used': round(psutil.virtual_memory().used / (1024**3), 2),
            'ram_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent
        }
    except:
        return {'hostname': 'Server', 'cpu': 0, 'ram_used': 0, 'ram_percent': 0, 'disk_percent': 0}

# --- DECORATOR DE LOGIN ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_input = request.form.get('username')
        pwd_input = request.form.get('password')
        
        users_db = load_json(ENV_FILE_USERS)
        
        # Fallback de segurança: se mesmo assim o arquivo estiver vazio
        if not users_db:
             flash('Erro crítico: Base de usuários vazia e não pôde ser recuperada.', 'danger')
             return render_template('login.html')
        
        if user_input in users_db and users_db[user_input]['senha'] == pwd_input:
            session['usuario'] = user_input
            session['role'] = users_db[user_input].get('role', 'VIEWER')
            return redirect(url_for('dashboard'))
            
        flash('Usuário ou senha inválidos', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    logs = parse_fortigate_logs()
    agora = datetime.now()
    limite_24h = agora - timedelta(hours=24)
    logs_24h = [l for l in logs if get_log_datetime(l) >= limite_24h]
    
    total = len(logs_24h)
    permitidos = len([l for l in logs_24h if l.get('action') in ['accept', 'allow', 'permit']])
    bloqueados = total - permitidos
    
    fabricantes = {}
    for l in logs_24h:
        os_name = l.get('osname', 'Outros')
        fabricantes[os_name] = fabricantes.get(os_name, 0) + 1
    
    return render_template('dashboard.html', 
                         sys_info=get_sys_info(),
                         total=total,
                         permitidos=permitidos,
                         bloqueados=bloqueados,
                         labels_fab=list(fabricantes.keys()),
                         values_fab=list(fabricantes.values()))

@app.route('/logs-realtime')
@login_required
def logs_realtime():
    todos_logs = parse_fortigate_logs()
    agora = datetime.now()
    limite = agora - timedelta(hours=24)
    logs_recentes = [l for l in todos_logs if get_log_datetime(l) >= limite]
    logs_recentes.reverse() 
    return render_template('logs_realtime.html', logs=logs_recentes, sys_info=get_sys_info())

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
                dt_ini = datetime.strptime(start_time, "%Y-%m-%dT%H:%M")
                dt_fim = datetime.strptime(end_time, "%Y-%m-%dT%H:%M")
                todos = parse_fortigate_logs()
                logs_filtrados = [l for l in todos if dt_ini <= get_log_datetime(l) <= dt_fim]
                logs_filtrados.reverse()
            except ValueError:
                flash('Formato de data inválido.', 'warning')
    return render_template('logs_relatorio.html', logs=logs_filtrados, start_time=start_time, end_time=end_time, sys_info=get_sys_info())

@app.route('/dispositivos', methods=['GET', 'POST'])
@login_required
def dispositivos():
    devices = load_json(ENV_FILE_MACS)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            mac = request.form.get('mac')
            if mac in devices:
                del devices[mac]
                save_json(ENV_FILE_MACS, devices)
                flash('Dispositivo removido.', 'success')
        else: 
            mac = request.form.get('mac')
            nome = request.form.get('nome')
            if mac and nome:
                devices[mac] = nome
                save_json(ENV_FILE_MACS, devices)
                flash('Dispositivo salvo!', 'success')
    return render_template('dispositivos.html', devices=devices, sys_info=get_sys_info())

@app.route('/destinos', methods=['GET', 'POST'])
@login_required
def destinos():
    redes = load_json(ENV_FILE_NETWORKS, {})
    
    if request.method == 'POST':
        if session.get('role') != 'ADM':
            flash('Apenas administradores podem gerenciar redes.', 'danger')
        else:
            action = request.form.get('action')
            
            if action == 'add':
                cidr = request.form.get('cidr')
                nome = request.form.get('nome')
                if cidr and nome:
                    redes[cidr] = nome
                    save_json(ENV_FILE_NETWORKS, redes)
                    flash('Rede monitorada adicionada!', 'success')
                else:
                    flash('Preencha todos os campos.', 'warning')
            
            elif action == 'delete':
                cidr = request.form.get('cidr')
                if cidr in redes:
                    del redes[cidr]
                    save_json(ENV_FILE_NETWORKS, redes)
                    flash('Rede removida.', 'success')

    logs = parse_fortigate_logs()
    contagem = {}
    for l in logs:
        dst = l.get('service', l.get('dstip'))
        contagem[dst] = contagem.get(dst, 0) + 1
    top_destinos = sorted(contagem.items(), key=lambda x: x[1], reverse=True)[:10]

    return render_template('destinos.html', top_destinos=top_destinos, redes=redes, sys_info=get_sys_info())

@app.route('/grupos', methods=['GET'])
@login_required
def grupos():
    mapa = load_json(ENV_FILE_GROUPS, {})
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

@app.route('/alertas', methods=['GET', 'POST'])
@login_required
def alertas():
    config_alertas = load_json(ENV_FILE_ALERTS_CONFIG, {})
    
    if session.get('role') != 'ADM': return redirect(url_for('dashboard'))
    if request.method == 'POST': flash('Configurações salvas!', 'success')
    
    return render_template('alertas.html', sys_info=get_sys_info(), config=config_alertas)

@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
def usuarios():
    if session.get('role') != 'ADM':
        flash('Acesso restrito.', 'danger')
        return redirect(url_for('dashboard'))

    users = load_json(ENV_FILE_USERS)

    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        telegram = request.form.get('telegram')
        login = request.form.get('login')
        senha = request.form.get('senha')
        confirmar_senha = request.form.get('confirmar_senha')
        nivel = request.form.get('nivel')
        grupo_restricao = request.form.get('grupo')

        if not login or not senha:
            flash('Login e Senha são obrigatórios.', 'warning')
        elif senha != confirmar_senha:
            flash('As senhas não coincidem!', 'danger')
        elif login in users:
            flash('Este login já existe.', 'danger')
        else:
            users[login] = {
                "senha": senha,
                "role": nivel,
                "nome": nome,
                "email": email,
                "telegram": telegram,
                "grupo_restricao": grupo_restricao,
                "ativo": True
            }
            save_json(ENV_FILE_USERS, users)
            flash(f'Usuário {login} criado com sucesso!', 'success')
            return redirect(url_for('usuarios'))

    return render_template('usuarios.html', users=users, sys_info=get_sys_info())

@app.route('/usuarios/excluir/<login>', methods=['POST'])
@login_required
def excluir_usuario(login):
    if session.get('role') != 'ADM':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('usuarios'))
    
    if login == session.get('usuario'):
        flash('Você não pode excluir seu próprio usuário logado!', 'warning')
        return redirect(url_for('usuarios'))

    users = load_json(ENV_FILE_USERS)
    
    if login in users:
        del users[login]
        save_json(ENV_FILE_USERS, users)
        flash(f'Usuário {login} excluído com sucesso.', 'success')
    else:
        flash('Usuário não encontrado.', 'warning')
        
    return redirect(url_for('usuarios'))

@app.route('/api/stats')
def api_stats():
    return jsonify(get_sys_info())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)