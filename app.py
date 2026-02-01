import os
import socket
import psutil
import json
import time
import csv
import io
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from dotenv import load_dotenv
from fpdf import FPDF

# Carrega variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'chave_secreta_fortilog_2026')

# --- CONFIGURAÇÕES DE CAMINHOS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOG_FILE = os.getenv('LOG_PATH', '/opt/fortilog/logs/fortigate.log')

# --- CONFIGURAÇÃO DOS ARQUIVOS JSON ---
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
    """Cria arquivos inexistentes com dados padrão."""
    arquivos = [ENV_FILE_USERS, ENV_FILE_SERVERS, ENV_FILE_MACS, ENV_FILE_GROUPS, 
                ENV_FILE_NETWORKS, ENV_FILE_ALERTS_CONFIG, ENV_FILE_ALERTS_LOG, ENV_FILE_DEVICES]

    print("--- Verificando integridade dos arquivos de dados ---")
    for filename in arquivos:
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            try:
                data = {}
                if filename == ENV_FILE_USERS:
                    data = {"admin": {"senha": "admin", "role": "ADM", "nome": "Administrador", "ativo": True}}
                elif filename == ENV_FILE_MACS:
                    default_env = os.getenv('DEFAULT_DEVICES')
                    if default_env:
                        try: data = json.loads(default_env)
                        except: pass
                
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
                print(f"✅ Arquivo criado: {filename}")
            except Exception as e:
                print(f"❌ Erro ao criar {filename}: {e}")
    print("---------------------------------------------------")

init_files()

# --- FUNÇÕES AUXILIARES ---

def load_json(filename, default=None):
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return default if default is not None else {}

def save_json(filename, data):
    try:
        with open(os.path.join(DATA_DIR, filename), 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Erro ao salvar: {e}")

def get_log_datetime(log_entry):
    try:
        dt_str = f"{log_entry.get('date')} {log_entry.get('time')}"
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    except:
        return datetime.min

def parse_fortigate_logs():
    logs = []
    if not os.path.exists(LOG_FILE): return []

    devices_map = load_json(ENV_FILE_MACS, {})
    groups_map = load_json(ENV_FILE_GROUPS, {})
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-5000:]
            
        # Lê de trás pra frente (mais recentes primeiro)
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
            except: continue 
    except: pass
    return logs

def get_sys_info():
    try:
        return {
            'hostname': socket.gethostname(),
            'cpu': psutil.cpu_percent(interval=None),
            'ram_used': round(psutil.virtual_memory().used / (1024**3), 2),
            'disk_percent': psutil.disk_usage('/').percent
        }
    except: return {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        users_db = load_json(ENV_FILE_USERS)
        
        if not users_db: # Fallback
            users_db = {"admin": {"senha": "admin", "role": "ADM"}}
            save_json(ENV_FILE_USERS, users_db)

        if user in users_db and users_db[user]['senha'] == pwd:
            session['usuario'] = user
            session['role'] = users_db[user].get('role', 'VIEWER')
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas', 'danger')
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
    limite = agora - timedelta(hours=24)
    logs_24h = [l for l in logs if get_log_datetime(l) >= limite]
    
    permitidos = len([l for l in logs_24h if l.get('action') in ['accept', 'allow', 'permit']])
    fabricantes = {}
    for l in logs_24h:
        os = l.get('osname', 'Outros')
        fabricantes[os] = fabricantes.get(os, 0) + 1
    
    return render_template('dashboard.html', sys_info=get_sys_info(),
                         total=len(logs_24h), permitidos=permitidos, bloqueados=len(logs_24h)-permitidos,
                         labels_fab=list(fabricantes.keys()), values_fab=list(fabricantes.values()))

@app.route('/logs-realtime', methods=['GET', 'POST'])
@login_required
def logs_realtime():
    # 1. Filtros
    term = request.form.get('term', '').lower()
    action_btn = request.form.get('action_btn', 'filter')
    
    if request.method == 'POST':
        show_allowed = 'show_allowed' in request.form
        show_blocked = 'show_blocked' in request.form
    else:
        show_allowed, show_blocked = True, True

    # 2. Processamento (Últimas 24h)
    logs = parse_fortigate_logs() # Já vem ordenado do mais recente para o mais antigo
    limite = datetime.now() - timedelta(hours=24)
    logs_filtrados = []

    for l in logs:
        # Filtro de tempo
        if get_log_datetime(l) < limite: continue
        
        # Filtro de ação
        allowed = l.get('action') in ['accept', 'allow', 'permit']
        if allowed and not show_allowed: continue
        if not allowed and not show_blocked: continue
        
        # Filtro de busca
        content = f"{l.get('srcip')} {l.get('srcname')} {l.get('dstip')} {l.get('service')} {l.get('policyname')}".lower()
        if term and term not in content: continue
        
        logs_filtrados.append(l)

    # --- EXPORTAÇÃO CSV ---
    if action_btn == 'csv':
        si = io.StringIO()
        cw = csv.writer(si, delimiter=';')
        cw.writerow(['Data', 'Hora', 'Origem', 'IP Origem', 'Destino', 'Aplicação', 'Ação', 'Política'])
        for l in logs_filtrados:
            cw.writerow([l.get('date'), l.get('time'), l.get('srcname'), l.get('srcip'), 
                         l.get('dstip'), l.get('service'), l.get('action'), l.get('policyname')])
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=realtime_{int(time.time())}.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    # --- EXPORTAÇÃO PDF ---
    if action_btn == 'pdf':
        class PDF(FPDF):
            def header(self):
                self.set_font('Arial', 'B', 12)
                self.cell(0, 10, 'Logs em Tempo Real (Ultimas 24h)', 0, 1, 'C')
                self.ln(5)
            def footer(self):
                self.set_y(-15)
                self.set_font('Arial', 'I', 8)
                self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

        pdf = PDF(orientation='L')
        pdf.add_page()
        pdf.set_font("Arial", size=8)
        
        cols = [30, 25, 40, 30, 40, 25, 20, 40]
        headers = ['Data/Hora', 'IP Origem', 'Nome Origem', 'MAC', 'Destino', 'App', 'Acao', 'Politica']
        
        pdf.set_fill_color(200, 220, 255)
        for i, h in enumerate(headers):
            pdf.cell(cols[i], 7, h, 1, 0, 'C', True)
        pdf.ln()
        
        # Limita a 500 linhas no PDF para não estourar
        for l in logs_filtrados[:500]: 
            dh = f"{l.get('date')} {l.get('time')}"
            row = [dh, l.get('srcip',''), l.get('srcname',''), l.get('srcmac',''), 
                   l.get('dstip',''), l.get('service',''), l.get('action',''), l.get('policyname','')]
            
            for i in range(8):
                pdf.cell(cols[i], 6, str(row[i])[:20], 1)
            pdf.ln()

        response = make_response(pdf.output(dest='S').encode('latin-1', 'ignore'))
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=realtime_{int(time.time())}.pdf'
        return response
    
    return render_template('logs_realtime.html', logs=logs_filtrados, term=term,
                           show_allowed=show_allowed, show_blocked=show_blocked, sys_info=get_sys_info())

@app.route('/logs-relatorio', methods=['GET', 'POST'])
@login_required
def logs_relatorio():
    # Parâmetros
    agora = datetime.now()
    start = request.form.get('start_time', (agora - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M"))
    end = request.form.get('end_time', agora.strftime("%Y-%m-%dT%H:%M"))
    term = request.form.get('term', '').lower()
    action_btn = request.form.get('action_btn', 'filter')
    
    # Checkboxes
    if request.method == 'POST':
        show_allowed = 'show_allowed' in request.form
        show_blocked = 'show_blocked' in request.form
    else:
        show_allowed, show_blocked = True, True

    logs_filtrados = []
    if request.method == 'POST' or True: # Sempre carrega
        try:
            dt_ini = datetime.strptime(start, "%Y-%m-%dT%H:%M")
            dt_fim = datetime.strptime(end, "%Y-%m-%dT%H:%M")
            all_logs = parse_fortigate_logs()
            
            for l in all_logs:
                # Filtro Data
                ldt = get_log_datetime(l)
                if not (dt_ini <= ldt <= dt_fim): continue
                
                # Filtro Ação
                allowed = l.get('action') in ['accept', 'allow', 'permit']
                if allowed and not show_allowed: continue
                if not allowed and not show_blocked: continue
                
                # Filtro Texto
                if term:
                    content = f"{l.get('srcip')} {l.get('srcname')} {l.get('srcmac')} {l.get('dstip')} {l.get('service')} {l.get('policyname')}".lower()
                    if term not in content: continue
                
                logs_filtrados.append(l)
        except: flash('Erro na data', 'warning')

    # --- EXPORTAÇÃO CSV ---
    if action_btn == 'csv':
        si = io.StringIO()
        cw = csv.writer(si, delimiter=';')
        cw.writerow(['Data', 'Hora', 'Origem', 'IP Origem', 'Destino', 'Aplicação', 'Ação', 'Política'])
        for l in logs_filtrados:
            cw.writerow([l.get('date'), l.get('time'), l.get('srcname'), l.get('srcip'), 
                         l.get('dstip'), l.get('service'), l.get('action'), l.get('policyname')])
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=relatorio_{int(time.time())}.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    # --- EXPORTAÇÃO PDF ---
    if action_btn == 'pdf':
        class PDF(FPDF):
            def header(self):
                self.set_font('Arial', 'B', 12)
                self.cell(0, 10, 'Relatorio de Logs - FortiLog Monitor', 0, 1, 'C')
                self.ln(5)
            def footer(self):
                self.set_y(-15)
                self.set_font('Arial', 'I', 8)
                self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

        pdf = PDF(orientation='L')
        pdf.add_page()
        pdf.set_font("Arial", size=8)
        
        cols = [30, 25, 40, 30, 40, 25, 20, 40]
        headers = ['Data/Hora', 'IP Origem', 'Nome Origem', 'MAC', 'Destino', 'App', 'Acao', 'Politica']
        
        pdf.set_fill_color(200, 220, 255)
        for i, h in enumerate(headers):
            pdf.cell(cols[i], 7, h, 1, 0, 'C', True)
        pdf.ln()
        
        for l in logs_filtrados:
            dh = f"{l.get('date')} {l.get('time')}"
            row = [dh, l.get('srcip',''), l.get('srcname',''), l.get('srcmac',''), 
                   l.get('dstip',''), l.get('service',''), l.get('action',''), l.get('policyname','')]
            
            for i in range(8):
                pdf.cell(cols[i], 6, str(row[i])[:20], 1)
            pdf.ln()

        response = make_response(pdf.output(dest='S').encode('latin-1', 'ignore'))
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=relatorio_{int(time.time())}.pdf'
        return response

    return render_template('logs_relatorio.html', logs=logs_filtrados, start_time=start, end_time=end, 
                           term=term, show_allowed=show_allowed, show_blocked=show_blocked, sys_info=get_sys_info())

# --- OUTRAS ROTAS ---
@app.route('/dispositivos', methods=['GET', 'POST'])
@login_required
def dispositivos():
    devices = load_json(ENV_FILE_MACS)
    if request.method == 'POST':
        act = request.form.get('action')
        mac = request.form.get('mac')
        if act == 'delete' and mac in devices: del devices[mac]
        else: devices[mac] = request.form.get('nome')
        save_json(ENV_FILE_MACS, devices)
    return render_template('dispositivos.html', devices=devices, sys_info=get_sys_info())

@app.route('/destinos', methods=['GET', 'POST'])
@login_required
def destinos():
    redes = load_json(ENV_FILE_NETWORKS)
    if request.method == 'POST':
        act = request.form.get('action')
        cidr = request.form.get('cidr')
        if act == 'delete' and cidr in redes: del redes[cidr]
        elif act == 'add': redes[cidr] = request.form.get('nome')
        save_json(ENV_FILE_NETWORKS, redes)
    
    logs = parse_fortigate_logs()
    count = {}
    for l in logs:
        dst = l.get('service', l.get('dstip'))
        count[dst] = count.get(dst, 0) + 1
    top = sorted(count.items(), key=lambda x:x[1], reverse=True)[:10]
    return render_template('destinos.html', top_destinos=top, redes=redes, sys_info=get_sys_info())

@app.route('/grupos')
@login_required
def grupos():
    return render_template('grupos.html', mapa=load_json(ENV_FILE_GROUPS), sys_info=get_sys_info())

@app.route('/alertas', methods=['GET', 'POST'])
@login_required
def alertas():
    if request.method == 'POST': flash('Salvo!', 'success')
    return render_template('alertas.html', config=load_json(ENV_FILE_ALERTS_CONFIG), sys_info=get_sys_info())

@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
def usuarios():
    users = load_json(ENV_FILE_USERS)
    if request.method == 'POST':
        login = request.form.get('login')
        users[login] = {"senha": request.form.get('senha'), "role": request.form.get('nivel'), 
                        "nome": request.form.get('nome'), "ativo": True}
        save_json(ENV_FILE_USERS, users)
    return render_template('usuarios.html', users=users, sys_info=get_sys_info())

@app.route('/usuarios/excluir/<login>', methods=['POST'])
@login_required
def excluir_usuario(login):
    users = load_json(ENV_FILE_USERS)
    if login in users and login != session.get('usuario'):
        del users[login]
        save_json(ENV_FILE_USERS, users)
    return redirect(url_for('usuarios'))

@app.route('/api/stats')
def api_stats(): return jsonify(get_sys_info())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)