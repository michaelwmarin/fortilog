import re
import subprocess
import json
import os
import psutil
import time
import threading
import csv
import io
import socket
import urllib.request
import urllib.parse
from datetime import datetime
from dotenv import load_dotenv
from collections import Counter, deque
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, make_response

# Carrega configurações do arquivo .env
load_dotenv()

# ==============================================================================
# CONFIGURAÇÃO GERAL
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Define arquivo de log (Do .env ou padrão)
LOG_FILE_PATH = os.getenv("LOG_PATH", "/var/log/syslog")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_KEY", "v118_smart_memory_final")

# ==============================================================================
# ARQUIVOS DE DADOS (Conectado ao .env)
# ==============================================================================
USERS_FILE         = os.path.join(DATA_DIR, os.getenv('FILE_USERS', 'users.json'))
SERVERS_FILE       = os.path.join(DATA_DIR, os.getenv('FILE_SERVERS', 'servers.json'))
MACS_FILE          = os.path.join(DATA_DIR, os.getenv('FILE_MACS', 'macs.json'))
GROUPS_FILE        = os.path.join(DATA_DIR, os.getenv('FILE_GROUPS', 'groups.json'))
NETS_FILE          = os.path.join(DATA_DIR, os.getenv('FILE_NETWORKS', 'networks.json'))
ALERTS_CONFIG_FILE = os.path.join(DATA_DIR, os.getenv('FILE_ALERTS_CONFIG', 'alerts_config.json'))
ALERTS_LOG_FILE    = os.path.join(DATA_DIR, os.getenv('FILE_ALERTS_LOG', 'alerts_log.json'))

# Telegram
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT_ID_DEFAULT = os.getenv("TG_CHAT_ID")

GLOBAL_ALERTS_STATE = {"count": 0, "messages": []}

POLITICAS_NOMES = {
    "3": "Usuario exeções",
    "5": "REDE_Comercial",
    "9": "LIMITADO",
    "0": "PADRÃO"
}

USER_GROUPS_LIST = [
    "Usuario", "Jovem Aprendiz", "WHATSAPP LIBERADO", "SUPORTE", "FINANCEIRO", "USUARIO_EX"
]

# --- MEMÓRIA ---
DNS_CACHE = {}
KNOWN_HOSTS_CACHE = {} 
ALERT_CACHE = deque(maxlen=50)
LAST_CPU_ALERT = 0

@app.context_processor
def inject_alerts():
    return dict(global_alerts=GLOBAL_ALERTS_STATE)

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================
def save_json(fp, c):
    try:
        with open(fp + '.tmp', 'w') as f: json.dump(c, f, indent=4)
        os.replace(fp + '.tmp', fp)
    except: pass

def load_json(fp, df=None):
    if df is None: df = {}
    if not os.path.exists(fp): save_json(fp, df); return df
    try: 
        with open(fp, 'r') as f: return json.load(f)
    except: return df

def get_sys():
    try: up = subprocess.getoutput("uptime -p").replace("up ", "")
    except: up = "-"
    try: hn = socket.gethostname()
    except: hn = "FortiLog"
    return {'hostname': hn, 'uptime': up}

def send_telegram_msg(msg):
    if not TG_TOKEN or not TG_CHAT_ID_DEFAULT: return
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": TG_CHAT_ID_DEFAULT, "text": msg}).encode()
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req)
    except: pass

def get_os_icon(os_raw, src_name):
    txt = (str(os_raw) + " " + str(src_name)).lower()
    if 'windows' in txt: return 'bi-windows', 'Windows'
    if 'android' in txt: return 'bi-android2', 'Android'
    if 'iphone' in txt: return 'bi-apple', 'Apple iOS'
    if 'mac' in txt: return 'bi-apple', 'MacOS'
    if 'linux' in txt: return 'bi-terminal', 'Linux'
    if 'câmera' in txt or 'intelbras' in txt or 'vigi' in txt: return 'bi-camera-video', 'Câmera IP'
    return 'bi-pc-display', 'Outro'

def detect_vendor(src_nome, os_nome):
    txt = (str(src_nome) + " " + str(os_nome)).lower()
    if 'iphone' in txt or 'mac' in txt or 'apple' in txt: return 'Apple'
    if 'samsung' in txt: return 'Samsung'
    if 'xiaomi' in txt: return 'Xiaomi'
    if 'intelbras' in txt: return 'Intelbras'
    if 'windows' in txt or 'pc' in txt: return 'PC/Windows'
    if 'vigi' in txt or 'tp-link' in txt: return 'TP-Link'
    return 'Outros'

def resolve_hostname(ip):
    if ip in DNS_CACHE: return DNS_CACHE[ip]
    try:
        socket.setdefaulttimeout(0.2)
        name, _, _ = socket.gethostbyaddr(ip)
        DNS_CACHE[ip] = name
        return name
    except:
        DNS_CACHE[ip] = None
        return None

def identificar_nome(d, line, macs_db, nets_db, raw_os, raw_srcname):
    ip_clean = d['ip'].strip()
    
    if d['mac'] != "-":
        nome = macs_db.get(d['mac'].lower().strip())
        if nome: return nome
        
    if ip_clean == "192.168.32.2": return "FortiGate"
    if ip_clean.startswith("192.168.240."): return "CÂMERAS INTELBRAS"
    
    user_match = re.search(r'user="([^"]+)"', line)
    unauth_match = re.search(r'unauthuser="([^"]+)"', line)
    usuario = user_match.group(1) if user_match else (unauth_match.group(1) if unauth_match else None)
    
    maquina = None
    if raw_srcname and raw_srcname not in ["-", "Unknown"]:
        maquina = raw_srcname
        KNOWN_HOSTS_CACHE[ip_clean] = maquina
    
    if not maquina and ip_clean in KNOWN_HOSTS_CACHE:
        maquina = KNOWN_HOSTS_CACHE[ip_clean]

    if usuario and maquina: return f"{usuario} ({maquina})"
    if usuario: return usuario
    if maquina: return maquina
    
    if ip_clean.startswith("192.168.") or ip_clean.startswith("172."):
        dns_name = resolve_hostname(ip_clean)
        if dns_name: return dns_name
    if raw_os and raw_os != "Unknown": return f"Dispositivo {raw_os}"
    return "-"

def get_country_iso(c):
    if not c: return "xx"
    return {"BRAZIL": "br", "UNITED STATES": "us"}.get(c.upper(), "xx")

def parse_line(line, srv, macs, groups, nets):
    if 'srcip=' not in line: return None
    try:
        d = {}
        line = line.strip()
        act = re.search(r'action=["\']?([\w-]+)', line)
        d['acao'] = act.group(1).lower() if act else "unknown"
        pid = re.search(r'policyid=([0-9]+)', line)
        d['policy_raw'] = pid.group(1) if pid else "-"
        d['politica_id'] = f"{d['policy_raw']} ({POLITICAS_NOMES.get(d['policy_raw'], 'ID '+d['policy_raw'])})"
        src = re.search(r'srcip=([0-9\.]+)', line)
        d['ip'] = src.group(1) if src else "-"
        mac = re.search(r'srcmac="([^"]+)"', line)
        d['mac'] = mac.group(1).lower() if mac else "-"
        os_match = re.search(r'osname="([^"]+)"', line)
        raw_os = os_match.group(1) if os_match else ""
        
        srcname_match = re.search(r'srcname=(?:"([^"]+)"|(\S+))', line)
        raw_srcname = ""
        if srcname_match:
            raw_srcname = srcname_match.group(1) if srcname_match.group(1) else srcname_match.group(2)
        
        d['src_nome'] = identificar_nome(d, line, macs, nets, raw_os, raw_srcname)
        d['icon_cls'], d['os_nome'] = get_os_icon(raw_os, d['src_nome'])
        d['vendor'] = detect_vendor(d['src_nome'], d['os_nome'])
        country = re.search(r'dstcountry="([^"]+)"', line)
        d['pais_nome'] = country.group(1) if country else "Unknown"
        d['pais_iso'] = get_country_iso(d['pais_nome']) 
        dst = re.search(r'dstip=([0-9\.]+)', line)
        dst_ip = dst.group(1) if dst else "-"
        host = re.search(r'hostname="([^"]+)"', line)
        srv_name = host.group(1) if host else srv.get(dst_ip)
        d['destino'] = f"{dst_ip} ({srv_name})" if srv_name else dst_ip
        dt = re.search(r'date=([\d-]+)', line)
        tm = re.search(r'time=([\d:]+)', line)
        d['hora'] = f"{dt.group(1)} {tm.group(1)}" if dt and tm else line[:15]
        sent = re.search(r'sentbyte=(\d+)', line)
        d['bytes_sent'] = int(sent.group(1)) if sent else 0
        service_match = re.search(r'service=["\']?([^"\']+)["\']?', line)
        d['servico'] = service_match.group(1) if service_match else "Geral"
        st = "Permitido"
        if any(x in d['acao'] for x in ['deny', 'block', 'drop', 'rst', 'timeout']): st = "Bloqueado"
        d['status_cat'] = st
        return d
    except: return None

# --- BUSCA DE LOGS ---
def get_logs_data(limit=1000, dt_ini=None, dt_fim=None, busca_filtro=None, ler_tudo=False):
    logs = []
    srv = load_json(SERVERS_FILE); macs = load_json(MACS_FILE)
    groups = load_json(GROUPS_FILE); nets = load_json(NETS_FILE)
    user_group = session.get('group_access', 'TODOS')
    allowed_ips = [k for k, v in groups.items() if v == user_group] if user_group != 'TODOS' else []
    
    try:
        cmd = ""
        if busca_filtro and len(busca_filtro) > 1:
            cmd = f"grep -a -h -i '{busca_filtro}' {LOG_FILE_PATH}"
        elif dt_ini:
            cmd = f"grep -a -h 'date={dt_ini}' {LOG_FILE_PATH}"
        else:
            lines_to_read = 100000 if ler_tudo else 50000
            cmd = f"tail -n {lines_to_read} {LOG_FILE_PATH}"

        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore')
        out, _ = process.communicate(timeout=90)
        lines = out.splitlines()
        
        if not (dt_ini or busca_filtro): 
            lines = reversed(lines)
            
        count = 0
        for line in lines:
            if 'type=' not in line or 'srcip=' not in line: continue
            d = parse_line(line, srv, macs, groups, nets)
            if d:
                if dt_fim:
                    if d['hora'].split()[0] > dt_fim: continue
                if dt_ini and dt_ini not in d['hora']: continue
                if not (dt_ini or busca_filtro) and d.get('policy_raw') == "0": continue
                if (d['ip'] == "192.168.32.2") and session.get('role') != 'ADM': continue
                if user_group != 'TODOS' and d['ip'] not in allowed_ips and d['src_nome'] not in allowed_ips: continue
                logs.append(d)
                count += 1
                if count >= limit: break
        
        if dt_ini or busca_filtro: logs.reverse()
            
    except: pass
    return logs

def get_system_logs():
    try:
        cmd = "tail -n 20000 /var/log/syslog"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True, errors='ignore')
        out, _ = p.communicate()
        events = []
        regex_iso = re.compile(r'^(\S+) (\S+) ([^:]+): (.*)$')
        regex_old = re.compile(r'^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+) (\S+) ([^:]+): (.*)$')
        for line in reversed(out.splitlines()):
            if 'srcip=' in line or 'devid=' in line or 'devname=' in line or 'type=' in line: continue
            if 'fortilog' in line and 'python' in line: continue 
            match = regex_iso.match(line)
            if match:
                raw_date, host, proc, msg = match.groups(); hora = raw_date[:19].replace('T', ' ')
            else:
                match_old = regex_old.match(line)
                if match_old: hora, host, proc, msg = match_old.groups()
                else: continue
            if "fortilog" in proc: continue 
            events.append({'hora': hora, 'processo': proc, 'msg': msg})
            if len(events) >= 50: break
        return events
    except: return []

# ==============================================================================
# MONITOR 24H E ALERTAS
# ==============================================================================
MAX_POINTS = 1440
HISTORY = {'cpu': [0]*MAX_POINTS, 'mem': [0]*MAX_POINTS, 'net_sent': [0]*MAX_POINTS, 'net_recv': [0]*MAX_POINTS, 'labels': [""]*MAX_POINTS}
LAST_NET = {'sent': 0, 'recv': 0}
CURRENT_STATS = {'cpu': 0, 'mem_used': 0, 'mem_percent': 0, 'net_sent': 0, 'net_recv': 0, 'disk_percent': 0, 'disk_free': 0}

def check_alerts(cpu):
    global LAST_CPU_ALERT
    if cpu > 90:
        now = time.time()
        if (now - LAST_CPU_ALERT) > 300:
            send_telegram_msg(f"🔥 *ALERTA CRÍTICO*\nO servidor FortiLog está com CPU em *{cpu}%*!")
            LAST_CPU_ALERT = now
    try:
        cmd = "tail -n 20 /var/log/syslog"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True, errors='ignore')
        out, _ = p.communicate()
        for line in out.splitlines():
            if "sshd" in line and ("Accepted password" in line or "Failed password" in line):
                if line not in ALERT_CACHE:
                    ALERT_CACHE.append(line)
                    status = "✅ SUCESSO" if "Accepted" in line else "🚨 FALHA"
                    user = re.search(r'for (invalid user )?(\w+)', line)
                    user_str = user.group(2) if user else "Desconhecido"
                    ip = re.search(r'from ([\d\.]+)', line)
                    ip_str = ip.group(1) if ip else "IP Oculto"
                    msg = f"{status}: Acesso SSH\n👤 Usuário: {user_str}\n🌐 IP: {ip_str}\n🖥️ Servidor: FortiLog"
                    send_telegram_msg(msg)
    except: pass

def data_collector():
    # CORREÇÃO F824: LAST_NET removido do global
    global CURRENT_STATS
    last_history_update = 0
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            io_net = psutil.net_io_counters()
            du = psutil.disk_usage('/')
            
            s_inst = max(0, io_net.bytes_sent - LAST_NET['sent']) / 1024
            r_inst = max(0, io_net.bytes_recv - LAST_NET['recv']) / 1024
            
            LAST_NET['sent'] = io_net.bytes_sent
            LAST_NET['recv'] = io_net.bytes_recv
            
            CURRENT_STATS = {
                'cpu': cpu, 'mem_used': round(mem.used/(1024**3), 2), 'mem_percent': mem.percent,
                'net_sent': s_inst, 'net_recv': r_inst, 'disk_percent': du.percent, 'disk_free': round(du.free/(1024**3), 1)
            }
            check_alerts(cpu)
            
            if time.time() - last_history_update > 60:
                now_str = datetime.now().strftime("%H:%M")
                HISTORY['cpu'].pop(0); HISTORY['cpu'].append(cpu)
                HISTORY['mem'].pop(0); HISTORY['mem'].append(CURRENT_STATS['mem_used'])
                HISTORY['net_sent'].pop(0); HISTORY['net_sent'].append(s_inst)
                HISTORY['net_recv'].pop(0); HISTORY['net_recv'].append(r_inst)
                HISTORY['labels'].pop(0); HISTORY['labels'].append(now_str)
                last_history_update = time.time()
        except: pass
        time.sleep(2)

t_data = threading.Thread(target=data_collector, daemon=True)
t_data.start()

# ==============================================================================
# ROTAS FLASK
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        try:
            u = load_json(USERS_FILE)
            if 'FortiLog' not in u:
                u['FortiLog'] = {"senha": "@FortiLog191207", "role": "ADM", "telegram": TG_CHAT_ID_DEFAULT}
                save_json(USERS_FILE, u)
            user = request.form.get('username')
            pwd = request.form.get('password')
            if user in u and u[user]['senha'] == pwd:
                session['logado'] = True; session['role'] = u[user]['role']
                session['usuario'] = user; session['group_access'] = u[user].get('group_access', 'TODOS')
                return redirect(url_for('dashboard') if session['role'] == 'ADM' else url_for('logs_view'))
            else: erro = "Login incorreto."
        except: erro = "Erro login."
    return render_template('login.html', erro=erro)

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@app.route('/')
def dashboard():
    if not session.get('logado'): return redirect(url_for('login'))
    try:
        logs = get_logs_data(limit=100)
        devices_unique = {}
        logs_graficos = []
        for l in logs:
            logs_graficos.append(l)
            dev_id = l['mac'] if l['mac'] != '-' else l['ip']
            if dev_id not in devices_unique: devices_unique[dev_id] = {'os': l['os_nome'], 'vendor': l['vendor']}
        c_vendor = Counter([d['vendor'] for d in devices_unique.values()])
        c_acoes = Counter([l['status_cat'] for l in logs_graficos])
        stacked = {}
        for l in logs_graficos:
            s = l.get('src_nome') or l['ip']
            if s not in stacked: stacked[s] = {'Permitido':0, 'Bloqueado':0}
            stacked[s][l['status_cat']] += 1
        top_src = sorted(stacked.items(), key=lambda x: x[1]['Permitido']+x[1]['Bloqueado'], reverse=True)[:10]
        return render_template('dashboard.html', 
            sys_info=get_sys(), 
            chart_acoes=[c_acoes.get('Permitido', 0), c_acoes.get('Bloqueado', 0)], 
            chart_stacked={'labels': [k for k,v in top_src], 'permitido': [v['Permitido'] for k,v in top_src], 'bloqueado': [v['Bloqueado'] for k,v in top_src]},
            initial_history=HISTORY, 
            chart_vendor={'labels': list(c_vendor.keys()), 'data': list(c_vendor.values())}, 
            total_devices=len(devices_unique))
    except: return "Erro DB"

@app.route('/logs')
def logs_view():
    if not session.get('logado'): return redirect(url_for('login'))
    dt_ini = request.args.get('data_inicio'); dt_fim = request.args.get('data_fim')
    busca = request.args.get('busca', '').lower(); st_f = request.args.getlist('status')
    try: limit = int(request.args.get('server_limit', 500))
    except: limit = 500
    raw_logs = get_logs_data(limit=limit, dt_ini=dt_ini, dt_fim=dt_fim, busca_filtro=busca, ler_tudo=(dt_ini or busca))
    final_logs = []
    for l in raw_logs:
        if busca and busca not in str(l.values()).lower(): continue
        if st_f and 'todos' not in st_f:
            if 'bloqueado' in st_f and l['status_cat'] == 'Permitido': continue
            if 'permitido' in st_f and l['status_cat'] == 'Bloqueado': continue
        final_logs.append(l)
    return render_template('logs.html', logs=final_logs, count=len(final_logs), limit=limit, sys_info=get_sys())

@app.route('/export_logs')
def export_logs():
    if not session.get('logado'): return redirect(url_for('login'))
    logs = get_logs_data(limit=100000, dt_ini=request.args.get('data_inicio'), dt_fim=request.args.get('data_fim'), busca_filtro=request.args.get('busca'), ler_tudo=True)
    si = io.StringIO(); cw = csv.writer(si, delimiter=';')
    cw.writerow(["Data", "Origem", "OS", "IP", "MAC", "Destino", "Pais", "Servico", "Acao", "Politica", "Bytes"])
    for l in logs:
        cw.writerow([l['hora'], l['src_nome'], l['os_nome'], l['ip'], l['mac'], l['destino'], l['pais_nome'], l['servico'], l['acao'], l['politica_id'], l['bytes_sent']])
    out = make_response(si.getvalue())
    out.headers["Content-Disposition"] = "attachment; filename=logs.csv"
    out.headers["Content-type"] = "text/csv"
    return out

@app.route('/dispositivos', methods=['GET','POST'])
def dispositivos():
    if not session.get('logado'): return redirect(url_for('login'))
    m = load_json(MACS_FILE)
    if request.method=='POST':
        if request.form.get('action')=='add': m[request.form['mac'].strip().lower()] = request.form['nome']
        elif request.form.get('action')=='delete': del m[request.form['del_mac']]
        save_json(MACS_FILE, m)
    return render_template('dispositivos.html', grouped_macs={v:[k for k,val in m.items() if val==v] for v in set(m.values())}, sys_info=get_sys())

@app.route('/usuarios', methods=['GET','POST'])
def usuarios():
    if not session.get('logado') or session.get('role') != 'ADM': return redirect(url_for('logs_view'))
    u = load_json(USERS_FILE)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            u[request.form['new_user'].strip()] = {'senha': request.form['new_pass'], 'role': request.form['new_role'], 'group_access': request.form.get('new_group_access', 'TODOS')}
            save_json(USERS_FILE, u)
        elif action == 'delete':
            if request.form['del_user'] in u: del u[request.form['del_user']]; save_json(USERS_FILE, u)
    return render_template('usuarios.html', users=u, available_groups=sorted(USER_GROUPS_LIST), sys_info=get_sys())

@app.route('/grupos', methods=['GET','POST'])
def grupos():
    if not session.get('logado'): return redirect(url_for('login'))
    g = load_json(GROUPS_FILE)
    if request.method=='POST':
        if request.form.get('action')=='add': g[request.form['membro'].strip()] = request.form['grupo'].strip()
        elif request.form.get('action')=='delete': 
            if request.form['del_membro'] in g: del g[request.form['del_membro']]
        save_json(GROUPS_FILE, g)
    all = {}; user_d = {}; serv_d = {}
    for k, v in g.items():
        if v not in all: all[v] = []
        all[v].append(k)
    for k, v in all.items():
        if k in USER_GROUPS_LIST: user_d[k] = v
        else: serv_d[k] = v
    return render_template('grupos.html', user_groups=user_d, service_groups=serv_d, sys_info=get_sys())

@app.route('/destinos', methods=['GET','POST'])
def destinos():
    if not session.get('logado'): return redirect(url_for('login'))
    s = load_json(SERVERS_FILE)
    if request.method=='POST':
        if request.form.get('action')=='add': s[request.form['server_ip'].strip()] = request.form['server_name']
        elif request.form.get('action')=='delete': del s[request.form['del_ip']]
        save_json(SERVERS_FILE, s)
    return render_template('destinos.html', grouped_destinos={v:[k for k,val in s.items() if val==v] for v in set(s.values())}, sys_info=get_sys())

@app.route('/recuperar_senha', methods=['POST'])
def recuperar_senha(): return jsonify({'status': 'ok', 'msg': 'Admin notificado!'})

@app.route('/alertas', methods=['GET','POST'])
def alertas():
    if not session.get('logado') or session.get('role') != 'ADM': return redirect(url_for('logs_view'))
    cfg = load_json(ALERTS_CONFIG_FILE); history = load_json(ALERTS_LOG_FILE, [])
    if request.method == 'POST':
        cfg['new_device'] = True if request.form.get('new_device') else False
        save_json(ALERTS_CONFIG_FILE, cfg)
    return render_template('alertas.html', cfg=cfg, history=history, sys_info=get_sys())

@app.route('/api/stats')
def api_stats():
    if not session.get('logado'): return jsonify({})
    data = CURRENT_STATS.copy()
    data['history_sent'] = HISTORY['net_sent']
    data['history_recv'] = HISTORY['net_recv']
    data['history_labels'] = HISTORY['labels']
    data['system_logs'] = get_system_logs()
    return jsonify(data)

if __name__ == '__main__':
    # Permite acesso externo (útil para acessar o WSL pelo Windows)
    app.run(host='0.0.0.0', port=5000, debug=True)