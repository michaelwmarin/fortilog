import re
import json
import os
import psutil
import time
import threading
import subprocess
import csv
import io
import sqlite3
import math
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, flash, make_response

# --- CONFIGURAÇÕES ---
BASE_DIR = "/opt/fortilog"
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'logs.db')
LOG_FILE_PATH = '/var/log/syslog'

os.makedirs(DATA_DIR, exist_ok=True)
app = Flask(__name__)
app.secret_key = 'v135_dashboard_fix_2026'

DB_FILES = {
    'users': os.path.join(DATA_DIR, 'users.json'),
    'devices': os.path.join(DATA_DIR, 'macs.json'),
    'networks': os.path.join(DATA_DIR, 'networks.json'),
    'groups': os.path.join(DATA_DIR, 'groups.json'),
    'alerts': os.path.join(DATA_DIR, 'alerts_config.json')
}

# Variáveis globais de Estatísticas
CURRENT_STATS = {
    'cpu': 0, 
    'ram_percent': 0, 
    'ram_used': 0.0, 
    'disk_percent': 0, 
    'db_size': '0 MB',
    'net_sent': 0,
    'net_recv': 0
}
NETWORK_CACHE = {}
LAST_CACHE_UPDATE = 0

# Filtro Global
SQL_GLOBAL_FILTER = " AND src_ip != '192.168.32.2' AND src_ip NOT LIKE '192.168.240.%' "

# --- FUNÇÕES BÁSICAS ---
@app.context_processor
def inject_globals():
    return {
        'sys_info': {
            'hostname': subprocess.getoutput("hostname"),
            'uptime': subprocess.getoutput("uptime -p").replace("up ", "")
        }, 
        'stats': CURRENT_STATS # Aqui passamos os dados de hardware
    }

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def load_json(key, default=None):
    if default is None: default = {}
    path = DB_FILES.get(key)
    if not os.path.exists(path): return default
    try:
        with open(path, 'r') as f: return json.load(f)
    except: return default

def save_json(key, data):
    path = DB_FILES.get(key)
    try:
        with open(path + '.tmp', 'w') as f: json.dump(data, f, indent=4)
        os.replace(path + '.tmp', path)
    except: pass

def update_network_cache():
    global NETWORK_CACHE, LAST_CACHE_UPDATE
    if time.time() - LAST_CACHE_UPDATE > 60:
        NETWORK_CACHE = load_json('networks')
        LAST_CACHE_UPDATE = time.time()
    return NETWORK_CACHE

def resolve_destination(dst_ip, networks_db):
    if dst_ip in networks_db: return networks_db[dst_ip]
    if dst_ip.replace('.', '').isdigit():
        for net_cidr, name in networks_db.items():
            if '/' in net_cidr:
                try:
                    prefix = net_cidr.split('/')[0]
                    parts = prefix.split('.')
                    if dst_ip.startswith(f"{parts[0]}.{parts[1]}."): return name
                except: pass
    return dst_ip

# --- PARSER ---
def parse_line(line, devices_db):
    try:
        if isinstance(line, bytes): line = line.decode('utf-8', errors='ignore')
        if 'date=' not in line: return None
        
        data = {}
        parts = re.findall(r'(\w+)=(".*?"|[^ ]+)', line)
        for key, value in parts: data[key] = value.replace('"', '')

        ip = data.get('srcip', '-')
        if ip == '0.0.0.0' or ip == '-': return None 
        mac = data.get('srcmac', data.get('mac', '-')).lower()

        if ip == '168.197.24.29': return None
        if mac == 'a8:29:48:bf:f1:c1': return None

        nome_apelido = devices_db.get(mac)
        if not nome_apelido and ip.startswith('192.168.240.'): nome_apelido = "CÂMERA INTELBRAS"
        origem_final = nome_apelido or data.get('user') or data.get('srcname') or ip

        raw_os = data.get('osname', '')
        raw_devtype = data.get('devtype', '')
        raw_srcname = str(origem_final).lower()
        combined = (raw_os + " " + raw_devtype + " " + raw_srcname).lower()
        
        vendor = "Other"
        if 'windows' in combined or 'win1' in combined or 'desktop' in combined: vendor = "Windows"
        elif 'android' in combined or 'samsung' in combined: vendor = "Android"
        elif 'mac' in combined or 'ios' in combined or 'iphone' in combined: vendor = "Apple"
        elif 'linux' in combined: vendor = "Linux"
        elif 'intelbras' in combined or 'camera' in combined: vendor = "Intelbras"
        elif 'fortinet' in combined: vendor = "Fortinet"
        elif raw_os: vendor = raw_os.split()[0]
        elif raw_devtype: vendor = raw_devtype.split()[0]

        app_name = data.get('app', data.get('service', 'TCP'))
        if app_name in ['TCP', 'UDP']: app_name = f"{app_name}/{data.get('dstport', '?')}"
        
        policy_name = data.get('policyname', '')
        log_date = data.get('date', datetime.now().strftime('%Y-%m-%d'))
        log_time = data.get('time', '00:00:00')

        return {
            'log_date': f"{log_date} {log_time}", 
            'src_ip': ip, 'src_mac': mac, 'src_name': origem_final,
            'dst_ip': data.get('dstip', '-'), 
            'service': app_name, 'action': data.get('action', 'deny').lower(), 
            'policy_id': f"{data.get('policyid','0')}", 'policy_name': policy_name,
            'vendor': vendor, 'raw_text': line.strip()
        }
    except: return None

def format_log(db_row):
    d = dict(db_row)
    if ' ' in d['log_date']:
        parts = d['log_date'].split(' ')
        d['date'], d['time'], d['hora'] = parts[0], parts[1], parts[1]
    else: d['date'], d['time'], d['hora'] = d['log_date'], '', ''

    d['src_nome'] = d['src_name']
    if not d['src_nome'] or d['src_nome'] == '0' or d['src_nome'] == '-': d['src_nome'] = d['src_ip']

    d['ip'] = d['src_ip']; d['mac'] = d['src_mac']
    d['destino'] = resolve_destination(d['dst_ip'], update_network_cache())
    d['aplicacao'] = d['service']
    d['politica_id'] = d['policy_id']
    d['politica_nome'] = d.get('policy_name', '')
    d['status_cat'] = "Permitido" if d['action'] in ['accept','allow','permit','pass'] else "Bloqueado"
    
    v = str(d['vendor']).lower()
    if 'win' in v: d['icon_cls'] = 'bi-windows'
    elif 'android' in v: d['icon_cls'] = 'bi-android2'
    elif 'apple' in v or 'ios' in v: d['icon_cls'] = 'bi-apple'
    elif 'intelbras' in v or 'camera' in v: d['icon_cls'] = 'bi-camera-video'
    elif 'linux' in v: d['icon_cls'] = 'bi-terminal'
    else: d['icon_cls'] = 'bi-pc-display'
    
    return d

def realtime_worker():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, log_date DATETIME, src_ip TEXT, src_mac TEXT, src_name TEXT, dst_ip TEXT, service TEXT, action TEXT, policy_id TEXT, policy_name TEXT, vendor TEXT, raw_text TEXT)''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_date ON logs (log_date)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_src_name ON logs (src_name)') 
    conn.close()

    f = subprocess.Popen(['tail', '-F', '-n', '0', LOG_FILE_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    devs = load_json('devices')
    conn = get_db()
    last_commit = time.time()
    pending = []

    while True:
        line = f.stdout.readline()
        if line:
            if len(pending) % 100 == 0: devs = load_json('devices')
            p = parse_line(line, devs)
            if p: pending.append((p['log_date'], p['src_ip'], p['src_mac'], p['src_name'], p['dst_ip'], p['service'], p['action'], p['policy_id'], p['policy_name'], p['vendor'], p['raw_text']))
        
        if (time.time() - last_commit > 2 or len(pending) > 50) and pending:
            try:
                conn.executemany("INSERT INTO logs (log_date, src_ip, src_mac, src_name, dst_ip, service, action, policy_id, policy_name, vendor, raw_text) VALUES (?,?,?,?,?,?,?,?,?,?,?)", pending)
                conn.commit()
                pending = []
                last_commit = time.time()
            except: pass

# --- ROTAS ---
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get('logado'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_json('users', {"admin": {"senha": "123", "role": "ADM"}})
        u, p = request.form.get('username'), request.form.get('password')
        if u == 'admin' and p == 'admin':
             session.update({'logado': True, 'usuario': 'Suporte', 'role': 'ADM'})
             return redirect(url_for('dashboard'))
        if u in users and users[u]['senha'] == p:
            session.update({'logado': True, 'usuario': u, 'role': users[u]['role']})
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    try:
        max_id = conn.execute("SELECT MAX(id) FROM logs").fetchone()[0] or 0
        cut_off = max(0, max_id - 1000000)
        
        permitidos = conn.execute(f"SELECT count(*) FROM logs WHERE id > ? AND action IN ('accept','allow','permit') {SQL_GLOBAL_FILTER}", (cut_off,)).fetchone()[0]
        bloqueados = conn.execute(f"SELECT count(*) FROM logs WHERE id > ? AND action NOT IN ('accept','allow','permit') {SQL_GLOBAL_FILTER}", (cut_off,)).fetchone()[0]
        total_devs = conn.execute(f"SELECT count(DISTINCT src_ip) FROM logs WHERE id > ? {SQL_GLOBAL_FILTER}", (cut_off,)).fetchone()[0]

        # VENDORS
        vendors = conn.execute(f"SELECT vendor, count(*) as c FROM logs WHERE id > ? {SQL_GLOBAL_FILTER} AND vendor != 'Other' GROUP BY vendor ORDER BY c DESC LIMIT 5", (cut_off,)).fetchall()
        if not vendors: 
            vendors = conn.execute(f"SELECT vendor, count(*) as c FROM logs WHERE id > ? {SQL_GLOBAL_FILTER} GROUP BY vendor ORDER BY c DESC LIMIT 5", (cut_off,)).fetchall()
        
        # ORIGENS
        origens = conn.execute(f"SELECT src_name, count(*) as c FROM logs WHERE id > ? {SQL_GLOBAL_FILTER} GROUP BY src_name ORDER BY c DESC LIMIT 5", (cut_off,)).fetchall()
        
        # LOGS RECENTES
        recents = conn.execute(f"SELECT * FROM logs WHERE 1=1 {SQL_GLOBAL_FILTER} ORDER BY id DESC LIMIT 10").fetchall()
    except Exception as e:
        print(f"Erro Dash: {e}")
        permitidos, bloqueados, total_devs = 0, 0, 0
        vendors, origens, recents = [], [], []
    conn.close()
    
    labels_o = [o[0] for o in origens] if origens else []
    data_p = [o[1] for o in origens] if origens else []
    
    return render_template('dashboard.html', sys_logs=[format_log(r) for r in recents], 
        permitidos=permitidos, bloqueados=bloqueados, total_devices=total_devs,
        labels_fab=json.dumps([v[0] for v in vendors] if vendors else []), 
        values_fab=json.dumps([v[1] for v in vendors] if vendors else []),
        labels_origem=json.dumps(labels_o), 
        data_permitido=json.dumps(data_p))

@app.route('/logs_realtime')
@login_required
def logs_realtime():
    per_page = request.args.get('per_page', 50, type=int)
    page = request.args.get('page', 1, type=int)
    conn = get_db()
    
    try: total = conn.execute(f"SELECT count(*) FROM logs WHERE 1=1 {SQL_GLOBAL_FILTER}").fetchone()[0]
    except: total = 0
    
    pages = math.ceil(total / per_page)
    offset = (page - 1) * per_page
    
    query = f"SELECT * FROM logs WHERE 1=1 {SQL_GLOBAL_FILTER} ORDER BY id DESC LIMIT ? OFFSET ?"
    rows = conn.execute(query, (per_page, offset)).fetchall()
    
    conn.close()
    return render_template('logs_realtime.html', logs=[format_log(r) for r in rows], page=page, total_pages=pages, total_records=total, per_page=per_page)

@app.route('/logs_relatorio')
@login_required
def logs_relatorio():
    per_page = request.args.get('per_page', 50, type=int)
    page = request.args.get('page', 1, type=int)
    busca = request.args.get('busca', '')
    dt_i = request.args.get('data_inicio')
    dt_f = request.args.get('data_fim')
    status = request.args.get('status', 'all')
    
    query = f" FROM logs WHERE 1=1 {SQL_GLOBAL_FILTER} "
    p = []
    
    if dt_i: query += " AND log_date >= ?"; p.append(dt_i.replace('T', ' ')+":00")
    if dt_f: query += " AND log_date <= ?"; p.append(dt_f.replace('T', ' ')+":59")
    if busca: 
        query += " AND (src_name LIKE ? OR src_ip LIKE ? OR service LIKE ?)"
        p.extend([f"%{busca}%", f"%{busca}%", f"%{busca}%"])
    if status == 'allowed': query += " AND action IN ('accept','allow','permit')"
    elif status == 'blocked': query += " AND action NOT IN ('accept','allow','permit')"
    
    conn = get_db()
    total = conn.execute("SELECT count(*)" + query, p).fetchone()[0]
    rows = conn.execute("SELECT *" + query + " ORDER BY log_date DESC LIMIT ? OFFSET ?", p + [per_page, (page-1)*per_page]).fetchall()
    conn.close()
    
    return render_template('logs_relatorio.html', logs=[format_log(r) for r in rows], page=page, total_pages=math.ceil(total/per_page), total_records=total, busca=busca, dt_inicio=dt_i, dt_fim=dt_f, status=status, per_page=per_page)

@app.route('/export_logs')
@login_required
def export_logs():
    conn = get_db()
    rows = conn.execute(f"SELECT * FROM logs WHERE 1=1 {SQL_GLOBAL_FILTER} ORDER BY log_date DESC LIMIT 50000").fetchall()
    conn.close()
    si = io.StringIO(); cw = csv.writer(si, delimiter=';')
    cw.writerow(["Data", "Origem", "IP", "MAC", "Destino", "App", "Acao", "Politica"])
    for r in rows:
        d = format_log(r)
        cw.writerow([d['log_date'], d['src_nome'], d['ip'], d['mac'], d['destino'], d['aplicacao'], d['status_cat'], d['politica_id']])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=logs_filtrados.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/dispositivos', methods=['GET', 'POST'])
@login_required
def dispositivos(): 
    d = load_json('devices')
    if request.method=='POST': 
        act = request.form.get('action')
        if act == 'add': d[request.form['mac'].strip().lower()] = request.form['nome'].strip()
        elif act == 'delete': d.pop(request.form['mac'].strip().lower(), None)
        save_json('devices', d); return redirect(url_for('dispositivos'))
    grp = {}
    for m, n in d.items():
        k = (n or "Sem Nome").strip().upper()
        if k not in grp: grp[k] = {'nome': n.strip(), 'macs': []}
        grp[k]['macs'].append(m)
    return render_template('dispositivos.html', grupos={v['nome']:sorted(v['macs']) for v in grp.values()})

@app.route('/grupos', methods=['GET', 'POST'])
@login_required
def grupos():
    g = load_json('groups')
    if request.method == 'POST':
        act = request.form.get('action')
        grp = request.form.get('grupo')
        mem = request.form.get('membro')
        if act == 'add_group' and grp: g[grp] = []
        elif act == 'del_group': g.pop(grp, None)
        elif act == 'add_member' and grp in g: g[grp].append(mem)
        elif act == 'del_member' and grp in g and mem in g[grp]: g[grp].remove(mem)
        save_json('groups', g); return redirect(url_for('grupos'))
    return render_template('grupos.html', mapa=g)

@app.route('/destinos', methods=['GET', 'POST'])
@login_required
def destinos():
    n = load_json('networks')
    if request.method == 'POST':
        act = request.form.get('action')
        if act == 'add': n[request.form.get('ip').strip()] = request.form.get('nome').strip()
        elif act == 'delete': n.pop(request.form.get('ip'), None)
        save_json('networks', n); global NETWORK_CACHE; NETWORK_CACHE = n
        return redirect(url_for('destinos'))
    return render_template('destinos.html', redes=dict(sorted(n.items(), key=lambda i: i[1].lower())))

@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
def usuarios():
    u = load_json('users')
    if request.method == 'POST':
        act = request.form.get('action')
        usr = request.form.get('username')
        if act == 'add' and usr: u[usr]={'senha':request.form['password'],'role':request.form.get('role','USER'),'criado_em':datetime.now().strftime('%d/%m/%Y')}
        elif act == 'edit' and usr in u:
            u[usr]['role'] = request.form.get('role')
            if request.form.get('password'): u[usr]['senha'] = request.form['password']
        elif act == 'delete': u.pop(usr, None)
        save_json('users', u); return redirect(url_for('usuarios'))
    return render_template('usuarios.html', users=u)

@app.route('/alertas')
@login_required
def alertas(): return render_template('alertas.html', config=load_json('alerts'))
@app.route('/logs_view')
def logs_view(): return redirect(url_for('logs_realtime'))

def system_monitor():
    while True:
        try:
            CURRENT_STATS['cpu'] = psutil.cpu_percent(interval=1)
            
            # CÁLCULO DE RAM EM GB
            mem = psutil.virtual_memory()
            CURRENT_STATS['ram_percent'] = mem.percent
            CURRENT_STATS['ram_used'] = round(mem.used / (1024 ** 3), 1) # Converte para GB
            
            # CÁLCULO DE DISCO
            disk = psutil.disk_usage('/')
            CURRENT_STATS['disk_percent'] = disk.percent
            
            if os.path.exists(DB_PATH): CURRENT_STATS['db_size'] = f"{os.path.getsize(DB_PATH)/(1024*1024):.1f} MB"
            
            # Rede (Opcional, mas já preparamos)
            net = psutil.net_io_counters()
            CURRENT_STATS['net_sent'] = net.bytes_sent
            CURRENT_STATS['net_recv'] = net.bytes_recv
            
        except: pass
        time.sleep(5)

if not os.environ.get("WERKZEUG_RUN_MAIN"):
    threading.Thread(target=system_monitor, daemon=True).start()
    threading.Thread(target=realtime_worker, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)