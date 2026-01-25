import re
import json
import os
import shutil
import ipaddress

# --- CONFIGURAÇÃO ---
BASE_DIR = '/root/fortilog'
ARQUIVO_ORIGEM = os.path.join(BASE_DIR, 'backups/fgt_objects.txt')
MACS_DESTINO = os.path.join(BASE_DIR, 'data/macs.json')
NETS_DESTINO = os.path.join(BASE_DIR, 'data/networks.json')

def carregar_json(fp):
    if not os.path.exists(fp): return {}
    try:
        with open(fp, 'r') as f: return json.load(f)
    except: return {}

def salvar_json(fp, dados):
    if os.path.exists(fp): shutil.copy(fp, fp + '.backup')
    try:
        with open(fp, 'w') as f: json.dump(dados, f, indent=4)
    except Exception as e: print(f"Erro salvar {fp}: {e}")

def subnet_to_cidr(ip, mask):
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net)
    except: return None

def importar():
    if not os.path.exists(ARQUIVO_ORIGEM):
        print(f"ERRO: {ARQUIVO_ORIGEM} não existe.")
        return

    print("--> Lendo Objetos do FortiGate...")
    try:
        with open(ARQUIVO_ORIGEM, 'r', encoding='utf-8') as f: linhas = f.readlines()
    except:
        with open(ARQUIVO_ORIGEM, 'r') as f: linhas = f.readlines()

    macs_db = carregar_json(MACS_DESTINO)
    nets_db = {} # Recria redes do zero para garantir limpeza
    
    nome_atual = None
    tipo_atual = None
    count_mac = 0
    count_net = 0

    for line in linhas:
        line = line.strip()

        # 1. Nome do Objeto (edit "Nome")
        match_nome = re.search(r'^edit\s+"?([^"]+)"?', line)
        if match_nome:
            nome_atual = match_nome.group(1)
            tipo_atual = None
            continue

        # 2. Tipo (set type mac/iprange/etc) - Opcional, inferimos pelo conteúdo
        
        # 3. Captura MACs
        if line.startswith('set macaddr') and nome_atual:
            macs = re.findall(r'"([0-9a-fA-F:]+)"', line)
            for mac in macs:
                macs_db[mac.lower()] = nome_atual
                count_mac += 1
                # print(f"   [MAC] {mac} -> {nome_atual}")

        # 4. Captura Subnets (set subnet 192.168.0.0 255.255.255.0)
        if line.startswith('set subnet') and nome_atual:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[2]
                mask = parts[3]
                cidr = subnet_to_cidr(ip, mask)
                if cidr:
                    nets_db[cidr] = nome_atual
                    count_net += 1
                    print(f"   [REDE] {cidr} -> {nome_atual}")

    salvar_json(MACS_DESTINO, macs_db)
    salvar_json(NETS_DESTINO, nets_db)
    
    print("-" * 30)
    print(f"SUCESSO! Importados:")
    print(f"   - {count_mac} MACs atualizados em macs.json")
    print(f"   - {count_net} Redes criadas em networks.json")

if __name__ == '__main__':
    importar()
