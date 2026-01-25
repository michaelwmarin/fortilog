import re
import json
import os
import shutil

# --- CONFIGURAÇÃO ---
ARQUIVO_ORIGEM = 'fgt_dump.txt'
ARQUIVO_DESTINO = 'macs.json'

def carregar_json(fp):
    if not os.path.exists(fp): return {}
    try:
        with open(fp, 'r') as f: return json.load(f)
    except: return {}

def salvar_json(fp, dados):
    # Backup de segurança
    if os.path.exists(fp):
        shutil.copy(fp, fp + '.backup')
    try:
        with open(fp, 'w') as f: json.dump(dados, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar: {e}")

def importar():
    if not os.path.exists(ARQUIVO_ORIGEM):
        print(f"ERRO: Arquivo '{ARQUIVO_ORIGEM}' não encontrado.")
        return

    print("--> Lendo arquivo do FortiGate...")
    try:
        with open(ARQUIVO_ORIGEM, 'r', encoding='utf-8') as f:
            linhas = f.readlines()
    except:
        # Fallback para encoding padrão se utf-8 falhar
        with open(ARQUIVO_ORIGEM, 'r') as f:
            linhas = f.readlines()

    macs_db = carregar_json(ARQUIVO_DESTINO)
    count = 0
    
    # Variáveis de Estado
    nome_atual = None
    eh_tipo_mac = False

    for linha in linhas:
        linha = linha.strip()

        # 1. Captura o Nome (edit "Nome")
        match_nome = re.search(r'^edit\s+"?([^"]+)"?', linha)
        if match_nome:
            nome_atual = match_nome.group(1)
            eh_tipo_mac = False # Reseta flag
            continue

        # 2. Verifica se é objeto de MAC (set type mac)
        if linha == 'set type mac':
            eh_tipo_mac = True
            continue

        # 3. Captura os MACs (set macaddr "AA:BB..." "CC:DD...")
        # Só processa se tivermos um nome e se for do tipo MAC
        if linha.startswith('set macaddr') and nome_atual and eh_tipo_mac:
            # Encontra todos os MACs dentro das aspas na mesma linha
            macs_encontrados = re.findall(r'"([0-9a-fA-F:]+)"', linha)
            
            for mac in macs_encontrados:
                mac_limpo = mac.lower()
                # Atualiza ou Adiciona
                if mac_limpo not in macs_db or macs_db[mac_limpo] != nome_atual:
                    macs_db[mac_limpo] = nome_atual
                    count += 1
                    print(f"   [+] {mac_limpo} -> {nome_atual}")

    if count > 0:
        salvar_json(ARQUIVO_DESTINO, macs_db)
        print(f"\nSUCESSO: {count} dispositivos importados/atualizados!")
    else:
        print("\nNenhum dispositivo novo encontrado.")

if __name__ == '__main__':
    importar()
