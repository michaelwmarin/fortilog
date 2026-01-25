import re
import json
import os
import shutil

# --- CONFIGURAÇÃO ---
BASE_DIR = '/root/fortilog'
ARQUIVO_ORIGEM = os.path.join(BASE_DIR, 'backups/fgt_groups.txt')
ARQUIVO_DESTINO = os.path.join(BASE_DIR, 'data/groups.json')

def carregar_json(fp):
    if not os.path.exists(fp): return {}
    try:
        with open(fp, 'r') as f:
            return json.load(f)
    except:
        return {}

def salvar_json(fp, dados):
    if os.path.exists(fp):
        shutil.copy(fp, fp + '.backup')
    try:
        with open(fp, 'w') as f:
            json.dump(dados, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar: {e}")

def importar():
    if not os.path.exists(ARQUIVO_ORIGEM):
        print(f"ERRO: Arquivo '{ARQUIVO_ORIGEM}' não encontrado.")
        return

    print("--> Lendo Grupos do FortiGate...")
    try:
        with open(ARQUIVO_ORIGEM, 'r', encoding='utf-8') as f:
            linhas = f.readlines()
    except:
        with open(ARQUIVO_ORIGEM, 'r') as f:
            linhas = f.readlines()

    grupos_db = carregar_json(ARQUIVO_DESTINO)
    count = 0
    grupo_atual = None

    for line in linhas:
        line = line.strip()

        # 1. Identifica o Grupo (edit "Nome do Grupo")
        match_grupo = re.search(r'^edit\s+"?([^"]+)"?', line)
        if match_grupo:
            grupo_atual = match_grupo.group(1)
            continue

        # 2. Identifica os Membros (set member "A" "B" ...)
        if line.startswith('set member') and grupo_atual:
            # Pega tudo que está entre aspas
            membros = re.findall(r'"([^"]+)"', line)
            
            for membro in membros:
                # Salva: CHAVE = Nome do Membro, VALOR = Nome do Grupo
                grupos_db[membro] = grupo_atual
                count += 1
                print(f"   [+] {membro} -> {grupo_atual}")

    if count > 0:
        salvar_json(ARQUIVO_DESTINO, grupos_db)
        print(f"\nSUCESSO: {count} associações importadas para groups.json!")
    else:
        print("\nNenhum grupo encontrado.")

if __name__ == '__main__':
    importar()