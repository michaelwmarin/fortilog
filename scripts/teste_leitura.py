import subprocess
import re
import os

print("--- INICIANDO DIAGNÓSTICO ---")

# 1. Verifica se os arquivos existem
arquivos = ['/var/log/syslog', '/var/log/syslog.1']
for arq in arquivos:
    if os.path.exists(arq):
        tamanho = os.path.getsize(arq) / 1024  # KB
        print(f"[OK] Arquivo {arq} existe ({tamanho:.2f} KB)")
    else:
        print(f"[ERRO] Arquivo {arq} NÃO ENCONTRADO!")

# 2. Tenta pescar uma linha bruta (raw)
print("\n--- TENTANDO LER 1 LINHA BRUTA (GREP) ---")
try:
    # Busca qualquer coisa com 'traffic'
    cmd = 'grep -a "type=\"traffic\"" /var/log/syslog | tail -n 1'
    linha = subprocess.getoutput(cmd)
    
    if len(linha) < 10:
        print("[AVISO] O grep não retornou nada no /var/log/syslog.")
        print("Tentando no syslog.1...")
        cmd = 'grep -a "type=\"traffic\"" /var/log/syslog.1 | tail -n 1'
        linha = subprocess.getoutput(cmd)

    if len(linha) > 10:
        print(f"Sucesso! Linha encontrada:\n{linha}")
        
        # 3. Testa o Parser (Tradutor)
        print("\n--- TESTANDO O TRADUTOR (PARSER) ---")
        d = {}
        # Teste Data
        dt = re.search(r'date=([\d-]+)', linha)
        print(f"Data identificada: {dt.group(1) if dt else 'FALHA'}")
        
        # Teste IP Origem
        src = re.search(r'srcip=([0-9\.]+)', linha)
        print(f"IP Origem: {src.group(1) if src else 'FALHA'}")
        
        # Teste Ação
        act = re.search(r'action=[\"\']?([\w-]+)[\"\']?', linha)
        print(f"Ação: {act.group(1) if act else 'FALHA'}")

    else:
        print("[CRÍTICO] Não consegui ler NENHUMA linha de log. O arquivo pode estar vazio ou sem permissão.")

except Exception as e:
    print(f"Erro no teste: {e}")

print("\n--- FIM ---")
