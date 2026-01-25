import json
import os

# Caminho do arquivo de redes
ARQUIVO = '/root/fortilog/data/networks.json'

def renomear():
    if not os.path.exists(ARQUIVO):
        print("Erro: Arquivo networks.json não encontrado.")
        return

    # 1. Carrega os dados
    with open(ARQUIVO, 'r') as f:
        redes = json.load(f)

    # 2. A rede que queremos mudar (CIDR)
    rede_alvo = "192.168.240.0/24"
    novo_nome = "CÂMERAS INTELBRAS"

    # 3. Verifica e altera
    if rede_alvo in redes:
        nome_antigo = redes[rede_alvo]
        redes[rede_alvo] = novo_nome
        
        # Salva de volta
        with open(ARQUIVO, 'w') as f:
            json.dump(redes, f, indent=4)
            
        print(f"SUCESSO! Rede '{rede_alvo}' alterada:")
        print(f"   DE:   {nome_antigo}")
        print(f"   PARA: {novo_nome}")
    else:
        print(f"Aviso: A rede {rede_alvo} não foi encontrada no arquivo.")
        print("Redes disponíveis:", list(redes.keys()))

if __name__ == '__main__':
    renomear()
