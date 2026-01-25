import json
import os
import shutil

ARQUIVO = 'macs.json'

def limpar():
    if not os.path.exists(ARQUIVO):
        print("Arquivo macs.json não encontrado!")
        return

    # 1. Carrega os dados atuais
    with open(ARQUIVO, 'r') as f:
        dados_sujos = json.load(f)

    print(f"Total de entradas antes da limpeza: {len(dados_sujos)}")

    dados_limpos = {}
    duplicados = 0

    # 2. Processa cada item
    for mac, nome in dados_sujos.items():
        # Normaliza o MAC (tira espaços e joga pra minúsculo)
        mac_limpo = mac.strip().lower()

        # Se o MAC já existe na lista limpa (duplicidade encontrada)
        if mac_limpo in dados_limpos:
            duplicados += 1
            print(f"   [x] Removendo duplicado: {mac} ({nome}) - Já existe como {dados_limpos[mac_limpo]}")
        else:
            # Adiciona na lista limpa
            dados_limpos[mac_limpo] = nome

    # 3. Salva o backup e o novo arquivo
    shutil.copy(ARQUIVO, ARQUIVO + '.antes_da_limpeza')
    
    with open(ARQUIVO, 'w') as f:
        json.dump(dados_limpos, f, indent=4)

    print("-" * 30)
    print(f"Limpeza concluída!")
    print(f"Duplicados removidos: {duplicados}")
    print(f"Total final de dispositivos: {len(dados_limpos)}")

if __name__ == '__main__':
    limpar()
