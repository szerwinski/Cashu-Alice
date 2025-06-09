import json
import requests

# Configurações
MINT_URL = "http://localhost:3338"
P2PK_OUTPUTS_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/p2pk_outputs_data.json"
WITNESS_OUTPUT_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/witness_signature.json"

def load_y_for_amount(amount: int) -> str:
    """Carrega o ponto Y correspondente ao token com o valor especificado."""
    with open(P2PK_OUTPUTS_FILE, "r") as f:
        data = json.load(f)
    
    outputs = data["outputs"]
    Ys = data["Ys"]
    
    # Encontra o índice do output com o valor desejado
    for i, output in enumerate(outputs):
        if output["amount"] == amount:
            return Ys[i]
    
    raise ValueError(f"Nenhum token encontrado com valor {amount} sats")

def check_token_state(y: str) -> dict:
    """Consulta o estado do token na mint usando NUT-07."""
    endpoint = f"{MINT_URL}/v1/checkstate"
    headers = {"Content-Type": "application/json"}
    payload = {
        "Ys": [y]
    }
    
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()  # Levanta exceção para erros HTTP
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
        return None

def save_witness_signature(y: str, signature: str):
    """Salva a assinatura s (últimos 32 bytes do witness) em um arquivo JSON."""
    # Extrai os últimos 32 bytes da assinatura (escalar s)
    if len(signature) != 128:  # 64 bytes em hex
        raise ValueError(f"Assinatura inválida: esperado 64 bytes, recebido {len(signature)//2}")
    s_hex = signature[64:]  # Últimos 32 bytes (s)
    
    witness_data = {
        "Y": y,
        "s": s_hex
    }
    
    with open(WITNESS_OUTPUT_FILE, "w") as f:
        json.dump(witness_data, f, indent=4)
    print(f"Assinatura s salva em: {WITNESS_OUTPUT_FILE}")

def main():
    # Passo 1: Carregar o ponto Y para o token de 8 sats
    try:
        y = load_y_for_amount(8)
        print(f"Ponto Y para token de 8 sats: {y}")
    except ValueError as e:
        print(f"Erro: {e}")
        return

    # Passo 2: Consultar o estado do token
    response = check_token_state(y)
    if not response:
        print("Falha ao consultar o estado do token.")
        return

    # Passo 3: Processar a resposta
    states = response.get("states", [])
    if not states:
        print("Nenhum estado retornado pela academia.")
        return

    for state in states:
        y_returned = state.get("Y")
        token_state = state.get("state")
        witness = state.get("witness")
        
        print(f"\nEstado do token (Y: {y_returned}):")
        print(f"Estado: {token_state}")
        if witness:
            try:
                witness_data = json.loads(witness)
                signatures = witness_data.get("signatures", [])
                if signatures:
                    print(f"Assinatura Schnorr (witness): {signatures[0]}")
                    if token_state == "SPENT":
                        save_witness_signature(y_returned, signatures[0])
                else:
                    print("Nenhuma assinatura encontrada no witness.")
            except json.JSONDecodeError:
                print(f"Witness inválido: {witness}")
        else:
            print("Nenhum witness retornado.")

if __name__ == "__main__":
    main()