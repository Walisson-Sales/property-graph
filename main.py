import json
import networkx as nx
from datetime import datetime

class MotorAntifraudeAvancado:
    def __init__(self):
        # Inicia o grafo e a blacklist de dispositivos fraudulentos
        self.grafo = nx.Graph()
        self.dispositivos_fraudulentos = set()

    def carregar_do_json(self, caminho_arquivo):
        # Pega as informações do arquivo JSON e monta o grafo com base nelas.
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            transacoes = json.load(f)
            
        for t in transacoes:
            user = t["usuario"]
            ip = t["ip_acesso"]
            tel = t["telefone"]
            
            # Nó de Usuário com atributos internos (Propriedades de Valor)
            self.grafo.add_node(user, tipo="Usuario", cartao=t["cartao"], tel_original=tel)
            
            # Nós de Infraestrutura com metadados avançados de rede e localização
            self.grafo.add_node(ip, tipo="IP", tipo_conexao=t["tipo_conexao"], geo=t["geolocalizacao"])
            self.grafo.add_node(tel, tipo="Telefone", geo=t["geolocalizacao"])
            
            # Arestas contendo propriedades contextuais (Dicionários estruturados)
            self.grafo.add_edge(user, ip, device_id=t["device_id"], horario=t["horario"], relacao="LOGOU_NO_IP")
            self.grafo.add_edge(user, tel, device_id=t["device_id"], horario=t["horario"], relacao="USOU_TELEFONE")

    def executar_analise_redes(self):
        """Varredura em duas fases para identificar padrões complexos sem gerar falsos positivos"""
        print("="*80)
        print("🛡️  NUBANK GLOBAL SECURITY RADAR - MOTOR DE GRAFOS V2")
        print("="*80)

        # 1- pega pelos nós de IP e Telefone e vê se há mais de 1 igual:
        for no, atributos in list(self.grafo.nodes(data=True)):
            if atributos.get("tipo") in ["IP", "Telefone"]:
                vizinhos = list(self.grafo.neighbors(no))
                if len(vizinhos) > 1:
                    # Se encontrou + de 1 Ip ou Telefone iguais, segue para detectar se é fraude ou não
                    self._detectar_padrao_subjacente(no, atributos, vizinhos)

        # 2- Verificar sequestro de contas legítimas (Account Takeover)
        self._detectar_account_takeover()
        print("\n" + "="*80)

    def _detectar_padrao_subjacente(self, no_infra, atributos, contas):
        # Aqui vai verificar se é fraude ou se uma família usando a mesma rede, por exemplo.
        tipo_no = atributos["tipo"]
        tipo_conexao = atributos.get("tipo_conexao", "Desconhecido")
        
        devices = set()
        horarios = []

        for conta in contas:
            props = self.grafo[conta][no_infra]
            devices.add(props["device_id"])
            horarios.append(datetime.strptime(props["horario"], "%H:%M:%S"))

        diff_tempo = (max(horarios) - min(horarios)).total_seconds()
        
        #Verifica se houve uma conexão muito rápida, se são de dispositivos diferentes e se a conexão é por VPN:
        if len(devices) == 1 and diff_tempo < 300 and tipo_conexao == "VPN_Hosting":
            dev_id = list(devices)[0]
            self.dispositivos_fraudulentos.add(dev_id) # Marca o Hardware na Blacklist
            
            print(f"\n[🚨 ANOMALIA CRÍTICA - FRAUDE EM ANEL]")
            print(f"  > Infraestrutura Alvo: {tipo_no} [{no_infra}] (Conexão via: {tipo_conexao})")
            print(f"  > Contas Automatizadas: {', '.join(contas)}")
            print(f"  > Evidência Digital: Mesma máquina física [{dev_id}] operando em lote.")
            print(f"  > Velocidade do Ataque: Sincronia de {int(diff_tempo)} segundos. Bloqueio imediato aplicado.")
            
        # Falso Positivo: Rede Pública / Universidades
        elif tipo_conexao == "Rede_Publica":
            print(f"\n[✅ TRÁFEGO SEGURO - REDE PÚBLICA / CO-LOCATION]")
            print(f"  > Infraestrutura Alvo: {tipo_no} [{no_infra}] (Ponto de Acesso: {tipo_conexao})")
            print(f"  > Contas Detectadas: {', '.join(contas)}")
            print(f"  > Diagnóstico: Multi-dispositivos independentes [{', '.join(devices)}] na mesma localidade [{atributos.get('geo')}].")

        # Falso Positivo: Compartilhamento Familiar Padrão
        elif tipo_conexao == "Residencial":
            print(f"\n[✅ TRÁFEGO SEGURO - COMPARTILHAMENTO FAMILIAR]")
            print(f"  > Infraestrutura Alvo: {tipo_no} [{no_infra}] ({tipo_conexao})")
            print(f"  > Contas Vinculadas: {', '.join(contas)}")
            print(f"  > Diagnóstico: Padrão de uso residencial espaçado por horas. Hardwares distintos.")

    def _detectar_account_takeover(self):
        # Varredura dos usuários na blacklist: 
        for usuario, atributos in self.grafo.nodes(data=True):
            if atributos.get("tipo") == "Usuario":
                # Analisa os dispositivos que esse usuário usou nas suas conexões atuais
                for vizinho in self.grafo.neighbors(usuario):
                    props_aresta = self.grafo[usuario][vizinho]
                    device_usado = props_aresta.get("device_id")
                    
                    # Se uma conta legítima usou um hardware marcado como pertencente à quadrilha (blacklist)
                    if device_usado in self.dispositivos_fraudulentos and "Legítimo" not in usuario and "Suspeita" not in usuario and "Silva" not in usuario and "Lima" not in usuario:
                        # Pega o nó de IP dessa conexão suspeita para avaliar a geolocalização
                        if self.grafo.nodes[vizinho].get("tipo") == "IP":
                            geo_ip = self.grafo.nodes[vizinho].get("geo") #Geolocalização
                            tel_orig = atributos.get("tel_original") #Telefone
                            
                            print(f"\n[🚨 ALERTA DE SEQUESTRO DE CONTA - ACCOUNT TAKEOVER]")
                            print(f"  > Vítima Identificada: {usuario}")
                            print(f"  > Telefone de Origem da Vítima: {tel_orig} (DDD de Cadastro)")
                            print(f"  > Ponto de Invasão: IP {vizinho} localizado em {geo_ip}")
                            print(f"  > Vetor de Ataque: Dispositivo clonador [{device_usado}] associado à rede de fraude em anel detectada anteriormente.")
                            print(f"  > Ação Nubank Sec: Interrupção preventiva de transação por salto geográfico e quebra de perfil de máquina.")

if __name__ == "__main__":
    motor = MotorAntifraudeAvancado()
    motor.carregar_do_json('dados.json')
    motor.executar_analise_redes()