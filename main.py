import json
import networkx as nx
from datetime import datetime

class MotorAntifraude:
    def __init__(self):
        # Inicializa um grafo não-direcionado para conexões bidirecionais
        self.grafo = nx.Graph()

    def carregar_do_json(self, caminho_arquivo):
        """Abre o arquivo .json físico e monta a topologia do Property Graph"""
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            transacoes = json.load(f)
            
        for transacao in transacoes:
            usuario = transacao["usuario"]
            ip = transacao["ip_acesso"]
            telefone = transacao["telefone"]
            
            # Adiciona o Nó de Usuário (escondendo propriedades de valor como o cartão)
            self.grafo.add_node(usuario, tipo="Usuario", cartao=transacao["cartao"])
            
            # Adiciona os Nós de Infraestrutura (pontos de estrangulamento da rede)
            self.grafo.add_node(ip, tipo="IP")
            self.grafo.add_node(telefone, tipo="Telefone")
            
            # Cria as Arestas com propriedades (Dicionários internos na conexão)
            self.grafo.add_edge(usuario, ip, 
                                device_id=transacao["device_id"], 
                                horario=transacao["horario"], 
                                relacao="ACESSOU_DO_IP")
            
            self.grafo.add_edge(usuario, telefone, 
                                device_id=transacao["device_id"], 
                                horario=transacao["horario"], 
                                relacao="VINCULADO_AO_TELEFONE")

    def executar_varredura(self):
        """Busca por fraudes estruturais analisando o grau e os metadados locais"""
        print("="*60)
        print("🛡️ NUBANK SEC - ANALISANDO GRAFO DE CONHECIMENTO")
        print("="*60)

        for no, atributos in self.grafo.nodes(data=True):
            tipo_no = atributos.get("tipo")
            
            # Foco nos nós centrais compartilháveis
            if tipo_no in ["IP", "Telefone"]:
                # Mede o grau do nó (Degree - vizinhos imediatos)
                usuarios_conectados = list(self.grafo.neighbors(no))
                
                # Se houver mais de uma conta vinculada ao mesmo recurso físico
                if len(usuarios_conectados) > 1:
                    self._avaliar_comportamento(no, tipo_no, usuarios_conectados)

    def _avaliar_comportamento(self, no_infra, tipo_no, contas):
        """Aplica regras de negócio para separar comportamento bot de uso residencial"""
        devices_encontrados = set()
        horarios_acesso = []

        # Varre as propriedades embutidas nas arestas de conexão locais
        for conta in contas:
            propriedades_aresta = self.grafo[conta][no_infra]
            devices_encontrados.add(propriedades_aresta["device_id"])
            
            hora_obj = datetime.strptime(propriedades_aresta["horario"], "%H:%M:%S")
            horarios_acesso.append(hora_obj)

        # Medição de tempo (Velocity Check)
        delta_segundos = (max(horarios_acesso) - min(horarios_acesso)).total_seconds()

        # Condições para caracterizar ataque automatizado em anel
        mesmo_dispositivo = len(devices_encontrados) == 1
        janela_curta = delta_segundos < 300 # Menos de 5 minutos

        if mesmo_dispositivo and janela_curta:
            print(f"\n[🚨 ALERTA CRÍTICO] DETECÇÃO DE FRAUDE EM ANEL!")
            print(f"  > Recurso Compartilhado: {tipo_no} ({no_infra})")
            print(f"  > Contas Laranjas Suspeitas: {', '.join(contas)}")
            print(f"  > Evidência Física: Hardware idêntico ({list(devices_encontrados)[0]})")
            print(f"  > Janela de Ação: Criadas/Acessadas em {int(delta_segundos)} segundos.")
        else:
            print(f"\n[✅ ACESSO LIBERADO] COMPARTILHAMENTO LEGÍTIMO.")
            print(f"  > Recurso Compartilhado: {tipo_no} ({no_infra})")
            print(f"  > Contas Vinculadas: {', '.join(contas)}")
            print(f"  > Evidência Física: Dispositivos distintos ({', '.join(devices_encontrados)}). Padrão familiar.")

# --- Execução do Fluxo ---
if __name__ == "__main__":
    motor = MotorAntifraude()
    # Ponto solicitado: Lendo dados diretamente do arquivo físico externo
    motor.carregar_do_json('dados.json')
    motor.executar_varredura()
    print("\n" + "="*60)