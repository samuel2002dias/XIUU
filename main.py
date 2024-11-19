# main.py
from lib.server import Server
from lib.client import Client

# menu
def menu():
    
    while(True):
        print("MODO DE UTILIZAÇÃO:")
        print("1 - Cliente")
        print("2 - Servidor")
        print("3 - Ajuda")
        print("0 - Sair")
        
        opcao = int(input("Escolha uma opção: "))
        if opcao == 0:
            break
        elif opcao == 1:
            portaCliente = -1
            portaCliente = int(input("Introduza a porta do servidor: "))
            endereco_ip = '192.168.1.158'
            Client.define_port(Client(), endereco_ip, portaCliente)
            # endereco_ip = input("Introduza o endereço IP do servidor: ")
           


            break
        elif opcao == 2:
            portaServidor = int(input("Introduza a porta do servidor: "))
            Server.define_port(Server(), portaServidor)
            break
        elif opcao == 3:
            print("Encontra aqui uma pequena ajuda caso tenha dúvidas ao operar com a nossa aplicação.\n" +
            "	-Caso pretenda enviar um segredo, terá de entrar no menu principal como cliente.\n" +
            "		Nesta fase terá de inserir o IP (do servidor), porta a conectar. \n" +
            "		De seguida, escolha a opção \"Cliente Remetente\"(caso seja você o utilizador que deseja envoar o segredo) ou escolha \"Cliente Recetor\"(caso deseje receber o segredo de outo utilizador).\n" +
            "		De seguida escolha um dos cinco modos de troca de segredos disponiveis.\n" +
            "			1-> Protocolo de acordo de chaves Diffie-Hellman\n" +
            "			2-> Puzzles de Merkle\n" +
            "			3-> RSA\n" +
            "			4-> Gerar uma nova chave a partir de chaves pré-distribuídas \n" +
            "			5-> Distribuição de novas chaves de cifra usando um agente de confiança e envio de um segredo\n\n" +
            "		Ao escolher um destes modos é necessário inserir a 2porta do cliente a comunicar.\n" +
            "\n" +
            "	-Caso pretenda ver os clientes que estão ligados à aplicação,\n" +
            "		entre no menu principal como cliente e escolha a opção \"Listar clientes ativos\"\n" +
            "\n" +
            "	-Caso pretenda gerar um segredo criptográfico através de uma chave gerada por palavra-passe,\n" +
            "		entre no menu principal como cliente e escolha a opção 3. Será gerado e mostrado no ecrã um segredo gerado através do tipo de cifra PBKDF2 (com a função de hash que selecionar).\n" +
            "\n" +
            "	-Caso pretenda ligar uma máquina como servidor, entre no menu inicial em modo de servidor e introduza a porta que pretende abrir.\n" +
            "\n" +
            "	-Para sair da aplicação, escolha a opção \"Sair\" do menu inicial.\n")
        else:
            print("Opção inválida!")
        
    
menu()