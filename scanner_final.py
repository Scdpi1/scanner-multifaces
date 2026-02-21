
"""
██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   
██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   

░█▀▀░█▀█░█▀▄░█▀▀░█░░░█▀█░█▀▀░░░█▀█░█▀█░█▀█░█▀█░█▀█░█▀▄░█▀▀
░█░░░█░█░█░█░█▀▀░█░░░█░█░█▀▀░░░█▀▀░█▀█░█▀█░█▀▀░█▀█░█░█░█▀▀
░▀▀▀░▀▀▀░▀▀░░▀▀▀░▀▀▀░▀▀▀░▀▀▀░░░▀░░░▀░▀░▀░▀░▀░░░▀░▀░▀▀░░▀▀▀

=================================================================
CRIADO POR: SCDPI.1 (https://github.com/scdpi.1)
HISTÓRIA: 57 anos, surdo total, autodidata em cibersegurança
MENSAGEM: "Limites são mentiras que contam pra quem desiste. 
           Eu não desisti. Você também não desista."
=================================================================

Este código prova que:
- ✅ Idade não é limite (57 anos e codando)
- ✅ Surdez não é barreira (comunicação vai além do som)
- ✅ Escolaridade não define inteligência (pensamento > diploma)
- ✅ Determinação vence qualquer obstáculo

USE, ESTUDE, COMPARTILHE, MELHORE.
Se esse código chegou até você, é porque alguém lutou pra isso existir.
"""

import socket
import sys
import time
from datetime import datetime
import subprocess
import re
import json
import threading
from queue import Queue
import ipaddress
import os
import hashlib
from functools import wraps

# =================================================================
# CORES E ESTILOS (acessibilidade visual)
# =================================================================
class Cores:
    """Cores para facilitar leitura - contraste alto pensado em acessibilidade"""
    VERDE = '\033[92m'      # Sucesso
    VERMELHO = '\033[91m'   # Erro
    AMARELO = '\033[93m'    # Atenção
    AZUL = '\033[94m'       # Informação
    MAGENTA = '\033[95m'    # Destaque
    CIANO = '\033[96m'      # Título
    RESET = '\033[0m'
    NEGRITO = '\033[1m'
    BACKGROUND = '\033[40m' # Fundo preto pra contraste

# =================================================================
# FACE 1: CLI (Interface de Linha de Comando - seu estilo!)
# =================================================================
class FaceCLI:
    """Interface CLI - Rápida, direta, do seu jeito (tópicos, números)"""
    
    @staticmethod
    def executar(alvo):
        print(f"{Cores.CIANO}{Cores.NEGRITO}")
        print("="*70)
        print(" MODO CLI ATIVADO - Scan Rápido e Direto")
        print("="*70)
        print(f"{Cores.RESET}")
        
        scanner = ScannerPrincipal(alvo)
        scanner.scan_completo()
        scanner.salvar_resultados()
        
        return scanner.resultados_tcp  

# =================================================================
# FACE 2: WEB (Flask - para acesso via navegador)
# =================================================================
class FaceWeb:
    """Interface Web - Para acessar de qualquer lugar"""
    
    @staticmethod
    def iniciar_servidor(porta=5000):
        try:
            from flask import Flask, render_template_string, request, jsonify
            import threading
            
            app = Flask(__name__)
            resultados_web = {}
            
            @app.route('/')
            def home():
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>SCDPI.1 Scanner</title>
                    <style>
                        body { 
                            background: #000; 
                            color: #0f0; 
                            font-family: 'Courier New', monospace;
                            margin: 0;
                            padding: 20px;
                        }
                        .container {
                            max-width: 1200px;
                            margin: auto;
                            border: 2px solid #0f0;
                            padding: 20px;
                            background: #111;
                        }
                        h1 {
                            color: #0f0;
                            text-align: center;
                            border-bottom: 1px solid #0f0;
                            padding-bottom: 10px;
                        }
                        .historia {
                            background: #1a1a1a;
                            padding: 15px;
                            border-left: 5px solid yellow;
                            margin: 20px 0;
                            color: #fff;
                        }
                        .menu {
                            display: grid;
                            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                            gap: 10px;
                            margin: 20px 0;
                        }
                        .botao {
                            background: #000;
                            color: #0f0;
                            border: 2px solid #0f0;
                            padding: 15px;
                            text-decoration: none;
                            text-align: center;
                            font-weight: bold;
                            cursor: pointer;
                        }
                        .botao:hover {
                            background: #0f0;
                            color: #000;
                        }
                        .resultados {
                            background: #000;
                            border: 1px solid #0f0;
                            padding: 10px;
                            font-size: 12px;
                            white-space: pre-wrap;
                        }
                        footer {
                            margin-top: 30px;
                            text-align: center;
                            color: #666;
                            font-size: 12px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔍 SCDPI.1 MULTISCANNER</h1>
                        
                        <div class="historia">
                            <strong>📖 HISTÓRIA DO CRIADOR:</strong><br><br>
                            57 anos • Surdo total • Autodidata em cibersegurança<br>
                            1º ano do ensino médio • 3 anos estudando hacking ético<br><br>
                            <em>"Se cheguei até aqui, você também pode. Barreiras existem pra serem quebradas."</em><br><br>
                            GitHub: <a href="https://github.com/scdpi.1" style="color:yellow">@scdpi.1</a>
                        </div>
                        
                        <div class="menu">
                            <form action="/scan" method="post">
                                <input type="text" name="alvo" placeholder="IP ou hostname" required 
                                       style="width: 70%; padding: 10px; background: #000; color: #0f0; border: 1px solid #0f0;">
                                <button type="submit" class="botao" style="width: 25%;">INICIAR SCAN</button>
                            </form>
                        </div>
                        
                        <h2>📊 Últimos Resultados</h2>
                        <div class="resultados">
                            {{ resultados }}
                        </div>
                        
                        <footer>
                            Criado por alguém que prova que limites são mentira.<br>
                            Use com ética. Estude com vontade. Compartilhe com orgulho.
                        </footer>
                    </div>
                </body>
                </html>
                """, resultados=str(resultados_web)[:1000] if resultados_web else "Nenhum scan realizado ainda")
            
            @app.route('/scan', methods=['POST'])
            def scan():
                alvo = request.form['alvo']
                scanner = ScannerPrincipal(alvo)
                scanner.scan_completo()
                resultados = scanner.salvar_resultados()
                
                global resultados_web
                resultados_web[alvo] = {
                    'data': str(datetime.now()),
                    'resultados': resultados,
                    'so': scanner.fingerprint_detalhado
                }
                
                return f"""
                <html>
                <head><meta http-equiv="refresh" content="2;url=/"></head>
                <body style="background:#000;color:#0f0;text-align:center;padding:50px;">
                    <h1>✅ SCAN CONCLUÍDO EM {alvo}</h1>
                    <p>Resultados salvos. Redirecionando...</p>
                </body>
                </html>
                """
            
            print(f"{Cores.VERDE}[+] Servidor web rodando em: http://localhost:{porta}{Cores.RESET}")
            print(f"{Cores.AMARELO}[!] Pressione Ctrl+C para parar{Cores.RESET}")
            app.run(host='0.0.0.0', port=porta, debug=False)
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] Flask não instalado. Para modo web: pip install flask{Cores.RESET}")

# =================================================================
# FACE 3: API (RESTful - para integração com outras ferramentas)
# =================================================================
class FaceAPI:
    """Interface API - Para automação e integração"""
    
    @staticmethod
    def iniciar_api(porta=8080):
        try:
            from flask import Flask, jsonify, request
            from flask_cors import CORS
            
            app = Flask(__name__)
            CORS(app)
            scans_api = {}
            
            @app.route('/api/v1/status', methods=['GET'])
            def status():
                return jsonify({
                    'status': 'online',
                    'versao': '3.0',
                    'criador': 'SCDPI.1',
                    'mensagem': 'Limites são mentira'
                })
            
            @app.route('/api/v1/scan', methods=['POST'])
            def scan_api():
                data = request.get_json()
                alvo = data.get('alvo')
                tipo = data.get('tipo', 'rapido')
                
                if not alvo:
                    return jsonify({'erro': 'Alvo não especificado'}), 400
                
                scanner = ScannerPrincipal(alvo)
                scanner.scan_completo()
                resultados = scanner.salvar_resultados()
                
                scan_id = hashlib.md5(f"{alvo}{time.time()}".encode()).hexdigest()[:8]
                scans_api[scan_id] = {
                    'alvo': alvo,
                    'tipo': tipo,
                    'data': str(datetime.now()),
                    'resultados': resultados
                }
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'concluido',
                    'resultados': resultados
                })
            
            @app.route('/api/v1/scan/<scan_id>', methods=['GET'])
            def get_scan(scan_id):
                if scan_id in scans_api:
                    return jsonify(scans_api[scan_id])
                return jsonify({'erro': 'Scan não encontrado'}), 404
            
            print(f"{Cores.VERDE}[+] API rodando em: http://localhost:{porta}/api/v1{Cores.RESET}")
            app.run(host='0.0.0.0', port=porta, debug=False)
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] Flask não instalado. Para modo API: pip install flask flask-cors{Cores.RESET}")

# =================================================================
# FACE 4: GUI (Tkinter - para desktop)
# =================================================================
class FaceGUI:
    """Interface GUI - Para quem prefere janelas"""
    
    @staticmethod
    def iniciar_gui():
        try:
            import tkinter as tk
            from tkinter import ttk, scrolledtext
            
            class ScannerGUI:
                def __init__(self):
                    self.janela = tk.Tk()
                    self.janela.title("SCDPI.1 Scanner - Interface Gráfica")
                    self.janela.geometry("800x600")
                    self.janela.configure(bg='black')
                    
                    # Título
                    titulo = tk.Label(self.janela, 
                                    text="🔍 SCDPI.1 MULTISCANNER",
                                    fg='green', bg='black',
                                    font=('Courier', 16, 'bold'))
                    titulo.pack(pady=10)
                    
                    # História (resumida)
                    historia = tk.Label(self.janela,
                                      text="57 anos | Surdo | Autodidata | Hacking Ético",
                                      fg='yellow', bg='black',
                                      font=('Courier', 10))
                    historia.pack(pady=5)
                    
                    # Frame de entrada
                    frame_input = tk.Frame(self.janela, bg='black')
                    frame_input.pack(pady=20)
                    
                    tk.Label(frame_input, text="Alvo:", fg='green', bg='black',
                            font=('Courier', 12)).pack(side=tk.LEFT, padx=5)
                    
                    self.alvo_entry = tk.Entry(frame_input, width=30,
                                             bg='#1a1a1a', fg='green',
                                             insertbackground='green')
                    self.alvo_entry.pack(side=tk.LEFT, padx=5)
                    
                    self.scan_btn = tk.Button(frame_input, text="INICIAR SCAN",
                                            bg='green', fg='black',
                                            command=self.iniciar_scan)
                    self.scan_btn.pack(side=tk.LEFT, padx=5)
                    
                    # Área de resultados
                    self.resultados = scrolledtext.ScrolledText(self.janela,
                                                               width=90, height=25,
                                                               bg='#1a1a1a', fg='green',
                                                               font=('Courier', 10))
                    self.resultados.pack(pady=10, padx=10)
                    
                    # Rodapé
                    footer = tk.Label(self.janela,
                                    text="GitHub: @scdpi.1 | Use com ética | Limites são mentira",
                                    fg='gray', bg='black',
                                    font=('Courier', 8))
                    footer.pack(pady=5)
                    
                def iniciar_scan(self):
                    alvo = self.alvo_entry.get()
                    if not alvo:
                        self.resultados.insert(tk.END, "[!] Digite um alvo\n")
                        return
                    
                    self.resultados.insert(tk.END, f"\n[*] Iniciando scan em {alvo}\n")
                    self.resultados.insert(tk.END, f"[*] Data: {datetime.now()}\n")
                    self.resultados.insert(tk.END, "="*60 + "\n")
                    self.resultados.see(tk.END)
                    self.janela.update()
                    
                    scanner = ScannerPrincipal(alvo)
                    scanner.scan_completo()
                    # Salva resultados com timestamp interno
                    arquivos = scanner.salvar_resultados()
                    
                    self.resultados.insert(tk.END, f"\n[+] Scan concluído!\n")
                    self.resultados.insert(tk.END, f"[+] Arquivos salvos: {arquivos}\n")
                    
                def rodar(self):
                    self.janela.mainloop()
            
            app = ScannerGUI()
            app.rodar()
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] Tkinter não disponível{Cores.RESET}")

# =================================================================
# FACE 5: BOT (Telegram - para scan de qualquer lugar)
# =================================================================
class FaceBot:
    """Interface Bot Telegram - Scan pelo celular"""
    
    @staticmethod
    def iniciar_bot(token):
        try:
            import telebot
            from telebot import types
            
            bot = telebot.TeleBot(token)
            
            @bot.message_handler(commands=['start'])
            def send_welcome(message):
                welcome_msg = """
🔰 BEM-VINDO AO SCDPI.1 SCANNER BOT

Criado por: @scdpi.1 (57 anos, surdo, autodidata)

Comandos disponíveis:
/scan <IP> - Inicia scan no alvo
/status - Ver status do bot
/sobre - História do criador
/ajuda - Ajuda

"Limites são mentira"
                """
                bot.reply_to(message, welcome_msg)
            
            @bot.message_handler(commands=['sobre'])
            def sobre(message):
                historia = """
📖 HISTÓRIA DO CRIADOR:

• 57 anos de idade
• Surdo total
• 1º ano do ensino médio
• 3 anos estudando hacking ético
• Autodidata

💪 MENSAGEM:
"Não foi o que me faltou que me definiu, 
mas sim o que construí com o que tinha."

GitHub: github.com/scdpi.1
                """
                bot.reply_to(message, historia)
            
            @bot.message_handler(commands=['scan'])
            def scan(message):
                try:
                    alvo = message.text.split()[1]
                    bot.reply_to(message, f"🔄 Iniciando scan em {alvo}...")
                    
                    scanner = ScannerPrincipal(alvo)
                    scanner.scan_completo()
                    arquivos = scanner.salvar_resultados()
                    
                    # Resume resultados
                    resumo = f"✅ SCAN CONCLUÍDO EM {alvo}\n\n"
                    resumo += f"📊 RESULTADOS:\n"
                    resumo += f"TCP abertas: {len(scanner.resultados_tcp)}\n"
                    resumo += f"SO: {scanner.fingerprint_detalhado.get('so_provavel', 'N/A')}\n"
                    resumo += f"\n📁 Arquivos salvos localmente"
                    
                    bot.reply_to(message, resumo)
                    
                except IndexError:
                    bot.reply_to(message, "❌ Use: /scan <IP>")
            
            print(f"{Cores.VERDE}[+] Bot Telegram iniciado{Cores.RESET}")
            bot.infinity_polling()
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] pyTelegramBotAPI não instalado. pip install pyTelegramBotAPI{Cores.RESET}")

# =================================================================
# SISTEMA DE MÚLTIPLOS USUÁRIOS
# =================================================================
class SistemaUsuarios:
    """Gerencia múltiplos usuários com diferentes permissões"""
    
    def __init__(self):
        self.usuarios = {}
        self.arquivo_db = "usuarios.json"
        self.carregar_usuarios()
        
        # Usuário admin padrão (criador)
        self.criar_usuario(
            username="scdpi.1",
            senha="57anosLutando",
            perfil="admin",
            nome="Criador Original"
        )
    
    def criar_usuario(self, username, senha, perfil="user", nome=""):
        """Cria novo usuário"""
        if username in self.usuarios:
            return False
        
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()
        
        self.usuarios[username] = {
            'nome': nome or username,
            'senha_hash': senha_hash,
            'perfil': perfil,
            'criado_em': str(datetime.now()),
            'scans_realizados': [],
            'ultimo_acesso': None
        }
        
        self.salvar_usuarios()
        return True
    
    def autenticar(self, username, senha):
        """Autentica usuário"""
        if username not in self.usuarios:
            return False
        
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()
        if self.usuarios[username]['senha_hash'] == senha_hash:
            self.usuarios[username]['ultimo_acesso'] = str(datetime.now())
            self.salvar_usuarios()
            return True
        
        return False
    
    def registrar_scan(self, username, alvo, resultados):
        """Registra scan realizado por usuário"""
        if username in self.usuarios:
            self.usuarios[username]['scans_realizados'].append({
                'data': str(datetime.now()),
                'alvo': alvo,
                'resultados': resultados
            })
            self.salvar_usuarios()
    
    def carregar_usuarios(self):
        """Carrega usuários do arquivo"""
        try:
            with open(self.arquivo_db, 'r') as f:
                self.usuarios = json.load(f)
        except:
            self.usuarios = {}
    
    def salvar_usuarios(self):
        """Salva usuários no arquivo"""
        with open(self.arquivo_db, 'w') as f:
            json.dump(self.usuarios, f, indent=4)

# =================================================================
# SCANNER PRINCIPAL (coração do sistema)
# =================================================================
class ScannerPrincipal:
    """Scanner principal com todas as funcionalidades dos prompts #1 e #2"""
    
    def __init__(self, alvo):
        self.alvo = alvo
        self.portas_comuns = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888]
        self.resultados_tcp = []
        self.resultados_udp = []
        self.log_erros = []
        self.banners = {}
        self.fingerprint_detalhado = {}
        self.inicio_scan = datetime.now()
        
    def scan_porta_tcp(self, ip, porta):
        """Scan TCP com tratamento de erros"""
        for tentativa in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                resultado = sock.connect_ex((ip, porta))
                
                if resultado == 0:
                    banner = self.pegar_banner(ip, porta)
                    return "ABERTA", banner
                
                sock.close()
                return "FECHADA", None
                
            except socket.timeout:
                self.log_erros.append(f"Timeout TCP {porta}")
                time.sleep(1)
                continue
            except PermissionError:
                return "PRECISA_SUDO", None
            except Exception as e:
                self.log_erros.append(f"Erro TCP {porta}: {str(e)}")
                return "ERRO", None
        
        return "FILTRADA", None
    
    def pegar_banner(self, ip, porta):
        """Pega banner do serviço"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, porta))
            
            if porta in [80, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif porta == 21:
                pass
            elif porta == 25:
                sock.send(b"EHLO scan.local\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100]
        except:
            return None
    
    def fingerprint_so(self, ip):
        """Detecta SO"""
        so_info = {'so_provavel': 'Desconhecido'}
        
        try:
            ping = subprocess.run(['ping', '-c', '2', ip], 
                                capture_output=True, text=True, timeout=5)
            
            ttl_match = re.search(r'ttl=(\d+)', ping.stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    so_info['so_provavel'] = 'Linux/Unix'
                elif ttl <= 128:
                    so_info['so_provavel'] = 'Windows'
                elif ttl <= 255:
                    so_info['so_provavel'] = 'Network Device'
        except:
            pass
        
        return so_info
    
    def scan_completo(self):
        """Executa scan completo"""
        print(f"\n{Cores.AZUL}[*] Scan iniciado em {self.alvo}{Cores.RESET}")
        
        # Resolve IP
        try:
            ip_resolvido = socket.gethostbyname(self.alvo)
            self.alvo = ip_resolvido
        except:
            pass
        
        # Scan TCP
        print(f"{Cores.AMARELO}[*] Escaneando portas TCP...{Cores.RESET}")
        for i, porta in enumerate(self.portas_comuns):
            print(f"\r  Progresso: {i+1}/{len(self.portas_comuns)}", end="")
            
            status, banner = self.scan_porta_tcp(self.alvo, porta)
            
            if status == "ABERTA":
                print(f"\n{Cores.VERDE}[+] Porta {porta}/TCP - ABERTA{Cores.RESET}")
                if banner:
                    print(f"    Banner: {banner}")
                
                self.resultados_tcp.append({
                    'porta': porta,
                    'protocolo': 'tcp',
                    'status': status,
                    'banner': banner
                })
            
            time.sleep(0.2)
        
        # Fingerprint SO
        self.fingerprint_detalhado = self.fingerprint_so(self.alvo)
        
        print(f"\n{Cores.VERDE}[+] Scan concluído em {datetime.now() - self.inicio_scan}{Cores.RESET}")
    
    def salvar_resultados(self):
        """Salva resultados em múltiplos formatos"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Remove caracteres inválidos para nome de arquivo
        alvo_limpo = self.alvo.replace('/', '_').replace('\\', '_').replace(':', '_')
        base = f"scan_{alvo_limpo}_{timestamp}"
        
        # TXT simples
        with open(f"{base}.txt", 'w') as f:
            f.write(f"SCAN REALIZADO POR: SCDPI.1 (github.com/scdpi.1)\n")
            f.write(f"DATA: {datetime.now()}\n")
            f.write(f"ALVO: {self.alvo}\n")
            f.write("="*60 + "\n\n")
            f.write("PORTAS ABERTAS:\n")
            for r in self.resultados_tcp:
                f.write(f"{r['porta']}/TCP - {r.get('banner', '')}\n")
            f.write(f"\nSO DETECTADO: {self.fingerprint_detalhado.get('so_provavel')}\n")
        
        # JSON
        with open(f"{base}.json", 'w') as f:
            json.dump({
                'criador': 'SCDPI.1',
                'github': 'https://github.com/scdpi.1',
                'data': str(datetime.now()),
                'alvo': self.alvo,
                'resultados_tcp': self.resultados_tcp,
                'so': self.fingerprint_detalhado,
                'erros': self.log_erros
            }, f, indent=4)
        
        print(f"{Cores.VERDE}[+] Resultados salvos em: {base}.txt e {base}.json{Cores.RESET}")
        return base
# =================================================================
# MENU PRINCIPAL - MULTIFACES
# =================================================================
def menu_principal():
    """Menu principal - escolha sua face!"""
    
    print(f"{Cores.CIANO}{Cores.NEGRITO}")
    print("╔" + "═"*70 + "╗")
    print("║             SCDPI.1 MULTISCANNER - VERSÃO FINAL               ║")
    print("║         'Limites são mentira - 57 anos, surdo, codando'       ║")
    print("╚" + "═"*70 + "╝")
    print(f"{Cores.RESET}")
    
    print(f"\n{Cores.AMARELO}ESCOLHA SUA INTERFACE (FACE):{Cores.RESET}")
    print(f"{Cores.VERDE}[1]{Cores.RESET} CLI - Terminal (rápido, seu estilo)")
    print(f"{Cores.VERDE}[2]{Cores.RESET} WEB - Navegador (Flask)")
    print(f"{Cores.VERDE}[3]{Cores.RESET} API - RESTful (integração)")
    print(f"{Cores.VERDE}[4]{Cores.RESET} GUI - Janela (Tkinter)")
    print(f"{Cores.VERDE}[5]{Cores.RESET} BOT - Telegram (scan móvel)")
    print(f"{Cores.VERDE}[6]{Cores.RESET} SAIR\n")
    
    opcao = input("Opção: ")
    return opcao

# =================================================================
# PONTO DE ENTRADA PRINCIPAL
# =================================================================
if __name__ == "__main__":
    try:
        # Mensagem inicial (sempre aparece)
        print(f"{Cores.MAGENTA}")
        print("="*80)
        print("  OI! MEU NOME É SCDPI.1")
        print("  57 ANOS, SURDO TOTAL, AUTODIDATA EM CIBERSEGURANÇA")
        print("  ESTE CÓDIGO É MINHA PROVA QUE LIMITES NÃO EXISTEM")
        print("="*80)
        print(f"{Cores.RESET}")
        
        while True:
            opcao = menu_principal()
            
            if opcao == "1":
                alvo = input("Digite o alvo (IP/hostname): ")
                cli = FaceCLI()
                cli.executar(alvo)
                
            elif opcao == "2":
                print(f"{Cores.AZUL}[*] Iniciando interface web...{Cores.RESET}")
                web = FaceWeb()
                web.iniciar_servidor()
                
            elif opcao == "3":
                print(f"{Cores.AZUL}[*] Iniciando API...{Cores.RESET}")
                api = FaceAPI()
                api.iniciar_api()
                
            elif opcao == "4":
                print(f"{Cores.AZUL}[*] Iniciando interface gráfica...{Cores.RESET}")
                gui = FaceGUI()
                gui.iniciar_gui()
                
            elif opcao == "5":
                token = input("Digite seu token do Telegram: ")
                bot = FaceBot()
                bot.iniciar_bot(token)
                
            elif opcao == "6":
                print(f"\n{Cores.VERDE}[+] Até mais! Lembre-se: limites são mentira.{Cores.RESET}")
                print(f"{Cores.CIANO}GitHub: github.com/scdpi.1{Cores.RESET}")
                break
            
            input(f"\n{Cores.AMARELO}Pressione ENTER para continuar...{Cores.RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}[!] Scan interrompido{Cores.RESET}")
    except Exception as e:
        print(f"\n{Cores.VERMELHO}[!] Erro: {str(e)}{Cores.RESET}")
        print(f"{Cores.AMARELO}[*] Mas erros também fazem parte. O importante é continuar.{Cores.RESET}")
