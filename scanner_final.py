#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

# =================================================================
# IMPORTS COM SEGURANÇA
# =================================================================
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
import signal
import logging
from logging.handlers import RotatingFileHandler

# =================================================================
# CONFIGURAÇÕES DE SEGURANÇA
# =================================================================
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[!] python-dotenv não instalado. Tokens ficarão visíveis!")
    print("[*] Instale com: pip install python-dotenv")

# Tokens e chaves (agora seguros!)
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-key-troque-em-producao')

# Configurações de segurança
TIMEOUT_GLOBAL = 60  # segundos máximo por scan
MAX_PORTAS = 1000    # limite para evitar scans muito grandes
RATE_LIMIT = 5       # máximo de scans por minuto por IP

# =================================================================
# LOGS SEGUROS (com rotação)
# =================================================================
handler = RotatingFileHandler('scanner.log', maxBytes=1048576, backupCount=3)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =================================================================
# CORES (acessibilidade visual)
# =================================================================
class Cores:
    VERDE = '\033[92m'
    VERMELHO = '\033[91m'
    AMARELO = '\033[93m'
    AZUL = '\033[94m'
    MAGENTA = '\033[95m'
    CIANO = '\033[96m'
    RESET = '\033[0m'
    NEGRITO = '\033[1m'

# =================================================================
# SEGURANÇA: Timeout global
# =================================================================
class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Scan excedeu tempo limite")

# =================================================================
# SEGURANÇA: Validação de entrada
# =================================================================
def validar_alvo(alvo):
    """
    Valida e sanitiza o alvo para prevenir injeção de comandos
    Permite: IPs, hostnames, domínios
    """
    if not alvo or len(alvo) > 255:
        raise ValueError("Alvo inválido: tamanho excedido")
    
    # Remove caracteres perigosos
    alvo = alvo.strip()
    
    # Padrões permitidos
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$'
    local_pattern = r'^localhost$'
    
    if re.match(ip_pattern, alvo):
        # Valida IP real
        partes = alvo.split('.')
        for p in partes:
            if int(p) > 255:
                raise ValueError("IP inválido: octeto > 255")
        return alvo
    elif re.match(hostname_pattern, alvo) or re.match(local_pattern, alvo):
        return alvo
    else:
        raise ValueError("Alvo inválido: use IP ou hostname válido")

# =================================================================
# SEGURANÇA: Rate limiting
# =================================================================
class RateLimiter:
    def __init__(self, max_requests=5, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}
    
    def permitir(self, ip):
        agora = time.time()
        if ip not in self.requests:
            self.requests[ip] = []
        
        # Limpa requisições antigas
        self.requests[ip] = [t for t in self.requests[ip] if agora - t < self.time_window]
        
        if len(self.requests[ip]) >= self.max_requests:
            return False
        
        self.requests[ip].append(agora)
        return True

rate_limiter = RateLimiter(max_requests=RATE_LIMIT)

# =================================================================
# CLASSE PRINCIPAL DO SCANNER
# =================================================================
class ScannerPrincipal:
    def __init__(self, alvo):
        try:
            self.alvo = validar_alvo(alvo)
        except ValueError as e:
            raise ValueError(f"Alvo inválido: {e}")
        
        self.portas_comuns = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888]
        self.resultados_tcp = []
        self.resultados_udp = []
        self.log_erros = []
        self.banners = {}
        self.fingerprint_detalhado = {}
        self.inicio_scan = datetime.now()
        self.scan_id = hashlib.md5(f"{alvo}{time.time()}".encode()).hexdigest()[:8]
        
        logger.info(f"Scan iniciado - ID: {self.scan_id} - Alvo: {alvo}")
    
    def scan_porta_tcp(self, ip, porta):
        """Scan TCP com tratamento de erros e timeout"""
        for tentativa in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                resultado = sock.connect_ex((ip, porta))
                
                if resultado == 0:
                    banner = self.pegar_banner(ip, porta)
                    sock.close()
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
        """Pega banner do serviço com segurança"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, porta))
            
            # Envia probes específicos por porta
            if porta in [80, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif porta == 21:
                pass  # FTP já envia banner
            elif porta == 25:
                sock.send(b"EHLO scan.local\r\n")
            elif porta == 443:
                sock.close()
                return "SSL/TLS"
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Sanitiza banner (remove caracteres perigosos)
            banner = re.sub(r'[^\x20-\x7E\n\r\t]', '', banner)
            return banner[:200]  # Limita tamanho
            
        except:
            return None
    
    def fingerprint_so(self, ip):
        """Detecta SO com segurança"""
        so_info = {'so_provavel': 'Desconhecido'}
        
        try:
            # Usa timeout no subprocess
            ping = subprocess.run(
                ['ping', '-c', '2', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
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
        """Executa scan completo com timeout global"""
        print(f"\n{Cores.AZUL}[*] Scan iniciado em {self.alvo} (ID: {self.scan_id}){Cores.RESET}")
        
        # Configura timeout global
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(TIMEOUT_GLOBAL)
        
        try:
            # Resolve IP
            try:
                ip_resolvido = socket.gethostbyname(self.alvo)
                self.alvo = ip_resolvido
            except:
                pass
            
            # Scan TCP
            print(f"{Cores.AMARELO}[*] Escaneando portas TCP...{Cores.RESET}")
            for i, porta in enumerate(self.portas_comuns[:MAX_PORTAS]):
                print(f"\r  Progresso: {i+1}/{len(self.portas_comuns)}", end="")
                
                status, banner = self.scan_porta_tcp(self.alvo, porta)
                
                if status == "ABERTA":
                    print(f"\n{Cores.VERDE}[+] Porta {porta}/TCP - ABERTA{Cores.RESET}")
                    if banner:
                        print(f"    Banner: {banner[:50]}...")
                    
                    self.resultados_tcp.append({
                        'porta': porta,
                        'protocolo': 'tcp',
                        'status': status,
                        'banner': banner,
                        'servico': self.detecta_servico(porta)
                    })
                
                time.sleep(0.1)  # Pequeno delay para não sobrecarregar
            
            # Fingerprint SO
            self.fingerprint_detalhado = self.fingerprint_so(self.alvo)
            
            print(f"\n{Cores.VERDE}[+] Scan concluído em {datetime.now() - self.inicio_scan}{Cores.RESET}")
            
            # Log do resultado
            logger.info(f"Scan concluído - ID: {self.scan_id} - Portas: {len(self.resultados_tcp)}")
            
        except TimeoutError:
            print(f"\n{Cores.VERMELHO}[!] Scan excedeu tempo limite ({TIMEOUT_GLOBAL}s){Cores.RESET}")
            logger.warning(f"Timeout - ID: {self.scan_id}")
        finally:
            signal.alarm(0)  # Desativa alarme
    
    def detecta_servico(self, porta):
        """Detecta serviço pela porta"""
        servicos = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            27017: "MongoDB", 9200: "Elasticsearch"
        }
        return servicos.get(porta, "Desconhecido")
    
    def salvar_resultados(self):
        """Salva resultados em múltiplos formatos com segurança"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        alvo_limpo = self.alvo.replace('/', '_').replace('\\', '_').replace(':', '_')
        base = f"scan_{alvo_limpo}_{timestamp}"
        
        # TXT simples (apenas dados essenciais)
        with open(f"{base}.txt", 'w') as f:
            f.write(f"SCAN REALIZADO POR: SCDPI.1 (github.com/scdpi.1)\n")
            f.write(f"DATA: {datetime.now()}\n")
            f.write(f"ALVO: {self.alvo}\n")
            f.write(f"ID: {self.scan_id}\n")
            f.write("="*60 + "\n\n")
            
            f.write("PORTAS ABERTAS:\n")
            for r in self.resultados_tcp:
                f.write(f"{r['porta']}/TCP - {r.get('servico', '')}\n")
                if r.get('banner'):
                    f.write(f"  Banner: {r['banner'][:100]}\n")
            
            f.write(f"\nSO DETECTADO: {self.fingerprint_detalhado.get('so_provavel')}\n")
        
        # JSON (dados completos, mas sem dados sensíveis)
        with open(f"{base}.json", 'w') as f:
            json.dump({
                'criador': 'SCDPI.1',
                'github': 'https://github.com/scdpi.1',
                'data': str(datetime.now()),
                'scan_id': self.scan_id,
                'alvo': self.alvo,
                'resultados_tcp': [
                    {k: v for k, v in r.items() if k != 'banner_bruto'} 
                    for r in self.resultados_tcp
                ],
                'so': self.fingerprint_detalhado,
                'erros': self.log_erros[-10:]  # Apenas últimos 10 erros
            }, f, indent=4)
        
        print(f"{Cores.VERDE}[+] Resultados salvos em: {base}.txt e {base}.json{Cores.RESET}")
        logger.info(f"Resultados salvos - ID: {self.scan_id} - Arquivo: {base}")
        return base

# =================================================================
# FACE 1: CLI
# =================================================================
class FaceCLI:
    @staticmethod
    def executar(alvo):
        try:
            scanner = ScannerPrincipal(alvo)
            scanner.scan_completo()
            scanner.salvar_resultados()
            return scanner.resultados_tcp
        except ValueError as e:
            print(f"{Cores.VERMELHO}[!] Erro: {e}{Cores.RESET}")
            return []

# =================================================================
# FACE 2: WEB (Flask)
# =================================================================
class FaceWeb:
    @staticmethod
    def iniciar_servidor(porta=5000):
        try:
            from flask import Flask, render_template_string, request
            
            app = Flask(__name__)
            app.secret_key = FLASK_SECRET_KEY
            
            resultados_web = {}
            
            @app.route('/')
            def home():
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>SCDPI.1 Scanner</title>
                    <style>
                        body { background: #000; color: #0f0; font-family: monospace; padding: 20px; }
                        .container { max-width: 800px; margin: auto; border: 2px solid #0f0; padding: 20px; }
                        .historia { background: #111; padding: 15px; border-left: 5px solid yellow; margin: 20px 0; }
                        input, button { background: #000; color: #0f0; border: 2px solid #0f0; padding: 10px; margin: 5px; }
                        button:hover { background: #0f0; color: #000; cursor: pointer; }
                        .resultados { background: #111; padding: 10px; max-height: 400px; overflow-y: auto; }
                        footer { margin-top: 30px; color: #666; text-align: center; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔍 SCDPI.1 MULTISCANNER</h1>
                        <div class="historia">
                            <strong>57 anos • Surdo • Autodidata</strong><br>
                            "Limites são mentira"
                        </div>
                        <form action="/scan" method="post">
                            <input type="text" name="alvo" placeholder="IP ou hostname" required>
                            <button type="submit">INICIAR SCAN</button>
                        </form>
                        <h2>📊 Resultados</h2>
                        <div class="resultados">
                            {{ resultados }}
                        </div>
                        <footer>
                            GitHub: <a href="https://github.com/scdpi.1" style="color:#0f0;">@scdpi.1</a>
                        </footer>
                    </div>
                </body>
                </html>
                """, resultados=str(resultados_web)[:1000] if resultados_web else "Nenhum scan ainda")
            
            @app.route('/scan', methods=['POST'])
            def scan():
                global resultados_web
                try:
                    alvo = request.form['alvo']
                    
                    # Rate limiting por IP
                    client_ip = request.remote_addr
                    if not rate_limiter.permitir(client_ip):
                        return "Muitas requisições. Aguarde.", 429
                    
                    scanner = ScannerPrincipal(alvo)
                    scanner.scan_completo()
                    arquivos = scanner.salvar_resultados()
                    
                    resultados_web[alvo] = {
                        'data': str(datetime.now()),
                        'resultados': arquivos,
                        'portas': len(scanner.resultados_tcp)
                    }
                    
                    return f"""
                    <html>
                    <head><meta http-equiv="refresh" content="2;url=/"></head>
                    <body style="background:#000;color:#0f0;text-align:center;padding:50px;">
                        <h1>✅ SCAN CONCLUÍDO</h1>
                        <p>Alvo: {alvo}</p>
                        <p>Portas abertas: {len(scanner.resultados_tcp)}</p>
                        <p>Redirecionando...</p>
                    </body>
                    </html>
                    """
                except ValueError as e:
                    return f"Erro: {e}", 400
                except Exception as e:
                    logger.error(f"Erro no scan web: {e}")
                    return "Erro interno", 500
            
            print(f"{Cores.VERDE}[+] Servidor web: http://localhost:{porta}{Cores.RESET}")
            app.run(host='0.0.0.0', port=porta, debug=False)
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] Flask não instalado. pip install flask{Cores.RESET}")

# =================================================================
# FACE 3: API (RESTful)
# =================================================================
class FaceAPI:
    @staticmethod
    def iniciar_api(porta=8080):
        try:
            from flask import Flask, jsonify, request
            from flask_cors import CORS
            
            app = Flask(__name__)
            CORS(app)
            app.secret_key = FLASK_SECRET_KEY
            
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
                try:
                    data = request.get_json()
                    if not data or 'alvo' not in data:
                        return jsonify({'erro': 'Alvo não especificado'}), 400
                    
                    alvo = data['alvo']
                    
                    # Rate limiting
                    client_ip = request.remote_addr
                    if not rate_limiter.permitir(client_ip):
                        return jsonify({'erro': 'Muitas requisições'}), 429
                    
                    scanner = ScannerPrincipal(alvo)
                    scanner.scan_completo()
                    arquivos = scanner.salvar_resultados()
                    
                    scan_id = hashlib.md5(f"{alvo}{time.time()}".encode()).hexdigest()[:8]
                    scans_api[scan_id] = {
                        'alvo': alvo,
                        'data': str(datetime.now()),
                        'resultados': arquivos,
                        'portas': len(scanner.resultados_tcp)
                    }
                    
                    return jsonify({
                        'scan_id': scan_id,
                        'status': 'concluido',
                        'portas_encontradas': len(scanner.resultados_tcp),
                        'arquivos': arquivos
                    })
                    
                except ValueError as e:
                    return jsonify({'erro': str(e)}), 400
                except Exception as e:
                    logger.error(f"Erro na API: {e}")
                    return jsonify({'erro': 'Erro interno'}), 500
            
            @app.route('/api/v1/scan/<scan_id>', methods=['GET'])
            def get_scan(scan_id):
                if scan_id in scans_api:
                    return jsonify(scans_api[scan_id])
                return jsonify({'erro': 'Scan não encontrado'}), 404
            
            print(f"{Cores.VERDE}[+] API rodando: http://localhost:{porta}{Cores.RESET}")
            app.run(host='0.0.0.0', port=porta, debug=False)
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] Flask/CORS não instalado. pip install flask flask-cors{Cores.RESET}")

# =================================================================
# FACE 4: GUI (Tkinter)
# =================================================================
class FaceGUI:
    @staticmethod
    def iniciar_gui():
        try:
            import tkinter as tk
            from tkinter import scrolledtext
            
            class ScannerGUI:
                def __init__(self):
                    self.janela = tk.Tk()
                    self.janela.title("SCDPI.1 Scanner")
                    self.janela.geometry("800x600")
                    self.janela.configure(bg='black')
                    
                    tk.Label(self.janela, text="🔍 SCDPI.1 MULTISCANNER",
                           fg='green', bg='black', font=('Courier', 16, 'bold')).pack(pady=10)
                    
                    tk.Label(self.janela, text="57 anos | Surdo | Autodidata",
                           fg='yellow', bg='black', font=('Courier', 10)).pack()
                    
                    frame = tk.Frame(self.janela, bg='black')
                    frame.pack(pady=20)
                    
                    tk.Label(frame, text="Alvo:", fg='green', bg='black',
                            font=('Courier', 12)).pack(side=tk.LEFT)
                    
                    self.alvo_entry = tk.Entry(frame, width=30,
                                              bg='#1a1a1a', fg='green',
                                              insertbackground='green')
                    self.alvo_entry.pack(side=tk.LEFT, padx=5)
                    
                    tk.Button(frame, text="SCAN", bg='green', fg='black',
                            command=self.iniciar_scan).pack(side=tk.LEFT)
                    
                    self.resultados = scrolledtext.ScrolledText(self.janela,
                                                               width=90, height=25,
                                                               bg='#1a1a1a', fg='green',
                                                               font=('Courier', 10))
                    self.resultados.pack(pady=10)
                    
                    tk.Label(self.janela, text="GitHub: @scdpi.1 | Limites são mentira",
                           fg='gray', bg='black', font=('Courier', 8)).pack()
                
                def iniciar_scan(self):
                    alvo = self.alvo_entry.get()
                    if not alvo:
                        self.resultados.insert(tk.END, "[!] Digite um alvo\n")
                        return
                    
                    try:
                        self.resultados.insert(tk.END, f"\n[*] Scan em {alvo}\n")
                        self.janela.update()
                        
                        scanner = ScannerPrincipal(alvo)
                        scanner.scan_completo()
                        arquivos = scanner.salvar_resultados()
                        
                        self.resultados.insert(tk.END, f"[+] Scan concluído!\n")
                        self.resultados.insert(tk.END, f"[+] Arquivos: {arquivos}\n")
                        
                        for r in scanner.resultados_tcp:
                            self.resultados.insert(tk.END, 
                                f"  • {r['porta']}/TCP - {r.get('servico', '')}\n")
                            
                    except ValueError as e:
                        self.resultados.insert(tk.END, f"[!] Erro: {e}\n")
                    except Exception as e:
                        self.resultados.insert(tk.END, f"[!] Erro inesperado\n")
                
                def rodar(self):
                    self.janela.mainloop()
            
            app = ScannerGUI()
            app.rodar()
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] Tkinter não disponível{Cores.RESET}")

# =================================================================
# FACE 5: BOT (Telegram)
# =================================================================
class FaceBot:
    @staticmethod
    def iniciar_bot(token=None):
        try:
            import telebot
            
            if token is None:
                token = TELEGRAM_TOKEN
            
            if not token:
                print(f"{Cores.VERMELHO}[!] Token não configurado{Cores.RESET}")
                print("[*] Crie um arquivo .env com TELEGRAM_TOKEN=seu_token")
                return
            
            bot = telebot.TeleBot(token)
            
            @bot.message_handler(commands=['start', 'ajuda'])
            def send_welcome(message):
                bot.reply_to(message, """
🔰 SCDPI.1 SCANNER BOT
Comandos:
/scan <IP> - Escanear alvo
/sobre - História do criador
/status - Status do bot
                """)
            
            @bot.message_handler(commands=['sobre'])
            def sobre(message):
                bot.reply_to(message, """
📖 CRIADOR: SCDPI.1
• 57 anos
• Surdo total
• Autodidata
• 3 anos em cibersegurança
"Limites são mentira"
                """)
            
            @bot.message_handler(commands=['scan'])
            def scan(message):
                try:
                    partes = message.text.split()
                    if len(partes) < 2:
                        bot.reply_to(message, "Use: /scan <IP>")
                        return
                    
                    alvo = partes[1]
                    
                    # Rate limiting por usuário
                    user_id = str(message.from_user.id)
                    if not rate_limiter.permitir(user_id):
                        bot.reply_to(message, "Muitos scans. Aguarde.")
                        return
                    
                    bot.reply_to(message, f"🔄 Escaneando {alvo}...")
                    
                    scanner = ScannerPrincipal(alvo)
                    scanner.scan_completo()
                    arquivos = scanner.salvar_resultados()
                    
                    resposta = f"✅ Scan concluído\n"
                    resposta += f"📊 Portas: {len(scanner.resultados_tcp)}\n"
                    resposta += f"📁 Arquivos: {arquivos}"
                    
                    for r in scanner.resultados_tcp[:5]:
                        resposta += f"\n  • {r['porta']}/TCP"
                    
                    bot.reply_to(message, resposta)
                    
                except ValueError as e:
                    bot.reply_to(message, f"❌ Erro: {e}")
                except Exception as e:
                    logger.error(f"Erro no bot: {e}")
                    bot.reply_to(message, "❌ Erro interno")
            
            @bot.message_handler(commands=['status'])
            def status(message):
                bot.reply_to(message, "✅ Bot online e funcionando!")
            
            print(f"{Cores.VERDE}[+] Bot Telegram iniciado{Cores.RESET}")
            print(f"{Cores.AMARELO}[*] Procure por: @scdpi1_scanner_bot{Cores.RESET}")
            bot.infinity_polling()
            
        except ImportError:
            print(f"{Cores.VERMELHO}[!] pyTelegramBotAPI não instalado{Cores.RESET}")

# =================================================================
# MENU PRINCIPAL
# =================================================================
def menu_principal():
    print(f"{Cores.CIANO}{Cores.NEGRITO}")
    print("╔" + "═"*70 + "╗")
    print("║             SCDPI.1 MULTISCANNER - VERSÃO 3.0              ║")
    print("║         'Limites são mentira - 57 anos, codando'           ║")
    print("╚" + "═"*70 + "╝")
    print(f"{Cores.RESET}")
    
    print("\nESCOLHA SUA INTERFACE:")
    print(f"{Cores.VERDE}[1]{Cores.RESET} CLI - Terminal")
    print(f"{Cores.VERDE}[2]{Cores.RESET} WEB - Navegador (Flask)")
    print(f"{Cores.VERDE}[3]{Cores.RESET} API - RESTful")
    print(f"{Cores.VERDE}[4]{Cores.RESET} GUI - Janela (Tkinter)")
    print(f"{Cores.VERDE}[5]{Cores.RESET} BOT - Telegram")
    print(f"{Cores.VERMELHO}[6]{Cores.RESET} SAIR\n")
    
    return input("Opção: ")

# =================================================================
# MAIN
# =================================================================
if __name__ == "__main__":
    try:
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
                alvo = input("Digite o alvo: ")
                FaceCLI().executar(alvo)
                
            elif opcao == "2":
                FaceWeb().iniciar_servidor()
                
            elif opcao == "3":
                FaceAPI().iniciar_api()
                
            elif opcao == "4":
                FaceGUI().iniciar_gui()
                
            elif opcao == "5":
                FaceBot().iniciar_bot()
                
            elif opcao == "6":
                print(f"\n{Cores.VERDE}[+] Até mais! Lembre-se: limites são mentira.{Cores.RESET}")
                print(f"{Cores.CIANO}GitHub: github.com/scdpi.1{Cores.RESET}")
                break
            
            input(f"\n{Cores.AMARELO}Pressione ENTER para continuar...{Cores.RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}[!] Até mais!{Cores.RESET}")
    except Exception as e:
        print(f"\n{Cores.VERMELHO}[!] Erro inesperado: {e}{Cores.RESET}")
        logger.error(f"Erro fatal: {e}")
