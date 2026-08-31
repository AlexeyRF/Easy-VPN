import sys
import os
import subprocess
import urllib.request
import urllib.parse
import json
import platform
import socket
import base64
import concurrent.futures
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLabel
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QThread
from PyQt6.QtGui import QFont

class ProxyTester(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, list)

    def run(self):
        try:
            self.progress.emit("Загрузка подписок...")
            subs_file = "subs.txt"
            if not os.path.exists(subs_file):
                self.finished.emit(False, ["Файл subs.txt не найден в папке"])
                return
                
            with open(subs_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
                
            nodes = []
            for u in urls:
                try:
                    req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
                    data = urllib.request.urlopen(req, timeout=10).read().decode('utf-8')
                    try:
                        # Пробуем декодировать base64, если файл закодирован
                        if "vless://" not in data:
                            data = base64.b64decode(data).decode('utf-8')
                    except Exception:
                        pass
                    for line in data.splitlines():
                        if line.startswith('vless://'):
                            nodes.append(line.strip())
                except Exception as e:
                    pass
            
            if not nodes:
                self.finished.emit(False, ["Не найдено ни одного vless конфига"])
                return
                
            self.progress.emit(f"Проверка серверов (найдено {len(nodes)})...")
            
            working_nodes = []
            checked = 0
            
            def check_node(link):
                try:
                    parsed = urllib.parse.urlparse(link)
                    host = parsed.hostname
                    port = parsed.port or 443
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.5)
                    sock.connect((host, int(port)))
                    sock.close()
                    return link
                except:
                    return None
            
            # Пул потоков для быстрой проверки TCP пинга
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(check_node, n): n for n in nodes}
                for future in concurrent.futures.as_completed(futures):
                    checked += 1
                    if checked % 20 == 0:
                        self.progress.emit(f"Проверка: {checked}/{len(nodes)} (Рабочих: {len(working_nodes)})")
                    res = future.result()
                    if res:
                        working_nodes.append(res)
            
            if not working_nodes:
                self.finished.emit(False, ["Нет доступных серверов"])
                return
                
            self.finished.emit(True, working_nodes)
        except Exception as e:
            self.finished.emit(False, [f"Ошибка: {e}"])

def build_singbox_config(nodes):
    outbounds = [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
    
    proxy_tags = []
    
    # Ограничиваем до 200, чтобы конфиг не был слишком огромным (этого более чем достаточно)
    for i, link in enumerate(nodes[:200]):
        try:
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username
            server = parsed.hostname
            port = parsed.port or 443
            qs = urllib.parse.parse_qs(parsed.query)
            
            # Название тега
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"proxy-{i}"
            tag = f"proxy-{i}" # Используем короткие теги для надежности
            
            security = qs.get("security", ["none"])[0]
            type_ = qs.get("type", ["tcp"])[0]
            flow = qs.get("flow", [""])[0]
            sni = qs.get("sni", [""])[0]
            fp = qs.get("fp", ["chrome"])[0]
            pbk = qs.get("pbk", [""])[0]
            sid = qs.get("sid", [""])[0]
            
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": int(port),
                "uuid": uuid,
                "packet_encoding": "xudp"
            }
            
            if flow:
                outbound["flow"] = flow
                
            if security in ["tls", "reality"]:
                tls_config = {
                    "enabled": True,
                    "server_name": sni or server,
                    "utls": {
                        "enabled": True,
                        "fingerprint": fp
                    }
                }
                if security == "reality":
                    tls_config["reality"] = {
                        "enabled": True,
                        "public_key": pbk,
                        "short_id": sid
                    }
                outbound["tls"] = tls_config
                
            if type_ == "ws":
                path = qs.get("path", ["/"])[0]
                host = qs.get("host", [""])[0]
                outbound["transport"] = {
                    "type": "ws",
                    "path": path,
                    "headers": {"Host": host} if host else {}
                }
            elif type_ == "grpc":
                serviceName = qs.get("serviceName", [""])[0]
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": serviceName
                }
                
            outbounds.append(outbound)
            proxy_tags.append(tag)
        except Exception:
            continue
            
    # Добавляем urltest outbound, который автоматически выберет самый быстрый сервер
    outbounds.insert(0, {
        "type": "urltest",
        "tag": "auto",
        "outbounds": proxy_tags,
        "url": "http://cp.cloudflare.com/generate_204",
        "interval": "3m",
        "tolerance": 5000
    })

    config = {
        "log": {
            "level": "info"
        },
        "dns": {
            "servers": [
                {"tag": "local", "address": "local", "detour": "direct"}
            ]
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "easy-vpn-tun",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed"
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"port": 53, "action": "hijack-dns"},
                {"inbound": "tun-in", "outbound": "auto"}
            ],
            "auto_detect_interface": True,
            "final": "auto"
        }
    }
    return config


class VpnWorker(QObject):
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.sb_process = None
        self.is_running = False
        self.tester = None
        self.working_nodes = []

    def start_vpn(self):
        if self.is_running:
            return
        
        self.is_running = True
        
        self.tester = ProxyTester()
        self.tester.progress.connect(self.status_changed.emit)
        self.tester.finished.connect(self._on_test_finished)
        self.tester.start()

    def _on_test_finished(self, success, result):
        if not success:
            self.error_occurred.emit(result[0])
            self.is_running = False
            self.status_changed.emit("VPN Выключен")
            return
            
        self.working_nodes = result
        self._start_singbox_with_nodes()

    def _start_singbox_with_nodes(self):
        if not self.working_nodes:
            self.error_occurred.emit("Нет доступных серверов!")
            self.is_running = False
            self.status_changed.emit("VPN Выключен")
            return
            
        self.status_changed.emit(f"Генерация конфига (сохранено {len(self.working_nodes[:200])} серверов)...")
        
        try:
            config = build_singbox_config(self.working_nodes)
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
                
            self.status_changed.emit("Запуск sing-box...")
            
            exe_prefix = ".\\" if platform.system() == "Windows" else "./"
            cmd = [
                f"{exe_prefix}sing-box.exe",
                "run",
                "-c", "config.json"
            ]
            
            kwargs = {}
            if platform.system() == "Windows":
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            
            env = os.environ.copy()
            env["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] = "true"
            env["ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM"] = "true"
            env["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] = "true"
            
            self.sb_process = subprocess.Popen(cmd, env=env, **kwargs)
            self.status_changed.emit("VPN Включен")
            
        except Exception as e:
            self.error_occurred.emit(f"Ошибка запуска sing-box:\n{e}")
            self.is_running = False
            self.status_changed.emit("VPN Выключен")

    def next_server(self):
        if not self.is_running or not self.working_nodes:
            return
        
        self.status_changed.emit("Переключение сервера...")
        if self.sb_process:
            self.sb_process.terminate()
            try:
                self.sb_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.sb_process.kill()
            self.sb_process = None
            
        # Сдвигаем список (текущие лучшие серверы уходят в конец)
        import random
        # Берем первый элемент и переносим его в конец, или просто перемешиваем топ
        top_node = self.working_nodes.pop(0)
        self.working_nodes.append(top_node)
        
        # Перезапускаем sing-box
        self._start_singbox_with_nodes()

    def stop_vpn(self):
        self.is_running = False
        self.status_changed.emit("Выключение...")
        
        if self.sb_process:
            self.sb_process.terminate()
            try:
                self.sb_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.sb_process.kill()
            self.sb_process = None
            
        self.status_changed.emit("VPN Выключен")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Easy VPN")
        self.setFixedSize(360, 550)
        self.setStyleSheet("background-color: #121212; color: #ffffff;")
        self.apply_dark_titlebar()

        self.worker = VpnWorker()
        self.worker.status_changed.connect(self.update_status)
        self.worker.error_occurred.connect(self.show_error)

    def apply_dark_titlebar(self):
        if platform.system() != "Windows":
            return
        try:
            import ctypes
            hwnd = int(self.winId())
            value = ctypes.c_int(1)
            # Windows 11
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
            # Windows 10
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(value), ctypes.sizeof(value))
            # Custom titlebar color (Windows 11)
            color = ctypes.c_int(0x00121212)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(color), ctypes.sizeof(color))
        except Exception:
            pass

        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        main_layout.setContentsMargins(20, 50, 20, 20)
        
        # Title
        self.title_label = QLabel("EASY VPN")
        self.title_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("color: #ffffff; letter-spacing: 2px;")
        main_layout.addWidget(self.title_label)
        
        main_layout.addSpacing(60)

        # Connection Button
        self.toggle_btn = QPushButton("OFF")
        self.toggle_btn.setFixedSize(160, 160)
        self.toggle_btn.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_btn_style_disconnected()
        self.toggle_btn.clicked.connect(self.toggle_vpn)
        
        btn_layout = QHBoxLayout()
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_layout.addWidget(self.toggle_btn)
        main_layout.addLayout(btn_layout)
        
        main_layout.addSpacing(20)
        
        # Switch Server Button
        self.next_btn = QPushButton("Сменить сервер")
        self.next_btn.setFixedSize(160, 40)
        self.next_btn.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.next_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.next_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #ffffff;
                border-radius: 20px;
                border: 2px solid #444444;
            }
            QPushButton:hover {
                background-color: #444444;
            }
            QPushButton:pressed {
                background-color: #222222;
            }
        """)
        self.next_btn.clicked.connect(self.next_server)
        self.next_btn.hide() # Hidden when disconnected
        
        next_btn_layout = QHBoxLayout()
        next_btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        next_btn_layout.addWidget(self.next_btn)
        main_layout.addLayout(next_btn_layout)
        
        main_layout.addSpacing(20)

        # Status Label
        self.status_label = QLabel("Отключено")
        self.status_label.setFont(QFont("Segoe UI", 16))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #aaaaaa;")
        main_layout.addWidget(self.status_label)
        
        main_layout.addSpacing(20)

        # Error Label
        self.error_label = QLabel("")
        self.error_label.setFont(QFont("Segoe UI", 10))
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setStyleSheet("color: #ff5555;")
        self.error_label.setWordWrap(True)
        main_layout.addWidget(self.error_label)
        
        main_layout.addStretch()

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def set_btn_style_disconnected(self):
        self.toggle_btn.setText("OFF")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #2b2b2b;
                color: #888888;
                border-radius: 80px;
                border: 6px solid #333333;
            }
            QPushButton:hover {
                background-color: #353535;
                border-color: #444444;
            }
            QPushButton:pressed {
                background-color: #222222;
                border-color: #2a2a2a;
            }
        """)

    def set_btn_style_connected(self):
        self.toggle_btn.setText("ON")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #1abc9c;
                color: #ffffff;
                border-radius: 80px;
                border: 6px solid #16a085;
            }
            QPushButton:hover {
                background-color: #1dd2af;
                border-color: #1abc9c;
            }
            QPushButton:pressed {
                background-color: #12876f;
                border-color: #16a085;
            }
        """)
        
    def set_btn_style_transitioning(self):
        self.toggle_btn.setText("...")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: #ffffff;
                border-radius: 80px;
                border: 6px solid #d35400;
            }
            QPushButton:hover {
                background-color: #f39c12;
                border-color: #e67e22;
            }
        """)

    def toggle_vpn(self):
        self.error_label.setText("")
        if self.worker.is_running:
            self.worker.stop_vpn()
        else:
            self.worker.start_vpn()
            
    def next_server(self):
        if self.worker.is_running:
            self.worker.next_server()

    def update_status(self, text):
        if "VPN Включен" in text:
            self.status_label.setText("Подключено")
            self.status_label.setStyleSheet("color: #1abc9c; font-weight: bold;")
            self.set_btn_style_connected()
            self.next_btn.show()
        elif "VPN Выключен" in text:
            self.status_label.setText("Отключено")
            self.status_label.setStyleSheet("color: #aaaaaa;")
            self.set_btn_style_disconnected()
            self.next_btn.hide()
        else:
            self.status_label.setText(text)
            self.status_label.setStyleSheet("color: #e67e22;")
            self.set_btn_style_transitioning()
            if "Переключение" not in text:
                self.next_btn.hide()

    def show_error(self, text):
        self.error_label.setText(text)

    def closeEvent(self, event):
        self.worker.stop_vpn()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
