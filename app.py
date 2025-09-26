#!/usr/bin/env python3
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import json
import shutil
from pathlib import Path
from OpenSSL import crypto

# === Цвета ===
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
NC = "\033[0m"

# === Константы ===
SINGBOX_VERSION = "1.11.15"
SINGBOX_TAR = f"sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
SINGBOX_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/{SINGBOX_TAR}"

HOME_DIR = os.environ.get("HOME", "/home/container")
SB_DIR = Path(HOME_DIR) / ".sb"
CERT_DIR = SB_DIR / "cert"
CERT_PATH = CERT_DIR / "cert.pem"
KEY_PATH = CERT_DIR / "key.pem"
SB_JSON_PATH = SB_DIR / "sb.json"

# === Твои данные (ЗАДАЙ ТУТ!) ===
HOST = "play.greathost.es"       # адрес сервера
UUID = "123e4567-e89b-12d3-a456-426614174000"  # UUID пользователя
PORT = 20361                      # порт
SNI = "time.android.com"        # SNI-домен

# === Утилиты логов ===
def log(msg): print(f"{CYAN}[INFO]{NC} {msg}")
def ok(msg):  print(f"{GREEN}[OK]{NC} {msg}")
def err(msg): 
    print(f"{RED}[ERR]{NC} {msg}", file=sys.stderr)
    sys.exit(1)

# === Проверка зависимостей ===
def install_deps():
    log("Проверка зависимостей...")

    # Проверка pyOpenSSL
    try:
        import OpenSSL
    except ImportError:
        log("Установка pyOpenSSL...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pyOpenSSL"])
    ok("pyOpenSSL готов")

# === Генерация сертификата ===
def generate_cert():
    log(f"Генерация сертификата для {SNI}")
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = SNI
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(CERT_PATH, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(KEY_PATH, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    ok("Сертификат создан")

# === Скачивание sing-box ===
def download_singbox():
    sb_bin = SB_DIR / "sb"
    if sb_bin.exists() and os.access(sb_bin, os.X_OK):
        log("sing-box уже скачан")
        return

    log("Скачивание sing-box...")
    SB_DIR.mkdir(parents=True, exist_ok=True)
    tmp_tar = Path(tempfile.gettempdir()) / SINGBOX_TAR

    urllib.request.urlretrieve(SINGBOX_URL, tmp_tar)

    with tarfile.open(tmp_tar, "r:gz") as tar:
        tar.extractall(path=tempfile.gettempdir())

    bin_path = Path(tempfile.gettempdir()) / f"sing-box-{SINGBOX_VERSION}-linux-amd64/sing-box"
    shutil.move(str(bin_path), str(sb_bin))   # исправлено os.rename -> shutil.move
    os.chmod(sb_bin, 0o755)
    tmp_tar.unlink()
    ok("sing-box установлен")

# === Генерация конфигурации ===
def generate_config():
    log("Создание конфигурации sb.json")
    config = {
        "inbounds": [
            {
                "type": "hysteria2",
                "listen": "::",
                "listen_port": PORT,
                "users": [{"password": UUID}],
                "tls": {
                    "enabled": True,
                    "server_name": SNI,
                    "key_path": str(KEY_PATH),
                    "certificate_path": str(CERT_PATH)
                },
                "masquerade": f"https://{SNI}"
            }
        ],
        "outbounds": [
            {"tag": "direct", "type": "direct"},
            {"tag": "block", "type": "block"}
        ]
    }
    SB_JSON_PATH.write_text(json.dumps(config, indent=2))
    ok("Конфиг создан")

# === Генерация ссылки ===
def generate_url():
    log("Генерация hysteria2-ссылки")
    try:
        org = subprocess.check_output(
            ["curl", "-s", "ipinfo.io/org"], text=True
        ).strip()
        org = org.split(" ", 1)[1] if " " in org else "hy2"
        org = org.replace(" ", "-").lower()
    except Exception:
        org = "hy2"

    url = f"hysteria2://{UUID}@{HOST}:{PORT}/?sni={SNI}&insecure=1#{org}"
    print(f"\n{GREEN}{url}{NC}\n")

# === Запуск sing-box ===
def run_singbox():
    log("Запуск sing-box...")
    os.execv(str(SB_DIR / "sb"), [str(SB_DIR / "sb"), "run", "-c", str(SB_JSON_PATH)])

# === Выполнение ===
if __name__ == "__main__":
    install_deps()
    generate_cert()
    download_singbox()
    generate_config()
    generate_url()
    run_singbox()
