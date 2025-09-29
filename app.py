#!/usr/bin/env python3

import os
import subprocess
import sys
import tarfile
import urllib.request
import json
import shutil
from pathlib import Path
from OpenSSL import crypto
import secrets
import signal
import time

# === Цвета для логов ===
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
NC = "\033[0m"

# === Константы sing-box ===
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
HOST = os.environ.get("SB_HOST", "nue.domcloud.co")       # адрес сервера
UUID = os.environ.get("SB_UUID", "37d4e59a-1807-4d0e-99e5-7ec8d6c25797")  # идентификатор клиента
PORT = int(os.environ.get("SB_PORT", "27558"))                      # порт
SNI = os.environ.get("SB_SNI", "time.android.com")        # SNI-домен

# === Настройки маскировки/обфускации ===
OBFS_PWD = os.environ.get("SB_OBFS_PWD") or secrets.token_urlsafe(24)
MASS_PROXY_URL = os.environ.get("SB_MASS_PROXY", "https://www.gstatic.com")

# === Простейшие функции логирования (минимум вывода) ===
def info(msg):
    print(f"{CYAN}[INFO]{NC} {msg}")

def ok(msg):
    print(f"{GREEN}[OK]{NC} {msg}")

def warn(msg):
    print(f"{RED}[WARN]{NC} {msg}", file=sys.stderr)

def fatal(msg):
    print(f"{RED}[ERR]{NC} {msg}", file=sys.stderr)
    sys.exit(1)

# === Проверка зависимостей ===
def install_deps():
    info("Проверка зависимостей")
    try:
        import OpenSSL  # noqa: F401
    except ImportError:
        info("Устанавливаю pyOpenSSL...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pyOpenSSL"])  # noqa: S603
    ok("Зависимости OK")

# === Генерация сертификата ===
def generate_cert():
    external_cert = os.environ.get("EXTERNAL_CERT")
    external_key = os.environ.get("EXTERNAL_KEY")
    if external_cert and external_key and Path(external_cert).exists() and Path(external_key).exists():
        info("Используются внешние сертификаты")
        return str(external_cert), str(external_key)

    info(f"Генерация самоподписного сертификата для {SNI}")
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = SNI
    cert.set_serial_number(secrets.randbits(64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(CERT_PATH, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(KEY_PATH, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    ok("Сертификат создан (самоподписной)")
    return str(CERT_PATH), str(KEY_PATH)

# === Скачивание sing-box ===
def download_singbox():
    sb_bin = SB_DIR / "sb"
    if sb_bin.exists() and os.access(sb_bin, os.X_OK):
        info("sing-box найден")
        return

    info("Скачиваю sing-box...")
    SB_DIR.mkdir(parents=True, exist_ok=True)

    # Скачиваем в текущую директорию вместо /tmp
    tmp_tar = Path.cwd() / SINGBOX_TAR

    try:
        urllib.request.urlretrieve(SINGBOX_URL, tmp_tar)
    except Exception as e:
        fatal(f"Ошибка скачивания: {e}")

    with tarfile.open(tmp_tar, "r:gz") as tar:
        tar.extractall(path=Path.cwd())

    bin_path = Path.cwd() / f"sing-box-{SINGBOX_VERSION}-linux-arm64/sing-box"
    if not bin_path.exists():
        fatal("Бинарник sing-box не найден в архиве")

    shutil.move(str(bin_path), str(sb_bin))
    os.chmod(sb_bin, 0o755)
    try:
        tmp_tar.unlink()
    except Exception:
        pass
    ok("sing-box установлен")

# === Генерация конфига ===
def generate_config(cert_path: str, key_path: str):
    info("Создаю конфиг sb.json")

    auth_password = UUID

    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "::",
                "listen_port": PORT,
                "users": [{"name": "client1", "password": auth_password}],
                "tls": {
                    "enabled": True,
                    "server_name": SNI,
                    "min_version": "1.3",
                    "alpn": ["h3", "http/1.1"],
                    "key_path": str(key_path),
                    "certificate_path": str(cert_path),
                },
                "obfs": {"type": "salamander", "password": OBFS_PWD},
                "masquerade": {"type": "proxy", "url": MASS_PROXY_URL, "rewrite_host": True},
                "ignore_client_bandwidth": True,
                "brutal_debug": False,
            }
        ],
        "outbounds": [{"tag": "direct", "type": "direct"}, {"tag": "block", "type": "block"}],
    }

    SB_DIR.mkdir(parents=True, exist_ok=True)
    SB_JSON_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    ok(f"Конфиг записан: {SB_JSON_PATH}")

# === Генерация ссылки для клиента (коротко) ===
def generate_url():
    info("Генерирую ссылку для клиента")
    try:
        org = subprocess.check_output(["curl", "-s", "ipinfo.io/org"], text=True).strip()
        org = org.split(" ", 1)[1] if " " in org else "hy2"
        org = org.replace(" ", "-").lower()
    except Exception:
        org = "hy2"

    from urllib.parse import quote_plus
    obfs_pwd_enc = quote_plus(OBFS_PWD)

    insecure_flag = "0" if os.environ.get("EXTERNAL_CERT") and os.environ.get("EXTERNAL_KEY") else "1"

    url = (
        f"hysteria2://{UUID}@{HOST}:{PORT}/"
        f"?sni={SNI}&obfs=salamander&obfs-password={obfs_pwd_enc}&insecure={insecure_flag}#{org}"
    )

    print("")
    ok("Ссылка для клиента готова")
    print(url)
    print("")

# === Запуск sing-box (минимальный вывод, фоновый процесс) ===
child_proc = None

def start_singbox():
    global child_proc
    info("Запуск sing-box")
    sb_path = SB_DIR / "sb"
    if not sb_path.exists():
        fatal("sing-box не найден. Запустите скачивание")

    try:
        child_proc = subprocess.Popen([str(sb_path), "run", "-c", str(SB_JSON_PATH)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        fatal(f"Не удалось запустить sing-box: {e}")

    ok(f"sing-box запущен и работает (PID={child_proc.pid})")
    print(f"{GREEN}sing-box работает{NC}")

    try:
        rc = child_proc.wait()
        if rc == 0:
            ok("sing-box завершил работу нормально")
        else:
            warn(f"sing-box завершился с кодом {rc}")
    except KeyboardInterrupt:
        info("Останавливаю sing-box по сигналу")
        terminate_child()

def terminate_child():
    global child_proc
    if child_proc and child_proc.poll() is None:
        try:
            child_proc.terminate()
            time.sleep(1)
            if child_proc.poll() is None:
                child_proc.kill()
        except Exception:
            pass

def _signal_handler(signum, frame):
    info(f"Получен сигнал {signum}, завершаю...")
    terminate_child()
    sys.exit(0)

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# === main ===
if __name__ == "__main__":
    install_deps()
    cert_p, key_p = generate_cert()
    download_singbox()
    generate_config(cert_p, key_p)
    generate_url()
    start_singbox()
