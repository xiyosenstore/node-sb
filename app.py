#!/usr/bin/env python3

from pathlib import Path
import os
import sys
import json
import tarfile
import tempfile
import shutil
import urllib.request
import subprocess
import secrets
import signal
import time
from typing import Tuple

try:
    from OpenSSL import crypto
except Exception as e:
    sys.exit("Требуется pyOpenSSL. Установите: pip install pyOpenSSL")

# ----------------- Конфигурация (можно задавать через окружение) -----------------
SINGBOX_VERSION = os.environ.get("SINGBOX_VERSION", "1.11.15")
SINGBOX_TAR = f"sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
SINGBOX_URL = os.environ.get("SINGBOX_URL") or f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/{SINGBOX_TAR}"

HOME = Path(os.environ.get("HOME", "/home/container"))
SB_DIR = HOME / ".sb"
CERT_DIR = SB_DIR / "cert"
CERT_PATH = CERT_DIR / "cert.pem"
KEY_PATH = CERT_DIR / "key.pem"
SB_JSON = SB_DIR / "sb.json"
SB_BIN = SB_DIR / "sb"

HOST = os.environ.get("SB_HOST", "node.waifly.com")
UUID = os.environ.get("SB_UUID", "d45cdd57-9ec0-4f51-9174-0cb7c554ce03")
# Default ports optimized for Cloudflare proxy:
PORT = int(os.environ.get("SB_PORT", "443"))               # VLESS default -> 443
TROJAN_PORT = int(os.environ.get("SB_TROJAN_PORT", "8443"))  # Trojan default -> 8443
SNI = os.environ.get("SB_SNI", HOST)

WS_PATH = os.environ.get("SB_WS_PATH", "/ws")
# Trojan needs a password/secret; default to OBFS_PWD (random) but override with SB_TROJAN_PWD env var if provided
DEFAULT_TROJAN_PWD = os.environ.get("SB_TROJAN_PWD")
OBFS_PWD = DEFAULT_TROJAN_PWD or os.environ.get("SB_OBFS_PWD") or secrets.token_urlsafe(24)

MASS_PROXY = os.environ.get("SB_MASS_PROXY", "https://www.gstatic.com")

# ----------------- Логирование -----------------
def log(level: str, msg: str, err: bool = False):
    colors = {"I": "\033[36m", "O": "\033[32m", "W": "\033[31m", "E": "\033[31m", "R": "\033[0m"}
    prefix = {"I": "[INFO]", "O": "[OK]", "W": "[WARN]", "E": "[ERR]"}[level]
    print(f"{colors.get(level,'')}{prefix}{colors['R']} {msg}", file=(sys.stderr if err else sys.stdout))

info = lambda m: log("I", m)
ok = lambda m: log("O", m)
warn = lambda m: log("W", m, err=True)
fatal = lambda m: (log("E", m, err=True), sys.exit(1))[1]

# ----------------- Сертификат -----------------
def load_external_cert() -> Tuple[str, str] | None:
    c = os.environ.get("EXTERNAL_CERT")
    k = os.environ.get("EXTERNAL_KEY")
    if c and k and Path(c).exists() and Path(k).exists():
        info("Используются внешние сертификаты")
        return str(c), str(k)
    return None

def generate_selfsigned_cert(sni: str) -> Tuple[str, str]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    info(f"Генерация самоподписного сертификата для {sni}")

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = sni
    cert.set_serial_number(secrets.randbits(64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 год
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    CERT_PATH.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    KEY_PATH.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    ok("Сертификат создан (самоподписной)")
    return str(CERT_PATH), str(KEY_PATH)

def get_cert_paths() -> Tuple[str, str]:
    ext = load_external_cert()
    return ext if ext is not None else generate_selfsigned_cert(SNI)

# ----------------- Скачивание sing-box -----------------
def download_and_extract_singbox(url: str, target: Path):
    """Скачивает tar.gz и извлекает бинарник sing-box -> target (файл, исполняемый)."""
    if target.exists() and os.access(target, os.X_OK):
        info("sing-box уже установлен")
        return

    SB_DIR.mkdir(parents=True, exist_ok=True)
    info(f"Скачивание {url}")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / SINGBOX_TAR
        try:
            urllib.request.urlretrieve(url, tmp)
        except Exception as e:
            fatal(f"Не удалось скачать {url}: {e}")

        try:
            with tarfile.open(tmp, "r:gz") as tar:
                member = next((m for m in tar.getmembers() if m.isreg() and Path(m.name).name == "sing-box"), None)
                if not member:
                    sample = [m.name for m in tar.getmembers()[:20]]
                    fatal(f"В архиве нет бинарника sing-box. Примеры файлов: {sample}")
                # извлекаем содержимое файла-участника в целевой файл
                with tar.extractfile(member) as fsrc:
                    if fsrc is None:
                        fatal("Не удалось извлечь sing-box из архива")
                    with open(target, "wb") as fout:
                        shutil.copyfileobj(fsrc, fout)
                os.chmod(target, 0o755)
        except tarfile.TarError as e:
            fatal(f"Ошибка при обработке архива: {e}")

    if not (target.exists() and os.access(target, os.X_OK)):
        fatal("После распаковки sing-box не найден или не исполняем.")
    ok("sing-box установлен")

# ----------------- Конфиг (VLESS+WS и Trojan+WS) -----------------
def write_config(cert_path: str, key_path: str):
    info("Формирую sb.json (VLESS+WS и Trojan+WS)")

    # Inbound VLESS over WebSocket (listens on PORT)
    vless_inbound = {
        "type": "vless",
        "tag": "vless-ws-in",
        "listen": "::",
        "listen_port": PORT,
        "users": [
            {
                "id": UUID
            }
        ],
        "tls": {
            "enabled": True,
            "server_name": SNI,
            "min_version": "1.3",
            "alpn": ["http/1.1"],
            "key_path": str(key_path),
            "certificate_path": str(cert_path)
        },
        "transport": {
            "type": "ws",
            "path": WS_PATH,
            "headers": {"Host": HOST}
        },
        "ignore_client_bandwidth": True
    }

    # Inbound Trojan over WebSocket (listens on TROJAN_PORT)
    # Note: field names for trojan users may vary across implementations. This covers common forms.
    trojan_inbound = {
        "type": "trojan",
        "tag": "trojan-ws-in",
        "listen": "::",
        "listen_port": TROJAN_PORT,
        # sing-box trojan user formats vary; include both 'passwords' and 'users' forms to increase compatibility
        "passwords": [OBFS_PWD],
        "users": [
            {
                "password": OBFS_PWD
            }
        ],
        "tls": {
            "enabled": True,
            "server_name": SNI,
            "min_version": "1.3",
            "alpn": ["http/1.1"],
            "key_path": str(key_path),
            "certificate_path": str(cert_path)
        },
        "transport": {
            "type": "ws",
            "path": WS_PATH,
            "headers": {"Host": HOST}
        },
        "ignore_client_bandwidth": True
    }

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [vless_inbound, trojan_inbound],
        "outbounds": [{"tag": "direct", "type": "direct"}, {"tag": "block", "type": "block"}]
    }

    SB_DIR.mkdir(parents=True, exist_ok=True)
    SB_JSON.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    ok(f"Конфиг записан: {SB_JSON}")

# ----------------- Генерация client URL -----------------
def generate_client_urls():
    info("Генерирую ссылки для клиента (VLESS dan Trojan)")

    from urllib.parse import quote_plus
    insecure = "0" if (os.environ.get("EXTERNAL_CERT") and os.environ.get("EXTERNAL_KEY")) else "1"

    # VLESS ws URL (common)
    vless_params = f"security=tls&type=ws&host={quote_plus(HOST)}&path={quote_plus(WS_PATH)}&sni={quote_plus(SNI)}"
    vless_url = f"vless://{UUID}@{HOST}:{PORT}?{vless_params}#{HOST}-vless"

    # Trojan ws URL (common form)
    # Example: trojan://password@host:port?type=ws&security=tls&path=%2Fws&sni=...#tag
    trojan_params = f"type=ws&security=tls&host={quote_plus(HOST)}&path={quote_plus(WS_PATH)}&sni={quote_plus(SNI)}"
    trojan_url = f"trojan://{quote_plus(OBFS_PWD)}@{HOST}:{TROJAN_PORT}?{trojan_params}#{HOST}-trojan"

    ok("Ссылки готовы")
    print()
    print("=== VLESS (WebSocket + TLS) ===")
    print(vless_url)
    print()
    print("=== Trojan (WebSocket + TLS) ===")
    print(trojan_url)
    print()
    print("Catatan:")
    print("- Default ports sudah diubah: VLESS=443, Trojan=8443 (cocok untuk Cloudflare proxy).")
    print("- Jika kamu menggunakan Cloudflare, pastikan domain di-proxy (orange cloud) dan SB_HOST/SB_SNI di-set ke domain itu.")
    print("- Jika pakai sertifikat Let's Encrypt / Cloudflare Origin CA, set EXTERNAL_CERT & EXTERNAL_KEY untuk sertifikat resmi.")
    print()

# ----------------- Запуск sing-box и обработка сигналов -----------------
_child = None

def _terminate_child():
    global _child
    if _child and _child.poll() is None:
        _child.terminate()
        time.sleep(1)
        if _child.poll() is None:
            _child.kill()

def _signal(signum, frame):
    info(f"Получен сигнал {signum}, завершаю...")
    _terminate_child()
    sys.exit(0)

signal.signal(signal.SIGINT, _signal)
signal.signal(signal.SIGTERM, _signal)

def start_singbox():
    global _child
    if not SB_BIN.exists():
        fatal("sing-box бинарник не найден. Сначала запустите скачивание.")
    info("Запускаю sing-box")
    _child = subprocess.Popen([str(SB_BIN), "run", "-c", str(SB_JSON)])
    ok(f"sing-box запущен (PID={_child.pid})")
    try:
        rc = _child.wait()
        if rc == 0:
            ok("sing-box завершился нормально")
        else:
            warn(f"sing-box завершился с кодом {rc}")
    except KeyboardInterrupt:
        info("KeyboardInterrupt: завершаю")
        _terminate_child()

# ----------------- main -----------------
def main():
    cert, key = get_cert_paths()
    download_and_extract_singbox(SINGBOX_URL, SB_BIN)
    write_config(cert, key)
    generate_client_urls()
    start_singbox()

if __name__ == "__main__":
    main()
