#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# User variables — измените тут
# -------------------------
HOST="node1.lunes.host"
UUID="669ae214-9a68-495d-882d-f23812d35529"
PORT="2021"
SNI="time.android.com"
# -------------------------

# Домашняя директория (по умолчанию /home/container если $HOME пуст)
HOME_DIR="${HOME:-/home/container}"
SB_DIR="$HOME_DIR/.sb"
CERT_DIR="$SB_DIR/cert"
CERT_PATH="$CERT_DIR/cert.pem"
KEY_PATH="$CERT_DIR/key.pem"
SB_JSON_PATH="$SB_DIR/sb.json"

SINGBOX_VERSION="1.11.15"
SINGBOX_TAR="sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SINGBOX_TAR}"
TEMP_DIR="$(mktemp -d)"

# Проверка необходимых команд
for cmd in curl tar python3 sed awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Ошибка: команда '$cmd' не найдена. Установите её и повторите." >&2
    exit 1
  fi
done

# Установка pyOpenSSL (пытаемся pip3, иначе pip)
echo "=== Установка зависимости pyOpenSSL ==="
if command -v pip3 >/dev/null 2>&1; then
  pip3 install --user pyOpenSSL || pip3 install pyOpenSSL
else
  pip install --user pyOpenSSL || pip install pyOpenSSL
fi

# Создание директорий
mkdir -p "$CERT_DIR"
mkdir -p "$SB_DIR"

# Генерация сертификата и ключа с помощью встроенного python-скрипта
echo "=== Генерация self-signed сертификата для ${SNI} ==="
cat > "$TEMP_DIR/generate_cert.py" <<'PY'
from OpenSSL import crypto
import sys
import os
import time
import random

def generate_self_signed_cert(domain, cert_file="cert.pem", key_file="key.pem"):
    # Создание ключа
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Создание сертификата
    cert = crypto.X509()
    cert.get_subject().CN = domain
    # Уникальный серийный номер
    cert.set_serial_number(int(time.time()) ^ random.getrandbits(64))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # 1 год
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    # Сохранение сертификата
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Сохранение ключа
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    print(f"Сертификат создан: {cert_file}, ключ: {key_file}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: generate_cert.py <domain> <cert_path> <key_path>", file=sys.stderr)
        sys.exit(2)
    domain = sys.argv[1]
    cert_path = sys.argv[2]
    key_path = sys.argv[3]
    # Убедимся, что папка для файлов существует
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    generate_self_signed_cert(domain, cert_file=cert_path, key_file=key_path)
PY

python3 "$TEMP_DIR/generate_cert.py" "$SNI" "$CERT_PATH" "$KEY_PATH"
chmod 600 "$KEY_PATH" || true
chmod 644 "$CERT_PATH" || true

# Создание sb.json с подстановкой переменных
cat > "$SB_JSON_PATH" <<JSON
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": ${PORT},
      "users": [
        {
          "password": "${UUID}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "key_path": "${HOME_DIR}/.sb/cert/key.pem",
        "certificate_path": "${HOME_DIR}/.sb/cert/cert.pem"
      },
      "masquerade": "https://${SNI}"
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ]
  }
}
JSON

# Скачивание sing-box и подготовка бинарника
cd "$TEMP_DIR"
curl -L -o "$SINGBOX_TAR" "$SINGBOX_URL"
tar -xzf "$SINGBOX_TAR"

# Найдём бинарь sing-box в распакованной структуре
EXTRACTED_DIR=$(tar -tzf "$SINGBOX_TAR" | head -1 | cut -f1 -d"/" || true)
# возможен случай, если tar не содержит путь в первом поле корректно — ищем файл 'sing-box' рекурсивно
BIN_SRC="$(find . -type f -name sing-box -print -quit || true)"
if [ -z "$BIN_SRC" ]; then
  # Попробуем развернуть через стандартную директорию
  BIN_SRC="$(find "${EXTRACTED_DIR:-.}" -type f -name sing-box -print -quit || true)"
fi

if [ -z "$BIN_SRC" ]; then
  tar -tzf "$SINGBOX_TAR" || true
  exit 1
fi

mv "$BIN_SRC" "$SB_DIR/sb"
chmod 777 "$SB_DIR/sb"

# Удаляем распакованные файлы и архив
cd /
rm -rf "$TEMP_DIR"

# Генерация hysteria2-ссылки
echo "=== Генерация hysteria2 ссылки ==="
# Получаем org через ipinfo.io/org (без ASN)
ORG_RAW="$(curl -s --max-time 10 ipinfo.io/org || true)"
if [ -z "$ORG_RAW" ]; then
  ORG_NAME="hys2"
else
  # Удаляем ведущий "AS12345 " если есть
  ORG_NOASN="$(echo "$ORG_RAW" | sed -E 's/^AS[0-9]+\s+//I' | tr -d '\r\n')"
  # Заменяем неподходящие символы пробела на '-'
  ORG_SANITIZED="$(echo "$ORG_NOASN" \
                    | sed 's/[^A-Za-z0-9 _-]/ /g' \
                    | tr '[:upper:]' '[:lower:]' \
                    | sed -E 's/[[:space:]]+/-/g' \
                    | sed -E 's/-+/-/g' \
                    | sed -E 's/^-|-$//g')"
  # Если получилось пусто — fallback
  if [ -z "$ORG_SANITIZED" ]; then
    ORG_NAME="hys2"
  else
    ORG_NAME="$ORG_SANITIZED"
  fi
fi

HYSTERIA_URL="hysteria2://${UUID}@${HOST}:${PORT}/?sni=${SNI}&insecure=1#${ORG_NAME}"

echo
echo "$HYSTERIA_URL"
echo
# Запуск sing-box
echo "=== Запуск sing-box ==="
exec "$SB_DIR/sb" run -c "$SB_JSON_PATH"
