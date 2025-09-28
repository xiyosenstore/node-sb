#!/usr/bin/env bash
set -euo pipefail

# === Цвета ===
GREEN="\e[32m"
RED="\e[31m"
CYAN="\e[36m"
NC="\e[0m"

# === Константы ===
SINGBOX_VERSION="1.11.15"
SINGBOX_TAR="sing-box-${SINGBOX_VERSION}-linux-386.tar.gz"
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SINGBOX_TAR}"

HOME_DIR="${HOME:-/home/container}"
SB_DIR="$HOME_DIR/.sb"
CERT_DIR="$SB_DIR/cert"
CERT_PATH="$CERT_DIR/cert.pem"
KEY_PATH="$CERT_DIR/key.pem"
SB_JSON_PATH="$SB_DIR/sb.json"

# === Переменные (будут заданы из аргументов) ===
HOST=""
UUID=""
PORT=""
SNI=""

# === Функции вывода ===
log() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

usage() {
  echo -e "Usage: $0 --host HOST --uuid UUID --port PORT --sni DOMAIN\n"
  echo "Options:"
  echo "  --host   Серверный адрес (например: node1.lunes.host)"
  echo "  --uuid   Уникальный UUID пользователя"
  echo "  --port   Порт для входящих соединений (например: 2021)"
  echo "  --sni    Домен для TLS SNI (например: time.android.com)"
  echo "  --help   Показать это сообщение и выйти"
  exit 0
}

# === Парсинг аргументов ===
if [[ $# -eq 0 ]]; then
  usage
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --uuid) UUID="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --sni)  SNI="$2"; shift 2 ;;
    --help) usage ;;
    *) err "Неизвестный аргумент: $1" ;;
  esac
done

# === Проверка обязательных параметров ===
[[ -z "$HOST" ]] && err "Не задан --host"
[[ -z "$UUID" ]] && err "Не задан --uuid"
[[ -z "$PORT" ]] && err "Не задан --port"
[[ -z "$SNI"  ]] && err "Не задан --sni"

# === Функции ===
install_deps() {
  log "Проверка зависимостей..."
  for cmd in curl tar python3; do
    command -v "$cmd" >/dev/null 2>&1 || err "Команда '$cmd' не найдена!"
  done

  log "Установка pyOpenSSL..."
  if ! python3 -c "import OpenSSL" 2>/dev/null; then
    pip3 install --user pyOpenSSL || pip install --user pyOpenSSL
  fi
  ok "pyOpenSSL готов"
}

generate_cert() {
  log "Генерация сертификата для ${SNI}"
  mkdir -p "$CERT_DIR"
  python3 - <<PY
from OpenSSL import crypto
key = crypto.PKey(); key.generate_key(crypto.TYPE_RSA, 2048)
cert = crypto.X509(); cert.get_subject().CN="${SNI}"
cert.set_serial_number(1); cert.gmtime_adj_notBefore(0); cert.gmtime_adj_notAfter(365*24*60*60)
cert.set_issuer(cert.get_subject()); cert.set_pubkey(key); cert.sign(key, 'sha256')
open("${CERT_PATH}","wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM,cert))
open("${KEY_PATH}","wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
PY
  ok "Сертификат создан"
}

download_singbox() {
  if [[ -x "$SB_DIR/sb" ]]; then
    log "sing-box уже скачан"
    return
  fi
  log "Скачивание sing-box..."
  mkdir -p "$SB_DIR"
  curl -L -o "/tmp/$SINGBOX_TAR" "$SINGBOX_URL"
  tar -xzf "/tmp/$SINGBOX_TAR" -C /tmp
  mv /tmp/sing-box*/sing-box "$SB_DIR/sb"
  chmod 755 "$SB_DIR/sb"
  rm -rf /tmp/sing-box* "/tmp/$SINGBOX_TAR"
  ok "sing-box установлен"
}

generate_config() {
  log "Создание конфигурации sb.json"
  cat > "$SB_JSON_PATH" <<JSON
{
  "inbounds": [
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": ${PORT},
      "users": [{ "password": "${UUID}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "key_path": "${KEY_PATH}",
        "certificate_path": "${CERT_PATH}"
      },
      "masquerade": "https://${SNI}"
    }
  ],
  "outbounds": [
    { "tag": "direct", "type": "direct" },
    { "tag": "block", "type": "block" }
  ]
}
JSON
  ok "Конфиг создан"
}

generate_url() {
  log "Генерация hysteria2-ссылки"
  local org="$(curl -s ipinfo.io/org | sed -E 's/^AS[0-9]+\s+//' | tr -d '\r\n' | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"
  [[ -z "$org" ]] && org="hy2"
  echo -e "\n${GREEN}hysteria2://${UUID}@${HOST}:${PORT}/?sni=${SNI}&insecure=1#${org}${NC}\n"
}

run_singbox() {
  log "Запуск sing-box..."
  exec "$SB_DIR/sb" run -c "$SB_JSON_PATH"
}

# === Выполнение ===
install_deps
generate_cert
download_singbox
generate_config
generate_url
run_singbox
