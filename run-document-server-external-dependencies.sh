#!/bin/bash
# =============================================================================
# OnlyOffice Document Server - Startup Script (External Services Only)
# =============================================================================
#
# REMOVED:
#   - Local PostgreSQL cluster creation/management
#   - Local RabbitMQ server management
#   - Local Redis server management
#   - Oracle database support
#   - MSSQL database support
#   - MySQL database support
#
# REQUIRED ENVIRONMENT VARIABLES:
#   - DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PWD (PostgreSQL)
#   - AMQP_URI (RabbitMQ, e.g., amqp://user:pass@host:5672)
#
# OPTIONAL:
#   - REDIS_SERVER_HOST, REDIS_SERVER_PORT (if not set, uses in-memory backplane)
#
# =============================================================================

# Enable mobile editing
/bin/bash -c "sed -i 's/isSupportEditFeature=()=>!1/isSupportEditFeature=()=>!0/g' /var/www/onlyoffice/documentserver/web-apps/apps/*/mobile/dist/js/app.js;"

umask 0022

start_process() {
  "$@" &
  CHILD=$!; wait "$CHILD"; CHILD="";
}

function clean_exit {
  [[ -z "$CHILD" ]] || kill -s SIGTERM "$CHILD" 2>/dev/null
  /usr/bin/documentserver-prepare4shutdown.sh
  exit
}

trap clean_exit SIGTERM SIGQUIT SIGABRT SIGINT

shopt -s globstar

APP_DIR="/var/www/${COMPANY_NAME}/documentserver"
DATA_DIR="/var/www/${COMPANY_NAME}/Data"
PRIVATE_DATA_DIR="${DATA_DIR}/.private"
DS_RELEASE_DATE="${PRIVATE_DATA_DIR}/ds_release_date"
LOG_DIR="/var/log/${COMPANY_NAME}"
DS_LOG_DIR="${LOG_DIR}/documentserver"
LIB_DIR="/var/lib/${COMPANY_NAME}"
DS_LIB_DIR="${LIB_DIR}/documentserver"
CONF_DIR="/etc/${COMPANY_NAME}/documentserver"
IS_UPGRADE="false"
PLUGINS_ENABLED=${PLUGINS_ENABLED:-true}

RELEASE_DATE="$(stat -c="%y" ${APP_DIR}/server/DocService/docservice | sed -r 's/=([0-9]+)-([0-9]+)-([0-9]+) ([0-9:.+ ]+)/\1-\2-\3/')";
if [ -f ${DS_RELEASE_DATE} ]; then
  PREV_RELEASE_DATE=$(head -n 1 ${DS_RELEASE_DATE})
else
  PREV_RELEASE_DATE="0"
fi

if [ "${RELEASE_DATE}" != "${PREV_RELEASE_DATE}" ]; then
  IS_UPGRADE="true";
fi

# SSL setup
SSL_CERTIFICATES_DIR="/usr/share/ca-certificates/ds"; mkdir -p ${SSL_CERTIFICATES_DIR}
find "${DATA_DIR}/certs" -type f \( -iname '*.crt' -o -iname '*.pem' -o -iname '*.key' \) -exec cp -f {} "${SSL_CERTIFICATES_DIR}"/ \; 2>/dev/null || true
if find "${SSL_CERTIFICATES_DIR}" -maxdepth 1 -type f 2>/dev/null | read _; then
  find "${SSL_CERTIFICATES_DIR}" -type f \( -iname '*.crt' -o -iname '*.pem' \) -exec chmod 644 {} \;
  find "${SSL_CERTIFICATES_DIR}" -type f -iname '*.key' -exec chmod 400 {} \;
fi

if [[ -z $SSL_CERTIFICATE_PATH ]] && [[ -f ${SSL_CERTIFICATES_DIR}/${COMPANY_NAME}.crt ]]; then
  SSL_CERTIFICATE_PATH=${SSL_CERTIFICATES_DIR}/${COMPANY_NAME}.crt
else
  SSL_CERTIFICATE_PATH=${SSL_CERTIFICATE_PATH:-${SSL_CERTIFICATES_DIR}/tls.crt}
fi
if [[ -z $SSL_KEY_PATH ]] && [[ -f ${SSL_CERTIFICATES_DIR}/${COMPANY_NAME}.key ]]; then
  SSL_KEY_PATH=${SSL_CERTIFICATES_DIR}/${COMPANY_NAME}.key
else
  SSL_KEY_PATH=${SSL_KEY_PATH:-${SSL_CERTIFICATES_DIR}/tls.key}
fi

NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS:-${SSL_CERTIFICATES_DIR}/extra-ca-certs.pem}
if [[ -f ${NODE_EXTRA_CA_CERTS} ]]; then
  NODE_EXTRA_ENVIRONMENT="${NODE_EXTRA_CA_CERTS}"
elif [[ -f ${SSL_CERTIFICATE_PATH} ]]; then
  SSL_CERTIFICATE_SUBJECT=$(openssl x509 -subject -noout -in "${SSL_CERTIFICATE_PATH}" | sed 's/subject=//')
  SSL_CERTIFICATE_ISSUER=$(openssl x509 -issuer -noout -in "${SSL_CERTIFICATE_PATH}" | sed 's/issuer=//')
  if [[ -n $SSL_CERTIFICATE_SUBJECT && $SSL_CERTIFICATE_SUBJECT == $SSL_CERTIFICATE_ISSUER ]]; then
    NODE_EXTRA_ENVIRONMENT="${SSL_CERTIFICATE_PATH}"
  fi
fi

if [[ -n $NODE_EXTRA_ENVIRONMENT ]]; then
  sed -i "s|^environment=.*$|&,NODE_EXTRA_CA_CERTS=${NODE_EXTRA_ENVIRONMENT}|" /etc/supervisor/conf.d/*.conf
fi

CA_CERTIFICATES_PATH=${CA_CERTIFICATES_PATH:-${SSL_CERTIFICATES_DIR}/ca-certificates.pem}
SSL_DHPARAM_PATH=${SSL_DHPARAM_PATH:-${SSL_CERTIFICATES_DIR}/dhparam.pem}
SSL_VERIFY_CLIENT=${SSL_VERIFY_CLIENT:-off}
USE_UNAUTHORIZED_STORAGE=${USE_UNAUTHORIZED_STORAGE:-false}
ONLYOFFICE_HTTPS_HSTS_ENABLED=${ONLYOFFICE_HTTPS_HSTS_ENABLED:-true}
ONLYOFFICE_HTTPS_HSTS_MAXAGE=${ONLYOFFICE_HTTPS_HSTS_MAXAGE:-31536000}
SYSCONF_TEMPLATES_DIR="/app/ds/setup/config"

NGINX_CONFD_PATH="/etc/nginx/conf.d";
NGINX_ONLYOFFICE_PATH="${CONF_DIR}/nginx"
NGINX_ONLYOFFICE_CONF="${NGINX_ONLYOFFICE_PATH}/ds.conf"
NGINX_ONLYOFFICE_EXAMPLE_PATH="${CONF_DIR}-example/nginx"
NGINX_ONLYOFFICE_EXAMPLE_CONF="${NGINX_ONLYOFFICE_EXAMPLE_PATH}/includes/ds-example.conf"

NGINX_CONFIG_PATH="/etc/nginx/nginx.conf"
NGINX_WORKER_PROCESSES=${NGINX_WORKER_PROCESSES:-1}
NGINX_ACCESS_LOG=${NGINX_ACCESS_LOG:-false}
LIMIT=$(ulimit -n); [ $LIMIT -gt 1048576 ] && LIMIT=1048576
NGINX_WORKER_CONNECTIONS=${NGINX_WORKER_CONNECTIONS:-$LIMIT}

JWT_ENABLED=${JWT_ENABLED:-true}
if [ "${JWT_ENABLED}" == "true" ]; then
  JWT_ENABLED="true"
else
  JWT_ENABLED="false"
fi

[ -z $JWT_SECRET ] && JWT_MESSAGE='JWT is enabled by default. A random secret is generated automatically. Run the command "docker exec $(sudo docker ps -q) sudo documentserver-jwt-status.sh" to get information about JWT.'

JWT_SECRET=${JWT_SECRET:-$(pwgen -s 32)}
JWT_HEADER=${JWT_HEADER:-Authorization}
JWT_IN_BODY=${JWT_IN_BODY:-false}

WOPI_ENABLED=${WOPI_ENABLED:-false}
ALLOW_META_IP_ADDRESS=${ALLOW_META_IP_ADDRESS:-false}
ALLOW_PRIVATE_IP_ADDRESS=${ALLOW_PRIVATE_IP_ADDRESS:-false}

GENERATE_FONTS=${GENERATE_FONTS:-true}

# Redis is optional - if not configured, uses in-memory backplane
REDIS_ENABLED=${REDIS_ENABLED:-false}
if [ -n "${REDIS_SERVER_HOST}" ]; then
  REDIS_ENABLED=true
fi

ONLYOFFICE_DEFAULT_CONFIG=${CONF_DIR}/local.json
ONLYOFFICE_LOG4JS_CONFIG=${CONF_DIR}/log4js/production.json
ONLYOFFICE_EXAMPLE_CONFIG=${CONF_DIR}-example/local.json

JSON_BIN=${APP_DIR}/npm/json
JSON="${JSON_BIN} -q -f ${ONLYOFFICE_DEFAULT_CONFIG}"
JSON_LOG="${JSON_BIN} -q -f ${ONLYOFFICE_LOG4JS_CONFIG}"
JSON_EXAMPLE="${JSON_BIN} -q -f ${ONLYOFFICE_EXAMPLE_CONFIG}"

METRICS_ENABLED="${METRICS_ENABLED:-false}"
METRICS_HOST="${METRICS_HOST:-localhost}"
METRICS_PORT="${METRICS_PORT:-8125}"
METRICS_PREFIX="${METRICS_PREFIX:-.ds}"

# Database settings (PostgreSQL only)
DB_TYPE="postgres"
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-onlyoffice}
DB_USER=${DB_USER:-onlyoffice}
DB_PWD=${DB_PWD:-onlyoffice}

# RabbitMQ settings
AMQP_URI=${AMQP_URI:-amqp://guest:guest@localhost:5672}
AMQP_TYPE=${AMQP_TYPE:-rabbitmq}

# Redis settings (optional)
REDIS_SERVER_HOST=${REDIS_SERVER_HOST:-}
REDIS_SERVER_PORT=${REDIS_SERVER_PORT:-6379}

DS_LOG_LEVEL=${DS_LOG_LEVEL:-WARN}

parse_rabbitmq_url(){
  local amqp=$1
  local proto="$(echo $amqp | grep :// | sed -e's,^\(.*://\).*,\1,g')"
  local url="$(echo ${amqp/$proto/})"
  local userpass="`echo $url | grep @ | cut -d@ -f1`"
  local pass=`echo $userpass | grep : | cut -d: -f2`
  local user
  if [ -n "$pass" ]; then
    user=`echo $userpass | grep : | cut -d: -f1`
  else
    user=$userpass
  fi
  local hostport="$(echo ${url/$userpass@/} | cut -d/ -f1)"
  local port="$(echo $hostport | grep : | sed -r 's_^.*:+|/.*$__g')"
  local host
  if [ -n "$port" ]; then
    host=`echo $hostport | grep : | cut -d: -f1`
  else
    host=$hostport
    port="5672"
  fi

  AMQP_SERVER_PROTO=${proto:0:-3}
  AMQP_SERVER_HOST=$host
  AMQP_SERVER_USER=$user
  AMQP_SERVER_PASS=$pass
  AMQP_SERVER_PORT=$port
}

waiting_for_connection(){
  until nc -z -w 3 "$1" "$2"; do
    >&2 echo "Waiting for connection to $1:$2..."
    sleep 1
  done
}

waiting_for_db(){
  waiting_for_connection $DB_HOST $DB_PORT
}

waiting_for_amqp(){
  parse_rabbitmq_url ${AMQP_URI}
  waiting_for_connection ${AMQP_SERVER_HOST} ${AMQP_SERVER_PORT}
}

waiting_for_redis(){
  waiting_for_connection ${REDIS_SERVER_HOST} ${REDIS_SERVER_PORT}
}

update_statsd_settings(){
  ${JSON} -I -e "if(this.statsd===undefined)this.statsd={};"
  ${JSON} -I -e "this.statsd.useMetrics = '${METRICS_ENABLED}'"
  ${JSON} -I -e "this.statsd.host = '${METRICS_HOST}'"
  ${JSON} -I -e "this.statsd.port = '${METRICS_PORT}'"
  ${JSON} -I -e "this.statsd.prefix = '${METRICS_PREFIX}'"
}

update_db_settings(){
  ${JSON} -I -e "this.services.CoAuthoring.sql.type = '${DB_TYPE}'"
  ${JSON} -I -e "this.services.CoAuthoring.sql.dbHost = '${DB_HOST}'"
  ${JSON} -I -e "this.services.CoAuthoring.sql.dbPort = '${DB_PORT}'"
  ${JSON} -I -e "this.services.CoAuthoring.sql.dbName = '${DB_NAME}'"
  ${JSON} -I -e "this.services.CoAuthoring.sql.dbUser = '${DB_USER}'"
  ${JSON} -I -e "this.services.CoAuthoring.sql.dbPass = '${DB_PWD}'"
}

update_rabbitmq_setting(){
  ${JSON} -I -e "if(this.queue===undefined)this.queue={};"
  ${JSON} -I -e "this.queue.type = 'rabbitmq'"
  ${JSON} -I -e "this.rabbitmq.url = '${AMQP_URI}'"
}

update_redis_settings(){
  ${JSON} -I -e "if(this.services.CoAuthoring.redis===undefined)this.services.CoAuthoring.redis={};"
  ${JSON} -I -e "this.services.CoAuthoring.redis.host = '${REDIS_SERVER_HOST}'"
  ${JSON} -I -e "this.services.CoAuthoring.redis.port = '${REDIS_SERVER_PORT}'"
  ${JSON} -I -e "this.services.CoAuthoring.redis.options = {
    ${REDIS_SERVER_USER:+username: '${REDIS_SERVER_USER}',}
    ${REDIS_SERVER_PASS:+password: '${REDIS_SERVER_PASS}',}
    ${REDIS_SERVER_DB:+database: '${REDIS_SERVER_DB}',}
  }"
}

update_ds_settings(){
  ${JSON} -I -e "this.services.CoAuthoring.token.enable.browser = ${JWT_ENABLED}"
  ${JSON} -I -e "this.services.CoAuthoring.token.enable.request.inbox = ${JWT_ENABLED}"
  ${JSON} -I -e "this.services.CoAuthoring.token.enable.request.outbox = ${JWT_ENABLED}"

  ${JSON} -I -e "this.services.CoAuthoring.secret.inbox.string = '${JWT_SECRET}'"
  ${JSON} -I -e "this.services.CoAuthoring.secret.outbox.string = '${JWT_SECRET}'"
  ${JSON} -I -e "this.services.CoAuthoring.secret.session.string = '${JWT_SECRET}'"
  ${JSON} -I -e "this.services.CoAuthoring.secret.browser.string = '${JWT_SECRET}'"

  ${JSON} -I -e "this.services.CoAuthoring.token.inbox.header = '${JWT_HEADER}'"
  ${JSON} -I -e "this.services.CoAuthoring.token.outbox.header = '${JWT_HEADER}'"

  ${JSON} -I -e "this.services.CoAuthoring.token.inbox.inBody = ${JWT_IN_BODY}"
  ${JSON} -I -e "this.services.CoAuthoring.token.outbox.inBody = ${JWT_IN_BODY}"

  if [ -f "${ONLYOFFICE_EXAMPLE_CONFIG}" ]; then
    ${JSON_EXAMPLE} -I -e "this.server.token.enable = ${JWT_ENABLED}"
    ${JSON_EXAMPLE} -I -e "this.server.token.secret = '${JWT_SECRET}'"
    ${JSON_EXAMPLE} -I -e "this.server.token.authorizationHeader = '${JWT_HEADER}'"
  fi
 
  if [ "${USE_UNAUTHORIZED_STORAGE}" == "true" ]; then
    ${JSON} -I -e "if(this.services.CoAuthoring.requestDefaults===undefined)this.services.CoAuthoring.requestDefaults={}"
    ${JSON} -I -e "if(this.services.CoAuthoring.requestDefaults.rejectUnauthorized===undefined)this.services.CoAuthoring.requestDefaults.rejectUnauthorized=false"
  fi

  WOPI_PRIVATE_KEY="${DATA_DIR}/wopi_private.key"
  WOPI_PUBLIC_KEY="${DATA_DIR}/wopi_public.key"

  [ ! -f "${WOPI_PRIVATE_KEY}" ] && echo -n "Generating WOPI private key..." && openssl genpkey -algorithm RSA -outform PEM -out "${WOPI_PRIVATE_KEY}" >/dev/null 2>&1 && echo "Done"
  [ ! -f "${WOPI_PUBLIC_KEY}" ] && echo -n "Generating WOPI public key..." && openssl rsa -RSAPublicKey_out -in "${WOPI_PRIVATE_KEY}" -outform "MS PUBLICKEYBLOB" -out "${WOPI_PUBLIC_KEY}" >/dev/null 2>&1  && echo "Done"
  WOPI_MODULUS=$(openssl rsa -pubin -inform "MS PUBLICKEYBLOB" -modulus -noout -in "${WOPI_PUBLIC_KEY}" | sed 's/Modulus=//' | xxd -r -p | openssl base64 -A)
  WOPI_EXPONENT=$(openssl rsa -pubin -inform "MS PUBLICKEYBLOB" -text -noout -in "${WOPI_PUBLIC_KEY}" | grep -oP '(?<=Exponent: )\d+')
  
  ${JSON} -I -e "if(this.wopi===undefined)this.wopi={};"
  ${JSON} -I -e "this.wopi.enable = ${WOPI_ENABLED}"
  ${JSON} -I -e "this.wopi.privateKey = '$(awk '{printf "%s\\n", $0}' ${WOPI_PRIVATE_KEY})'"
  ${JSON} -I -e "this.wopi.privateKeyOld = '$(awk '{printf "%s\\n", $0}' ${WOPI_PRIVATE_KEY})'"
  ${JSON} -I -e "this.wopi.publicKey = '$(openssl base64 -in ${WOPI_PUBLIC_KEY} -A)'"
  ${JSON} -I -e "this.wopi.publicKeyOld = '$(openssl base64 -in ${WOPI_PUBLIC_KEY} -A)'"
  ${JSON} -I -e "this.wopi.modulus = '${WOPI_MODULUS}'"
  ${JSON} -I -e "this.wopi.modulusOld = '${WOPI_MODULUS}'"
  ${JSON} -I -e "this.wopi.exponent = ${WOPI_EXPONENT}"
  ${JSON} -I -e "this.wopi.exponentOld = ${WOPI_EXPONENT}"

  if [ "${ALLOW_META_IP_ADDRESS}" = "true" ] || [ "${ALLOW_PRIVATE_IP_ADDRESS}" = "true" ]; then
    ${JSON} -I -e "if(this.services.CoAuthoring['request-filtering-agent']===undefined)this.services.CoAuthoring['request-filtering-agent']={}"
    [ "${ALLOW_META_IP_ADDRESS}" = "true" ] && ${JSON} -I -e "this.services.CoAuthoring['request-filtering-agent'].allowMetaIPAddress = true"
    [ "${ALLOW_PRIVATE_IP_ADDRESS}" = "true" ] && ${JSON} -I -e "this.services.CoAuthoring['request-filtering-agent'].allowPrivateIPAddress = true"
  fi
}

create_db_tbl() {
  if [ -n "$DB_PWD" ]; then
    export PGPASSWORD=$DB_PWD
  fi
  PSQL="psql -q -h$DB_HOST -p$DB_PORT -d$DB_NAME -U$DB_USER -w"
  
  DB_SCHEMA=${DB_SCHEMA:-$(${JSON} services.CoAuthoring.sql.pgPoolExtraOptions.options 2>/dev/null | sed -n 's/.*search_path=\([^, ]*\).*/\1/p')}
  if [ -n "${DB_SCHEMA}" ]; then
    export PGOPTIONS="-c search_path=${DB_SCHEMA}"
    $PSQL -c "CREATE SCHEMA IF NOT EXISTS ${DB_SCHEMA};" >/dev/null 2>&1
    ${JSON} -I -e "this.services.CoAuthoring.sql.pgPoolExtraOptions ||= {}; this.services.CoAuthoring.sql.pgPoolExtraOptions.options = '${PGOPTIONS}'"
  fi
  
  $PSQL -f "$APP_DIR/server/schema/postgresql/createdb.sql"
}

upgrade_db_tbl() {
  if [ -n "$DB_PWD" ]; then
    export PGPASSWORD=$DB_PWD
  fi
  PSQL="psql -q -h$DB_HOST -p$DB_PORT -d$DB_NAME -U$DB_USER -w"

  DB_SCHEMA=${DB_SCHEMA:-$(${JSON} services.CoAuthoring.sql.pgPoolExtraOptions.options 2>/dev/null | sed -n 's/.*search_path=\([^, ]*\).*/\1/p')}
  if [ -n "${DB_SCHEMA}" ]; then
    export PGOPTIONS="-c search_path=${DB_SCHEMA}"
    $PSQL -c "CREATE SCHEMA IF NOT EXISTS ${DB_SCHEMA};" >/dev/null 2>&1
    ${JSON} -I -e "this.services.CoAuthoring.sql.pgPoolExtraOptions ||= {}; this.services.CoAuthoring.sql.pgPoolExtraOptions.options = '${PGOPTIONS}'"
  fi

  $PSQL -f "$APP_DIR/server/schema/postgresql/removetbl.sql"
  $PSQL -f "$APP_DIR/server/schema/postgresql/createdb.sql"
}

update_nginx_settings(){
  sed 's/^worker_processes.*/'"worker_processes ${NGINX_WORKER_PROCESSES};"'/' -i ${NGINX_CONFIG_PATH}
  sed 's/worker_connections.*/'"worker_connections ${NGINX_WORKER_CONNECTIONS};"'/' -i ${NGINX_CONFIG_PATH}

  if [ "${NGINX_ACCESS_LOG}" = "true" ]; then
    touch "${DS_LOG_DIR}/nginx.access.log"
    sed -ri 's|^\s*access_log\b.*;|access_log '"${DS_LOG_DIR}"'/nginx.access.log;|' "${NGINX_CONFIG_PATH}" "${NGINX_ONLYOFFICE_PATH}/includes/ds-common.conf" 2>/dev/null
  else
    sed -ri 's|^\s*access_log\b.*;|access_log off;|' "${NGINX_CONFIG_PATH}"
  fi

  if [ -f "${SSL_CERTIFICATE_PATH}" -a -f "${SSL_KEY_PATH}" ]; then
    cp -f ${NGINX_ONLYOFFICE_PATH}/ds-ssl.conf.tmpl ${NGINX_ONLYOFFICE_CONF}
    sed 's,{{SSL_CERTIFICATE_PATH}},'"${SSL_CERTIFICATE_PATH}"',' -i ${NGINX_ONLYOFFICE_CONF}
    sed 's,{{SSL_KEY_PATH}},'"${SSL_KEY_PATH}"',' -i ${NGINX_ONLYOFFICE_CONF}
    sed 's,\(443 ssl\),\1 http2,' -i ${NGINX_ONLYOFFICE_CONF}

    if [ -r "${SSL_DHPARAM_PATH}" ]; then
      sed 's,\(\#* *\)\?\(ssl_dhparam \).*\(;\)$,'"\2${SSL_DHPARAM_PATH}\3"',' -i ${NGINX_ONLYOFFICE_CONF}
    else
      sed '/ssl_dhparam/d' -i ${NGINX_ONLYOFFICE_CONF}
    fi

    sed 's,\(ssl_verify_client \).*\(;\)$,'"\1${SSL_VERIFY_CLIENT}\2"',' -i ${NGINX_ONLYOFFICE_CONF}

    if [ -f "${CA_CERTIFICATES_PATH}" ]; then
      sed '/ssl_verify_client/a '"ssl_client_certificate ${CA_CERTIFICATES_PATH}"';' -i ${NGINX_ONLYOFFICE_CONF}
    fi

    if [ "${ONLYOFFICE_HTTPS_HSTS_ENABLED}" == "true" ]; then
      sed 's,\(max-age=\).*\(;\)$,'"\1${ONLYOFFICE_HTTPS_HSTS_MAXAGE}\2"',' -i ${NGINX_ONLYOFFICE_CONF}
    else
      sed '/max-age=/d' -i ${NGINX_ONLYOFFICE_CONF}
    fi
  else
    ln -sf ${NGINX_ONLYOFFICE_PATH}/ds.conf.tmpl ${NGINX_ONLYOFFICE_CONF}
  fi

  if [ ! -f /proc/net/if_inet6 ]; then
    sed '/listen\s\+\[::[0-9]*\].\+/d' -i $NGINX_ONLYOFFICE_CONF
  fi

  if [ -f "${NGINX_ONLYOFFICE_EXAMPLE_CONF}" ]; then
    sed 's/linux/docker/' -i ${NGINX_ONLYOFFICE_EXAMPLE_CONF}
  fi

  start_process documentserver-update-securelink.sh -s ${SECURE_LINK_SECRET:-$(pwgen -s 20)} -r false
}

update_log_settings(){
   ${JSON_LOG} -I -e "this.categories.default.level = '${DS_LOG_LEVEL}'"
}

update_logrotate_settings(){
  sed 's|\(^su\b\).*|\1 root root|' -i /etc/logrotate.conf
}

update_release_date(){
  mkdir -p ${PRIVATE_DATA_DIR}
  echo ${RELEASE_DATE} > ${DS_RELEASE_DATE}
}

# Create base folders
for i in converter docservice metrics; do
  mkdir -p "$DS_LOG_DIR/$i" && touch "$DS_LOG_DIR/$i"/{out,err}.log
done

mkdir -p "${DS_LOG_DIR}-example" && touch "${DS_LOG_DIR}-example"/{out,err}.log

# Create app folders
for i in ${DS_LIB_DIR}/App_Data/cache/files ${DS_LIB_DIR}/App_Data/docbuilder ${DS_LIB_DIR}-example/files; do
  mkdir -p "$i"
done

# Change folder rights
chown ds:ds "${DATA_DIR}"
for i in ${DS_LOG_DIR} ${DS_LOG_DIR}-example ${LIB_DIR}; do
  chown -R ds:ds "$i"
  chmod -R 755 "$i"
done

# Update settings
if [ $METRICS_ENABLED = "true" ]; then
  update_statsd_settings
fi

update_log_settings
update_ds_settings
update_db_settings
update_rabbitmq_setting
if [ "${REDIS_ENABLED}" = "true" ]; then
  update_redis_settings
fi

find /etc/${COMPANY_NAME} ! -path '*logrotate*' -exec chown ds:ds {} \;

# Wait for external services
echo "Waiting for external services..."
waiting_for_db
waiting_for_amqp
if [ "${REDIS_ENABLED}" = "true" ]; then
  waiting_for_redis
else
  echo "Redis not configured, using in-memory backplane"
fi
echo "All services available."

# Initialize/upgrade database
if [ "${IS_UPGRADE}" = "true" ]; then
  echo "Upgrading database schema..."
  upgrade_db_tbl
  update_release_date
else
  echo "Initializing database schema..."
  create_db_tbl
fi

update_nginx_settings

service supervisor start

update_logrotate_settings
service cron start

start_process documentserver-flush-cache.sh -r false

service nginx start

# Regenerate fonts
if [ "${GENERATE_FONTS}" == "true" ]; then
  start_process documentserver-generate-allfonts.sh false
fi

if [ "${PLUGINS_ENABLED}" = "true" ]; then
  echo -n "Installing plugins..."
  start_process documentserver-pluginsmanager.sh -r false --update=\"${APP_DIR}/sdkjs-plugins/plugin-list-default.json\" >/dev/null
  echo "Done"
fi

start_process documentserver-static-gzip.sh false

echo "${JWT_MESSAGE}"

start_process find "$DS_LOG_DIR" "$DS_LOG_DIR-example" -type f -name "*.log" | xargs tail -F
