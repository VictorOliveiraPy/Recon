#!/usr/bin/env bash
#
# recon.sh — pipeline de enumeração para VALIDAÇÃO DEFENSIVA de apps próprias
#
# FILOSOFIA (leia antes de confiar no resultado):
#   Isto NÃO é um scanner que "tenta não incomodar". É um verificador de
#   segurança. A pior falha aqui não é quebrar — é reportar "limpo" quando na
#   verdade não escaneou nada. Por isso este script FALHA ALTO: se uma
#   dependência, wordlist ou etapa não puder rodar de verdade, ela é marcada
#   como FALHOU/PENDENTE — nunca como "sem achados". O relatório separa
#   explicitamente "escaneei e está limpo" de "não consegui escanear".
#   Ausência de evidência != evidência de ausência. E nunca pular em silêncio.
#
# Correções desta versão (2ª review) — pontos que ainda geravam falso-negativo:
#   * headers: agora isola SÓ o último bloco de resposta (a página que o browser
#     realmente renderiza) e deriva o esquema do destino FINAL — antes, com -L,
#     misturava headers de todos os hops de redirect.
#   * STAGES é normalizado (sem espaços) para não pular etapa em silêncio.
#   * params/vhost iteram sobre TODOS os hosts vivos, não só o BASE_URL.
#   * JSON do ffuf que existe mas não parseia => FALHOU (não "limpo").
#   * throttle aplicado também ao katana e ao loop de headers.
#
# Fluxo: portas -> probe HTTP -> headers de segurança -> conteúdo (ffuf)
#        -> crawl (katana) -> parâmetros (ffuf) -> vhosts (ffuf) -> nuclei
#
# Uso:
#   ./recon.sh                      # defaults (localhost:8000)
#   ./recon.sh 127.0.0.1 8000       # host e porta
#   ./recon.sh 127.0.0.1 8000 full  # 'full' = todas as portas
#
# Selecionar etapas (STAGES): ports,http,headers,content,crawl,params,vhost,nuclei
#   STAGES=headers,nuclei ./recon.sh      # nomes inválidos abortam (não silenciam)
#
# Variáveis de ambiente úteis:
#   OUT=<dir>              diretório de saída (default inclui timestamp)
#   THREADS RATE DELAY FFUF_TIMEOUT     controle do ffuf (validados como números)
#   NUCLEI_SEVERITY=low,medium,high,critical   (adicione 'info' p/ cobertura máx.)
#   NUCLEI_UPDATE=auto|always|never    update de templates (auto = no máx. 1x/24h)
#   NUCLEI_RL=<n>         rate-limit do nuclei (default: RATE se >0, senão 150)
#
# Códigos de saída:
#   0 = todas as etapas solicitadas rodaram (com ou sem achados)
#   1 = alguma etapa solicitada FALHOU/PENDENTE (resultado não confiável)
#   2 = erro de configuração (entrada inválida, dependência-núcleo ou bash < 4)
#
# Requisito: bash >= 4 (usa arrays associativos).
#
# ATENÇÃO LEGAL: só rode contra alvos que você controla ou tem autorização
# escrita para testar. Contra terceiros sem permissão é crime (BR: Lei 12.737).
# ---------------------------------------------------------------------------

set -euo pipefail

# guarda de versão: no bash 3.x (ex.: macOS de fábrica) 'declare -A' falha com
# erro obscuro. Falha cedo e com mensagem clara.
if ((${BASH_VERSINFO[0]:-0} < 4)); then
  echo "[x] este script requer bash >= 4 (usa arrays associativos)." >&2
  echo "    versão atual: ${BASH_VERSION:-desconhecida}" >&2
  exit 2
fi

# ============================= CONFIG ======================================
TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8000}"
SCAN_MODE="${3:-single}"
STAGES="${STAGES:-}"
STAGES="${STAGES//[[:space:]]/}"   # remove espaços/tabs: 'a, b' não deve pular 'b' em silêncio

THREADS="${THREADS:-40}"
RATE="${RATE:-0}"                 # req/s ffuf (0 = ilimitado; ok p/ local)
DELAY="${DELAY:-0}"               # atraso entre req (s); use >0 em remoto
FFUF_TIMEOUT="${FFUF_TIMEOUT:-10}"

NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
NUCLEI_UPDATE="${NUCLEI_UPDATE:-auto}"   # auto|always|never

SECLISTS="${SECLISTS:-/usr/share/seclists}"
WL_DIR="${WL_DIR:-${SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt}"
WL_FILE="${WL_FILE:-${SECLISTS}/Discovery/Web-Content/raft-medium-files.txt}"
WL_PARAM="${WL_PARAM:-${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt}"
WL_VHOST="${WL_VHOST:-${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt}"

EXTENSIONS="${EXTENSIONS:-php,html,js,json,txt,bak,old,zip,env,config,py,sql,log}"

# Matcher de códigos HTTP para o ffuf.
# CRÍTICO: inclui 5xx e 405 de propósito. Um 500 numa rota fuzzada é sinal
# forte de ponto de injeção / vazamento de stack trace — um defensor QUER ver.
# Excluímos 404 (ruído) e deixamos o -ac tratar soft-404 (200 falso).
FFUF_MC="200-299,301,302,307,308,401,403,405,406,410,500,501,502,503"

# --------- validação de entrada (evita path traversal, URL malformada, ------
# --------- flags quebradas e STAGES digitado errado que "silenciava" tudo) --
_fail_cfg() { echo "[x] config inválida: $*" >&2; exit 2; }
is_uint()   { [[ "$1" =~ ^[0-9]+$ ]]; }
is_ufloat() { [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; }

# host: só caracteres seguros p/ URL e p/ nome de diretório (bloqueia '/', espaço,
# metacaracteres de shell e, portanto, path traversal via argumento).
[[ "$TARGET_HOST" =~ ^[A-Za-z0-9._:-]+$ ]] \
  || _fail_cfg "TARGET_HOST '$TARGET_HOST' tem caractere não permitido (use [A-Za-z0-9._:-])"
{ is_uint "$TARGET_PORT" && (( 10#$TARGET_PORT >= 1 && 10#$TARGET_PORT <= 65535 )); } \
  || _fail_cfg "TARGET_PORT '$TARGET_PORT' deve ser inteiro entre 1 e 65535"
case "$SCAN_MODE" in single|full) : ;; *) _fail_cfg "SCAN_MODE '$SCAN_MODE' deve ser 'single' ou 'full'";; esac
{ is_uint "$THREADS"      && (( 10#$THREADS >= 1 )); }      || _fail_cfg "THREADS deve ser inteiro >= 1"
is_uint "$RATE"                                             || _fail_cfg "RATE deve ser inteiro >= 0 (0 = ilimitado)"
{ is_uint "$FFUF_TIMEOUT" && (( 10#$FFUF_TIMEOUT >= 1 )); } || _fail_cfg "FFUF_TIMEOUT deve ser inteiro >= 1"
is_ufloat "$DELAY"                                         || _fail_cfg "DELAY deve ser número >= 0 (ex.: 0, 0.5)"
case "$NUCLEI_UPDATE" in auto|always|never) : ;; *) _fail_cfg "NUCLEI_UPDATE deve ser auto|always|never";; esac

# severidades do nuclei (valida cada token; typo aqui não deve virar FALHOU tardio)
for sev in ${NUCLEI_SEVERITY//,/ }; do
  case "$sev" in info|low|medium|high|critical|unknown) : ;; *) _fail_cfg "NUCLEI_SEVERITY inválida: '$sev'";; esac
done

# STAGES: valida cada nome (split por vírgula via read, SEM glob expansion)
VALID_STAGES="ports http headers content crawl params vhost nuclei"
if [[ -n "$STAGES" ]]; then
  IFS=',' read -ra _stg <<< "$STAGES"
  for s in "${_stg[@]}"; do
    [[ -z "$s" ]] && continue
    case " $VALID_STAGES " in
      *" $s "*) : ;;
      *) _fail_cfg "STAGE desconhecido em STAGES: '$s' (válidos: ${VALID_STAGES// /, })";;
    esac
  done
fi

# rate-limit do nuclei: honra RATE quando definido (antes o nuclei ignorava
# RATE/DELAY e mandava 150 req/s fixo, agressivo demais em alvo remoto).
NUCLEI_RL="${NUCLEI_RL:-$([[ "$RATE" -gt 0 ]] && echo "$RATE" || echo 150)}"
{ is_uint "$NUCLEI_RL" && (( 10#$NUCLEI_RL >= 1 )); } || _fail_cfg "NUCLEI_RL deve ser inteiro >= 1"

# --------- derivados / saída ------------------------------------------------
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"
WEB_ALIVE=unknown                 # yes|no|unknown — gate das etapas dependentes de web

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-recon-${TARGET_HOST}-${TARGET_PORT}-${STAMP}}"
LOGDIR="${OUT}/logs"
mkdir -p "$LOGDIR"
chmod 700 "$OUT" 2>/dev/null || true   # pode conter dados sensíveis (headers, cookies, respostas)

# Todos os caminhos de saída num só lugar (o relatório sempre os conhece,
# mesmo quando a etapa que os produziria não rodou).
PORTS_FILE="${OUT}/1_ports.txt"
HTTP_JSON="${OUT}/2_http.json"
LIVE_FILE="${OUT}/2_http_live.txt"
HEADERS_OUT="${OUT}/3_security_headers.txt"
DIRS_FILE="${OUT}/4_content.txt"
CRAWL_FILE="${OUT}/5_crawl.txt"
PARAM_URLS="${OUT}/5_urls_with_params.txt"
NUCLEI_OUT="${OUT}/8_nuclei.txt"
# (params -> 6_params_<host>.json ; vhost -> 7_vhosts_<host>.json, um por host vivo)

# Args de rate/delay do ffuf, montados uma vez. '-p 0' é evitado (algumas
# versões do ffuf reclamam); '-rate 0' é válido (= ilimitado).
FFUF_RATE_ARGS=(-rate "$RATE")
[[ "$DELAY" =~ ^0+([.]0+)?$ ]] || FFUF_RATE_ARGS+=(-p "$DELAY")

# Throttle do katana (mesma política do ffuf; antes o crawl ignorava RATE).
KATANA_ARGS=()
if [[ "$RATE" -gt 0 ]]; then KATANA_ARGS+=(-rl "$RATE"); fi

# ============================ CORES / LOG ==================================
if [[ -t 1 ]]; then
  c_reset=$'\033[0m'; c_blue=$'\033[1;34m'; c_grn=$'\033[1;32m'
  c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'
else
  c_reset=''; c_blue=''; c_grn=''; c_yel=''; c_red=''
fi
log()  { echo "${c_blue}[*]${c_reset} $*"; }
ok()   { echo "${c_grn}[+]${c_reset} $*"; }
warn() { echo "${c_yel}[!]${c_reset} $*"; }
err()  { echo "${c_red}[x]${c_reset} $*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# nº de linhas sem espaços à esquerda (portável BSD/GNU); 0 se ausente
count_lines() { local n; n="$(wc -l < "$1" 2>/dev/null)" || n=0; echo "${n//[[:space:]]/}"; }

# ===================== CONTROLE DE ETAPAS / STATUS =========================
# STATUS de cada etapa. Valores:
#   OK             rodou e ENCONTROU algo (revisar)
#   LIMPO          rodou com sucesso e não encontrou nada (bom sinal, confiável)
#   FALHOU         a ferramenta rodou mas erro/JSON inválido (NÃO confiável)
#   PENDENTE       depende de host web vivo, mas nada respondeu (NÃO verificado)
#   SEM_ALVO       (só http) probe funcionou e confirmou: nenhum host web vivo
#   SEM_FERRAMENTA a ferramenta não está instalada
#   SEM_WORDLIST   wordlist obrigatória ausente
#   FILTRADO       excluída pelo filtro STAGES (você pediu para pular)
declare -A STATUS=()
FALHAS=0   # conta etapas solicitadas que NÃO puderam ser verificadas de verdade

set_status() {
  STATUS["$1"]="$2"
  case "$2" in
    OK|LIMPO|FILTRADO|SEM_ALVO) : ;;      # cobertura ok ou puramente informativa
    *) FALHAS=$((FALHAS+1)) ;;            # FALHOU/PENDENTE/SEM_FERRAMENTA/SEM_WORDLIST = gap
  esac
}

should_run() { [[ -z "$STAGES" ]] && return 0; [[ ",${STAGES}," == *",$1,"* ]]; }

# Garante ao menos um host vivo em LIVE_FILE. Se o arquivo já tem hosts (ex.:
# preenchido pelo httpx), não faz nada. Caso contrário, CONFIRMA por curl que
# BASE_URL responde — só então o adiciona. Atualiza WEB_ALIVE e retorna 1 se
# nada responder (para a etapa se marcar PENDENTE em vez de fingir "limpo").
ensure_live() {
  if [[ -s "$LIVE_FILE" ]]; then WEB_ALIVE=yes; return 0; fi
  if curl -s -o /dev/null --max-time 10 "$BASE_URL" </dev/null 2>>"$LOGDIR/2_curl_probe.log"; then
    echo "$BASE_URL" > "$LIVE_FILE"; WEB_ALIVE=yes; return 0
  fi
  WEB_ALIVE=no; return 1
}

# run: executa um comando, manda stderr+stdout para um log, devolve o rc.
# stdin vem de /dev/null: nenhuma ferramenta pode "comer" o stdin de um
# 'while read < arquivo' e encerrar o loop cedo.
run() {  # run <logfile> <cmd...>
  local logf="$1"; shift
  local rc=0
  set +e
  "$@" >>"$logf" 2>&1 </dev/null
  rc=$?
  set -e
  return $rc
}

# exige wordlist; se faltar, marca a etapa e retorna 1 (não roda no vazio)
require_wl() {  # require_wl <stage> <path>
  if [[ ! -f "$2" ]]; then
    err "[$1] wordlist ausente: $2"
    err "     instale o SecLists (apt install seclists) ou aponte via variável."
    set_status "$1" SEM_WORDLIST
    return 1
  fi
  return 0
}

# conta results de um JSON do ffuf. Ecoa o número. Retorna 1 se o arquivo
# EXISTIR mas não parsear (JSON corrompido) — para não mascarar como "limpo".
count_results() {  # count_results <json>
  local f="$1" out
  [[ -f "$f" ]] || { echo 0; return 0; }
  if out="$(jq '.results | length' "$f" 2>/dev/null)"; then
    echo "${out:-0}"; return 0
  fi
  echo 0; return 1
}

# tag de arquivo derivada da URL. Além de trocar não-alfanuméricos por '_',
# anexa um hash da URL original para evitar COLISÃO (ex.: 'a.b' e 'a-b').
sanitize() {
  local safe hash
  safe="$(printf '%s' "$1" | sed 's#[^a-zA-Z0-9]#_#g')"
  hash="$(printf '%s' "$1" | cksum | cut -d' ' -f1)"
  printf '%s_%s' "$safe" "$hash"
}

# stage_begin <stage> [web]
#   Gates universais. Retorna 0 se a etapa deve rodar; 1 se não (status já setado):
#     - FILTRADO: excluída via STAGES
#     - PENDENTE: precisa de host web vivo, mas já sabemos que nada respondeu
stage_begin() {
  local st="$1" needs="${2:-}"
  if ! should_run "$st"; then
    warn "$st: FILTRADO"; set_status "$st" FILTRADO; return 1
  fi
  if [[ "$needs" == web && "$WEB_ALIVE" == "no" ]]; then
    err "$st: nenhum host web vivo — superfície NÃO verificada (PENDENTE)"
    set_status "$st" PENDENTE; return 1
  fi
  return 0
}

# ==================== 0. DEPENDÊNCIAS ======================================
log "Checando dependências..."

# Dependências OBRIGATÓRIAS do harness (sem elas o resultado é não confiável).
HARD_MISSING=()
for t in jq curl awk; do
  have "$t" || HARD_MISSING+=("$t")
done
if ((${#HARD_MISSING[@]})); then
  err "Dependências obrigatórias ausentes: ${HARD_MISSING[*]}"
  err "  jq, curl e awk são o núcleo do parsing, checagem de headers e relatório."
  err "  Instale antes de rodar:  sudo apt install jq curl gawk"
  err "ABORTANDO — rodar sem elas produziria um relatório enganoso."
  exit 2
fi
ok "jq, curl, awk: presentes"

for t in naabu nmap httpx ffuf katana nuclei; do
  if have "$t"; then ok "$t: presente"; else warn "$t: AUSENTE (a etapa dependente será marcada, não 'limpa')"; fi
done
cat <<'EOF'
  Instalação das ferramentas de recon (se faltar alguma):
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/ffuf/ffuf/v2@latest
    sudo apt install nmap seclists
EOF
echo

# ==================== RELATÓRIO + TRAP =====================================
# O relatório é gerado por uma função sob 'trap'. Assim, se o usuário abortar
# com Ctrl-C no meio de um scan longo, ainda sai um relatório PARCIAL com a
# tabela de cobertura — antes, o Ctrl-C matava o script antes de gerar nada.
REPORT="${OUT}/RESUMO.md"
_report_done=0

label() {  # tradução legível do status
  case "$1" in
    OK)             echo "🔴 ACHADOS — revisar";;
    LIMPO)          echo "🟢 escaneado, limpo";;
    FALHOU)         echo "⚠️ FALHOU — resultado NÃO confiável";;
    PENDENTE)       echo "⛔ NÃO VERIFICADO — host web indisponível";;
    SEM_ALVO)       echo "🚫 nenhum host web vivo";;
    SEM_FERRAMENTA) echo "⚪ não rodou (ferramenta ausente)";;
    SEM_WORDLIST)   echo "⚪ não rodou (wordlist ausente)";;
    FILTRADO)       echo "➖ pulado (você filtrou)";;
    *)              echo "? $1";;
  esac
}

# emite conteúdo de arquivo como bloco de código INDENTADO (4 espaços).
# Imune a ``` vindo do alvo — um Server/título com três crases NÃO consegue
# quebrar a formatação do relatório (antes: injeção de Markdown via alvo).
emit_block() {  # emit_block <arquivo> <texto-se-vazio>
  if [[ -s "$1" ]]; then sed 's/^/    /' "$1"; else echo "_${2:-nenhum ou não verificado}_"; fi
}

gerar_relatorio() {
  local ec=$?
  [[ $_report_done -eq 1 ]] && return
  _report_done=1
  set +e   # o relatório nunca deve abortar pela metade

  {
    echo "# Recon — ${BASE_URL}"
    echo
    echo "Data: $(date)"
    echo
    echo "> ⚠️ Este diretório pode conter dados sensíveis (headers, cookies,"
    echo "> respostas do alvo). Foi criado com permissão 700. Não versione nem"
    echo "> compartilhe sem revisar."
    echo
    echo "## Cobertura por etapa"
    echo
    echo "> Leia esta tabela antes de tirar conclusões. \"🟢 limpo\" = a etapa"
    echo "> rodou de verdade e não achou nada. \"⚠️ FALHOU\", \"⛔ NÃO VERIFICADO\""
    echo "> e \"⚪ não rodou\" = aquela superfície **não foi verificada** — não"
    echo "> presuma que está segura."
    echo
    echo "| Etapa | Status |"
    echo "|-------|--------|"
    for s in ports http headers content crawl params vhost nuclei; do
      echo "| $s | $(label "${STATUS[$s]:-—}") |"
    done
    echo
    echo "## Hosts web vivos"
    echo
    if [[ -s "$LIVE_FILE" ]]; then sed 's/.*/- `&`/' "$LIVE_FILE"; else echo "_nenhum verificado_"; fi
    echo
    echo "## Headers de segurança ausentes"
    echo
    emit_block "$HEADERS_OUT" "não verificado"
    echo
    echo "## Conteúdo descoberto (status + URL; 5xx é sinal de atenção)"
    echo
    emit_block "$DIRS_FILE" "nenhum ou não verificado"
    echo
    echo "## URLs com parâmetros (candidatas a teste de injeção)"
    echo
    if [[ -s "$PARAM_URLS" ]]; then sed 's/.*/- `&`/' "$PARAM_URLS"; else echo "_nenhuma ou não verificado_"; fi
    echo
    echo "## Achados nuclei"
    echo
    emit_block "$NUCLEI_OUT" "nenhum ou não verificado"
    echo
    echo "## Próximo passo"
    echo
    echo "Rodar o scanner de XSS nas URLs com parâmetro acima:"
    echo '```bash'
    echo 'python scripts/xss_scanner.py --url "<url-com-?param=...>"'
    echo '```'
  } > "$REPORT" 2>/dev/null

  echo "==================================================================="
  if [[ ${FALHAS:-0} -gt 0 ]]; then
    err "ATENÇÃO: ${FALHAS} etapa(s) solicitada(s) NÃO puderam ser verificadas."
    err "O relatório NÃO representa uma varredura completa. Veja a tabela de"
    err "cobertura em: $REPORT"
  else
    ok "Todas as etapas solicitadas rodaram. Resultado confiável."
  fi
  ok "Resultados em: ${OUT}/"
  ok "Logs por etapa em: ${LOGDIR}/"
  ok "Resumo legível: ${REPORT}"

  return "$ec"
}

on_signal() {
  echo >&2
  warn "interrompido pelo usuário — gerando relatório parcial…"
  gerar_relatorio
  exit 130
}

trap on_signal INT TERM
trap gerar_relatorio EXIT

# ==================== 1. SCAN DE PORTAS ====================================
STAGE=ports
if stage_begin "$STAGE"; then
  : > "$PORTS_FILE"
  ports_rc=0; tool_used=none
  if have naabu; then
    tool_used=naabu
    log "naabu: enumerando portas (modo: $SCAN_MODE)"
    if [[ "$SCAN_MODE" == "full" ]]; then
      run "$LOGDIR/1_naabu.log" naabu -host "$TARGET_HOST" -p - -silent -o "$PORTS_FILE" || ports_rc=$?
    else
      run "$LOGDIR/1_naabu.log" naabu -host "$TARGET_HOST" -tp 1000 -silent -o "$PORTS_FILE" || ports_rc=$?
    fi
  elif have nmap; then
    tool_used=nmap
    log "nmap: fallback (naabu ausente)"
    RANGE=$([[ "$SCAN_MODE" == "full" ]] && echo "-p-" || echo "--top-ports 1000")
    # shellcheck disable=SC2086
    run "$LOGDIR/1_nmap.log" nmap -sV -T4 $RANGE "$TARGET_HOST" \
        -oG "${OUT}/1_nmap.gnmap" -oN "${OUT}/1_nmap.txt" || ports_rc=$?
    # parsing robusto via saída greppable (-oG), em vez do texto humano
    if [[ -f "${OUT}/1_nmap.gnmap" ]]; then
      grep -oE '[0-9]+/open/tcp' "${OUT}/1_nmap.gnmap" 2>/dev/null \
        | cut -d/ -f1 | sort -un \
        | awk -v h="$TARGET_HOST" '{print h":"$1}' >> "$PORTS_FILE" || true
    fi
  fi
  # Sempre garante o alvo informado (você disse que é ali). Mas isso NÃO
  # substitui a descoberta: o STATUS reflete se a descoberta funcionou mesmo.
  echo "${TARGET_HOST}:${TARGET_PORT}" >> "$PORTS_FILE"
  sort -u -o "$PORTS_FILE" "$PORTS_FILE" || true

  if [[ "$tool_used" == none ]]; then
    warn "$STAGE: sem naabu/nmap — apenas o alvo informado será usado"
    set_status "$STAGE" SEM_FERRAMENTA
  elif [[ $ports_rc -ne 0 ]]; then
    err "$STAGE: $tool_used retornou erro (rc=$ports_rc) — descoberta NÃO confiável (ver logs)"
    set_status "$STAGE" FALHOU
  else
    ok "$(count_lines "$PORTS_FILE") porta(s) em $PORTS_FILE"; set_status "$STAGE" OK
  fi
fi
echo

# ==================== 2. PROBE HTTP =======================================
# Esta etapa ESTABELECE a liveness web (WEB_ALIVE) usada como gate pelas demais.
STAGE=http
if stage_begin "$STAGE"; then
  [[ -s "$PORTS_FILE" ]] || echo "${TARGET_HOST}:${TARGET_PORT}" > "$PORTS_FILE"
  probe_rc=0
  if have httpx; then
    log "httpx: identificando serviços web vivos"
    run "$LOGDIR/2_httpx.log" httpx -l "$PORTS_FILE" -silent \
        -status-code -title -tech-detect -web-server -content-length \
        -json -o "$HTTP_JSON" || probe_rc=$?
    if [[ -f "$HTTP_JSON" ]]; then
      jq -r 'select(.url!=null) | .url' "$HTTP_JSON" 2>>"$LOGDIR/2_httpx.log" \
        | sort -u > "$LIVE_FILE" || true
    fi
    [[ $probe_rc -ne 0 ]] && err "$STAGE: httpx retornou erro (rc=$probe_rc) — veja $LOGDIR/2_httpx.log"
  else
    warn "$STAGE: httpx ausente — confirmando liveness por curl"
  fi

  # Se o httpx não achou hosts (ou está ausente), confirma BASE_URL por curl.
  [[ -s "$LIVE_FILE" ]] || ensure_live || true

  if [[ -s "$LIVE_FILE" ]]; then
    WEB_ALIVE=yes
    ok "$(count_lines "$LIVE_FILE") host(s) web vivo(s)"
    if ! have httpx; then
      set_status "$STAGE" SEM_FERRAMENTA   # vivo confirmado, mas sem enumeração rica
    elif [[ $probe_rc -ne 0 ]]; then
      set_status "$STAGE" FALHOU
    else
      set_status "$STAGE" OK
    fi
  else
    WEB_ALIVE=no
    if [[ $probe_rc -ne 0 ]] && have httpx; then
      err "$STAGE: httpx falhou e nada respondeu — liveness NÃO confiável"
      set_status "$STAGE" FALHOU
    else
      warn "$STAGE: nenhum host web respondeu (verificado por curl)"
      set_status "$STAGE" SEM_ALVO
    fi
  fi
fi
echo

# ==================== 3. HEADERS DE SEGURANÇA (curl) ======================
# Segue redirects (-L) mas analisa SÓ o último bloco de resposta (a página que
# o browser realmente renderiza) e deriva o esquema do destino FINAL (via
# %{url_effective}). Assim não creditamos um header que só existia num hop 301,
# nem marcamos HSTS como "n/a" quando o destino final é HTTPS.
STAGE=headers
if stage_begin "$STAGE" web; then
  if ! ensure_live; then
    err "$STAGE: host web não respondeu — PENDENTE"; set_status "$STAGE" PENDENTE
  else
    : > "$HEADERS_OUT"
    faltando_total=0; nao_conectou=0
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      log "headers: $url"
      curl_rc=0
      raw="$(curl -s -L -D - -o /dev/null --max-time 10 \
             -w $'\n__EFFURL__:%{url_effective}' "$url" </dev/null 2>>"$LOGDIR/3_curl.log")" || curl_rc=$?
      if [[ $curl_rc -ne 0 ]]; then
        { echo "=== $url ==="
          echo "  [ERRO]  não conectou (curl rc=$curl_rc) — headers NÃO verificados"
          echo; } >> "$HEADERS_OUT"
        nao_conectou=$((nao_conectou+1)); continue
      fi
      raw="$(tr -d '\r' <<< "$raw")"
      eff_url="$(sed -n 's/^__EFFURL__://p' <<< "$raw" | tail -n1)"
      [[ -z "$eff_url" ]] && eff_url="$url"
      hdrs_only="$(sed '/^__EFFURL__:/d' <<< "$raw")"
      # último bloco separado por linha em branco = headers da resposta FINAL
      final_block="$(awk 'BEGIN{RS="";}{b=$0}END{print b}' <<< "$hdrs_only")"
      flc="$(tr 'A-Z' 'a-z' <<< "$final_block")"
      is_https=0; [[ "$eff_url" == https://* ]] && is_https=1
      {
        echo "=== $url ==="
        [[ "$eff_url" != "$url" ]] && echo "  [->]     redirect -> $eff_url"
        for h in content-security-policy strict-transport-security \
                 x-content-type-options x-frame-options \
                 referrer-policy permissions-policy; do
          if [[ "$h" == strict-transport-security && $is_https -eq 0 ]]; then
            echo "  [n/a]    $h — destino final é HTTP"; continue
          fi
          # here-string em vez de 'echo |' evita SIGPIPE espúrio com grep -q
          if grep -q "^${h}:" <<< "$flc"; then
            echo "  [OK]     $h presente"
          else
            echo "  [FALTA]  $h AUSENTE"; faltando_total=$((faltando_total+1))
          fi
        done
        # divulgação de versão (ajuda o atacante a mapear CVEs)
        grep -iE '^(server|x-powered-by|x-aspnet-version):' <<< "$final_block" \
          | sed 's/^/  [INFO] divulga: /' || true
        echo
      } >> "$HEADERS_OUT"
      [[ "$DELAY" =~ ^0+([.]0+)?$ ]] || sleep "$DELAY"   # throttle entre hosts
    done < "$LIVE_FILE"

    [[ $nao_conectou -gt 0 ]] && warn "headers: $nao_conectou host(s) não conectaram — ver $HEADERS_OUT"
    if [[ $faltando_total -gt 0 ]]; then
      ok "headers: $faltando_total header(s) de proteção ausente(s) — ver $HEADERS_OUT"
      set_status "$STAGE" OK
    elif [[ $nao_conectou -gt 0 ]]; then
      err "headers: nada faltando, mas houve falha de conexão — não é 'limpo'"
      set_status "$STAGE" FALHOU
    else
      ok "headers: todos os headers de proteção presentes"
      set_status "$STAGE" LIMPO
    fi
  fi
fi
echo

# ==================== 4. DESCOBERTA DE CONTEÚDO (ffuf) ====================
STAGE=content
if stage_begin "$STAGE" web; then
  if ! ensure_live; then
    err "$STAGE: host web não respondeu — PENDENTE"; set_status "$STAGE" PENDENTE
  elif ! have ffuf; then
    err "$STAGE: ffuf ausente"; set_status "$STAGE" SEM_FERRAMENTA
  elif ! require_wl "$STAGE" "$WL_DIR" || ! require_wl "$STAGE" "$WL_FILE"; then
    : # require_wl já marcou SEM_WORDLIST e logou
  else
    : > "$DIRS_FILE"; any_fail=0; parse_fail=0
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      tag="$(sanitize "$url")"
      jdir="${OUT}/4_dirs_${tag}.json"; jfile="${OUT}/4_files_${tag}.json"

      log "ffuf: diretórios em $url"
      run "$LOGDIR/4_ffuf_${tag}.log" ffuf -u "${url}/FUZZ" -w "$WL_DIR" \
           -ac -recursion -recursion-depth 2 -mc "$FFUF_MC" \
           -t "$THREADS" "${FFUF_RATE_ARGS[@]}" -timeout "$FFUF_TIMEOUT" \
           -o "$jdir" -of json -s || any_fail=1

      log "ffuf: arquivos (+extensões) em $url"
      run "$LOGDIR/4_ffuf_${tag}.log" ffuf -u "${url}/FUZZ" -w "$WL_FILE" \
           -e ".${EXTENSIONS//,/,.}" -ac -mc "$FFUF_MC" \
           -t "$THREADS" "${FFUF_RATE_ARGS[@]}" -timeout "$FFUF_TIMEOUT" \
           -o "$jfile" -of json -s || any_fail=1

      # extrai results; se o JSON existir mas não parsear, marca parse_fail
      for j in "$jdir" "$jfile"; do
        [[ -f "$j" ]] || continue
        if ! jq -r '.results[]? | "\(.status) \(.url)"' "$j" \
             >> "$DIRS_FILE" 2>>"$LOGDIR/4_ffuf_${tag}.log"; then
          parse_fail=1
        fi
      done
    done < "$LIVE_FILE"
    sort -u -o "$DIRS_FILE" "$DIRS_FILE" || true
    if [[ $any_fail -ne 0 || $parse_fail -ne 0 ]]; then
      err "$STAGE: ffuf falhou ou gerou JSON inválido — resultado NÃO confiável (ver $LOGDIR/4_ffuf_*.log)"
      set_status "$STAGE" FALHOU
    elif [[ -s "$DIRS_FILE" ]]; then
      ok "$(count_lines "$DIRS_FILE") item(ns) de conteúdo — inclui 5xx se houver"
      set_status "$STAGE" OK
    else
      ok "$STAGE: nada encontrado (escaneado com sucesso)"; set_status "$STAGE" LIMPO
    fi
  fi
fi
echo

# ==================== 5. CRAWL (katana) ===================================
STAGE=crawl
if stage_begin "$STAGE" web; then
  if ! ensure_live; then
    err "$STAGE: host web não respondeu — PENDENTE"; set_status "$STAGE" PENDENTE
  elif ! have katana; then
    err "$STAGE: katana ausente"; set_status "$STAGE" SEM_FERRAMENTA
  else
    : > "$CRAWL_FILE"; : > "$PARAM_URLS"; rc=0
    run "$LOGDIR/5_katana.log" katana -list "$LIVE_FILE" -jc -kf all -d 3 -silent \
         ${KATANA_ARGS[@]+"${KATANA_ARGS[@]}"} -o "$CRAWL_FILE" || rc=$?
    [[ -f "$CRAWL_FILE" ]] && grep '?' "$CRAWL_FILE" 2>/dev/null | sort -u > "$PARAM_URLS" || true
    if [[ $rc -ne 0 ]]; then
      err "$STAGE: katana retornou erro (rc=$rc) — ver $LOGDIR/5_katana.log"
      set_status "$STAGE" FALHOU
    elif [[ -s "$CRAWL_FILE" ]]; then
      ok "$(count_lines "$CRAWL_FILE") URLs; $(count_lines "$PARAM_URLS") com parâmetros"
      set_status "$STAGE" OK
    else
      ok "$STAGE: nada crawleado (escaneado com sucesso)"; set_status "$STAGE" LIMPO
    fi
  fi
fi
echo

# ==================== 6. PARÂMETROS OCULTOS (ffuf) ========================
# Itera sobre TODOS os hosts vivos (antes só o BASE_URL era testado).
STAGE=params
if stage_begin "$STAGE" web; then
  if ! ensure_live; then
    err "$STAGE: host web não respondeu — PENDENTE"; set_status "$STAGE" PENDENTE
  elif ! have ffuf; then
    err "$STAGE: ffuf ausente"; set_status "$STAGE" SEM_FERRAMENTA
  elif ! require_wl "$STAGE" "$WL_PARAM"; then
    :
  else
    any_fail=0; parse_fail=0; n_total=0
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      tag="$(sanitize "$url")"; jout="${OUT}/6_params_${tag}.json"
      log "ffuf: parâmetros GET ocultos em $url"
      # -ac calibra o baseline; matchamos tudo menos 404. Para apps que refletem
      # o valor, considere filtrar por tamanho (-fs) após inspecionar o log.
      run "$LOGDIR/6_ffuf_params_${tag}.log" ffuf -u "${url}/?FUZZ=fuzztest" -w "$WL_PARAM" \
           -ac -mc all -fc 404 \
           -t "$THREADS" "${FFUF_RATE_ARGS[@]}" -timeout "$FFUF_TIMEOUT" \
           -o "$jout" -of json -s || any_fail=1
      c="$(count_results "$jout")" || parse_fail=1
      n_total=$((n_total + c))
    done < "$LIVE_FILE"
    if [[ $any_fail -ne 0 || $parse_fail -ne 0 ]]; then
      err "$STAGE: ffuf falhou ou gerou JSON inválido — resultado NÃO confiável (ver logs)"
      set_status "$STAGE" FALHOU
    elif [[ $n_total -gt 0 ]]; then
      ok "$STAGE: $n_total parâmetro(s) candidato(s) — ver ${OUT}/6_params_*.json"
      set_status "$STAGE" OK
    else
      ok "$STAGE: nenhum parâmetro oculto (escaneado com sucesso)"; set_status "$STAGE" LIMPO
    fi
  fi
fi
echo

# ==================== 7. VHOSTS (ffuf) ====================================
# Itera sobre TODOS os hosts vivos (antes só o BASE_URL era testado).
STAGE=vhost
if stage_begin "$STAGE" web; then
  if ! ensure_live; then
    err "$STAGE: host web não respondeu — PENDENTE"; set_status "$STAGE" PENDENTE
  elif ! have ffuf; then
    err "$STAGE: ffuf ausente"; set_status "$STAGE" SEM_FERRAMENTA
  elif ! require_wl "$STAGE" "$WL_VHOST"; then
    :
  else
    any_fail=0; parse_fail=0; n_total=0
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      tag="$(sanitize "$url")"; jout="${OUT}/7_vhosts_${tag}.json"
      log "ffuf: virtual hosts em $url (Host: FUZZ.${TARGET_HOST})"
      run "$LOGDIR/7_ffuf_vhost_${tag}.log" ffuf -u "$url" -H "Host: FUZZ.${TARGET_HOST}" \
           -w "$WL_VHOST" -ac -t "$THREADS" "${FFUF_RATE_ARGS[@]}" -timeout "$FFUF_TIMEOUT" \
           -o "$jout" -of json -s || any_fail=1
      c="$(count_results "$jout")" || parse_fail=1
      n_total=$((n_total + c))
    done < "$LIVE_FILE"
    if [[ $any_fail -ne 0 || $parse_fail -ne 0 ]]; then
      err "$STAGE: ffuf falhou ou gerou JSON inválido — resultado NÃO confiável"
      set_status "$STAGE" FALHOU
    elif [[ $n_total -gt 0 ]]; then
      ok "$STAGE: $n_total vhost(s) — ver ${OUT}/7_vhosts_*.json"; set_status "$STAGE" OK
    else
      ok "$STAGE: nenhum vhost (escaneado com sucesso)"; set_status "$STAGE" LIMPO
    fi
  fi
fi
echo

# ==================== 8. NUCLEI ===========================================
STAGE=nuclei
if stage_begin "$STAGE" web; then
  if ! ensure_live; then
    err "$STAGE: host web não respondeu — PENDENTE"; set_status "$STAGE" PENDENTE
  elif ! have nuclei; then
    err "$STAGE: nuclei ausente"; set_status "$STAGE" SEM_FERRAMENTA
  else
    # Atualização de templates: sem eles o nuclei acha ZERO (falso 'limpo').
    # 'auto' atualiza no máx. 1x/24h (evita bater na rede a cada scan).
    tpl_marker="${HOME:-/tmp}/.recon_nuclei_tpl_update"
    do_update=0
    case "$NUCLEI_UPDATE" in
      always) do_update=1 ;;
      never)  do_update=0 ;;
      *)      if [[ ! -f "$tpl_marker" ]] || [[ -n "$(find "$tpl_marker" -mtime +1 2>/dev/null)" ]]; then
                do_update=1
              fi ;;
    esac
    if [[ $do_update -eq 1 ]]; then
      log "nuclei: atualizando templates (evita falso-negativo)"
      if run "$LOGDIR/8_nuclei_update.log" nuclei -update-templates; then
        touch "$tpl_marker"
      else
        warn "nuclei: update de templates falhou — resultado pode ser incompleto"
      fi
    else
      log "nuclei: templates recentes (pulando update; NUCLEI_UPDATE=always força)"
    fi

    log "nuclei: varredura (severidade: $NUCLEI_SEVERITY, rate-limit: $NUCLEI_RL)"
    rc=0
    run "$LOGDIR/8_nuclei.log" nuclei -l "$LIVE_FILE" \
         -severity "$NUCLEI_SEVERITY" -rl "$NUCLEI_RL" -timeout 10 \
         -o "$NUCLEI_OUT" || rc=$?
    if [[ $rc -ne 0 ]]; then
      err "$STAGE: nuclei retornou erro (rc=$rc) — ver $LOGDIR/8_nuclei.log"
      set_status "$STAGE" FALHOU
    elif [[ -s "$NUCLEI_OUT" ]]; then
      ok "$STAGE: $(count_lines "$NUCLEI_OUT") achado(s) em $NUCLEI_OUT"; set_status "$STAGE" OK
    else
      ok "$STAGE: nenhum achado (escaneado com sucesso)"; set_status "$STAGE" LIMPO
    fi
  fi
fi
echo

# ==================== 9. FIM ==============================================
# O relatório e o resumo são emitidos pela trap de EXIT (gerar_relatorio).
# Código de saída gateável para CI: != 0 se algo não pôde ser verificado.
if [[ $FALHAS -gt 0 ]]; then exit 1; fi
exit 0
