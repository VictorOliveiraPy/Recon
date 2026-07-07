#!/usr/bin/env bash
#
# recon.sh — pipeline de enumeração para VALIDAÇÃO DEFENSIVA de apps próprias
#
# FILOSOFIA DESTA FERRAMENTA (leia antes de confiar no resultado):
#   Isto NÃO é um scanner que "tenta não incomodar". É um verificador de
#   segurança. A pior falha aqui não é quebrar — é reportar "limpo" quando na
#   verdade não escaneou nada. Por isso este script FALHA ALTO: se uma
#   dependência, wordlist ou etapa não puder rodar de verdade, ela é marcada
#   como FALHOU/PENDENTE — nunca como "sem achados". O relatório final separa
#   explicitamente "escaneei e está limpo" de "não consegui escanear".
#   Ausência de evidência != evidência de ausência.
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
#   STAGES=headers,nuclei ./recon.sh
#
# Códigos de saída:
#   0 = todas as etapas solicitadas rodaram (com ou sem achados)
#   1 = alguma etapa solicitada FALHOU ou ficou PENDENTE (resultado não confiável)
#
# ATENÇÃO LEGAL: só rode contra alvos que você controla ou tem autorização
# escrita para testar. Contra terceiros sem permissão é crime (BR: Lei 12.737).
# ---------------------------------------------------------------------------

set -euo pipefail

# ============================= CONFIG ======================================
TARGET_HOST="app.qualified-dev.com"
TARGET_PORT="${2:-8000}"
SCAN_MODE="${3:-single}"
BASE_URL="app.qualified-dev.com"
STAGES="${STAGES:-}"

THREADS="${THREADS:-40}"
RATE="${RATE:-0}"                 # req/s ffuf (0 = ilimitado; ok p/ local)
DELAY="${DELAY:-0}"               # atraso entre req (s); use >0 em remoto
FFUF_TIMEOUT="${FFUF_TIMEOUT:-10}"

# Matcher de códigos HTTP para o ffuf.
# CRÍTICO: inclui 5xx e 405 de propósito. Um 500 numa rota fuzzada é sinal
# forte de ponto de injeção / vazamento de stack trace — um defensor QUER ver.
# Excluímos 404 (ruído) e deixamos o -ac tratar soft-404 (200 falso).
FFUF_MC="200-299,301,302,307,308,401,403,405,406,410,500,501,502,503"

SECLISTS="${SECLISTS:-/usr/share/seclists}"
WL_DIR="${WL_DIR:-${SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt}"
WL_FILE="${WL_FILE:-${SECLISTS}/Discovery/Web-Content/raft-medium-files.txt}"
WL_PARAM="${WL_PARAM:-${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt}"
WL_VHOST="${WL_VHOST:-${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt}"

EXTENSIONS="${EXTENSIONS:-php,html,js,json,txt,bak,old,zip,env,config,py,sql,log}"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="recon-${BASE_URL}-${STAMP}"
LOGDIR="${OUT}/logs"
mkdir -p "$LOGDIR"
LIVE_FILE="${OUT}/2_http_live.txt"

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

# ===================== CONTROLE DE ETAPAS / STATUS =========================
# STATUS de cada etapa. Valores:
#   OK            rodou e ENCONTROU algo
#   LIMPO         rodou com sucesso e não encontrou nada (bom sinal, confiável)
#   FALHOU        a ferramenta rodou mas retornou erro (resultado NÃO confiável)
#   SEM_FERRAMENTA a ferramenta não está instalada
#   SEM_WORDLIST  wordlist obrigatória ausente
#   FILTRADO      excluída pelo filtro STAGES (você pediu para pular)
declare -A STATUS=()
FALHAS=0   # conta etapas solicitadas que NÃO puderam rodar de verdade

set_status() {
  STATUS["$1"]="$2"
  # qualquer coisa que não seja OK/LIMPO/FILTRADO conta como falha de cobertura
  case "$2" in
    OK|LIMPO|FILTRADO) : ;;
    *) FALHAS=$((FALHAS+1)) ;;
  esac
}

should_run() { [[ -z "$STAGES" ]] && return 0; [[ ",${STAGES}," == *",$1,"* ]]; }
done_file() { echo "${OUT}/.done_$1"; }
is_done()   { [[ -f "$(done_file "$1")" ]]; }
mark_done() { touch "$(done_file "$1")"; }
ensure_live() { [[ -s "$LIVE_FILE" ]] || echo "$BASE_URL" > "$LIVE_FILE"; }

# run: executa um comando, manda stderr+stdout para um log, devolve o rc.
# Nunca engole o código de saída — quem chama decide o status.
run() {  # run <logfile> <cmd...>
  local logf="$1"; shift
  local rc=0
  set +e
  "$@" >>"$logf" 2>&1
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

sanitize() { echo "$1" | sed 's#[^a-zA-Z0-9]#_#g'; }

# ==================== 0. DEPENDÊNCIAS ======================================
log "Checando dependências..."

# Dependências OBRIGATÓRIAS do harness (sem elas o resultado é não confiável).
HARD_MISSING=()
for t in jq curl; do
  have "$t" || HARD_MISSING+=("$t")
done
if ((${#HARD_MISSING[@]})); then
  err "Dependências obrigatórias ausentes: ${HARD_MISSING[*]}"
  err "  jq e curl são o núcleo do parsing e da checagem de headers."
  err "  Instale antes de rodar:  sudo apt install jq curl"
  err "ABORTANDO — rodar sem elas produziria um relatório enganoso."
  exit 2
fi
ok "jq, curl: presentes"

# Ferramentas por etapa (ausência => etapa marcada SEM_FERRAMENTA, não 'limpo')
declare -A TOOL_OF=(
  [content]=ffuf [params]=ffuf [vhost]=ffuf
  [http]=httpx [crawl]=katana [nuclei]=nuclei
)
for t in naabu nmap httpx ffuf katana nuclei; do
  if have "$t"; then ok "$t: presente"; else warn "$t: AUSENTE"; fi
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

# ==================== 1. SCAN DE PORTAS ====================================
PORTS_FILE="${OUT}/1_ports.txt"
STAGE=ports
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
else
  : > "$PORTS_FILE"
  if have naabu; then
    log "naabu: enumerando portas (modo: $SCAN_MODE)"
    if [[ "$SCAN_MODE" == "full" ]]; then
      run "$LOGDIR/1_naabu.log" naabu -host "$TARGET_HOST" -p - -silent -o "$PORTS_FILE" || true
    else
      run "$LOGDIR/1_naabu.log" naabu -host "$TARGET_HOST" -tp 1000 -silent -o "$PORTS_FILE" || true
    fi
    echo "${TARGET_HOST}:${TARGET_PORT}" >> "$PORTS_FILE"   # garante o alvo
  elif have nmap; then
    log "nmap: fallback (naabu ausente)"
    RANGE=$([[ "$SCAN_MODE" == "full" ]] && echo "-p-" || echo "--top-ports 1000")
    # shellcheck disable=SC2086
    run "$LOGDIR/1_nmap.log" nmap -sV -T4 $RANGE "$TARGET_HOST" -oN "${OUT}/1_nmap.txt" || true
    if [[ -f "${OUT}/1_nmap.txt" ]]; then
      grep -Eo '^[0-9]+/tcp +open' "${OUT}/1_nmap.txt" \
        | awk -v h="$TARGET_HOST" '{split($1,a,"/"); print h":"a[1]}' >> "$PORTS_FILE" || true
    fi
    echo "${TARGET_HOST}:${TARGET_PORT}" >> "$PORTS_FILE"
  else
    warn "sem naabu/nmap — assumindo apenas ${TARGET_HOST}:${TARGET_PORT}"
    echo "${TARGET_HOST}:${TARGET_PORT}" >> "$PORTS_FILE"
  fi
  # dedup seguro (arquivo garantidamente existe)
  sort -u -o "$PORTS_FILE" "$PORTS_FILE"
  if [[ -s "$PORTS_FILE" ]]; then
    ok "$(wc -l < "$PORTS_FILE") porta(s) em $PORTS_FILE"; set_status "$STAGE" OK
  else
    err "$STAGE: nenhuma porta registrada (inesperado)"; set_status "$STAGE" FALHOU
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 2. PROBE HTTP =======================================
STAGE=http
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
elif ! have httpx; then
  err "$STAGE: httpx ausente — usando BASE_URL como único host"
  echo "$BASE_URL" > "$LIVE_FILE"; set_status "$STAGE" SEM_FERRAMENTA
else
  [[ -s "$PORTS_FILE" ]] || echo "${TARGET_HOST}:${TARGET_PORT}" > "$PORTS_FILE"
  log "httpx: identificando serviços web vivos"
  rc=0
  run "$LOGDIR/2_httpx.log" httpx -l "$PORTS_FILE" -silent \
      -status-code -title -tech-detect -web-server -content-length \
      -json -o "${OUT}/2_http.json" || rc=$?
  if [[ -f "${OUT}/2_http.json" ]]; then
    jq -r 'select(.url!=null) | .url' "${OUT}/2_http.json" 2>>"$LOGDIR/2_httpx.log" \
      | sort -u > "$LIVE_FILE" || true
  fi
  if [[ $rc -ne 0 ]]; then
    err "$STAGE: httpx retornou erro (rc=$rc) — veja $LOGDIR/2_httpx.log"
    ensure_live; set_status "$STAGE" FALHOU
  elif [[ -s "$LIVE_FILE" ]]; then
    ok "$(wc -l < "$LIVE_FILE") host(s) web vivo(s)"; set_status "$STAGE" OK
  else
    warn "$STAGE: nenhum host web respondeu"; ensure_live; set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 3. HEADERS DE SEGURANÇA (curl) ======================
# Cobertura defensiva essencial e sem dependência de templates: verifica a
# presença dos headers de proteção e denuncia divulgação de versão.
STAGE=headers
HEADERS_OUT="${OUT}/3_security_headers.txt"
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
else
  ensure_live
  : > "$HEADERS_OUT"
  faltando_total=0
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    log "headers: $url"
    hdr="$(curl -s -D - -o /dev/null --max-time 10 "$url" 2>>"$LOGDIR/3_curl.log" | tr -d '\r' || true)"
    hlc="$(echo "$hdr" | tr 'A-Z' 'a-z')"
    {
      echo "=== $url ==="
      for h in \
        "content-security-policy" \
        "strict-transport-security" \
        "x-content-type-options" \
        "x-frame-options" \
        "referrer-policy" \
        "permissions-policy"; do
        if echo "$hlc" | grep -q "^${h}:"; then
          echo "  [OK]     $h presente"
        else
          echo "  [FALTA]  $h AUSENTE"
          faltando_total=$((faltando_total+1))
        fi
      done
      # divulgação de versão (ajuda o atacante a mapear CVEs)
      echo "$hdr" | grep -iE '^(server|x-powered-by|x-aspnet-version):' \
        | sed 's/^/  [INFO] divulga: /' || true
      echo
    } >> "$HEADERS_OUT"
  done < "$LIVE_FILE"
  if [[ $faltando_total -gt 0 ]]; then
    ok "headers: $faltando_total header(s) de proteção ausente(s) — ver $HEADERS_OUT"
    set_status "$STAGE" OK
  else
    ok "headers: todos os headers de proteção presentes"
    set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 4. DESCOBERTA DE CONTEÚDO (ffuf) ====================
STAGE=content
DIRS_FILE="${OUT}/4_content.txt"
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
elif ! have ffuf; then
  err "$STAGE: ffuf ausente"; set_status "$STAGE" SEM_FERRAMENTA
elif ! require_wl "$STAGE" "$WL_DIR" || ! require_wl "$STAGE" "$WL_FILE"; then
  : # require_wl já marcou SEM_WORDLIST e logou
else
  ensure_live
  : > "$DIRS_FILE"
  any_fail=0
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    tag="$(sanitize "$url")"
    jdir="${OUT}/4_dirs_${tag}.json"
    jfile="${OUT}/4_files_${tag}.json"

    log "ffuf: diretórios em $url"
    run "$LOGDIR/4_ffuf_${tag}.log" ffuf -u "${url}/FUZZ" -w "$WL_DIR" \
         -ac -recursion -recursion-depth 2 -mc "$FFUF_MC" \
         -t "$THREADS" -rate "$RATE" -p "$DELAY" -timeout "$FFUF_TIMEOUT" \
         -o "$jdir" -of json -s || any_fail=1

    log "ffuf: arquivos (+extensões) em $url"
    run "$LOGDIR/4_ffuf_${tag}.log" ffuf -u "${url}/FUZZ" -w "$WL_FILE" \
         -e ".${EXTENSIONS//,/,.}" -ac -mc "$FFUF_MC" \
         -t "$THREADS" -rate "$RATE" -p "$DELAY" -timeout "$FFUF_TIMEOUT" \
         -o "$jfile" -of json -s || any_fail=1

    for j in "$jdir" "$jfile"; do
      [[ -f "$j" ]] && jq -r '.results[]? | "\(.status) \(.url)"' "$j" \
        2>>"$LOGDIR/4_ffuf_${tag}.log" >> "$DIRS_FILE" || true
    done
  done < "$LIVE_FILE"
  sort -u -o "$DIRS_FILE" "$DIRS_FILE"
  if [[ $any_fail -ne 0 ]]; then
    err "$STAGE: ffuf retornou erro em algum host — ver $LOGDIR/4_ffuf_*.log"
    set_status "$STAGE" FALHOU
  elif [[ -s "$DIRS_FILE" ]]; then
    ok "$(wc -l < "$DIRS_FILE") item(ns) de conteúdo — inclui 5xx se houver"
    set_status "$STAGE" OK
  else
    ok "$STAGE: nada encontrado (escaneado com sucesso)"; set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 5. CRAWL (katana) ===================================
STAGE=crawl
CRAWL_FILE="${OUT}/5_crawl.txt"
PARAM_URLS="${OUT}/5_urls_with_params.txt"
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
elif ! have katana; then
  err "$STAGE: katana ausente"; set_status "$STAGE" SEM_FERRAMENTA
else
  ensure_live
  : > "$CRAWL_FILE"; : > "$PARAM_URLS"
  rc=0
  run "$LOGDIR/5_katana.log" katana -list "$LIVE_FILE" -jc -kf all -d 3 -silent \
       -o "$CRAWL_FILE" || rc=$?
  [[ -f "$CRAWL_FILE" ]] && grep '?' "$CRAWL_FILE" 2>/dev/null | sort -u > "$PARAM_URLS" || true
  if [[ $rc -ne 0 ]]; then
    err "$STAGE: katana retornou erro (rc=$rc) — ver $LOGDIR/5_katana.log"
    set_status "$STAGE" FALHOU
  elif [[ -s "$CRAWL_FILE" ]]; then
    ok "$(wc -l < "$CRAWL_FILE") URLs; $(wc -l < "$PARAM_URLS" 2>/dev/null || echo 0) com parâmetros"
    set_status "$STAGE" OK
  else
    ok "$STAGE: nada crawleado (escaneado com sucesso)"; set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 6. PARÂMETROS OCULTOS (ffuf) ========================
STAGE=params
PARAMS_JSON="${OUT}/6_params.json"
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
elif ! have ffuf; then
  err "$STAGE: ffuf ausente"; set_status "$STAGE" SEM_FERRAMENTA
elif ! require_wl "$STAGE" "$WL_PARAM"; then
  :
else
  log "ffuf: parâmetros GET ocultos em $BASE_URL/"
  # -ac calibra o baseline; matchamos tudo menos 404. Para apps que refletem
  # o valor, considere filtrar por tamanho (-fs) manualmente após ver o log.
  rc=0
  run "$LOGDIR/6_ffuf_params.log" ffuf -u "${BASE_URL}/?FUZZ=fuzztest" -w "$WL_PARAM" \
       -ac -mc all -fc 404 \
       -t "$THREADS" -rate "$RATE" -p "$DELAY" -timeout "$FFUF_TIMEOUT" \
       -o "$PARAMS_JSON" -of json -s || rc=$?
  n=0; [[ -f "$PARAMS_JSON" ]] && n="$(jq '.results | length' "$PARAMS_JSON" 2>/dev/null || echo 0)"
  if [[ $rc -ne 0 ]]; then
    err "$STAGE: ffuf retornou erro (rc=$rc) — ver $LOGDIR/6_ffuf_params.log"
    set_status "$STAGE" FALHOU
  elif [[ "$n" -gt 0 ]]; then
    ok "$STAGE: $n parâmetro(s) candidato(s) em $PARAMS_JSON"; set_status "$STAGE" OK
  else
    ok "$STAGE: nenhum parâmetro oculto (escaneado com sucesso)"; set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 7. VHOSTS (ffuf) ====================================
STAGE=vhost
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
elif ! have ffuf; then
  err "$STAGE: ffuf ausente"; set_status "$STAGE" SEM_FERRAMENTA
elif ! require_wl "$STAGE" "$WL_VHOST"; then
  :
else
  log "ffuf: virtual hosts"
  rc=0
  run "$LOGDIR/7_ffuf_vhost.log" ffuf -u "$BASE_URL" -H "Host: FUZZ.${TARGET_HOST}" \
       -w "$WL_VHOST" -ac -t "$THREADS" -rate "$RATE" -timeout "$FFUF_TIMEOUT" \
       -o "${OUT}/7_vhosts.json" -of json -s || rc=$?
  n=0; [[ -f "${OUT}/7_vhosts.json" ]] && n="$(jq '.results | length' "${OUT}/7_vhosts.json" 2>/dev/null || echo 0)"
  if [[ $rc -ne 0 ]]; then
    err "$STAGE: ffuf retornou erro (rc=$rc)"; set_status "$STAGE" FALHOU
  elif [[ "$n" -gt 0 ]]; then
    ok "$STAGE: $n vhost(s) em 7_vhosts.json"; set_status "$STAGE" OK
  else
    ok "$STAGE: nenhum vhost (escaneado com sucesso)"; set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 8. NUCLEI ===========================================
STAGE=nuclei
NUCLEI_OUT="${OUT}/8_nuclei.txt"
if ! should_run "$STAGE"; then
  warn "$STAGE: FILTRADO"; set_status "$STAGE" FILTRADO
elif is_done "$STAGE"; then
  ok "$STAGE: já feito, pulando"
elif ! have nuclei; then
  err "$STAGE: nuclei ausente"; set_status "$STAGE" SEM_FERRAMENTA
else
  ensure_live
  # Garante templates: sem eles o nuclei roda e acha ZERO (falso 'limpo').
  log "nuclei: atualizando templates (evita falso-negativo)"
  run "$LOGDIR/8_nuclei_update.log" nuclei -update-templates || \
    warn "nuclei: update de templates falhou — resultado pode ser incompleto"
  log "nuclei: varredura por templates"
  # SEM -silent: queremos ver avisos. Saída de achados vai para arquivo próprio.
  rc=0
  run "$LOGDIR/8_nuclei.log" nuclei -l "$LIVE_FILE" \
       -severity low,medium,high,critical -rl 150 -timeout 10 \
       -o "$NUCLEI_OUT" || rc=$?
  if [[ $rc -ne 0 ]]; then
    err "$STAGE: nuclei retornou erro (rc=$rc) — ver $LOGDIR/8_nuclei.log"
    set_status "$STAGE" FALHOU
  elif [[ -s "$NUCLEI_OUT" ]]; then
    ok "$STAGE: $(wc -l < "$NUCLEI_OUT") achado(s) em 8_nuclei.txt"; set_status "$STAGE" OK
  else
    ok "$STAGE: nenhum achado (escaneado com sucesso)"; set_status "$STAGE" LIMPO
  fi
  mark_done "$STAGE"
fi
echo

# ==================== 9. RELATÓRIO ========================================
REPORT="${OUT}/RESUMO.md"
label() {  # tradução legível do status
  case "$1" in
    OK)             echo "🔴 ACHADOS — revisar";;
    LIMPO)          echo "🟢 escaneado, limpo";;
    FALHOU)         echo "⚠️  FALHOU — resultado NÃO confiável";;
    SEM_FERRAMENTA) echo "⚪ não rodou (ferramenta ausente)";;
    SEM_WORDLIST)   echo "⚪ não rodou (wordlist ausente)";;
    FILTRADO)       echo "➖ pulado (você filtrou)";;
    *)              echo "? $1";;
  esac
}

{
  echo "# Recon — ${BASE_URL}"
  echo
  echo "Data: $(date)"
  echo
  echo "## Cobertura por etapa"
  echo
  echo "> Leia esta tabela antes de tirar conclusões. \"🟢 limpo\" significa que a"
  echo "> etapa rodou de verdade e não achou nada. \"⚠️ FALHOU\" e \"⚪ não rodou\""
  echo "> significam que aquela superfície **não foi verificada** — não presuma"
  echo "> que está segura."
  echo
  echo "| Etapa | Status |"
  echo "|-------|--------|"
  for s in ports http headers content crawl params vhost nuclei; do
    st="${STATUS[$s]:-—}"
    echo "| $s | $(label "$st") |"
  done
  echo
  echo "## Hosts web vivos"
  [[ -s "$LIVE_FILE" ]] && sed 's/^/- /' "$LIVE_FILE" || echo "_nenhum_"
  echo
  echo "## Headers de segurança ausentes"
  if [[ -s "$HEADERS_OUT" ]]; then echo '```'; cat "$HEADERS_OUT"; echo '```'; else echo "_não verificado_"; fi
  echo
  echo "## Conteúdo descoberto (status + URL; 5xx é sinal de atenção)"
  if [[ -s "$DIRS_FILE" ]]; then echo '```'; cat "$DIRS_FILE"; echo '```'; else echo "_nenhum ou não verificado_"; fi
  echo
  echo "## URLs com parâmetros (candidatas a teste de injeção)"
  if [[ -s "$PARAM_URLS" ]]; then sed 's/^/- /' "$PARAM_URLS"; else echo "_nenhuma ou não verificado_"; fi
  echo
  echo "## Achados nuclei"
  if [[ -s "$NUCLEI_OUT" ]]; then echo '```'; cat "$NUCLEI_OUT"; echo '```'; else echo "_nenhum ou não verificado_"; fi
  echo
  echo "## Próximo passo"
  echo "Rodar o scanner de XSS nas URLs com parâmetro acima:"
  echo '```bash'
  echo "python scripts/xss_scanner.py --url \"<url-com-?param=...>\""
  echo '```'
} > "$REPORT"

echo "==================================================================="
if [[ $FALHAS -gt 0 ]]; then
  err "ATENÇÃO: $FALHAS etapa(s) solicitada(s) NÃO puderam ser verificadas."
  err "O relatório NÃO representa uma varredura completa. Veja a tabela de"
  err "cobertura em: $REPORT"
else
  ok "Todas as etapas solicitadas rodaram. Resultado confiável."
fi
ok "Resultados em: ${OUT}/"
ok "Logs por etapa em: ${LOGDIR}/"
ok "Resumo legível: ${REPORT}"

# Código de saída gateável para CI: != 0 se algo não pôde ser verificado.
[[ $FALHAS -eq 0 ]]
