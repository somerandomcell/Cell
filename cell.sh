#!/bin/bash

#-----------------------------------------------------------------------------------------#
#                          🔎 CyberSleuth - Recon & Access Mapper 🔍                       #
#-----------------------------------------------------------------------------------------#
# Description:                                                                            #
#   Automates subdomain enumeration, live host probing, directory fuzzing,                #
#   Wayback Machine URL discovery (using waybackurls), and entry point ID.                #
#                                                                                         #
# Prerequisites: sublist3r, httpx (ProjectDiscovery), ffuf, waybackurls, curl,            #
#                gf (optional), anew (optional), jq (optional)                            #
#-----------------------------------------------------------------------------------------#


DEFAULT_TARGET_DOMAIN=""

SUBLIST3R_CMD="sublist3r"; HTTPX_CMD="httpx"; FFUF_CMD="ffuf"
WAYBACKURLS_CMD="waybackurls"
CURL_CMD="curl"; GF_CMD="gf"; ANEW_CMD="anew"; JQ_CMD="jq"

FFUF_THREADS=40 # <--- SET TO 40 THREADS
FFUF_MATCH_CODES="200,301,302"
FFUF_RECURSION_DEPTH=0
FFUF_TIMEOUT=10
FFUF_MAX_JOB_TIME=300
FFUF_NO_NEW_RESULT_TIMEOUT=20

FFUF_WORDLIST_FILENAME="raft-medium-directories.txt"
FFUF_WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/${FFUF_WORDLIST_FILENAME}"
OUTPUT_BASE_DIR="recon_results"
SKIP_FFUF=false
SKIP_WAYBACKURLS=false
C_RED='\033[1;31m'; C_GREEN='\033[1;32m'; C_YELLOW='\033[1;33m'; C_BLUE='\033[1;34m'
C_PURPLE='\033[1;35m'; C_CYAN='\033[1;36m'; C_WHITE='\033[1;37m'; C_RESET='\033[0m'
PROGRESS_CHARS=".oO0Oo"; PROGRESS_DELAY=0.2

if [[ $EUID -eq 0 ]]; then FFUF_WORDLIST_DIR_EFFECTIVE="/usr/share/seclists/Discovery/Web-Content"
else FFUF_WORDLIST_DIR_EFFECTIVE="$HOME/wordlists"; fi
FFUF_WORDLIST="${FFUF_WORDLIST_DIR_EFFECTIVE}/${FFUF_WORDLIST_FILENAME}"

print_banner() {
    echo -e "${C_CYAN}"
    echo "                      .--\"\"--."
    echo "                     /        \\"
    echo "                    |   ⊙ ►    |  "
    echo "                     \\  .--.  /"
    echo "                      '-|__|-'  "
    echo "                         \\  /   "
    echo "                          \\/    "
    echo -e "${C_GREEN}"
    echo " ____      _        ____            _       _     "
    echo "/ ___| ___| | ___  / ___| ___ _   _| |_ __ | | ___ "
    echo "\\___ \\ / _ \\ |/ _ \\ \\___ \\/ __| | | | | '_ \\| |/ _ \\"
    echo " ___) |  __/ |  __/  ___) \\__ \\ |_| | | |_) | |  __/"
    echo "|____/ \\___|_|\\___| |____/|___/\\__,_|_| .__/|_|\\___|"
    echo "                                      |_|          "
    echo -e "${C_PURPLE}         Digital Probe & Initial Access Mapper v2.3 ${C_RESET}"
    echo -e "${C_CYAN}=============================================================================${C_RESET}"
}

_log() { echo -e "$1[$2]${C_RESET} $3"; }
log_info() { _log "${C_BLUE}" "INFO" "$1"; }
log_success() { _log "${C_GREEN}" "SUCCESS" "$1"; }
log_warning() { _log "${C_YELLOW}" "WARN" "$1"; }
log_error() { _log "${C_RED}" "ERROR" "$1"; }
log_step() { echo -e "\n${C_PURPLE}===> STEP $1: $2 ${C_RESET}"; }

check_tool() {
    local cmd_var_name="$1"; local cmd_path="${!cmd_var_name}"
    if ! command -v "$cmd_path" &> /dev/null; then
        log_error "Tool ${C_YELLOW}${cmd_path}${C_RESET} (var ${C_WHITE}${cmd_var_name}${C_RESET}) not found."; exit 1
    fi; log_info "Tool ${C_GREEN}${cmd_path}${C_RESET} found."
}
show_progress() {
    local pid=$1; local message=${2:-"Processing..."}; local i=0
    echo -n -e "${C_CYAN}${message}${C_RESET} "
    while kill -0 "$pid" 2>/dev/null; do
        echo -n -e "${C_YELLOW}${PROGRESS_CHARS:$i:1}${C_RESET}"; sleep "$PROGRESS_DELAY"
        echo -n -e "\b"; i=$(( (i+1) % ${#PROGRESS_CHARS} ))
    done; echo -e "\b ${C_GREEN}Done.${C_RESET}"
}
download_wordlist_if_needed() {
    if [ ! -f "$FFUF_WORDLIST" ]; then
        log_warning "FFUF wordlist not found: ${C_PURPLE}${FFUF_WORDLIST}${C_RESET}"
        log_info "Downloading ${C_YELLOW}${FFUF_WORDLIST_FILENAME}${C_RESET}..."
        if mkdir -p "$(dirname "$FFUF_WORDLIST")"; then log_info "Ensured dir exists: $(dirname "$FFUF_WORDLIST")"
        else log_error "Failed to create dir: $(dirname "$FFUF_WORDLIST")"; exit 1; fi
        if "$CURL_CMD" -L --progress-bar -o "$FFUF_WORDLIST" "$FFUF_WORDLIST_URL"; then
            if [ -s "$FFUF_WORDLIST" ]; then log_success "Wordlist downloaded: ${C_PURPLE}${FFUF_WORDLIST}${C_RESET}"
            else log_error "Downloaded wordlist empty. Removing."; rm "$FFUF_WORDLIST"; exit 1; fi
        else log_error "Failed to download wordlist from: ${FFUF_WORDLIST_URL}"; exit 1; fi
    else log_info "FFUF wordlist found: ${C_GREEN}${FFUF_WORDLIST}${C_RESET}"; fi
}


print_banner
TARGET_DOMAIN="${1:-$DEFAULT_TARGET_DOMAIN}"
if [ -z "$TARGET_DOMAIN" ]; then log_error "No target domain. Usage: $0 <domain>"; exit 1; fi

TARGET_OUTPUT_DIR="${OUTPUT_BASE_DIR}/${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TARGET_OUTPUT_DIR"/{subdomains,ffuf,entry_points,logs,wayback_data}
LOG_FILE="${TARGET_OUTPUT_DIR}/logs/CyberSleuth_run.log"; exec &> >(tee -a "${LOG_FILE}") 

log_info "Target: ${C_YELLOW}${TARGET_DOMAIN}${C_RESET}"; log_info "Output: ${C_PURPLE}${TARGET_OUTPUT_DIR}${C_RESET}"
log_info "Log: ${C_PURPLE}${LOG_FILE}${C_RESET}"; if [[ $EUID -eq 0 ]]; then log_warning "Running as root."; fi
log_info "Effective FFUF wordlist: ${C_PURPLE}${FFUF_WORDLIST}${C_RESET}"

log_step "0" "TOOL VERIFICATION"
check_tool "SUBLIST3R_CMD"; check_tool "HTTPX_CMD"; check_tool "FFUF_CMD"
check_tool "WAYBACKURLS_CMD"; check_tool "CURL_CMD"; check_tool "JQ_CMD"
GF_INSTALLED=false
if command -v "$GF_CMD" &> /dev/null && command -v "$ANEW_CMD" &> /dev/null; then
    log_info "${C_GREEN}gf${C_RESET} & ${C_GREEN}anew${C_RESET} found. Adv entry points enabled."
    GF_INSTALLED=true
else log_warning "${C_YELLOW}gf${C_RESET}/${C_YELLOW}anew${C_RESET} not found. Basic entry points only."; fi
download_wordlist_if_needed

SUBDOMAINS_RAW_FILE="${TARGET_OUTPUT_DIR}/subdomains/subdomains_raw.txt"
LIVE_SUBDOMAINS_FILE="${TARGET_OUTPUT_DIR}/subdomains/live_subdomains.txt"; touch "$LIVE_SUBDOMAINS_FILE"
ALL_HISTORICAL_URLS_FILE="${TARGET_OUTPUT_DIR}/wayback_data/all_historical_urls.txt"; touch "$ALL_HISTORICAL_URLS_FILE"

log_step "1" "SUBDOMAIN ENUMERATION (Sublist3r)"
"$SUBLIST3R_CMD" -d "$TARGET_DOMAIN" -o "$SUBDOMAINS_RAW_FILE" > "${TARGET_OUTPUT_DIR}/logs/sublist3r.log" 2>&1 &
SUBLIST3R_PID=$!; show_progress $SUBLIST3R_PID "Sublist3r running"; wait $SUBLIST3R_PID; SUBLIST3R_EC=$?
if [ $SUBLIST3R_EC -eq 0 ] && [ -s "$SUBDOMAINS_RAW_FILE" ]; then
    SUB_COUNT=$(wc -l < "$SUBDOMAINS_RAW_FILE"); log_success "Sublist3r found ${C_GREEN}${SUB_COUNT}${C_RESET} raw subdomains."
elif [ -s "$SUBDOMAINS_RAW_FILE" ]; then
    SUB_COUNT=$(wc -l < "$SUBDOMAINS_RAW_FILE"); log_warning "Sublist3r (EC:$SUBLIST3R_EC) may have errors but found ${C_YELLOW}${SUB_COUNT}${C_RESET} raw subdomains."
else log_warning "Sublist3r (EC:$SUBLIST3R_EC) found no subdomains or failed. Log: ${TARGET_OUTPUT_DIR}/logs/sublist3r.log"; fi

log_step "2" "LIVE SUBDOMAIN PROBING (httpx)"
HTTPX_SUCCESS=false
LIVE_HOSTNAMES_FILE="${TARGET_OUTPUT_DIR}/subdomains/live_hostnames_for_wayback.txt"
if [ -s "$SUBDOMAINS_RAW_FILE" ]; then
    LIVE_SUBDOMAINS_FILE_TEMP="${TARGET_OUTPUT_DIR}/subdomains/live_subdomains_temp.txt"
    "$HTTPX_CMD" -list "$SUBDOMAINS_RAW_FILE" -silent -threads 100 -o "$LIVE_SUBDOMAINS_FILE_TEMP" > "${TARGET_OUTPUT_DIR}/logs/httpx_probe.log" 2>&1 &
    HTTPX_PID=$!; show_progress $HTTPX_PID "httpx probing"; wait $HTTPX_PID; HTTPX_EC=$?
    if [ $HTTPX_EC -eq 0 ] && [ -s "$LIVE_SUBDOMAINS_FILE_TEMP" ]; then
        awk -F/ '{print $3}' "$LIVE_SUBDOMAINS_FILE_TEMP" | sort -u > "$LIVE_HOSTNAMES_FILE"
        mv "$LIVE_SUBDOMAINS_FILE_TEMP" "$LIVE_SUBDOMAINS_FILE"
        LIVE_COUNT=$(wc -l < "$LIVE_SUBDOMAINS_FILE"); log_success "httpx found ${C_GREEN}${LIVE_COUNT}${C_RESET} live subdomains (full URLs)."
        HTTPX_SUCCESS=true
    else log_error "httpx (EC:$HTTPX_EC) failed or found no live subdomains. Log: ${TARGET_OUTPUT_DIR}/logs/httpx_probe.log"; fi
    rm -f "$LIVE_SUBDOMAINS_FILE_TEMP"
else log_warning "Skipping httpx: No raw subdomains."; fi

TOTAL_LIVE_SUBDOMAINS_COUNT=0
if [ -s "$LIVE_SUBDOMAINS_FILE" ]; then TOTAL_LIVE_SUBDOMAINS_COUNT=$(wc -l < "$LIVE_SUBDOMAINS_FILE"); fi

if [ "$TOTAL_LIVE_SUBDOMAINS_COUNT" -gt 0 ]; then
    if [ "$SKIP_FFUF" = true ]; then
        log_warning "Skipping FFUF scans (configured)."
    else
        CURRENT_LIVE_NUM=0
        log_step "3A" "FFUF SCANNING for ${C_GREEN}${TOTAL_LIVE_SUBDOMAINS_COUNT}${C_RESET} live host(s)"
        while IFS= read -r live_url; do
            if [ -z "$live_url" ]; then continue; fi
            CURRENT_LIVE_NUM=$((CURRENT_LIVE_NUM + 1))
            domain_for_filename=$(echo "$live_url" | sed -e 's|^http[s]*://||' -e 's|/|_|g')
            log_info "Processing FFUF host (${CURRENT_LIVE_NUM}/${TOTAL_LIVE_SUBDOMAINS_COUNT}): ${C_YELLOW}${live_url}${C_RESET}"
            FFUF_OUTPUT_FILE="${TARGET_OUTPUT_DIR}/ffuf/${domain_for_filename}_ffuf.json"; touch "$FFUF_OUTPUT_FILE"
            log_info "  Starting FFUF (Threads: ${FFUF_THREADS}, Codes: ${FFUF_MATCH_CODES}, Max No-New-Result: ${FFUF_NO_NEW_RESULT_TIMEOUT}s, Overall Max: ${FFUF_MAX_JOB_TIME}s)..."
            "$FFUF_CMD" -u "${live_url}/FUZZ" -w "$FFUF_WORDLIST" -t "$FFUF_THREADS" \
                       -mc "$FFUF_MATCH_CODES" -recursion -recursion-depth "$FFUF_RECURSION_DEPTH" \
                       -o "$FFUF_OUTPUT_FILE" -of json \
                       -ac -timeout "$FFUF_TIMEOUT" -maxtime-job "$FFUF_MAX_JOB_TIME" \
                       > "${TARGET_OUTPUT_DIR}/logs/ffuf_${domain_for_filename}.log" 2>&1 &
            FFUF_PID=$!
            ffuf_last_size=-1; ffuf_current_size=0; ffuf_killed_by_monitor=false
            SECONDS_SINCE_LAST_FFUF_RESULT=0; FFUF_MONITOR_INTERVAL=5; elapsed_ffuf_time=0
            while kill -0 $FFUF_PID 2>/dev/null; do
                sleep $FFUF_MONITOR_INTERVAL; elapsed_ffuf_time=$((elapsed_ffuf_time + FFUF_MONITOR_INTERVAL))
                if [ ! -f "$FFUF_OUTPUT_FILE" ]; then ffuf_current_size=0
                else ffuf_current_size=$(wc -c < "$FFUF_OUTPUT_FILE"); fi
                echo -n -e "${C_CYAN}  FFUF on ${domain_for_filename} [${elapsed_ffuf_time}s] (Size: ${ffuf_current_size}b)...${PROGRESS_CHARS:$((elapsed_ffuf_time % ${#PROGRESS_CHARS})):1}${C_RESET}\r"
                if [ "$ffuf_last_size" -eq -1 ]; then ffuf_last_size=$ffuf_current_size; SECONDS_SINCE_LAST_FFUF_RESULT=0
                elif [ "$ffuf_current_size" -gt "$ffuf_last_size" ]; then ffuf_last_size=$ffuf_current_size; SECONDS_SINCE_LAST_FFUF_RESULT=0
                else SECONDS_SINCE_LAST_FFUF_RESULT=$((SECONDS_SINCE_LAST_FFUF_RESULT + FFUF_MONITOR_INTERVAL))
                    if [ "$SECONDS_SINCE_LAST_FFUF_RESULT" -ge "$FFUF_NO_NEW_RESULT_TIMEOUT" ]; then
                        log_warning "  FFUF: No new results for ${domain_for_filename} in ${FFUF_NO_NEW_RESULT_TIMEOUT}s. Stopping FFUF."
                        kill -TERM $FFUF_PID 2>/dev/null; sleep 0.5; kill -KILL $FFUF_PID 2>/dev/null
                        ffuf_killed_by_monitor=true; break
                    fi
                fi
                if [ "$elapsed_ffuf_time" -ge "$FFUF_MAX_JOB_TIME" ]; then log_info "  FFUF: Reached overall max time for ${domain_for_filename}."; break; fi
            done; echo; wait $FFUF_PID; FFUF_EC=$?
            ffuf_results_count=0
            if [ -f "$FFUF_OUTPUT_FILE" ] && command -v "$JQ_CMD" &>/dev/null; then
                ffuf_results_count=$("$JQ_CMD" '.results | length' "$FFUF_OUTPUT_FILE" 2>/dev/null); ffuf_results_count=${ffuf_results_count:-0}
            elif [ -f "$FFUF_OUTPUT_FILE" ]; then if [ "$(wc -c < "$FFUF_OUTPUT_FILE")" -gt 250 ]; then ffuf_results_count=1; fi; fi
            if [ "$ffuf_killed_by_monitor" = true ]; then
                if [ "$ffuf_results_count" -gt 0 ]; then log_warning "  FFUF for ${live_url} stopped by monitor, but ${C_GREEN}${ffuf_results_count}${C_RESET} prior results found."
                else log_warning "  FFUF for ${live_url} stopped by monitor (no new results)."; fi
            elif [ $FFUF_EC -eq 0 ] && [ "$ffuf_results_count" -gt 0 ]; then log_success "  FFUF scan completed for ${live_url} with ${C_GREEN}${ffuf_results_count}${C_RESET} results."
            elif [ $FFUF_EC -eq 0 ]; then log_info "  FFUF scan completed for ${live_url} but found no matching results."
            else log_warning "  FFUF scan (EC:$FFUF_EC) for ${live_url} had issues. Log: ${TARGET_OUTPUT_DIR}/logs/ffuf_${domain_for_filename}.log"; fi
        done < "$LIVE_SUBDOMAINS_FILE"
    fi
else
    log_warning "Skipping FFUF scans: No live subdomains found."
fi

if [ -s "$LIVE_HOSTNAMES_FILE" ]; then
    if [ "$SKIP_WAYBACKURLS" = true ]; then
        log_warning "Skipping Waybackurls (configured)."
    else
        log_step "3B" "HISTORICAL URL DISCOVERY (waybackurls)"
        log_info "Running waybackurls on all live hostnames..."
        cat "$LIVE_HOSTNAMES_FILE" | "$WAYBACKURLS_CMD" > "$ALL_HISTORICAL_URLS_FILE" 2> "${TARGET_OUTPUT_DIR}/logs/waybackurls.log" &
        WAYBACK_PID=$!
        show_progress $WAYBACK_PID "waybackurls running"
        wait $WAYBACK_PID
        WAYBACK_EC=$?
        if [ $WAYBACK_EC -eq 0 ] && [ -s "$ALL_HISTORICAL_URLS_FILE" ]; then
            HISTORICAL_URL_COUNT=$(wc -l < "$ALL_HISTORICAL_URLS_FILE")
            log_info "Sorting and uniquing waybackurls output..."
            sort -u "$ALL_HISTORICAL_URLS_FILE" -o "$ALL_HISTORICAL_URLS_FILE"
            UNIQUE_HISTORICAL_URL_COUNT=$(wc -l < "$ALL_HISTORICAL_URLS_FILE")
            log_success "waybackurls found ${C_GREEN}${UNIQUE_HISTORICAL_URL_COUNT}${C_RESET} unique historical URLs (raw: ${HISTORICAL_URL_COUNT})."
        elif [ $WAYBACK_EC -eq 0 ]; then
            log_info "waybackurls found no URLs."
        else
            log_error "waybackurls (EC:$WAYBACK_EC) failed. Check Log: ${TARGET_OUTPUT_DIR}/logs/waybackurls.log"
        fi
    fi
else
    log_warning "Skipping Waybackurls: No live hostnames extracted (httpx might have failed or found none)."
fi

log_step "4" "ENTRY POINT IDENTIFICATION"
ENTRY_POINTS_BASIC_FILE="${TARGET_OUTPUT_DIR}/entry_points/entry_points_basic_params.txt"
LIVE_ENTRY_POINTS_FILE="${TARGET_OUTPUT_DIR}/entry_points/live_entry_points_params.txt"
if [ -s "$ALL_HISTORICAL_URLS_FILE" ]; then
    log_info "Searching basic parameter entry points from historical URLs..."
    grep -Ei '(\?|\&)[a-zA-Z0-9_.-]+=' "$ALL_HISTORICAL_URLS_FILE" > "$ENTRY_POINTS_BASIC_FILE"
    TOTAL_POTENTIAL_PARAMS=$(wc -l < "$ENTRY_POINTS_BASIC_FILE")
    if [ "$TOTAL_POTENTIAL_PARAMS" -gt 0 ]; then
        log_success "Found ${C_GREEN}${TOTAL_POTENTIAL_PARAMS}${C_RESET} potential parameter URLs."
        log_info "Checking liveness (excluding 404s)..."; touch "$LIVE_ENTRY_POINTS_FILE"; LIVE_COUNT_EP=0; PROCESSED_URL_COUNT=0
        MAX_PARALLEL_CURL=10; TEMP_LIVE_ENTRY_POINTS="${TARGET_OUTPUT_DIR}/entry_points/temp_live_ep_par.txt"; touch "$TEMP_LIVE_ENTRY_POINTS"
        check_url_liveness() {
            local url="$1"; local temp_output_file="$2"
            status_code=$("$CURL_CMD" -s -o /dev/null -w "%{http_code}" -L --connect-timeout 5 --max-time 10 "$url")
            if [[ "$status_code" -ne 404 && "$status_code" -ne 000 && "$status_code" -ne 400 ]]; then
                echo "$url [Status: $status_code]" >> "$temp_output_file"; fi; return 0; }
        export -f check_url_liveness; export CURL_CMD
        if [ "$TOTAL_POTENTIAL_PARAMS" -gt $((MAX_PARALLEL_CURL * 3)) ]; then
            log_info "Using parallel curl (Max ${MAX_PARALLEL_CURL} concurrent)..."
            cat "$ENTRY_POINTS_BASIC_FILE" | xargs -P"$MAX_PARALLEL_CURL" -I{} bash -c 'check_url_liveness "{}" "$0"' "$TEMP_LIVE_ENTRY_POINTS" &
            XARGS_PID=$!; show_progress $XARGS_PID "Parallel URL liveness"; wait $XARGS_PID
        else
            log_info "Using sequential curl for liveness checks..."
            while IFS= read -r url; do
                PROCESSED_URL_COUNT=$((PROCESSED_URL_COUNT + 1)); if [ -z "$url" ]; then continue; fi
                echo -n -e "${C_CYAN}Checking URL (${PROCESSED_URL_COUNT}/${TOTAL_POTENTIAL_PARAMS})${C_RESET}: ${url:0:50}...\r"
                check_url_liveness "$url" "$TEMP_LIVE_ENTRY_POINTS"
            done < "$ENTRY_POINTS_BASIC_FILE"; echo -ne "\n"
        fi
        cat "$TEMP_LIVE_ENTRY_POINTS" > "$LIVE_ENTRY_POINTS_FILE"; rm "$TEMP_LIVE_ENTRY_POINTS"
        LIVE_COUNT_EP=$(wc -l < "$LIVE_ENTRY_POINTS_FILE"); log_success "Found ${C_GREEN}${LIVE_COUNT_EP}${C_RESET} live parameter URLs (non-404)."
    else log_info "No basic parameter entry points in historical URLs."; fi

    if [ "$GF_INSTALLED" = true ] && [ -s "$LIVE_ENTRY_POINTS_FILE" ]; then
        log_info "Using ${C_GREEN}gf${C_RESET} for advanced entry point patterns..."
        GF_PATTERNS=("xss" "sqli" "ssrf" "redirect" "lfi" "idor" "interestingparams" "debug_logic")
        for pattern in "${GF_PATTERNS[@]}"; do
            GF_OUTPUT_FILE="${TARGET_OUTPUT_DIR}/entry_points/gf_${pattern}.txt"
            cat "$LIVE_ENTRY_POINTS_FILE" | "$GF_CMD" "$pattern" | "$ANEW_CMD" "$GF_OUTPUT_FILE" > /dev/null 2>&1
            if [ -s "$GF_OUTPUT_FILE" ]; then
                GF_COUNT=$(wc -l < "$GF_OUTPUT_FILE"); log_success "  Found ${C_GREEN}${GF_COUNT}${C_RESET} potential ${C_YELLOW}${pattern}${C_RESET} entry points."
            fi; done
    fi
else log_info "No historical URLs found, skipping entry point ID."; fi

log_step "END" "CYBERSLEUTH SUMMARY"
log_info "Scan for ${C_YELLOW}${TARGET_DOMAIN}${C_RESET} completed."
log_info "Output: ${C_PURPLE}${TARGET_OUTPUT_DIR}${C_RESET}"; log_info "--- Key Files ---"
[ -s "$SUBDOMAINS_RAW_FILE" ] && log_info "  Raw Subdomains: $(wc -l < "$SUBDOMAINS_RAW_FILE") in ${SUBDOMAINS_RAW_FILE}"
[ -s "$LIVE_SUBDOMAINS_FILE" ] && log_info "  Live Subdomains: $(wc -l < "$LIVE_SUBDOMAINS_FILE") in ${LIVE_SUBDOMAINS_FILE}"
FFUF_FILES_COUNT=0
if command -v "$JQ_CMD" &>/dev/null; then FFUF_FILES_COUNT=$(find "${TARGET_OUTPUT_DIR}/ffuf" -name "*.json" -type f -print0 | xargs -0 -I{} "$JQ_CMD" -e '.results | length > 0' {} 2>/dev/null | wc -l)
else FFUF_FILES_COUNT=$(find "${TARGET_OUTPUT_DIR}/ffuf" -name "*.json" -type f -size +250c 2>/dev/null | wc -l); fi
[ "$FFUF_FILES_COUNT" -gt 0 ] && log_info "  FFUF Scans w/ Results: ${FFUF_FILES_COUNT} JSON files in ${TARGET_OUTPUT_DIR}/ffuf/"
[ -s "$ALL_HISTORICAL_URLS_FILE" ] && log_info "  Historical URLs (waybackurls): $(wc -l < "$ALL_HISTORICAL_URLS_FILE") in ${ALL_HISTORICAL_URLS_FILE}"
[ -s "$LIVE_ENTRY_POINTS_FILE" ] && log_info "  Live Param Entry Points: $(wc -l < "$LIVE_ENTRY_POINTS_FILE") in ${LIVE_ENTRY_POINTS_FILE}"
GF_RESULTS_COUNT=0
if [ "$GF_INSTALLED" = true ]; then
    GF_FILES_WITH_CONTENT=$(find "${TARGET_OUTPUT_DIR}/entry_points/" -name "gf_*.txt" -type f -size +0c -print0 | xargs -0 -I {} wc -l {} 2>/dev/null | awk '{sum+=$1} END{print sum}')
    GF_RESULTS_COUNT=${GF_FILES_WITH_CONTENT:-0}
    [ "$GF_RESULTS_COUNT" -gt 0 ] && log_info "  GF Pattern Matches: ${GF_RESULTS_COUNT} total lines across gf_*.txt files."
fi
log_info "-----------------------------------------------------------------------------"
if [ -s "$LIVE_ENTRY_POINTS_FILE" ] || { [ "$GF_INSTALLED" = true ] && [ "$GF_RESULTS_COUNT" -gt 0 ]; }; then
    log_success "Potential entry points! Review ${C_PURPLE}${TARGET_OUTPUT_DIR}/entry_points/${C_RESET}"
fi; echo -e "${C_GREEN}Happy Sleuthing!${C_RESET}"
