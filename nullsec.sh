#!/bin/bash
# Exit on unset variables; pipefail catches mid-pipeline failures.
# Note: 'set -e' is intentionally omitted — individual phase failures should
# be non-fatal so remaining phases can still run.
set -uo pipefail

################################################################################
#                                                                              #
#      ███╗   ██╗ ██╗   ██╗ ██╗      ██╗      ███████╗ ███████╗  ██████╗       #
#      ████╗  ██║ ██║   ██║ ██║      ██║      ██╔════╝ ██╔════╝ ██╔════╝       #
#      ██╔██╗ ██║ ██║   ██║ ██║      ██║      ███████╗ █████╗   ██║            #
#      ██║╚██╗██║ ██║   ██║ ██║      ██║      ╚════██║ ██╔══╝   ██║            #
#      ██║ ╚████║ ╚██████╔╝ ███████╗ ███████╗ ███████║ ███████╗ ╚██████╗       #
#      ╚═╝  ╚═══╝  ╚═════╝  ╚══════╝ ╚══════╝ ╚══════╝ ╚══════╝  ╚═════╝       #
#                                                                              #
#            BUG BOUNTY RECONNAISSANCE AUTOMATION FRAMEWORK                    #
#                       Complete 12-Phase Methodology                          #
#                                                                              #
#                          Written by: NULLSEC                                 #
#                    Bug Bounty Researcher & Security Practitioner             #
#                                                                              #
################################################################################

#==============================================================================#
#                           CONFIGURATION SECTION                              #
#==============================================================================#

TARGET=""
OUTPUT_DIR=""

# Wordlist paths (modify to match your system)
WORDLIST_DIR="/usr/share/wordlists"
SECLISTS="$WORDLIST_DIR/SecLists"
RESOLVERS="$WORDLIST_DIR/resolvers.txt"
DNS_WORDLIST="$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt"
PERM_WORDLIST="$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt"
WEB_WORDLIST="$SECLISTS/Discovery/Web-Content/raft-large-directories.txt"

# Thread / concurrency controls
HTTPX_THREADS=30
GAU_THREADS=5
ARJUN_THREADS=10
FFUF_THREADS=20
NUCLEI_RATE_LIMIT=50   # requests/second — lower if target is sensitive
GOWITNESS_THREADS=4

# Limits
MAX_JS_FILES=50         # max JS files to download in phase 8
MAX_ARJUN_HOSTS=5       # max hosts to run Arjun against
MAX_SCREENSHOTS=50      # max screenshots per category in phase 10
MAX_CORS_HOSTS=100      # max hosts to test CORS against
MAX_SCORE_HOSTS=200     # max hosts to score in asset scoring phase

# Cloud Storage Enumeration (Phase 2.5)
MAX_BUCKET_MUTATIONS=200    # max generated bucket name variants to test
CLOUD_ENUM_THREADS=20       # parallel curl checks
AWS_REGIONS=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")

# ── Phase 9 / 11 rate-control and wall-clock timeout settings ──────────────────
# Set by apply_scan_mode(); override manually after that call if needed.
#
# DALFOX_DELAY        ms between dalfox payloads (--delay). Floor: 50 ms on live
#                     targets — below that you risk WAF bans and program warnings.
# DALFOX_TIMEOUT      wall-clock seconds before `timeout` kills dalfox.  Prevents
#                     the 3-hour hang seen when feeding hundreds of XSS candidates
#                     at 300 ms each with no ceiling.
# XSS_CANDIDATE_CAP   URLs fed to dalfox (head -N).  Second line of defence after
#                     DALFOX_TIMEOUT; ensures even without timeout the set is bounded.
# SQLI_CANDIDATE_CAP  URLs fed to sqlmap per Phase 9 run.
# SQLMAP_TIMEOUT      wall-clock seconds before `timeout` kills sqlmap.
# FFUF_TIMEOUT        wall-clock seconds per ffuf host invocation in Phase 11.
# PHASE9_WALL_TIMEOUT hard ceiling (seconds) on the whole Phase 9 function;
#                     applied in main() around the background subshell.
# PHASE11_WALL_TIMEOUT hard ceiling (seconds) on the whole Phase 11 function.
DALFOX_DELAY=100
DALFOX_TIMEOUT=1800
XSS_CANDIDATE_CAP=500
SQLI_CANDIDATE_CAP=10
SQLMAP_TIMEOUT=1800
FFUF_TIMEOUT=300
PHASE9_WALL_TIMEOUT=3600
PHASE11_WALL_TIMEOUT=3600

# Nuclei templates path
NUCLEI_TEMPLATES="$HOME/nuclei-templates"

# Scan mode — set by --mode flag (fast | normal | deep)
# Can also be overridden by individual flags after apply_scan_mode() is called.
SCAN_MODE="normal"

# Flags
SKIP_TOOL_CHECK=false
UPDATE_NUCLEI=false     # use -u flag to enable nuclei template updates
RATE_LIMIT=false        # use -r flag to enable rate limiting between phases

# ── Telegram Notifications ─────────────────────────────────────────────────────
# Fill in your bot token and personal chat ID to receive real-time alerts.
# Leave both empty (default) to run silently with no notifications.
# Setup: message @BotFather → /newbot → copy token below.
#        Then message your bot once and run:
#          curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[0].message.chat.id'
#        to retrieve your chat ID.
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""

#==============================================================================#
#                         MODE-CONTROLLED SETTINGS                             #
# These are set automatically by apply_scan_mode() based on --mode.            #
# You can override any of them manually after that call if needed.             #
#==============================================================================#

# Phase enable/disable flags (all true by default; fast mode disables several)
RUN_DNS_BRUTEFORCE=true       # Phase 1: PureDNS wordlist bruteforce
RUN_PERMUTATIONS=true         # Phase 1: Gotator permutation generation
RUN_CLOUD_ENUM=true           # Phase 2.5: Cloud storage bucket enumeration
RUN_PORT_SCAN=true            # Phase 4: Naabu port scan
RUN_PARAM_DISCOVERY=true      # Phase 6: Arjun active parameter discovery
RUN_ASSET_SCORING=true         # Phase 6b: Score & rank assets by attack potential
RUN_JS_ANALYSIS=true          # Phase 8: JS download + TruffleHog + regex
RUN_PATTERN_HUNTING=true      # Phase 9: SSRF/XSS/SQLi/LFI/IDOR/CORS/HHI
RUN_SCREENSHOTS=true          # Phase 10: Gowitness screenshots
RUN_VHOST_DISCOVERY=true      # Phase 3: ffuf virtual-host Host-header fuzzing
RUN_FUZZING=true              # Phase 11: ffuf directory brute-force
RUN_ACTIVE_VULNS=true         # Phase 12: active vuln confirmation

# Nuclei severity filter (comma-separated; passed to nuclei -severity)
NUCLEI_SEVERITY="critical,high,medium"

# Katana crawl depth
KATANA_DEPTH=3

# Amass passive timeout in seconds (fast mode uses a shorter cap)
AMASS_TIMEOUT=600

#==============================================================================#
#                            UTILITY FUNCTIONS                                 #
#==============================================================================#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ── Interrupt / terminate cleanup ──────────────────────────────────────────────
# Ensures temp files and orphaned .bak files are removed when the user hits
# Ctrl+C or the process receives SIGTERM (e.g. from a scheduler).
#
# _PARALLEL_PIDS is populated by main() just before launching background phases.
# The trap sends SIGTERM to each child and waits for them to exit BEFORE merging
# .bak files — this prevents merge_phase_backup from racing a still-writing child.
_PARALLEL_PIDS=()

_nullsec_cleanup() {
    echo ""
    warn "Scan interrupted — cleaning up temp files and restoring backups..."

    # Terminate and drain any background parallel-phase children (BUG-4).
    # Send SIGTERM first (polite); then poll until exit or 5 s deadline.
    if [ ${#_PARALLEL_PIDS[@]} -gt 0 ]; then
        for _cpid in "${_PARALLEL_PIDS[@]}"; do
            kill -TERM "$_cpid" 2>/dev/null || true
        done
        local _deadline=$(( $(date +%s) + 5 ))
        for _cpid in "${_PARALLEL_PIDS[@]}"; do
            local _elapsed=0
            local _remaining=$(( _deadline - $(date +%s) ))
            [ "$_remaining" -lt 1 ] && _remaining=1
            while kill -0 "$_cpid" 2>/dev/null && [ "$_elapsed" -lt "$_remaining" ]; do
                sleep 0.2
                _elapsed=$(( _elapsed + 1 ))
            done
            wait "$_cpid" 2>/dev/null || true
        done
    fi

    # Remove known temp files that phases create mid-run
    rm -f "${OUTPUT_DIR}/phase7-vulns/.combined-targets.txt" 2>/dev/null

    # Remove Phase 2.5 temp files (BUG-5 — only cleaned on happy path normally)
    rm -f "${OUTPUT_DIR}/phase2.5-cloud/.tokens.txt" \
          "${OUTPUT_DIR}/phase2.5-cloud/.candidates.txt" 2>/dev/null

    # Remove asset-scoring temp dir
    rm -rf "${OUTPUT_DIR}/asset-scoring/.tmp" \
           "${OUTPUT_DIR}/asset-scoring/.host-universe.txt" 2>/dev/null

    # Merge any in-flight .bak files so prior-run findings are not lost.
    # Children have already exited above, so this is now race-free.
    for phase_dir in \
        "${OUTPUT_DIR}/phase7-vulns" \
        "${OUTPUT_DIR}/phase8-javascript" \
        "${OUTPUT_DIR}/phase9-patterns" \
        "${OUTPUT_DIR}/phase11-fuzzing" \
        "${OUTPUT_DIR}/phase12-active-vulns"; do
        merge_phase_backup "$phase_dir" 2>/dev/null || true
    done

    warn "Cleanup complete. Re-run with -c '$OUTPUT_DIR' to resume from the last checkpoint."
    exit 130   # 128 + SIGINT signal number
}
trap _nullsec_cleanup SIGINT SIGTERM

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║      ███╗   ██╗ ██╗   ██╗ ██╗      ██╗      ███████╗ ███████╗  ██████╗       ║"
    echo "║      ████╗  ██║ ██║   ██║ ██║      ██║      ██╔════╝ ██╔════╝ ██╔════╝       ║"
    echo "║      ██╔██╗ ██║ ██║   ██║ ██║      ██║      ███████╗ █████╗   ██║            ║"
    echo "║      ██║╚██╗██║ ██║   ██║ ██║      ██║      ╚════██║ ██╔══╝   ██║            ║"
    echo "║      ██║ ╚████║ ╚██████╔╝ ███████╗ ███████╗ ███████║ ███████╗ ╚██████╗       ║"
    echo "║      ╚═╝  ╚═══╝  ╚═════╝  ╚══════╝ ╚══════╝ ╚══════╝ ╚══════╝  ╚═════╝       ║"
    echo "║                                                                              ║"
    echo "║            BUG BOUNTY RECONNAISSANCE AUTOMATION FRAMEWORK                    ║"
    echo "║                      Complete 12-Phase Methodology                           ║"
    echo "║                                                                              ║"
    echo "║                          Author: NULLSEC                                     ║"
    echo "║                    Bug Bounty Hunter & Security Researcher                   ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

print_phase() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} ${YELLOW}$1${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

info()    { echo -e "${BLUE}[$(date +%H:%M)][INFO]${NC} $1"; }
success() { echo -e "${GREEN}[$(date +%H:%M)][SUCCESS]${NC} $1"; }
warn()    { echo -e "${YELLOW}[$(date +%H:%M)][WARNING]${NC} $1"; }
error()   { echo -e "${RED}[$(date +%H:%M)][ERROR]${NC} $1"; }

check_command() {
    command -v "$1" &>/dev/null
}

# Safe line count — handles missing or empty files gracefully
count_lines() {
    local file="$1"
    if [ -f "$file" ]; then
        wc -l < "$file"
    else
        echo "0"
    fi
}

# Optional sleep between phases when -r flag is used
polite_sleep() {
    if [ "$RATE_LIMIT" = true ]; then
        info "Rate-limit mode: sleeping 10s before next phase..."
        sleep 10
    fi
}

# ── Telegram notification helper ───────────────────────────────────────────────
# Sends a message to your Telegram bot.  Silently no-ops if TELEGRAM_TOKEN or
# TELEGRAM_CHAT_ID are empty, so it is always safe to call.
#
# Usage: notify "<severity_label>" "<message body>"
# Examples:
#   notify "🔥 CRITICAL" "3 writable S3 buckets found"
#   notify "✅ Done" "All 12 phases finished in 42m 17s"
#
# Messages are sent in Markdown format.  Asterisks and backticks are safe to
# use in the severity label and message body.
notify() {
    [ -z "${TELEGRAM_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ] && return 0
    local label="$1"
    local body="$2"
    local text
    text=$(printf '*[NullSec]* %s\n`Target:` %s\n`Time:  ` %s\n\n%s' \
        "$label" "$TARGET" "$(date '+%Y-%m-%d %H:%M')" "$body")
    curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${text}" \
        --data-urlencode "parse_mode=Markdown" \
        -o /dev/null || true
}

CHECKPOINT_FILE=""
RESUME_FROM=0

save_checkpoint() {
    local phase_num="$1"
    if [ -n "$CHECKPOINT_FILE" ]; then
        echo "$phase_num" > "$CHECKPOINT_FILE"
    fi
}

phase_done() {
    local phase_num="$1"
    local resume_int="${RESUME_FROM%.*}"  # drop any fractional part ("2.5" → "2")
    if [ "${resume_int:-0}" -ge "$phase_num" ]; then
        info "Phase $phase_num already completed — skipping (checkpoint)."
        return 0  # true = skip
    fi
    return 1  # false = run
}

backup_phase_outputs() {
    local phase_dir="$1"
    if [ ! -d "$phase_dir" ]; then return; fi
    local backed_up=0
    for f in "$phase_dir"/*.txt; do
        [ -s "$f" ] || continue   # skip empty files
        cp "$f" "${f}.bak"
        backed_up=$(( backed_up + 1 ))
    done
    [ "$backed_up" -gt 0 ] && info "  Backed up $backed_up existing output files in $(basename "$phase_dir")"
}

merge_phase_backup() {
    local phase_dir="$1"
    if [ ! -d "$phase_dir" ]; then return; fi
    for bak in "$phase_dir"/*.txt.bak; do
        [ -f "$bak" ] || continue
        local fresh="${bak%.bak}"
        if [ -s "$fresh" ]; then
            # Both backup and fresh exist — merge and deduplicate
            sort -u "$bak" "$fresh" > "${fresh}.merged"
            mv "${fresh}.merged" "$fresh"
        else
            # Fresh run produced nothing — restore backup so findings aren't lost
            cp "$bak" "$fresh"
        fi
        rm -f "$bak"
    done
}

#==============================================================================#
#                           SCAN MODE PRESETS                                  #
#==============================================================================#

apply_scan_mode() {
    case "$SCAN_MODE" in

        # ── FAST ─────────────────────────────────────────────────────────────
        # Passive subdomain sources only, critical-only Nuclei, no heavy active
        # steps. Good for hourly scheduled runs. Typical runtime: 5–15 min.
        fast)
            info "Scan mode: FAST — passive sources, critical vulns, no bruteforce/fuzzing"

            # Phase 1 — passive only; skip bruteforce and permutations
            RUN_DNS_BRUTEFORCE=false
            RUN_PERMUTATIONS=false

            # Phase 2.5 — skip cloud enum (passive only in fast mode)
            RUN_CLOUD_ENUM=false

            # Phase 4 — skip port scan
            RUN_PORT_SCAN=false

            # Phase 6 — skip active parameter discovery (Arjun is slow)
            RUN_PARAM_DISCOVERY=false

            # Phase 8 — skip JS download and secret extraction
            RUN_JS_ANALYSIS=false

            # Asset scoring — skip (not enough data in fast mode)
            RUN_ASSET_SCORING=false

            # Phase 9 — skip pattern hunting (no URLs from crawl anyway)
            RUN_PATTERN_HUNTING=false

            # Phase 10 — skip screenshots
            RUN_SCREENSHOTS=false

            # Phase 11 — skip directory fuzzing
            RUN_FUZZING=false

            # Phase 3 vhost discovery — skip (requires ffuf; fast mode avoids active steps)
            RUN_VHOST_DISCOVERY=false

            # Phase 12 — skip active confirmation
            RUN_ACTIVE_VULNS=false

            # Nuclei — critical severity only
            NUCLEI_SEVERITY="critical"

            # Katana — shallower crawl
            KATANA_DEPTH=1

            # Amass — short timeout so it doesn't block everything
            AMASS_TIMEOUT=120

            # Concurrency — lower threads since we're running more often
            HTTPX_THREADS=15
            NUCLEI_RATE_LIMIT=30

            # Phase 9 / 11 timing — fast mode skips both phases entirely, but
            # set conservative floors in case flags are overridden manually.
            # DALFOX_DELAY floor is 50 ms; never set lower on live targets.
            DALFOX_DELAY=50
            DALFOX_TIMEOUT=600          # 10 min hard cap
            XSS_CANDIDATE_CAP=100
            SQLI_CANDIDATE_CAP=5
            SQLMAP_TIMEOUT=300          # 5 min
            FFUF_TIMEOUT=120            # 2 min per host
            PHASE9_WALL_TIMEOUT=900     # 15 min absolute ceiling
            PHASE11_WALL_TIMEOUT=900
            ;;

        # ── NORMAL ───────────────────────────────────────────────────────────
        # Adds DNS bruteforce, full crawling, JS analysis, and pattern hunting.
        # Skips the most expensive active steps. Good for daily runs.
        # Typical runtime: 30–60 min.
        normal)
            info "Scan mode: NORMAL — full discovery + JS analysis, no fuzzing/active confirm"

            RUN_DNS_BRUTEFORCE=true
            RUN_PERMUTATIONS=false      # permutations are expensive; deep only
            RUN_CLOUD_ENUM=true         # cloud enum runs in normal + deep
            RUN_PORT_SCAN=true
            RUN_PARAM_DISCOVERY=false   # Arjun is slow; skip for daily cadence
            RUN_ASSET_SCORING=true      # Score & rank targets for focused effort
            RUN_JS_ANALYSIS=true
            RUN_PATTERN_HUNTING=true
            RUN_SCREENSHOTS=true
            RUN_VHOST_DISCOVERY=true    # vhost discovery enabled in normal + deep
            RUN_FUZZING=false           # ffuf recursive fuzzing; deep only
            RUN_ACTIVE_VULNS=false      # active confirmation; deep only

            NUCLEI_SEVERITY="critical,high,medium"
            KATANA_DEPTH=2
            AMASS_TIMEOUT=300

            HTTPX_THREADS=30
            NUCLEI_RATE_LIMIT=50

            # Phase 9 / 11 timing — normal mode runs both phases.
            # 100 ms delay ≈ 10 req/s ceiling, well within programme tolerances.
            DALFOX_DELAY=100
            DALFOX_TIMEOUT=1800         # 30 min — enough for 500 URLs at 100 ms each
            XSS_CANDIDATE_CAP=500
            SQLI_CANDIDATE_CAP=10
            SQLMAP_TIMEOUT=1800         # 30 min
            FFUF_TIMEOUT=300            # 5 min per host
            PHASE9_WALL_TIMEOUT=3600    # 60 min absolute ceiling
            PHASE11_WALL_TIMEOUT=3600
            ;;

        # ── DEEP ─────────────────────────────────────────────────────────────
        # Full 12-phase pipeline — everything enabled, no caps reduced.
        # Good for weekly runs or first-time target onboarding.
        # Typical runtime: 1–4+ hours depending on target size.
        deep)
            info "Scan mode: DEEP — full 12-phase pipeline, all phases enabled"

            RUN_DNS_BRUTEFORCE=true
            RUN_PERMUTATIONS=true
            RUN_CLOUD_ENUM=true
            RUN_PORT_SCAN=true
            RUN_PARAM_DISCOVERY=true
            RUN_ASSET_SCORING=true
            RUN_JS_ANALYSIS=true
            RUN_PATTERN_HUNTING=true
            RUN_SCREENSHOTS=true
            RUN_VHOST_DISCOVERY=true
            RUN_FUZZING=true
            RUN_ACTIVE_VULNS=true

            NUCLEI_SEVERITY="critical,high,medium,low"
            KATANA_DEPTH=3
            AMASS_TIMEOUT=600

            HTTPX_THREADS=30
            NUCLEI_RATE_LIMIT=50
            MAX_JS_FILES=100
            MAX_ARJUN_HOSTS=5
            MAX_SCREENSHOTS=100
            MAX_CORS_HOSTS=200
            MAX_BUCKET_MUTATIONS=500    # deeper bucket name generation in deep mode

            # Phase 9 / 11 timing — deep mode is thorough; slower delay, larger
            # candidate caps, longer timeouts.  Runtime can reach 4+ hours total;
            # that is expected and documented in the mode description.
            # 200 ms delay ≈ 5 req/s ceiling — polite for a full deep scan.
            DALFOX_DELAY=200
            DALFOX_TIMEOUT=3600         # 60 min — allows up to ~1000 URLs at 200 ms
            XSS_CANDIDATE_CAP=1000
            SQLI_CANDIDATE_CAP=20
            SQLMAP_TIMEOUT=3600         # 60 min
            FFUF_TIMEOUT=600            # 10 min per host
            PHASE9_WALL_TIMEOUT=7200    # 120 min absolute ceiling
            PHASE11_WALL_TIMEOUT=7200
            ;;

        *)
            error "Unknown scan mode: '$SCAN_MODE'. Valid options: fast | normal | deep"
            exit 1
            ;;
    esac
}

#==============================================================================#
#                            TOOL CHECKING                                     #
#==============================================================================#

check_tools() {
    print_phase "🔧 CHECKING REQUIRED TOOLS"

    # Core required tools — script will exit if any are missing
    local required_tools=("subfinder" "amass" "assetfinder" "puredns" "dnsx"
        "httpx-toolkit" "naabu" "katana" "waybackurls" "gau" "unfurl"
        "arjun" "nuclei" "ffuf" "jq" "curl" "trufflehog")

    # Optional tools — script skips relevant steps if missing
    local optional_tools=("gotator" "gowitness" "dalfox" "sqlmap" "gf"
        "anew" "qsreplace" "hakrawler" "cariddi" "dig"
        "cloud_enum" "s3scanner")

    local missing_required=()

    echo -e "${CYAN}--- Required Tools ---${NC}"
    for tool in "${required_tools[@]}"; do
        if check_command "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            missing_required+=("$tool")
        fi
    done

    echo ""
    echo -e "${CYAN}--- Optional Tools (enhance results) ---${NC}"
    for tool in "${optional_tools[@]}"; do
        if check_command "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}○${NC} $tool (not installed — some steps will be skipped)"
        fi
    done

    if [ ${#missing_required[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_required[*]}"
        error "Please install them before running. Exiting."
        exit 1
    fi

    echo ""
    success "All required tools available!"
}

#==============================================================================#
#                         DIRECTORY STRUCTURE                                  #
#==============================================================================#

create_structure() {
    print_phase "📁 CREATING DIRECTORY STRUCTURE"

    # Ensure parent directory exists before resolving absolute path
    # (fixes original bug where cd would fail if parent didn't exist)
    local parent_dir
    parent_dir="$(dirname "$OUTPUT_DIR")"
    mkdir -p "$parent_dir"
    OUTPUT_DIR="$(cd "$parent_dir" && pwd)/$(basename "$OUTPUT_DIR")"

    mkdir -p "$OUTPUT_DIR"/{phase1-subdomains,phase2-validation,phase2.5-cloud,phase3-probing,\
phase4-portscan,phase5-urls,phase6-parameters,asset-scoring,phase7-vulns,phase8-javascript,\
phase9-patterns,phase10-screenshots,phase11-fuzzing,phase12-active-vulns,reports}

    mkdir -p "$OUTPUT_DIR/phase10-screenshots"/{403,admin,interesting,all}
    mkdir -p "$OUTPUT_DIR/phase8-javascript/js-files"
    mkdir -p "$OUTPUT_DIR/phase11-fuzzing"/{dirs,vhosts}
    mkdir -p "$OUTPUT_DIR/phase2.5-cloud"/{s3,gcs,azure,exposed}

    success "Directory structure created: $OUTPUT_DIR"
}

#==============================================================================#
#                                USAGE                                         #
#==============================================================================#

usage() {
    echo "Usage: $0 -d <target-domain> [options]"
    echo ""
    echo "Options:"
    echo "  -d <domain>       Target domain (required)"
    echo "  -o <dir>          Output directory (default: ./recon-<domain>-<timestamp>)"
    echo "  -m <mode>         Scan mode: fast | normal | deep  (default: normal)"
    echo "  -s                Skip tool checking"
    echo "  -u                Update Nuclei templates before scanning"
    echo "  -r                Enable rate limiting / polite delays between phases"
    echo "  -c <dir>          Resume scan from checkpoint in existing output directory"
    echo "  -h                Show this help message"
    echo ""
    echo "Scan Modes:"
    echo "  fast    Passive subdomain sources only, critical Nuclei, no bruteforce/fuzzing"
    echo "          Skips: DNS bruteforce, port scan, JS analysis, fuzzing, active confirm"
    echo "          Runtime: ~5-15 min  |  Good for: hourly scheduled runs"
    echo ""
    echo "  normal  Full discovery + JS analysis + pattern hunting, no heavy active steps"
    echo "          Skips: permutations, Arjun, directory fuzzing, active confirmation"
    echo "          Runtime: ~30-60 min  |  Good for: daily scheduled runs"
    echo ""
    echo "  deep    Full 12-phase pipeline — everything enabled, all caps raised"
    echo "          Runtime: 1-4+ hours  |  Good for: weekly runs, new target onboarding"
    echo ""
    echo "Examples:"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -m fast"
    echo "  $0 -d example.com -m deep -u -r"
    echo "  $0 -d example.com -m normal -o /path/to/output"
    exit 1
}

#==============================================================================#
#                              PHASE FUNCTIONS                                 #
#==============================================================================#

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: Subdomain Discovery
# ─────────────────────────────────────────────────────────────────────────────
phase1_subdomain_discovery() {
    phase_done 1 && { polite_sleep; return; }
    print_phase "🔍 PHASE 1: SUBDOMAIN DISCOVERY"

    local p1dir="$OUTPUT_DIR/phase1-subdomains"

    # 1.1 Subfinder — passive multi-source enumeration
    info "Running Subfinder (passive)..."
    subfinder -d "$TARGET" -all -silent -o "$p1dir/subfinder.txt" 2>/dev/null
    success "Subfinder: $(count_lines "$p1dir/subfinder.txt") subdomains"

    # 1.2 Amass — passive enumeration (v3 linear mode with source tracking)
    info "Running Amass (passive)..."

    # Fast, passive gathering. The timeout safely preserves everything found.
    timeout "$AMASS_TIMEOUT" amass enum -passive -src -d "$TARGET" -o "$p1dir/amass.txt" 2>/dev/null

    success "Amass: $(count_lines "$p1dir/amass.txt") subdomains"

    # 1.3 Assetfinder — related asset discovery
    info "Running Assetfinder..."
    assetfinder --subs-only "$TARGET" > "$p1dir/assetfinder.txt" 2>/dev/null
    success "Assetfinder: $(count_lines "$p1dir/assetfinder.txt") subdomains"

    # 1.4 Certificate Transparency — crt.sh
    info "Querying crt.sh (Certificate Transparency)..."
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "$p1dir/crtsh.txt"
    success "crt.sh: $(count_lines "$p1dir/crtsh.txt") subdomains"

    # 1.5 Merge all passive sources
    # NOTE: Explicit file list prevents the all-subdomains.txt self-inclusion bug
    info "Merging passive enumeration results..."
    cat "$p1dir/subfinder.txt" \
        "$p1dir/amass.txt" \
        "$p1dir/assetfinder.txt" \
        "$p1dir/crtsh.txt" \
        2>/dev/null | sort -u > "$p1dir/all-subdomains-passive.txt"
    success "Unique passive subdomains: $(count_lines "$p1dir/all-subdomains-passive.txt")"

    # 1.6 Hakrawler — finds subdomains referenced in HTTP responses
    if check_command "hakrawler"; then
        info "Running Hakrawler for response-based subdomain discovery..."
        local target_escaped
        target_escaped=$(printf '%s' "$TARGET" | sed 's/\./\\./g')
        sed 's|^|https://|' "$p1dir/all-subdomains-passive.txt" \
            | httpx-toolkit -silent 2>/dev/null \
            | hakrawler -subs -depth 2 -timeout 10 2>/dev/null \
            | grep -oE "[a-zA-Z0-9._-]+\.$target_escaped" \
            | sort -u > "$p1dir/hakrawler.txt"
        success "Hakrawler: $(count_lines "$p1dir/hakrawler.txt") subdomains"
    else
        touch "$p1dir/hakrawler.txt"
    fi

    # 1.7 DNS Bruteforce with Puredns
    if [ "$RUN_DNS_BRUTEFORCE" = true ]; then
        if [ -f "$DNS_WORDLIST" ] && [ -f "$RESOLVERS" ]; then
            info "Running Puredns bruteforce..."
            puredns bruteforce "$DNS_WORDLIST" "$TARGET" \
                -r "$RESOLVERS" \
                --rate-limit 200 \
                -w "$p1dir/puredns.txt" 2>/dev/null
            success "Puredns bruteforce: $(count_lines "$p1dir/puredns.txt") subdomains"
        else
            warn "Wordlist or resolvers file not found — skipping DNS bruteforce."
            touch "$p1dir/puredns.txt"
        fi
    else
        info "DNS bruteforce skipped (mode: $SCAN_MODE)."
        touch "$p1dir/puredns.txt"
    fi

    # 1.8 Merge passive + bruteforce
    cat "$p1dir/all-subdomains-passive.txt" "$p1dir/puredns.txt" 2>/dev/null \
        | sort -u > "$p1dir/all-subdomains.txt"

    # 1.9 Permutation generation with Gotator
    if [ "$RUN_PERMUTATIONS" = true ] && check_command "gotator" && [ -f "$PERM_WORDLIST" ] && [ -f "$RESOLVERS" ]; then
        info "Generating subdomain permutations with Gotator..."
        gotator -sub "$p1dir/all-subdomains.txt" \
            -perm "$PERM_WORDLIST" \
            -depth 1 \
            -silent > "$p1dir/permutations-raw.txt" 2>/dev/null

        info "Resolving permutations with Puredns..."
        puredns resolve "$p1dir/permutations-raw.txt" \
            -r "$RESOLVERS" \
            -w "$p1dir/permutations-resolved.txt" 2>/dev/null

        # Use anew for efficient deduplication if available, otherwise sort -u
        if check_command "anew"; then
            cat "$p1dir/permutations-resolved.txt" \
                | anew "$p1dir/all-subdomains.txt"
        else
            cat "$p1dir/all-subdomains.txt" "$p1dir/permutations-resolved.txt" \
                | sort -u > "$p1dir/all-subdomains-tmp.txt"
            mv "$p1dir/all-subdomains-tmp.txt" "$p1dir/all-subdomains.txt"
        fi
        success "Permutations added: $(count_lines "$p1dir/permutations-resolved.txt") new subdomains"
    elif [ "$RUN_PERMUTATIONS" = false ]; then
        info "Permutation generation skipped (mode: $SCAN_MODE)."
    else
        warn "Gotator/wordlist/resolvers not available — skipping permutations."
    fi

    local p1_total
    p1_total=$(count_lines "$p1dir/all-subdomains.txt")
    success "Phase 1 complete! Total subdomains: $p1_total"
    notify "🌐 Phase 1 Complete" \
        "Subdomain discovery finished.\nFound *${p1_total}* subdomains for \`${TARGET}\`."
    save_checkpoint 1
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: Validation & Resolution
# ─────────────────────────────────────────────────────────────────────────────
phase2_validation() {
    phase_done 2 && { polite_sleep; return; }
    print_phase "✅ PHASE 2: VALIDATION & RESOLUTION"

    local p1dir="$OUTPUT_DIR/phase1-subdomains"
    local p2dir="$OUTPUT_DIR/phase2-validation"

    if [ ! -s "$p1dir/all-subdomains.txt" ]; then
        error "No subdomains found in Phase 1. Skipping Phase 2."
        return
    fi

    # 2.1 Resolve with dnsx — collect A records and detect wildcards
    info "Resolving subdomains with dnsx..."
    touch "$p2dir/wildcards.txt"

    local resolvers_file="$p2dir/resolvers.txt"
    printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n' > "$resolvers_file"

    dnsx -l "$p1dir/all-subdomains.txt" \
        -r "$resolvers_file" \
        -o "$p2dir/resolved.txt" \
        -wd "$p2dir/wildcards.txt" \
        -a -resp -silent -rl 100 2>/dev/null

    # 2.2 Extract clean subdomain list
    awk '{print $1}' "$p2dir/resolved.txt" | sort -u > "$p2dir/valid-subdomains.txt"

    local total_enum valid wildcards
    total_enum=$(count_lines "$p1dir/all-subdomains.txt")
    valid=$(count_lines "$p2dir/valid-subdomains.txt")
    wildcards=$(count_lines "$p2dir/wildcards.txt")

    info "Total enumerated  : $total_enum"
    info "Actually resolved : $valid"
    info "Wildcards filtered: $wildcards"

    # 2.3 Subdomain takeover scanning
    if [ -s "$p2dir/valid-subdomains.txt" ]; then
        info "Scanning for subdomain takeover vulnerabilities..."
        nuclei -l "$p2dir/valid-subdomains.txt" \
            -t "$NUCLEI_TEMPLATES/http/takeovers/" \
            -o "$p2dir/takeover-findings.txt" \
            -silent 2>/dev/null

        if [ -s "$p2dir/takeover-findings.txt" ]; then
            success "🚨 Potential takeover vulnerabilities found! → $p2dir/takeover-findings.txt"
        else
            info "No takeover vulnerabilities detected."
        fi
    fi

    success "Phase 2 complete! Valid subdomains: $valid"
    save_checkpoint 2
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2.5: Cloud Storage Enumeration
# Tests AWS S3, Google Cloud Storage, and Azure Blob Storage for:
#   - Publicly readable buckets (information disclosure)
#   - Publicly writable buckets (critical — arbitrary file upload)
#   - Bucket existence (even non-public buckets confirm infrastructure)
#
# Name generation strategy:
#   Takes the base target (e.g. "acme.com" → "acme") and all discovered
#   subdomains, then generates permutations with common cloud naming patterns
#   (acme-backup, acme-dev, acme-assets, acme-prod, etc.)
#
# Output feeds into:
#   - Phase 5: exposed bucket URLs added to all-urls.txt
#   - Phase 7: exposed buckets added to Nuclei target list
#   - Report:  dedicated cloud findings section
# ─────────────────────────────────────────────────────────────────────────────
phase2_5_cloud_enum() {
    # Phase 2.5 sits between integer checkpoints 2 and 3 — it cannot be
    # expressed as an integer, so it has no checkpoint guard.  If the scan is
    # interrupted mid-phase-2.5 it will re-run on resume (safe; idempotent).
    print_phase "☁️  PHASE 2.5: CLOUD STORAGE ENUMERATION"

    if [ "$RUN_CLOUD_ENUM" = false ]; then
        info "Cloud storage enumeration skipped (mode: $SCAN_MODE)."
        return
    fi

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local cdir="$OUTPUT_DIR/phase2.5-cloud"

    # ── 2.5.1 Generate bucket name candidates ────────────────────────────────
    # Strategy: extract meaningful tokens from target domain and subdomains,
    # combine with high-signal cloud naming suffixes seen in the wild.
    info "Generating bucket name candidates..."

    # Extract base company name — second-level domain only, regardless of subdomain depth.
    # e.g. api.staging.example.com → example; example.com → example
    #      example.co.uk → example; example.com.au → example
    #
    #   example.com        → example   (strip 1 TLD label)
    #   example.co.uk      → example   (strip 2-label ccTLD)
    #   api.example.com    → example   (strip subdomain + TLD)
    #   sub.example.co.uk  → example   (strip subdomain + 2-label ccTLD)
    local base_name
    base_name=$(echo "$TARGET" \
        | sed -E 's/^(.*\.)?([a-z0-9-]+)\.(com|net|org|edu|gov|mil|int)\.[a-z]{2}$/\2/; t done
                  s/^(.*\.)?([a-z0-9-]+)\.[a-z0-9-]{2,}\.[a-z]{2}$/\2/; t done
                  s/^(.*\.)?([a-z0-9-]+)\.[a-z]{2,}$/\2/
                  :done')

    # Build token list from subdomains (strip common low-signal prefixes)
    local token_file="$cdir/.tokens.txt"
    {
        echo "$base_name"
        # Extract unique subdomain labels, skip www/mail/ns/ftp noise
        if [ -s "$p2dir/valid-subdomains.txt" ]; then
            sed -E "s/\.$TARGET$//" "$p2dir/valid-subdomains.txt" \
                | tr '.' '\n' \
                | grep -vE '^(www|mail|ns[0-9]*|ftp|smtp|pop|imap|vpn|cdn)$' \
                | sort -u
        fi
    } | sort -u > "$token_file"

    # Cloud naming patterns — covers what developers actually name buckets
    local suffixes=("" "-backup" "-backups" "-bak" "-prod" "-production"
        "-dev" "-development" "-staging" "-stage" "-test" "-testing"
        "-qa" "-uat" "-assets" "-static" "-media" "-uploads" "-files"
        "-data" "-logs" "-archive" "-public" "-private" "-internal"
        "-config" "-configs" "-deploy" "-releases" "-builds" "-ci"
        "-images" "-img" "-videos" "-docs" "-documents" "-reports"
        "-api" "-app" "-web" "-mobile" "-android" "-ios" "-frontend"
        "-backend" "-infra" "-infrastructure" "-security" "-audit"
        "backup" "backups" "prod" "dev" "staging" "assets" "static"
        "media" "uploads" "logs" "data" "files" "images" "cdn")

    # Generate all token × suffix combinations, cap at MAX_BUCKET_MUTATIONS
    local candidates_file="$cdir/.candidates.txt"
    {
        while IFS= read -r token; do
            for suffix in "${suffixes[@]}"; do
                echo "${token}${suffix}"
                echo "${token//-/.}${suffix}"   # dots variant (acme.dev)
            done
        done < "$token_file"
    } | tr '[:upper:]' '[:lower:]' \
      | grep -E '^[a-z0-9][a-z0-9\.\-]{2,61}[a-z0-9]$' \
      | sort -u \
      | head -n "$MAX_BUCKET_MUTATIONS" > "$candidates_file"

    local candidate_count
    candidate_count=$(count_lines "$candidates_file")
    success "Generated $candidate_count bucket name candidates"

    # ── 2.5.2 AWS S3 Enumeration ─────────────────────────────────────────────
    info "Testing AWS S3 buckets..."

    local s3_exists="$cdir/s3/exists.txt"
    local s3_readable="$cdir/s3/readable.txt"
    local s3_writable="$cdir/s3/writable.txt"
    touch "$s3_exists" "$s3_readable" "$s3_writable"

    if check_command "s3scanner"; then
        info "  Using s3scanner for comprehensive S3 checks..."
        s3scanner --buckets-file "$candidates_file" \
            --out-file "$cdir/s3/s3scanner-results.txt" \
            2>/dev/null || true

        grep -i "exists"                          "$cdir/s3/s3scanner-results.txt" 2>/dev/null | awk '{print $1}' >> "$s3_exists"
        grep -i "open\|public\|readable"          "$cdir/s3/s3scanner-results.txt" 2>/dev/null | awk '{print $1}' >> "$s3_readable"
        grep -i "writable\|AllUsers.*WRITE"       "$cdir/s3/s3scanner-results.txt" 2>/dev/null | awk '{print $1}' >> "$s3_writable"
    else
        # Fallback: direct HTTP checks — no extra tools required
        info "  s3scanner not found — using direct HTTP checks..."

        _check_s3_bucket() {
            local name="$1"
            local s3_exists="$2" s3_readable="$3" s3_writable="$4"
            local url="https://${name}.s3.amazonaws.com"
            local response
            response=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$url")

            case "$response" in
                200)
                    echo "$url" >> "$s3_exists"
                    echo "$url" >> "$s3_readable"
                    local acl_resp
                    acl_resp=$(curl -sk --max-time 5 "${url}?acl" 2>/dev/null)
                    if echo "$acl_resp" | grep -q "AllUsers" && echo "$acl_resp" | grep -q "WRITE"; then
                        echo "$url" >> "$s3_writable"
                    fi
                    ;;
                403)
                    # 403 = bucket exists but access denied — still useful intel
                    echo "$url" >> "$s3_exists"
                    ;;
            esac
        }
        export -f _check_s3_bucket

        cat "$candidates_file" | xargs -P "$CLOUD_ENUM_THREADS" -I {} \
            bash -c 'set -uo pipefail; _check_s3_bucket "$@"' _ {} "$s3_exists" "$s3_readable" "$s3_writable" 2>/dev/null || true

        unset -f _check_s3_bucket
    fi

    # Check region-specific endpoints for top candidates
    info "  Checking region-specific S3 endpoints..."
    head -50 "$candidates_file" | while IFS= read -r name; do
        for region in "${AWS_REGIONS[@]}"; do
            regional_url="https://${name}.s3.${region}.amazonaws.com"
            rc=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$regional_url")
            [ "$rc" = "200" ] && {
                echo "$regional_url" >> "$s3_readable"
                warn "  🪣 READABLE regional S3: $regional_url"
            }
        done
    done

    success "S3: exists=$(count_lines "$s3_exists")  readable=$(count_lines "$s3_readable")  writable=$(count_lines "$s3_writable")"

    # ── 2.5.3 Google Cloud Storage Enumeration ───────────────────────────────
    info "Testing Google Cloud Storage buckets..."

    local gcs_exists="$cdir/gcs/exists.txt"
    local gcs_readable="$cdir/gcs/readable.txt"
    local gcs_writable="$cdir/gcs/writable.txt"
    touch "$gcs_exists" "$gcs_readable" "$gcs_writable"

    _check_gcs_bucket() {
        local name="$1"
        local gcs_exists="$2" gcs_readable="$3" gcs_writable="$4"
        local gcs_url="https://storage.googleapis.com/${name}"
        local rc
        rc=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$gcs_url")

        case "$rc" in
            200)
                echo "$gcs_url" >> "$gcs_exists"
                echo "$gcs_url" >> "$gcs_readable"
                # Check IAM for allUsers with a WRITE-capable role.
                #
                #   roles/storage.objectCreator    — create/overwrite objects
                #   roles/storage.objectAdmin      — full object control
                #   roles/storage.legacyBucketWriter — ACL-based write
                #   roles/storage.admin            — full bucket control
                local acl_resp
                acl_resp=$(curl -sk --max-time 5 \
                    "https://www.googleapis.com/storage/v1/b/${name}/iam" 2>/dev/null)
                if echo "$acl_resp" | grep -q "allUsers" && \
                   echo "$acl_resp" | grep -qE '(objectCreator|objectAdmin|legacyBucketWriter|storage\.admin)'; then
                    echo "$gcs_url" >> "$gcs_writable"
                fi
                ;;
            403)
                echo "$gcs_url" >> "$gcs_exists"
                ;;
        esac
    }
    export -f _check_gcs_bucket

    cat "$candidates_file" | xargs -P "$CLOUD_ENUM_THREADS" -I {} \
        bash -c 'set -uo pipefail; _check_gcs_bucket "$@"' _ {} "$gcs_exists" "$gcs_readable" "$gcs_writable" 2>/dev/null || true

    unset -f _check_gcs_bucket

    # Report readable GCS findings after parallel run completes
    if [ -s "$gcs_readable" ]; then
        while IFS= read -r url; do
            warn "  🪣 READABLE GCS bucket: $url"
        done < "$gcs_readable"
    fi
    if [ -s "$gcs_writable" ]; then
        while IFS= read -r url; do
            warn "  🚨 GCS bucket has allUsers ACL: $url"
        done < "$gcs_writable"
    fi

    success "GCS: exists=$(count_lines "$gcs_exists")  readable=$(count_lines "$gcs_readable")  writable=$(count_lines "$gcs_writable")"

    # ── 2.5.4 Azure Blob Storage Enumeration ─────────────────────────────────
    info "Testing Azure Blob Storage..."

    local az_exists="$cdir/azure/exists.txt"
    local az_readable="$cdir/azure/readable.txt"
    touch "$az_exists" "$az_readable"

    _check_azure_bucket() {
        local name="$1"
        local az_exists="$2" az_readable="$3"
        local az_url="https://${name}.blob.core.windows.net"
        local rc
        rc=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$az_url")

        case "$rc" in
            200|400)
                # 400 = account exists but request needs a container name
                echo "$az_url" >> "$az_exists"
                # Try common public container names.
                # NOTE: This inner loop fires up to 7 sequential curl requests per
                # candidate.  The parent xargs pool is capped at AZURE_ENUM_THREADS
                # (half of CLOUD_ENUM_THREADS) to avoid the effective concurrency of
                # 20 × 7 = 140 simultaneous connections, which reliably triggers
                # Azure's DDoS protection and produces unreliable results.
                for container in "public" '$web' "assets" "backup" "data" "uploads" "media"; do
                    local container_url="${az_url}/${container}?restype=container&comp=list"
                    local crc
                    crc=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$container_url")
                    [ "$crc" = "200" ] && echo "$container_url" >> "$az_readable"
                done
                ;;
        esac

        # Check for Azure CDN / static web endpoints
        local cdn_url="https://${name}.azureedge.net"
        local cdn_rc
        cdn_rc=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$cdn_url")
        [ "$cdn_rc" = "200" ] && echo "$cdn_url" >> "$az_readable"
    }
    export -f _check_azure_bucket

    # Cap Azure parallelism at half of CLOUD_ENUM_THREADS — each job fires up to
    # 8 curl requests internally, so effective concurrency is already much higher.
    local azure_threads
    azure_threads=$(( CLOUD_ENUM_THREADS / 2 ))
    [ "$azure_threads" -lt 1 ] && azure_threads=1
    cat "$candidates_file" | xargs -P "$azure_threads" -I {} \
        bash -c 'set -uo pipefail; _check_azure_bucket "$@"' _ {} "$az_exists" "$az_readable" 2>/dev/null || true

    unset -f _check_azure_bucket

    # Report findings after parallel run completes
    if [ -s "$az_readable" ]; then
        while IFS= read -r url; do
            warn "  🪣 READABLE Azure container/CDN: $url"
        done < "$az_readable"
    fi

    success "Azure: exists=$(count_lines "$az_exists")  readable=$(count_lines "$az_readable")"

    # ── 2.5.5 cloud_enum integration (if installed) ───────────────────────────
    if check_command "cloud_enum"; then
        info "Running cloud_enum for comprehensive multi-cloud coverage..."
        cloud_enum \
            -k "$base_name" \
            -k "$(echo "$TARGET" | tr '.' '-')" \
            --disable-azure-websites \
            -t "$CLOUD_ENUM_THREADS" \
            -l "$cdir/cloud_enum-results.txt" \
            2>/dev/null || true

        if [ -s "$cdir/cloud_enum-results.txt" ]; then
            grep -iE "OPEN|public|readable" "$cdir/cloud_enum-results.txt" \
                >> "$cdir/exposed/cloud_enum-open.txt" 2>/dev/null || true
            success "cloud_enum: $(count_lines "$cdir/cloud_enum-results.txt") results"
        fi
    fi

    # ── 2.5.6 Consolidate all exposed buckets ────────────────────────────────
    info "Consolidating exposed bucket findings..."
    local exposed_file="$cdir/exposed/all-exposed-buckets.txt"
    local critical_file="$cdir/exposed/critical-writable.txt"

    cat "$s3_readable" "$gcs_readable" "$az_readable" \
        "$cdir/exposed/cloud_enum-open.txt" \
        2>/dev/null | sort -u > "$exposed_file"

    cat "$s3_writable" "$gcs_writable" \
        2>/dev/null | sort -u > "$critical_file"

    # ── 2.5.7 Feed findings into Phase 5 URL corpus ──────────────────────────
    local cloud_urls_for_p5="$cdir/exposed/cloud-urls-for-phase5.txt"
    if [ -s "$exposed_file" ]; then
        cp "$exposed_file" "$cloud_urls_for_p5"
        info "Staged $(count_lines "$cloud_urls_for_p5") bucket URLs for Phase 5 merge"
    else
        touch "$cloud_urls_for_p5"
    fi

    # ── 2.5.8 Summary ────────────────────────────────────────────────────────
    local total_exposed total_writable
    total_exposed=$(count_lines "$exposed_file")
    total_writable=$(count_lines "$critical_file")

    if [ "$total_writable" -gt 0 ]; then
        error "🚨 CRITICAL: $total_writable WRITABLE bucket(s) found! → $critical_file"
        notify "🚨 CRITICAL — Writable Buckets" \
            "*${total_writable}* publicly WRITABLE cloud bucket(s) found!\nReview immediately: \`${critical_file}\`"
    fi

    if [ "$total_exposed" -gt 0 ]; then
        warn "☁️  $total_exposed publicly readable bucket(s) found → $exposed_file"
        notify "☁️ Cloud Storage Exposed" \
            "*${total_exposed}* publicly readable bucket(s) found.\nSee: \`${exposed_file}\`"
    else
        success "No publicly exposed cloud storage found."
    fi

    # Cleanup temp files
    rm -f "$cdir/.tokens.txt" "$cdir/.candidates.txt"

    success "Phase 2.5 complete!"
    # No save_checkpoint here — phase 2.5 has no integer checkpoint slot.
    # Checkpoint 3 is written by phase3_probing after it completes.
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: Live Web Service Probing
# ─────────────────────────────────────────────────────────────────────────────
phase3_probing() {
    phase_done 3 && { polite_sleep; return; }
    print_phase "🌐 PHASE 3: LIVE WEB SERVICE PROBING"

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local p3dir="$OUTPUT_DIR/phase3-probing"

    if [ ! -s "$p2dir/valid-subdomains.txt" ]; then
        error "No valid subdomains from Phase 2. Skipping Phase 3."
        return
    fi

    # 3.1 Basic HTTP probing (clean URL list for downstream phases)
    info "Probing for live web hosts..."
    httpx-toolkit -l "$p2dir/valid-subdomains.txt" \
        -silent \
        -random-agent \
        -timeout 15 \
        -retries 2 \
        -rl 10 \
        -o "$p3dir/live-hosts.txt" 2>/dev/null
    success "Live web hosts: $(count_lines "$p3dir/live-hosts.txt")"

    # 3.2 Rich metadata collection — titles, tech stack, headers
    info "Collecting detailed metadata..."
    httpx-toolkit -l "$p2dir/valid-subdomains.txt" \
        -title -status-code -tech-detect -content-length -web-server \
        -follow-redirects -random-agent \
        -timeout 15 \
        -retries 2 \
        -threads 10 \
        -rl 10 \
        -o "$p3dir/live-hosts-detailed.txt" 2>/dev/null

    # 3.3 Strip ANSI color codes and categorize by HTTP status
    info "Categorizing hosts by HTTP status code..."
    sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGKHF]//g" \
        "$p3dir/live-hosts-detailed.txt" > "$p3dir/clean-hosts.txt"

    grep -E '\[([0-9]+,)*200\]'            "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-200.txt"
    grep -E '\[([0-9]+,)*403\]'            "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-403.txt"
    grep -E '\[([0-9]+,)*401\]'            "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-401.txt"
    grep -E '\[([0-9]+,)*(301|302|307|308)\]' \
                                           "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-redirects.txt"
    grep -E '\[([0-9]+,)*500\]'            "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-500.txt"

    info "Status breakdown:"
    echo "  200 OK      : $(count_lines "$p3dir/status-200.txt")"
    echo "  403 Forbidden: $(count_lines "$p3dir/status-403.txt")"
    echo "  401 Unauth  : $(count_lines "$p3dir/status-401.txt")"
    echo "  Redirects   : $(count_lines "$p3dir/status-redirects.txt")"
    echo "  500 Errors  : $(count_lines "$p3dir/status-500.txt")"

    # 3.4 Virtual host discovery — finds hidden vhosts via Host header injection
    # Resolves target to IP, then fuzzes Host header against the IP so we find
    # vhosts that DON'T have their own DNS records (the whole point — Phase 1
    # already covers subdomains that resolve via DNS).
    if [ "$RUN_VHOST_DISCOVERY" = true ] && check_command "ffuf" && [ -f "$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt" ]; then
        info "Running virtual host discovery via Host header injection (top 5 live hosts)..."
        local vhost_count=0
        while IFS= read -r host && [ $vhost_count -lt 5 ]; do
            local safe_name scheme hostname target_ip
            safe_name=$(echo "$host" | tr '/:' '__')
            scheme=$(echo "$host" | grep -oE '^https?')
            hostname=$(echo "$host" | sed -E 's|https?://||; s|/.*||; s|:[0-9]+$||')

            # Resolve hostname to IP for direct connection.
            target_ip=$(dig +short "$hostname" A 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
            if [ -z "$target_ip" ]; then
                warn "  Could not resolve $hostname to IP — skipping vhost scan."
                vhost_count=$(( vhost_count + 1 ))
                continue
            fi

            info "  Vhost fuzzing: $hostname ($target_ip)"
            ffuf -u "${scheme}://${target_ip}/" \
                -H "Host: FUZZ.$TARGET" \
                -w "$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt" \
                -mc 200,301,302,401,403 \
                -t "$FFUF_THREADS" \
                -rate 50 \
                -o "$OUTPUT_DIR/phase11-fuzzing/vhosts/vhost-$safe_name.json" \
                -of json \
                -fs 0 \
                -ac \
                -s 2>/dev/null
            vhost_count=$(( vhost_count + 1 ))
        done < "$p3dir/status-200.txt"
        success "Virtual host discovery complete ($vhost_count hosts checked)"
    fi

    success "Phase 3 complete!"
    save_checkpoint 3
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4: Port Scanning
# ─────────────────────────────────────────────────────────────────────────────
phase4_portscan() {
    phase_done 4 && { polite_sleep; return; }
    print_phase "🔌 PHASE 4: PORT SCANNING"

    if [ "$RUN_PORT_SCAN" = false ]; then
        info "Port scanning skipped (mode: $SCAN_MODE)."
        return
    fi

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p4dir="$OUTPUT_DIR/phase4-portscan"

    if [ ! -s "$p2dir/valid-subdomains.txt" ]; then
        warn "No valid subdomains for port scanning. Skipping Phase 4."
        return
    fi

    # 4.1 Scan top 1000 ports with Naabu
    info "Scanning top 1000 ports with Naabu..."
    naabu -list "$p2dir/valid-subdomains.txt" \
        -top-ports 1000 \
        -silent \
        -rate 300 \
        -o "$p4dir/open-ports.txt" 2>/dev/null
    success "Open ports discovered: $(count_lines "$p4dir/open-ports.txt")"

    # 4.2 Probe non-standard ports for web services
    if [ -s "$p4dir/open-ports.txt" ]; then
        info "Probing open ports for HTTP/HTTPS services..."
        httpx-toolkit -l "$p4dir/open-ports.txt" \
            -silent \
            -random-agent \
            -rl 50 \
            -o "$p4dir/services-on-ports.txt" 2>/dev/null

        # Merge into live-hosts (anew is more efficient, falls back to sort -u)
        if check_command "anew"; then
            cat "$p4dir/services-on-ports.txt" | anew "$p3dir/live-hosts.txt" > /dev/null
        else
            cat "$p3dir/live-hosts.txt" "$p4dir/services-on-ports.txt" \
                | sort -u > "$p3dir/live-hosts-tmp.txt"
            mv "$p3dir/live-hosts-tmp.txt" "$p3dir/live-hosts.txt"
        fi
        success "Additional web services on non-standard ports: $(count_lines "$p4dir/services-on-ports.txt")"
    fi

    success "Phase 4 complete!"
    save_checkpoint 4
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5: URL Discovery & Crawling
# ─────────────────────────────────────────────────────────────────────────────
phase5_url_discovery() {
    phase_done 5 && { polite_sleep; return; }
    print_phase "🔗 PHASE 5: URL DISCOVERY & CRAWLING"

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p5dir="$OUTPUT_DIR/phase5-urls"

    # 5.1 Active crawling with Katana (JS-aware, finds modern SPA endpoints)
    if [ -s "$p3dir/live-hosts.txt" ]; then
        info "Crawling with Katana (depth 3, JS-aware)..."
        katana -list "$p3dir/live-hosts.txt" \
            -depth "$KATANA_DEPTH" \
            -js-crawl \
            -known-files all \
            -silent \
            -rl 50 \
            -o "$p5dir/katana-urls.txt" 2>/dev/null
        success "Katana: $(count_lines "$p5dir/katana-urls.txt") URLs"
    else
        touch "$p5dir/katana-urls.txt"
    fi

    # 5.2 Hakrawler — lightweight spider for additional coverage
    if check_command "hakrawler" && [ -s "$p3dir/live-hosts.txt" ]; then
        info "Running Hakrawler..."
        cat "$p3dir/live-hosts.txt" \
            | hakrawler -depth 2 -timeout 10 -plain 2>/dev/null \
            > "$p5dir/hakrawler-urls.txt"
        success "Hakrawler: $(count_lines "$p5dir/hakrawler-urls.txt") URLs"
    else
        touch "$p5dir/hakrawler-urls.txt"
    fi

    # 5.3 Cariddi — full crawler with built-in secrets/endpoint detection
    if check_command "cariddi" && [ -s "$p3dir/live-hosts.txt" ]; then
        info "Running Cariddi (secrets + endpoint mode)..."
        cat "$p3dir/live-hosts.txt" \
            | cariddi -s -e -intensive 1 \
            > "$p5dir/cariddi-urls.txt" 2>/dev/null
        success "Cariddi: $(count_lines "$p5dir/cariddi-urls.txt") items"
    else
        touch "$p5dir/cariddi-urls.txt"
    fi

    # 5.4 Historical URL mining — Waybackurls
    info "Mining Wayback Machine for historical URLs..."
    cat "$p3dir/live-hosts.txt" \
        | waybackurls 2>/dev/null \
        > "$p5dir/wayback-urls.txt"
    success "Waybackurls: $(count_lines "$p5dir/wayback-urls.txt") URLs"

    # 5.5 Historical URL mining — GAU (Common Crawl + Wayback + OTX)
    info "Running GAU for additional historical URLs..."
    cat "$p2dir/valid-subdomains.txt" \
        | timeout 5m gau --threads "$GAU_THREADS" 2>/dev/null \
        > "$p5dir/gau-urls.txt"
    success "GAU: $(count_lines "$p5dir/gau-urls.txt") URLs"

    # 5.6 Merge all URL sources — explicit list prevents self-inclusion bug
    info "Merging and deduplicating all URL sources..."
    local cloud_p5_feed="$OUTPUT_DIR/phase2.5-cloud/exposed/cloud-urls-for-phase5.txt"
    cat "$p5dir/katana-urls.txt" \
        "$p5dir/hakrawler-urls.txt" \
        "$p5dir/cariddi-urls.txt" \
        "$p5dir/wayback-urls.txt" \
        "$p5dir/gau-urls.txt" \
        "${cloud_p5_feed:-/dev/null}" \
        2>/dev/null | sort -u > "$p5dir/all-urls.txt"
    success "Total unique URLs: $(count_lines "$p5dir/all-urls.txt")"

    # 5.7 Categorize URLs by content type
    info "Categorizing URLs by type..."

    grep -iE '\.(js|json|xml|config|yml|yaml|env|bak|backup|sql|db|log)(\?.*)?$' \
        "$p5dir/all-urls.txt" > "$p5dir/interesting-files.txt" 2>/dev/null || touch "$p5dir/interesting-files.txt"

    # Tighter API pattern — matches path segments, not just keywords anywhere in URL
    grep -iE '(/api/|/v1/|/v2/|/v3/|graphql|/rest/)' \
        "$p5dir/all-urls.txt" > "$p5dir/api-endpoints.txt" 2>/dev/null || touch "$p5dir/api-endpoints.txt"

    grep -iE '(admin|login|dashboard|upload|config|backup|dev|staging|test|debug|manage|panel)' \
        "$p5dir/all-urls.txt" > "$p5dir/sensitive-endpoints.txt" 2>/dev/null || touch "$p5dir/sensitive-endpoints.txt"

    grep -iE '\.js(\?.*)?$' \
        "$p5dir/all-urls.txt" > "$p5dir/all-js-files.txt" 2>/dev/null || touch "$p5dir/all-js-files.txt"

    # 5.8 Validate live JS files (200 OK only)
    if [ -s "$p5dir/all-js-files.txt" ]; then
        httpx-toolkit -l "$p5dir/all-js-files.txt" \
            -silent -mc 200 \
            -random-agent \
            -rl 50 \
            -o "$p5dir/live-js-files.txt" 2>/dev/null
        success "Live JS files: $(count_lines "$p5dir/live-js-files.txt")"
    fi

    # 5.9 GF pattern matching — tomnomnom/gf gives higher-signal URL filtering
    if check_command "gf"; then
        info "Running GF pattern matching on all URLs..."
        for pattern in xss sqli ssrf redirect lfi idor; do
            # Check if the gf pattern is actually installed before running
            if gf -list 2>/dev/null | grep -q "^$pattern$"; then
                gf "$pattern" "$p5dir/all-urls.txt" \
                    > "$p5dir/gf-$pattern.txt" 2>/dev/null || touch "$p5dir/gf-$pattern.txt"
                local cnt
                cnt=$(count_lines "$p5dir/gf-$pattern.txt")
                [ "$cnt" -gt 0 ] && info "  gf-$pattern: $cnt URLs"
            else
                warn "  gf pattern '$pattern' not installed — skipping."
                touch "$p5dir/gf-$pattern.txt"
            fi
        done
        success "GF pattern matching complete"
    else
        warn "gf not found — install tomnomnom/gf for higher-accuracy URL filtering."
    fi

    success "Phase 5 complete!"
    save_checkpoint 5
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6: Parameter Discovery
# ─────────────────────────────────────────────────────────────────────────────
phase6_parameters() {
    phase_done 6 && { polite_sleep; return; }
    print_phase "📊 PHASE 6: PARAMETER DISCOVERY"

    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p6dir="$OUTPUT_DIR/phase6-parameters"
    local p3dir="$OUTPUT_DIR/phase3-probing"

    # 6.1 Passive parameter extraction with Unfurl
    info "Extracting known parameters from URL corpus with Unfurl..."
    unfurl keys < "$p5dir/all-urls.txt" 2>/dev/null \
        | sort -u > "$p6dir/parameters.txt"
    success "Unique parameter names: $(count_lines "$p6dir/parameters.txt")"

    # 6.2 Active parameter discovery with Arjun (configurable limit)
    if [ "$RUN_PARAM_DISCOVERY" = false ]; then
        info "Active parameter discovery skipped (mode: $SCAN_MODE)."
    elif [ -s "$p3dir/status-200.txt" ]; then
        info "Running Arjun on up to $MAX_ARJUN_HOSTS hosts..."
        local count=0
        while IFS= read -r url && [ $count -lt $MAX_ARJUN_HOSTS ]; do
            info "  Arjun → $url"
            arjun -u "$url" \
                -t "$ARJUN_THREADS" \
                -oT "$p6dir/arjun-params-$count.txt" \
                -d 500 2>/dev/null
            count=$(( count + 1 ))
        done < "$p3dir/status-200.txt"

        cat "$p6dir"/arjun-params-*.txt 2>/dev/null \
            | sort -u > "$p6dir/arjun-all-params.txt"
        success "Arjun scanned $count hosts"
    else
        warn "No status-200 hosts for Arjun."
    fi

    success "Phase 6 complete!"
    save_checkpoint 6
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6b: Asset Scoring & Prioritization
# ─────────────────────────────────────────────────────────────────────────────
phase_asset_scoring() {
    # NOTE: No checkpoint guard — this phase is a fast local computation (no
    # network I/O) so it always re-runs, guaranteeing scores reflect the latest
    # data even on resume.  Runs in <2s on typical scan outputs.
    print_phase "📊 PHASE 6b: ASSET SCORING & PRIORITIZATION"

    if [ "$RUN_ASSET_SCORING" = false ]; then
        info "Asset scoring skipped (mode: $SCAN_MODE)."
        return
    fi

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p4dir="$OUTPUT_DIR/phase4-portscan"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p6dir="$OUTPUT_DIR/phase6-parameters"
    local score_dir="$OUTPUT_DIR/asset-scoring"

    if [ ! -s "$p3dir/live-hosts.txt" ]; then
        warn "No live hosts from Phase 3. Skipping asset scoring."
        return
    fi

    # ── Build the host universe ──────────────────────────────────────────────
    # Normalize all live-host URLs to scheme://hostname (no trailing path/port
    # variations) so we can match against URL-based files consistently.
    info "Building host universe from live-hosts.txt..."
    local host_list="$score_dir/.host-universe.txt"
    sed -E 's|^(https?://[^/]+).*|\1|' "$p3dir/live-hosts.txt" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u \
        | head -"$MAX_SCORE_HOSTS" > "$host_list"

    local total_hosts
    total_hosts=$(count_lines "$host_list")
    info "Scoring $total_hosts unique hosts..."

    # ── Prepare lookup files ─────────────────────────────────────────────────
    # Pre-lowercase all input files into temp copies so grep -c matches are
    # case-insensitive without paying per-host grep -i overhead.
    local tmp_dir="$score_dir/.tmp"
    mkdir -p "$tmp_dir"

    _lc_copy() {
        # Usage: _lc_copy <src> <dest>  — lowercases into dest, or touches empty
        if [ -s "$1" ]; then
            tr '[:upper:]' '[:lower:]' < "$1" > "$2"
        else
            : > "$2"
        fi
    }

    _lc_copy "$p3dir/status-200.txt"            "$tmp_dir/s200"
    _lc_copy "$p3dir/status-401.txt"            "$tmp_dir/s401"
    _lc_copy "$p3dir/status-403.txt"            "$tmp_dir/s403"
    _lc_copy "$p3dir/status-500.txt"            "$tmp_dir/s500"
    _lc_copy "$p3dir/clean-hosts.txt"           "$tmp_dir/detailed"
    _lc_copy "$p4dir/services-on-ports.txt"     "$tmp_dir/alt-ports"
    _lc_copy "$p5dir/api-endpoints.txt"         "$tmp_dir/apis"
    _lc_copy "$p5dir/sensitive-endpoints.txt"   "$tmp_dir/sensitive"
    _lc_copy "$p5dir/interesting-files.txt"     "$tmp_dir/interesting"
    _lc_copy "$p5dir/live-js-files.txt"         "$tmp_dir/jsfiles"

    # Merge all GF pattern matches into one file for counting
    local gf_merged="$tmp_dir/gf-all"
    : > "$gf_merged"
    for gf_file in "$p5dir"/gf-*.txt; do
        [ -s "$gf_file" ] && cat "$gf_file" >> "$gf_merged"
    done
    tr '[:upper:]' '[:lower:]' < "$gf_merged" > "$gf_merged.lc" && mv "$gf_merged.lc" "$gf_merged"

    # Merge all parameter files (passive + Arjun) — count unique params per host
    # Parameters from Unfurl are global (not per-host), so we go back to the
    # raw URL corpus and extract params per host directly.
    local param_source="$tmp_dir/url-params"
    if [ -s "$p5dir/all-urls.txt" ]; then
        tr '[:upper:]' '[:lower:]' < "$p5dir/all-urls.txt" > "$param_source"
    else
        : > "$param_source"
    fi

    # Tech keywords that boost score — common high-value/vuln-prone stacks
    local tech_keywords="wordpress|wp-content|jira|jenkins|drupal|tomcat|struts|coldfusion|phpmyadmin|weblogic|grafana|kibana|elasticsearch|solr|confluence|bitbucket|gitlab|sonarqube|spring-boot|actuator|swagger|openapi|graphql"

    # ── Score each host ──────────────────────────────────────────────────────
    local scored_file="$score_dir/scored-targets.txt"
    local summary_file="$score_dir/scoring-summary.txt"
    : > "$scored_file"
    : > "$summary_file"

    while IFS= read -r host; do
        local score=0
        local reasons=""

        # Extract just the hostname portion for matching inside URLs
        local hostname
        hostname=$(echo "$host" | sed -E 's|^https?://||')

        # ── Status code signals ──────────────────────────────────────────
        if grep -qF "$hostname" "$tmp_dir/s200" 2>/dev/null; then
            score=$((score + 5))
            reasons="${reasons}200:+5 "
        fi
        if grep -qF "$hostname" "$tmp_dir/s401" 2>/dev/null; then
            score=$((score + 15))
            reasons="${reasons}401:+15 "
        fi
        if grep -qF "$hostname" "$tmp_dir/s403" 2>/dev/null; then
            score=$((score + 15))
            reasons="${reasons}403:+15 "
        fi
        if grep -qF "$hostname" "$tmp_dir/s500" 2>/dev/null; then
            score=$((score + 20))
            reasons="${reasons}500:+20 "
        fi

        # ── Non-standard port services ───────────────────────────────────
        # BUG-12: grep -cF prints "0" AND exits 1 on zero matches.  The naive
        # `$(grep -cF ... || echo 0)` pattern captures TWO lines ("0\n0") because
        # grep already emitted "0" before exiting 1, then || fires echo 0 adding
        # a second line.  The subsequent `[ "$count" -gt 0 ]` then fails with
        # "integer expression expected".
        # Fix: brace-group the grep + fallback and pipe to head -1 so we always
        # take only the first output line regardless of which branch ran.
        local alt_port_count=0
        if [ -s "$tmp_dir/alt-ports" ]; then
            alt_port_count=$( { grep -cF "$hostname" "$tmp_dir/alt-ports" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$alt_port_count" -gt 0 ]; then
            local pts=$((alt_port_count * 10))
            score=$((score + pts))
            reasons="${reasons}alt-ports(${alt_port_count}):+${pts} "
        fi

        # ── API endpoints ────────────────────────────────────────────────
        local api_count=0
        if [ -s "$tmp_dir/apis" ]; then
            api_count=$( { grep -cF "$hostname" "$tmp_dir/apis" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$api_count" -gt 0 ]; then
            local pts=$((api_count * 3))
            score=$((score + pts))
            reasons="${reasons}apis(${api_count}):+${pts} "
        fi

        # ── Sensitive endpoints ──────────────────────────────────────────
        local sens_count=0
        if [ -s "$tmp_dir/sensitive" ]; then
            sens_count=$( { grep -cF "$hostname" "$tmp_dir/sensitive" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$sens_count" -gt 0 ]; then
            local pts=$((sens_count * 5))
            score=$((score + pts))
            reasons="${reasons}sensitive(${sens_count}):+${pts} "
        fi

        # ── Interesting files (config/bak/env) ───────────────────────────
        local int_count=0
        if [ -s "$tmp_dir/interesting" ]; then
            int_count=$( { grep -cF "$hostname" "$tmp_dir/interesting" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$int_count" -gt 0 ]; then
            local pts=$((int_count * 4))
            score=$((score + pts))
            reasons="${reasons}files(${int_count}):+${pts} "
        fi

        # ── GF pattern matches ───────────────────────────────────────────
        local gf_count=0
        if [ -s "$gf_merged" ]; then
            gf_count=$( { grep -cF "$hostname" "$gf_merged" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$gf_count" -gt 0 ]; then
            local pts=$((gf_count * 2))
            score=$((score + pts))
            reasons="${reasons}gf-patterns(${gf_count}):+${pts} "
        fi

        # ── Live JS files ────────────────────────────────────────────────
        local js_count=0
        if [ -s "$tmp_dir/jsfiles" ]; then
            js_count=$( { grep -cF "$hostname" "$tmp_dir/jsfiles" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$js_count" -gt 0 ]; then
            local pts=$((js_count * 2))
            score=$((score + pts))
            reasons="${reasons}js(${js_count}):+${pts} "
        fi

        # ── Parameters (from URL corpus) ─────────────────────────────────
        local param_count=0
        if [ -s "$param_source" ]; then
            # Count unique param keys in URLs matching this host
            param_count=$(grep -F "$hostname" "$param_source" 2>/dev/null \
                | grep -oE '[?&][a-zA-Z0-9_-]+=' \
                | sed 's/[?&]//;s/=$//' \
                | sort -u \
                | wc -l)
        fi
        if [ "$param_count" -gt 0 ]; then
            score=$((score + param_count))
            reasons="${reasons}params(${param_count}):+${param_count} "
        fi

        # ── Tech stack keywords ──────────────────────────────────────────
        if [ -s "$tmp_dir/detailed" ]; then
            local tech_match
            tech_match=$(grep -iF "$hostname" "$tmp_dir/detailed" 2>/dev/null \
                | grep -oiE "$tech_keywords" \
                | sort -u | head -5)
            if [ -n "$tech_match" ]; then
                # Award 10 points per unique tech keyword match (cap at 3)
                local tech_count
                tech_count=$(echo "$tech_match" | wc -l)
                [ "$tech_count" -gt 3 ] && tech_count=3
                local pts=$((tech_count * 10))
                local tech_list
                tech_list=$(echo "$tech_match" | tr '\n' ',' | sed 's/,$//')
                score=$((score + pts))
                reasons="${reasons}tech(${tech_list}):+${pts} "
            fi
        fi

        # ── Write results ────────────────────────────────────────────────
        # Pad score to 4 digits for clean sort alignment
        printf "%04d | %-60s | %s\n" "$score" "$reasons" "$host" >> "$scored_file"

        # Detailed summary for manual review
        if [ "$score" -gt 0 ]; then
            {
                echo "── $host ── score: $score"
                echo "   $reasons"
                echo ""
            } >> "$summary_file"
        fi

    done < "$host_list"

    # ── Sort by score descending ─────────────────────────────────────────────
    sort -t'|' -k1 -rn "$scored_file" -o "$scored_file"

    # ── Generate top-targets list (top 25%, minimum 5) ───────────────────────
    local top_count
    top_count=$(( total_hosts / 4 ))
    [ "$top_count" -lt 5 ] && top_count=5
    [ "$top_count" -gt "$total_hosts" ] && top_count="$total_hosts"

    head -"$top_count" "$scored_file" \
        | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3}' \
        > "$score_dir/top-targets.txt"

    # ── Print summary ────────────────────────────────────────────────────────
    local max_score min_score avg_score
    max_score=$(head -1 "$scored_file" | awk -F'|' '{gsub(/^[ \t]+/, "", $1); print $1+0}')
    min_score=$(tail -1 "$scored_file" | awk -F'|' '{gsub(/^[ \t]+/, "", $1); print $1+0}')
    avg_score=$(awk -F'|' '{gsub(/^[ \t]+/, "", $1); sum += $1+0} END {if (NR>0) printf "%d", sum/NR; else print 0}' "$scored_file")

    info "Score distribution:"
    echo "  Hosts scored     : $total_hosts"
    echo "  Highest score    : $max_score"
    echo "  Lowest score     : $min_score"
    echo "  Average score    : $avg_score"
    echo "  Top targets (25%): $(count_lines "$score_dir/top-targets.txt")"
    echo ""

    # Show the top 10 for quick eyeball
    info "Top 10 targets by score:"
    head -10 "$scored_file" | while IFS= read -r line; do
        echo "  $line"
    done

    # ── Cleanup temp files ───────────────────────────────────────────────────
    rm -rf "$tmp_dir" "$host_list"

    success "Asset scoring complete! → $score_dir/"
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7: Vulnerability Scanning (Nuclei)
# ─────────────────────────────────────────────────────────────────────────────
phase7_vulnerability_scanning() {
    phase_done 7 && { polite_sleep; return; }
    print_phase "🛡️  PHASE 7: VULNERABILITY SCANNING (NUCLEI)"

    local p7dir="$OUTPUT_DIR/phase7-vulns"
    backup_phase_outputs "$p7dir"

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p5dir="$OUTPUT_DIR/phase5-urls"

    if [ ! -s "$p3dir/live-hosts.txt" ]; then
        warn "No live hosts for Nuclei. Skipping Phase 7."
        return
    fi

    # Optional template update — auto-updates if templates are older than 7 days
    local nuclei_stamp="$HOME/.nuclei-last-update"
    local needs_update=false
    if [ "$UPDATE_NUCLEI" = true ]; then
        needs_update=true
    elif [ ! -f "$nuclei_stamp" ]; then
        needs_update=true
        info "Nuclei templates have never been updated — auto-updating..."
    else
        local days_since
        days_since=$(( ( $(date +%s) - $(date -r "$nuclei_stamp" +%s) ) / 86400 ))
        if [ "$days_since" -ge 7 ]; then
            needs_update=true
            info "Nuclei templates are $days_since days old — auto-updating..."
        else
            info "Nuclei templates are up to date ($days_since days old). Use -u to force update."
        fi
    fi

    if [ "$needs_update" = true ]; then
        info "Updating Nuclei templates..."
        nuclei -ut 2>/dev/null && touch "$nuclei_stamp"
        success "Nuclei templates updated."
    fi

    # ── Build a unified target list ─────────────────────────────────────────
    # Instead of running Nuclei 5–7 times against overlapping host lists, we
    # build ONE combined target list (live hosts + sensitive endpoints + JS
    # files + API endpoints), run Nuclei ONCE with JSON export, then split
    # findings into the same output files downstream phases expect.
    # This typically cuts Phase 7 wall-clock time by 50-70%.

    local combined_targets="$p7dir/.combined-targets.txt"
    {
        cat "$p3dir/live-hosts.txt"
        [ -s "$p5dir/sensitive-endpoints.txt" ] && cat "$p5dir/sensitive-endpoints.txt"
        [ -s "$p5dir/live-js-files.txt" ]       && cat "$p5dir/live-js-files.txt"
        [ -s "$p5dir/api-endpoints.txt" ]        && cat "$p5dir/api-endpoints.txt"
    } 2>/dev/null | sort -u > "$combined_targets"

    info "Unified target list: $(count_lines "$combined_targets") unique URLs"

    # 7.1 Single consolidated Nuclei scan — JSON export for post-processing
    info "Running consolidated Nuclei scan ($NUCLEI_SEVERITY severity)..."
    nuclei -l "$combined_targets" \
        -severity "$NUCLEI_SEVERITY" \
        -exclude-tags headers,cookie-flags,info \
        -rate-limit "$NUCLEI_RATE_LIMIT" \
        -timeout 10 \
        -je "$p7dir/all-findings.json" \
        -o "$p7dir/all-findings.txt" \
        -silent 2>/dev/null

    # 7.2 Exposure / misconfig templates on the same combined list
    # These use tag-based selection, which may pull in templates that the
    # severity filter above excluded (e.g. info-severity exposure templates).
    info "Scanning for exposures and misconfigurations..."
    nuclei -l "$combined_targets" \
        -tags exposure,config,misconfig \
        -exclude-tags headers,cookie-flags,info \
        -rate-limit "$NUCLEI_RATE_LIMIT" \
        -timeout 10 \
        -je "$p7dir/exposure-findings.json" \
        -o "$p7dir/exposure-findings.txt" \
        -silent 2>/dev/null

    # 7.3 Split consolidated JSON into the category files other phases expect
    info "Splitting findings into category files..."

    # Critical-only findings
    jq -r 'select(.info.severity == "critical") | .["template-id"] + " " + .host' \
        "$p7dir/all-findings.json" 2>/dev/null \
        > "$p7dir/critical-findings.txt" || touch "$p7dir/critical-findings.txt"
    [ -s "$p7dir/critical-findings.txt" ] && \
        success "🚨 CRITICAL findings! → $p7dir/critical-findings.txt"

    # High + medium findings
    jq -r 'select(.info.severity == "high" or .info.severity == "medium") | .["template-id"] + " " + .host' \
        "$p7dir/all-findings.json" 2>/dev/null \
        > "$p7dir/high-medium-findings.txt" || touch "$p7dir/high-medium-findings.txt"

    # CVE findings (any template whose ID starts with CVE-)
    jq -r 'select(.["template-id"] | test("^CVE-"; "i")) | .["template-id"] + " " + .host' \
        "$p7dir/all-findings.json" 2>/dev/null \
        > "$p7dir/cve-findings.txt" || touch "$p7dir/cve-findings.txt"

    # JS exposure findings (matched URL contains .js)
    jq -r 'select(.host | test("\\.js(\\?|$)")) | .["template-id"] + " " + .host' \
        "$p7dir/all-findings.json" 2>/dev/null \
        > "$p7dir/js-exposure-findings.txt" || touch "$p7dir/js-exposure-findings.txt"

    # API endpoint findings (matched URL contains /api/ or /graphql etc.)
    jq -r 'select(.host | test("/api/|/v[0-9]+/|graphql|/rest/"; "i")) | .["template-id"] + " " + .host' \
        "$p7dir/all-findings.json" 2>/dev/null \
        > "$p7dir/api-findings.txt" || touch "$p7dir/api-findings.txt"

    # Sensitive endpoint findings (admin, login, etc.)
    jq -r 'select(.host | test("admin|login|dashboard|upload|config|backup|dev|staging|test|debug"; "i")) | .["template-id"] + " " + .host' \
        "$p7dir/all-findings.json" 2>/dev/null \
        > "$p7dir/endpoint-findings.txt" || touch "$p7dir/endpoint-findings.txt"

    # Clean up temp file
    rm -f "$combined_targets"

    # 7.4 Tally all findings (deduplicated — the JSON is the source of truth)
    local total_findings
    total_findings=$(jq -s 'length' "$p7dir/all-findings.json" 2>/dev/null || echo "0")
    local exposure_count
    exposure_count=$(count_lines "$p7dir/exposure-findings.txt")

    merge_phase_backup "$p7dir"
    success "Phase 7 complete! Total findings: $total_findings (+ $exposure_count exposure/misconfig)"

    # Notify on anything worth acting on immediately
    local p7_critical p7_high_med p7_cves
    p7_critical=$(count_lines "$p7dir/critical-findings.txt")
    p7_high_med=$(count_lines "$p7dir/high-medium-findings.txt")
    p7_cves=$(count_lines "$p7dir/cve-findings.txt")

    if [ "$p7_critical" -gt 0 ]; then
        notify "🔥 CRITICAL Vulns — Phase 7" \
            "*${p7_critical}* critical Nuclei finding(s) on \`${TARGET}\`.\nCheck: \`${p7dir}/critical-findings.txt\`"
    fi
    if [ "$p7_high_med" -gt 0 ]; then
        notify "⚠️ High/Medium Vulns — Phase 7" \
            "*${p7_high_med}* high/medium finding(s). CVEs: *${p7_cves}*.\nCheck: \`${p7dir}/high-medium-findings.txt\`"
    fi

    save_checkpoint 7
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8: JavaScript Analysis & Secret Extraction
# ─────────────────────────────────────────────────────────────────────────────
phase8_javascript_analysis() {
    phase_done 8 && { polite_sleep; return; }
    print_phase "📜 PHASE 8: JAVASCRIPT ANALYSIS & SECRET EXTRACTION"

    if [ "$RUN_JS_ANALYSIS" = false ]; then
        info "JavaScript analysis skipped (mode: $SCAN_MODE)."
        return
    fi

    local p8dir_backup="$OUTPUT_DIR/phase8-javascript"
    backup_phase_outputs "$p8dir_backup"

    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p8dir="$OUTPUT_DIR/phase8-javascript"

    if [ ! -s "$p5dir/live-js-files.txt" ]; then
        warn "No live JS files found. Skipping Phase 8."
        return
    fi

    # 8.1 Download JS files (capped at MAX_JS_FILES)
    info "Downloading up to $MAX_JS_FILES JavaScript files..."
    local js_count=0
    while IFS= read -r js_url && [ $js_count -lt $MAX_JS_FILES ]; do
        local filename
        filename=$(echo "$js_url" | md5sum | awk '{print $1}')
        curl -sk --max-time 10 \
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            "$js_url" \
            -o "$p8dir/js-files/$filename.js" 2>/dev/null
        js_count=$(( js_count + 1 ))
    done < "$p5dir/live-js-files.txt"
    success "Downloaded $js_count JavaScript files"

    # 8.2 Concatenate for bulk regex scanning (guard against empty download dir)
    if compgen -G "$p8dir/js-files/*.js" > /dev/null 2>&1; then
        cat "$p8dir/js-files/"*.js > "$p8dir/all-js-content.txt" 2>/dev/null
    else
        warn "No JS files downloaded — skipping regex secret extraction."
        touch "$p8dir/all-js-content.txt"
    fi

    # ── TruffleHog — industry-grade secret scanner with verification ──────────
    # Replaces the noisy grep-for-"api_key" approach from v1 which produced
    # thousands of false positives (variable names, not actual key values).
    if check_command "trufflehog" && [ -d "$p8dir/js-files" ]; then
        info "Running TruffleHog for verified secret detection..."
        trufflehog filesystem "$p8dir/js-files/" \
            --only-verified \
            --json 2>/dev/null \
            > "$p8dir/trufflehog-secrets.json"

        jq -r '
            select(.SourceMetadata != null) |
            "[" + .DetectorName + "] " + (.SourceMetadata.Data.Filesystem.file // "unknown")
        ' "$p8dir/trufflehog-secrets.json" 2>/dev/null \
            | sort -u > "$p8dir/trufflehog-summary.txt"

        local secret_count
        secret_count=$(count_lines "$p8dir/trufflehog-summary.txt")
        # Ensure numeric value before comparison (trim whitespace from wc -l)
        secret_count=$(echo "$secret_count" | tr -d ' ')
        secret_count=${secret_count:-0}
        if [ "$secret_count" -gt 0 ]; then
            success "🔑 TruffleHog: $secret_count verified secrets → $p8dir/trufflehog-summary.txt"
        else
            info "TruffleHog: no verified secrets found."
        fi
    fi

    # ── Targeted high-precision regex for specific secret formats ─────────────
    info "Extracting secrets with targeted regex patterns..."

    # AWS Access Key IDs — very high-confidence pattern (AKIA prefix + 16 chars)
    grep -oE 'AKIA[0-9A-Z]{16}' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/aws-access-keys.txt" 2>/dev/null || touch "$p8dir/aws-access-keys.txt"

    # Google API keys — AIza prefix + 35 alphanum chars
    grep -oE 'AIza[0-9A-Za-z_-]{35}' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/google-api-keys.txt" 2>/dev/null || touch "$p8dir/google-api-keys.txt"

    # GitHub tokens — ghp_, gho_, ghu_, ghs_, ghr_ prefixes (classic + fine-grained)
    grep -oE '(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/github-tokens.txt" 2>/dev/null || touch "$p8dir/github-tokens.txt"

    # Slack tokens — xox prefix variants
    grep -oE 'xox[baprs]-[0-9a-zA-Z-]{10,}' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/slack-tokens.txt" 2>/dev/null || touch "$p8dir/slack-tokens.txt"

    # Stripe live keys — sk_live_ / pk_live_ prefixes
    grep -oE '(sk_live_|pk_live_)[0-9a-zA-Z]{24,}' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/stripe-keys.txt" 2>/dev/null || touch "$p8dir/stripe-keys.txt"

    # PEM private keys embedded in JS
    grep -i 'BEGIN.*PRIVATE KEY' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/private-keys.txt" 2>/dev/null || touch "$p8dir/private-keys.txt"

    info "Secret extraction results:"
    echo "  TruffleHog verified : $(count_lines "$p8dir/trufflehog-summary.txt")"
    echo "  AWS Access Keys     : $(count_lines "$p8dir/aws-access-keys.txt")"
    echo "  Google API Keys     : $(count_lines "$p8dir/google-api-keys.txt")"
    echo "  GitHub Tokens       : $(count_lines "$p8dir/github-tokens.txt")"
    echo "  Slack Tokens        : $(count_lines "$p8dir/slack-tokens.txt")"
    echo "  Stripe Keys         : $(count_lines "$p8dir/stripe-keys.txt")"
    echo "  Private Keys        : $(count_lines "$p8dir/private-keys.txt")"

    # 8.3 Endpoint discovery inside JS
    info "Discovering API endpoints embedded in JavaScript..."
    # Extract full URLs from JS (these are usable as-is)
    grep -Eo 'https?://[a-zA-Z0-9./\-_?=&%#@]+' "$p8dir/all-js-content.txt" \
        | sort -u > "$p8dir/js-endpoints.txt" 2>/dev/null || touch "$p8dir/js-endpoints.txt"

    # Extract relative API paths and prepend live hosts to make them probe-able.
    # Run the grep once (not once-per-host) then fan out with sed.
    local p3dir_ref="$OUTPUT_DIR/phase3-probing"
    if [ -s "$p3dir_ref/live-hosts.txt" ]; then
        local api_paths_tmp
        api_paths_tmp=$(mktemp)
        grep -oE '/api/[a-zA-Z0-9/_-]*' "$p8dir/all-js-content.txt" 2>/dev/null \
            | sort -u > "$api_paths_tmp"
        if [ -s "$api_paths_tmp" ]; then
            while IFS= read -r base; do
                sed "s|^|$base|" "$api_paths_tmp" >> "$p8dir/js-endpoints.txt"
            done < "$p3dir_ref/live-hosts.txt"
        fi
        rm -f "$api_paths_tmp"
        sort -u "$p8dir/js-endpoints.txt" -o "$p8dir/js-endpoints.txt"
    fi

    if [ -s "$p8dir/js-endpoints.txt" ]; then
        httpx-toolkit -l "$p8dir/js-endpoints.txt" \
            -silent \
            -random-agent \
            -o "$p8dir/live-js-endpoints.txt" 2>/dev/null
        success "Live endpoints from JS: $(count_lines "$p8dir/live-js-endpoints.txt")"
    fi

    merge_phase_backup "$p8dir_backup"
    success "Phase 8 complete!"

    # Notify if any verified secrets were extracted
    local p8_secrets p8_aws p8_privkeys
    p8_secrets=$(count_lines "$p8dir/trufflehog-summary.txt")
    p8_aws=$(count_lines "$p8dir/aws-access-keys.txt")
    p8_privkeys=$(count_lines "$p8dir/private-keys.txt")
    local p8_total
    p8_total=$(( p8_secrets + p8_aws + p8_privkeys ))
    if [ "$p8_total" -gt 0 ]; then
        notify "🔑 JS Secrets Found — Phase 8" \
            "Secrets extracted from JavaScript files:\nTruffleHog verified: *${p8_secrets}*\nAWS keys: *${p8_aws}*\nPrivate keys: *${p8_privkeys}*\nDir: \`${p8dir}\`"
    fi
    # NOTE: checkpoint for phases 8–11 is saved as a group in main() after
    # all parallel phases complete — do not checkpoint individually here.
    # NOTE: polite_sleep is intentionally omitted — these phases run in parallel
    # background jobs, so per-phase delays have no rate-limiting effect and would
    # only add latency to the wait() call in main() before Phase 12 starts.
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9: Vulnerability Pattern Hunting
# ─────────────────────────────────────────────────────────────────────────────
phase9_pattern_hunting() {
    phase_done 9 && { polite_sleep; return; }
    print_phase "🎯 PHASE 9: VULNERABILITY PATTERN HUNTING"

    if [ "$RUN_PATTERN_HUNTING" = false ]; then
        info "Vulnerability pattern hunting skipped (mode: $SCAN_MODE)."
        return
    fi

    local p9dir_backup="$OUTPUT_DIR/phase9-patterns"
    backup_phase_outputs "$p9dir_backup"

    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p9dir="$OUTPUT_DIR/phase9-patterns"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local url_source="$p5dir/all-urls.txt"

    # 9.1 SSRF candidates — prefer gf output (higher signal) over grep
    info "Finding SSRF candidates..."
    if [ -s "$p5dir/gf-ssrf.txt" ]; then
        cp "$p5dir/gf-ssrf.txt" "$p9dir/ssrf-candidates.txt"
    else
        grep -iE '(url|uri|path|dest|redirect|proxy|continue|view|target|load|fetch|host|ping)=' \
            "$url_source" > "$p9dir/ssrf-candidates.txt" 2>/dev/null || touch "$p9dir/ssrf-candidates.txt"
    fi
    success "SSRF candidates: $(count_lines "$p9dir/ssrf-candidates.txt")"

    # 9.2 Open Redirect candidates
    info "Finding Open Redirect candidates..."
    if [ -s "$p5dir/gf-redirect.txt" ]; then
        cp "$p5dir/gf-redirect.txt" "$p9dir/redirect-candidates.txt"
    else
        grep -iE '(redirect|url|next|return|redir|goto|continue|dest|forward|location)=' \
            "$url_source" > "$p9dir/redirect-candidates.txt" 2>/dev/null || touch "$p9dir/redirect-candidates.txt"
    fi
    success "Open Redirect candidates: $(count_lines "$p9dir/redirect-candidates.txt")"

    # 9.3 XSS candidates + Dalfox automated testing
    info "Finding XSS candidates..."
    if [ -s "$p5dir/gf-xss.txt" ]; then
        cp "$p5dir/gf-xss.txt" "$p9dir/xss-candidates.txt"
    else
        grep -iE '(q|search|query|keyword|s|name|p|callback|input|text|term|v)=' \
            "$url_source" > "$p9dir/xss-candidates.txt" 2>/dev/null || touch "$p9dir/xss-candidates.txt"
    fi
    success "XSS candidates: $(count_lines "$p9dir/xss-candidates.txt")"

    if check_command "dalfox" && [ -s "$p9dir/xss-candidates.txt" ]; then
        local xss_total
        xss_total=$(count_lines "$p9dir/xss-candidates.txt")
        info "Running Dalfox XSS testing (cap: ${XSS_CANDIDATE_CAP} of ${xss_total} candidates, delay: ${DALFOX_DELAY}ms, timeout: ${DALFOX_TIMEOUT}s)..."

        # Asset-scored top targets are already in score order (highest first) thanks
        # to Phase 6b.  head -N feeds the highest-value URLs into dalfox so the cap
        # spends its budget on the best candidates, not random ones.
        #
        # `timeout DALFOX_TIMEOUT` is the primary guard against infinite hangs.
        # XSS_CANDIDATE_CAP is the secondary guard — even without timeout, dalfox
        # sees at most this many URLs.  Both are set per scan-mode in apply_scan_mode.
        #
        # SIGTERM is sent first; dalfox writes confirmed findings incrementally so
        # partial output is safe.  timeout sends SIGKILL after a further 30 s if the
        # process doesn't exit cleanly on SIGTERM.
        head -"${XSS_CANDIDATE_CAP}" "$p9dir/xss-candidates.txt" \
            | timeout --kill-after=30 "${DALFOX_TIMEOUT}" \
                dalfox pipe \
                --silence \
                --no-color \
                --delay "${DALFOX_DELAY}" \
                --output "$p9dir/dalfox-xss-confirmed.txt" 2>/dev/null
        local dalfox_exit=$?
        if [ $dalfox_exit -eq 124 ]; then
            warn "Dalfox hit the ${DALFOX_TIMEOUT}s wall-clock timeout — partial results saved to $p9dir/dalfox-xss-confirmed.txt"
        fi
        if [ -s "$p9dir/dalfox-xss-confirmed.txt" ]; then
            success "🚨 Dalfox confirmed XSS! → $p9dir/dalfox-xss-confirmed.txt"
        else
            info "Dalfox: no confirmed XSS."
        fi
    else
        ! check_command "dalfox" && warn "dalfox not installed — install hahwul/dalfox for automated XSS confirmation."
    fi

    # 9.4 SQL Injection candidates + SQLMap
    info "Finding SQLi candidates..."
    if [ -s "$p5dir/gf-sqli.txt" ]; then
        cp "$p5dir/gf-sqli.txt" "$p9dir/sqli-candidates.txt"
    else
        grep -iE '(id|select|report|role|update|query|user|sort|where|order|group|cat)=' \
            "$url_source" > "$p9dir/sqli-candidates.txt" 2>/dev/null || touch "$p9dir/sqli-candidates.txt"
    fi
    success "SQLi candidates: $(count_lines "$p9dir/sqli-candidates.txt")"

    if check_command "sqlmap" && [ -s "$p9dir/sqli-candidates.txt" ]; then
        local sqli_total
        sqli_total=$(count_lines "$p9dir/sqli-candidates.txt")
        info "Running SQLMap on up to ${SQLI_CANDIDATE_CAP} of ${sqli_total} SQLi candidates (batch, timeout: ${SQLMAP_TIMEOUT}s)..."
        head -"${SQLI_CANDIDATE_CAP}" "$p9dir/sqli-candidates.txt" \
            > "$p9dir/sqli-top${SQLI_CANDIDATE_CAP}.txt"

        # Build a regex scope pattern from the target domain so SQLMap
        # never follows redirects to out-of-scope domains.
        local escaped_target
        escaped_target=$(echo "$TARGET" | sed 's/\./\\./g')

        # timeout prevents sqlmap from running indefinitely on slow/deep targets.
        timeout --kill-after=30 "${SQLMAP_TIMEOUT}" \
            sqlmap -m "$p9dir/sqli-top${SQLI_CANDIDATE_CAP}.txt" \
                --batch \
                --smart \
                --level=1 \
                --risk=1 \
                --delay=2 \
                --random-agent \
                --scope="https?://([a-zA-Z0-9._-]+\\.)?${escaped_target}" \
                --tamper=between,randomcase \
                --timeout=15 \
                --retries=1 \
                --output-dir="$p9dir/sqlmap-results" \
                2>/dev/null
        local sqlmap_exit=$?
        if [ $sqlmap_exit -eq 124 ]; then
            warn "SQLMap hit the ${SQLMAP_TIMEOUT}s wall-clock timeout — partial results in $p9dir/sqlmap-results/"
        fi
        success "SQLMap scan complete → $p9dir/sqlmap-results/"
    fi

    # 9.5 LFI candidates
    info "Finding LFI candidates..."
    if [ -s "$p5dir/gf-lfi.txt" ]; then
        cp "$p5dir/gf-lfi.txt" "$p9dir/lfi-candidates.txt"
    else
        grep -iE '(file|path|folder|include|doc|page|archive|download|template|dir)=' \
            "$url_source" > "$p9dir/lfi-candidates.txt" 2>/dev/null || touch "$p9dir/lfi-candidates.txt"
    fi
    success "LFI candidates: $(count_lines "$p9dir/lfi-candidates.txt")"

    # 9.6 IDOR candidates — numeric IDs in parameters are prime IDOR targets
    info "Finding IDOR candidates (numeric param values)..."
    if [ -s "$p5dir/gf-idor.txt" ]; then
        cp "$p5dir/gf-idor.txt" "$p9dir/idor-candidates.txt"
    else
        grep -iE '(id|user_id|account|profile|order|invoice|ticket|record|member)=[0-9]+' \
            "$url_source" | sort -u > "$p9dir/idor-candidates.txt" 2>/dev/null \
            || touch "$p9dir/idor-candidates.txt"
    fi
    success "IDOR candidates: $(count_lines "$p9dir/idor-candidates.txt")"

    # 9.7 CORS misconfiguration testing (improved over v1)
    # v1 only checked for evil.nullsec.com in ACAO, missed the critical ACAC: true + ACAO: * case
    # Distinguishes CORS-CRITICAL (reflected origin) from CORS-HIGH (* + credentials)
    info "Testing CORS misconfigurations (up to $MAX_CORS_HOSTS hosts)..."
    local cors_count=0
    local cors_failures=0
    if [ -s "$p3dir/live-hosts.txt" ]; then
        while IFS= read -r url && [ $cors_count -lt $MAX_CORS_HOSTS ]; do
            local headers acao acac
            headers=$(curl -sk --max-time 5 \
                -H 'Origin: https://evil.nullsec.com' \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                -I "$url" 2>/dev/null)

            if [ -z "$headers" ]; then
                cors_failures=$(( cors_failures + 1 ))
                # Bail early if >25% of requests are failing — likely throttled
                if [ $cors_count -gt 10 ] && [ $((cors_failures * 100 / cors_count)) -gt 25 ]; then
                    warn "CORS scan: ${cors_failures}/${cors_count} requests failed (>25%) — possible throttling. Stopping early."
                    break
                fi
                cors_count=$(( cors_count + 1 ))
                continue
            fi

            acao=$(echo "$headers" | grep -i 'access-control-allow-origin' | tr -d '\r')
            acac=$(echo "$headers" | grep -i 'access-control-allow-credentials' | tr -d '\r')

            if echo "$acao" | grep -qiE '(evil\.nullsec\.com|^null$)'; then
                echo "[CORS-CRITICAL] $url | $acao | $acac" >> "$p9dir/cors-findings.txt"
            elif echo "$acao" | grep -q '\*' && echo "$acac" | grep -qi 'true'; then
                echo "[CORS-HIGH] $url | $acao | $acac" >> "$p9dir/cors-findings.txt"
            fi
            cors_count=$(( cors_count + 1 ))
        done < "$p3dir/live-hosts.txt"
    fi

    if [ -s "$p9dir/cors-findings.txt" ]; then
        success "🚨 CORS issues found: $(count_lines "$p9dir/cors-findings.txt")"
    else
        info "No CORS misconfigurations detected."
    fi
    [ "$cors_failures" -gt 0 ] && warn "CORS scan: $cors_failures/$cors_count requests failed (timeouts/resets)."

    # 9.8 Host Header Injection testing
    info "Testing for Host Header Injection..."
    local hhi_count=0
    local hhi_failures=0
    if [ -s "$p3dir/live-hosts.txt" ]; then
        while IFS= read -r url && [ $hhi_count -lt 30 ]; do
            local resp
            resp=$(curl -sk --max-time 5 \
                -H 'Host: evil.nullsec.com' \
                -H 'X-Forwarded-Host: evil.nullsec.com' \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                "$url" 2>/dev/null)

            if [ -z "$resp" ]; then
                hhi_failures=$(( hhi_failures + 1 ))
                if [ $hhi_count -gt 5 ] && [ $((hhi_failures * 100 / hhi_count)) -gt 25 ]; then
                    warn "HHI scan: ${hhi_failures}/${hhi_count} requests failed (>25%) — possible throttling. Stopping early."
                    break
                fi
                hhi_count=$(( hhi_count + 1 ))
                continue
            fi

            if echo "$resp" | grep -q 'evil.nullsec.com'; then
                echo "[HOST-INJECTION] $url" >> "$p9dir/host-injection-findings.txt"
            fi
            hhi_count=$(( hhi_count + 1 ))
        done < "$p3dir/live-hosts.txt"
    fi

    if [ -s "$p9dir/host-injection-findings.txt" ]; then
        success "🚨 Host header injection candidates: $(count_lines "$p9dir/host-injection-findings.txt")"
    else
        info "No host header injection detected."
    fi
    [ "$hhi_failures" -gt 0 ] && warn "HHI scan: $hhi_failures/$hhi_count requests failed (timeouts/resets)."

    merge_phase_backup "$p9dir_backup"
    success "Phase 9 complete!"

    # Notify on high-signal pattern hits
    local p9_cors p9_ssrf p9_xss p9_hhi
    p9_cors=$(count_lines "$p9dir/cors-findings.txt")
    p9_ssrf=$(count_lines "$p9dir/ssrf-candidates.txt")
    p9_xss=$(count_lines "$p9dir/dalfox-xss-confirmed.txt")
    p9_hhi=$(count_lines "$p9dir/host-injection-findings.txt")
    local p9_total
    p9_total=$(( p9_cors + p9_ssrf + p9_xss + p9_hhi ))
    if [ "$p9_total" -gt 0 ]; then
        notify "🎯 Pattern Hits — Phase 9" \
            "Vulnerability patterns detected on \`${TARGET}\`:\nCORS misconfigs: *${p9_cors}*\nSSRF candidates: *${p9_ssrf}*\nXSS confirmed: *${p9_xss}*\nHost-header inject: *${p9_hhi}*"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10: Screenshots & Visual Reconnaissance
# ─────────────────────────────────────────────────────────────────────────────
phase10_screenshots() {
    phase_done 10 && { polite_sleep; return; }
    print_phase "📸 PHASE 10: SCREENSHOTS & VISUAL RECONNAISSANCE"

    if [ "$RUN_SCREENSHOTS" = false ]; then
        info "Screenshots skipped (mode: $SCAN_MODE)."
        return
    fi

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p10dir="$OUTPUT_DIR/phase10-screenshots"

    if ! check_command "gowitness"; then
        warn "gowitness not installed — skipping Phase 10."
        return
    fi

    # Use gowitness batch mode (scan file) instead of a slow per-URL loop.
    # This is dramatically faster and is the intended usage pattern.

    # 10.1 Screenshot 403 pages (bypass candidates)
    if [ -s "$p3dir/status-403.txt" ]; then
        info "Capturing 403 Forbidden screenshots (batch)..."
        head -"$MAX_SCREENSHOTS" "$p3dir/status-403.txt" > "$p10dir/403/targets.txt"
        gowitness scan file \
            -f "$p10dir/403/targets.txt" \
            --screenshot-path "$p10dir/403/" \
            --threads "$GOWITNESS_THREADS" 2>/dev/null
        success "403 screenshots captured"
    fi

    # 10.2 Screenshot sensitive endpoints
    if [ -s "$p5dir/sensitive-endpoints.txt" ]; then
        info "Capturing sensitive endpoint screenshots (batch)..."
        head -"$MAX_SCREENSHOTS" "$p5dir/sensitive-endpoints.txt" > "$p10dir/interesting/targets.txt"
        gowitness scan file \
            -f "$p10dir/interesting/targets.txt" \
            --screenshot-path "$p10dir/interesting/" \
            --threads "$GOWITNESS_THREADS" 2>/dev/null
        success "Sensitive endpoint screenshots captured"
    fi

    # 10.3 Screenshot admin/panel/dashboard hosts
    if [ -s "$p3dir/live-hosts.txt" ]; then
        grep -iE '(admin|manage|panel|dashboard|control)' \
            "$p3dir/live-hosts.txt" \
            | head -"$MAX_SCREENSHOTS" > "$p10dir/admin/targets.txt" 2>/dev/null || true

        if [ -s "$p10dir/admin/targets.txt" ]; then
            info "Capturing admin panel screenshots (batch)..."
            gowitness scan file \
                -f "$p10dir/admin/targets.txt" \
                --screenshot-path "$p10dir/admin/" \
                --threads "$GOWITNESS_THREADS" 2>/dev/null
            success "Admin panel screenshots captured"
        fi
    fi

    # 10.4 Screenshot all live hosts (capped)
    if [ -s "$p3dir/live-hosts.txt" ]; then
        info "Capturing live host screenshots (first $MAX_SCREENSHOTS, batch)..."
        head -"$MAX_SCREENSHOTS" "$p3dir/live-hosts.txt" > "$p10dir/all/targets.txt"
        gowitness scan file \
            -f "$p10dir/all/targets.txt" \
            --screenshot-path "$p10dir/all/" \
            --threads "$GOWITNESS_THREADS" 2>/dev/null
        success "Live host screenshots captured"
    fi

    success "Phase 10 complete!"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 11: Directory & Content Fuzzing  [NEW]
# ─────────────────────────────────────────────────────────────────────────────
phase11_fuzzing() {
    phase_done 11 && { polite_sleep; return; }
    print_phase "💥 PHASE 11: DIRECTORY & CONTENT FUZZING"

    if [ "$RUN_FUZZING" = false ]; then
        info "Directory fuzzing skipped (mode: $SCAN_MODE)."
        return
    fi

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p11dir="$OUTPUT_DIR/phase11-fuzzing"

    if ! check_command "ffuf"; then
        warn "ffuf not installed — skipping Phase 11."
        return
    fi

    if [ ! -f "$WEB_WORDLIST" ]; then
        warn "Web wordlist not found at $WEB_WORDLIST — skipping directory fuzzing."
        return
    fi

    if [ ! -s "$p3dir/status-200.txt" ]; then
        warn "No status-200 hosts available for fuzzing."
        return
    fi

    # 11.1 Directory brute-force with smart auto-calibration (-ac)
    info "Running recursive directory fuzzing on top 10 live hosts..."
    local fuzz_count=0
    while IFS= read -r url && [ $fuzz_count -lt 10 ]; do
        local safe_name
        safe_name=$(echo "$url" | sed 's|https\?://||' | tr '/.:' '___')
        info "  Fuzzing: $url"

        ffuf -u "$url/FUZZ" \
            -w "$WEB_WORDLIST" \
            -mc 200,201,204,301,302,307,401,403,405 \
            -t "$FFUF_THREADS" \
            -rate 100 \
            -o "$p11dir/dirs/ffuf-$safe_name.json" \
            -of json \
            -recursion -recursion-depth 2 \
            -ac \
            -timeout 10 \
            -silent 2>/dev/null &
        local ffuf_pid=$!
        # Per-host wall-clock cap prevents a single slow host from blocking the loop
        ( sleep "$FFUF_TIMEOUT" && kill -TERM "$ffuf_pid" 2>/dev/null ) &
        local watchdog_pid=$!
        if ! wait "$ffuf_pid" 2>/dev/null; then
            warn "ffuf timed out on $url after ${FFUF_TIMEOUT}s — partial results saved."
        fi
        kill -TERM "$watchdog_pid" 2>/dev/null; wait "$watchdog_pid" 2>/dev/null || true

        jq -r '.results[]? | "\(.status) \(.url)"' \
            "$p11dir/dirs/ffuf-$safe_name.json" 2>/dev/null \
            >> "$p11dir/dirs/all-found-paths.txt"

        fuzz_count=$(( fuzz_count + 1 ))
    done < "$p3dir/status-200.txt"

    success "Directory fuzzing complete: $(count_lines "$p11dir/dirs/all-found-paths.txt") paths found"

    # 11.2 Backup & config file discovery
    if [ -f "$SECLISTS/Discovery/Web-Content/raft-large-files.txt" ]; then
        info "Scanning for exposed backup and config files..."
        local backup_count=0
        while IFS= read -r url && [ $backup_count -lt 5 ]; do
            local safe_name
            safe_name=$(echo "$url" | sed 's|https\?://||' | tr '/.:' '___')
            ffuf -u "$url/FUZZ" \
                -w "$SECLISTS/Discovery/Web-Content/raft-large-files.txt" \
                -mc 200 \
                -t "$FFUF_THREADS" \
                -rate 100 \
                -o "$p11dir/dirs/backups-$safe_name.json" \
                -of json \
                -ac \
                -timeout 10 \
                -silent 2>/dev/null &
            local ffuf_bak_pid=$!
            ( sleep "$FFUF_TIMEOUT" && kill -TERM "$ffuf_bak_pid" 2>/dev/null ) &
            local watchdog_bak_pid=$!
            if ! wait "$ffuf_bak_pid" 2>/dev/null; then
                warn "Backup ffuf timed out on $url after ${FFUF_TIMEOUT}s."
            fi
            kill -TERM "$watchdog_bak_pid" 2>/dev/null; wait "$watchdog_bak_pid" 2>/dev/null || true
            backup_count=$(( backup_count + 1 ))
        done < "$p3dir/status-200.txt"
        success "Backup file scan complete"
    fi

    success "Phase 11 complete!"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 12: Active Vulnerability Confirmation  [NEW]
# ─────────────────────────────────────────────────────────────────────────────
phase12_active_vulns() {
    phase_done 12 && { polite_sleep; return; }
    print_phase "🔥 PHASE 12: ACTIVE VULNERABILITY CONFIRMATION"

    if [ "$RUN_ACTIVE_VULNS" = false ]; then
        info "Active vulnerability confirmation skipped (mode: $SCAN_MODE)."
        return
    fi

    local p12dir_backup="$OUTPUT_DIR/phase12-active-vulns"
    backup_phase_outputs "$p12dir_backup"

    local p9dir="$OUTPUT_DIR/phase9-patterns"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p12dir="$OUTPUT_DIR/phase12-active-vulns"

    # 12.1 SSRF — Nuclei OAST-based templates
    if [ -s "$p9dir/ssrf-candidates.txt" ]; then
        info "Testing SSRF candidates with Nuclei OAST templates..."
        nuclei -l "$p9dir/ssrf-candidates.txt" \
            -tags ssrf \
            -severity medium,high,critical \
            -rate-limit "$NUCLEI_RATE_LIMIT" \
            -timeout 10 \
            -o "$p12dir/ssrf-confirmed.txt" \
            -silent 2>/dev/null
        [ -s "$p12dir/ssrf-confirmed.txt" ] && \
            success "🚨 SSRF confirmed! → $p12dir/ssrf-confirmed.txt"
    fi

    # 12.2 Open Redirect confirmation
    if [ -s "$p9dir/redirect-candidates.txt" ]; then
        info "Confirming Open Redirect candidates with Nuclei..."
        nuclei -l "$p9dir/redirect-candidates.txt" \
            -tags redirect \
            -rate-limit "$NUCLEI_RATE_LIMIT" \
            -timeout 10 \
            -o "$p12dir/redirect-confirmed.txt" \
            -silent 2>/dev/null
        [ -s "$p12dir/redirect-confirmed.txt" ] && \
            success "🚨 Open Redirects confirmed! → $p12dir/redirect-confirmed.txt"
    fi

    # 12.3 LFI confirmation
    if [ -s "$p9dir/lfi-candidates.txt" ]; then
        info "Confirming LFI candidates with Nuclei..."
        nuclei -l "$p9dir/lfi-candidates.txt" \
            -tags lfi \
            -rate-limit "$NUCLEI_RATE_LIMIT" \
            -timeout 10 \
            -o "$p12dir/lfi-confirmed.txt" \
            -silent 2>/dev/null
        [ -s "$p12dir/lfi-confirmed.txt" ] && \
            success "🚨 LFI confirmed! → $p12dir/lfi-confirmed.txt"
    fi

    # 12.4 403 bypass attempts
    if [ -s "$OUTPUT_DIR/phase3-probing/status-403.txt" ]; then
        info "Attempting 403 Forbidden bypass techniques..."
        nuclei -l "$OUTPUT_DIR/phase3-probing/status-403.txt" \
            -t "$NUCLEI_TEMPLATES/http/fuzzing/403-bypass.yaml" \
            -rate-limit "$NUCLEI_RATE_LIMIT" \
            -timeout 10 \
            -o "$p12dir/403-bypass-confirmed.txt" \
            -silent 2>/dev/null
        [ -s "$p12dir/403-bypass-confirmed.txt" ] && \
            success "🚨 403 bypass found! → $p12dir/403-bypass-confirmed.txt"
    fi

    # 12.5 GraphQL introspection & misconfiguration
    if [ -s "$p5dir/api-endpoints.txt" ]; then
        info "Testing GraphQL endpoints for introspection..."
        grep -i 'graphql' "$p5dir/api-endpoints.txt" \
            | head -20 > "$p12dir/graphql-targets.txt" 2>/dev/null || true

        if [ -s "$p12dir/graphql-targets.txt" ]; then
            nuclei -l "$p12dir/graphql-targets.txt" \
                -tags graphql \
                -rate-limit "$NUCLEI_RATE_LIMIT" \
                -timeout 10 \
                -o "$p12dir/graphql-findings.txt" \
                -silent 2>/dev/null
            [ -s "$p12dir/graphql-findings.txt" ] && \
                success "🚨 GraphQL issues found! → $p12dir/graphql-findings.txt"
        fi
    fi

    merge_phase_backup "$p12dir_backup"
    success "Phase 12 complete!"
    save_checkpoint 12
}

#==============================================================================#
#                           REPORT GENERATION                                  #
#==============================================================================#

generate_report() {
    local elapsed_mins="${1:-0}"
    local elapsed_secs="${2:-0}"

    print_phase "📋 GENERATING FINAL REPORT"

    local report_file="$OUTPUT_DIR/reports/recon-report.txt"

    cat > "$report_file" << EOF
================================================================================
                    BUG BOUNTY RECONNAISSANCE REPORT
                         Generated by NULLSEC
================================================================================

TARGET         : $TARGET
DATE           : $(date)
OUTPUT DIR     : $OUTPUT_DIR
SCAN DURATION  : ${elapsed_mins}m ${elapsed_secs}s

================================================================================
                           EXECUTIVE SUMMARY
================================================================================

SUBDOMAIN DISCOVERY:
  Total Enumerated   : $(count_lines "$OUTPUT_DIR/phase1-subdomains/all-subdomains.txt")
  Resolved / Valid   : $(count_lines "$OUTPUT_DIR/phase2-validation/valid-subdomains.txt")
  Wildcards Filtered : $(count_lines "$OUTPUT_DIR/phase2-validation/wildcards.txt")

LIVE WEB SERVICES:
  Live Hosts         : $(count_lines "$OUTPUT_DIR/phase3-probing/live-hosts.txt")
  Status 200         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-200.txt")
  Status 403         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-403.txt")
  Status 401         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-401.txt")
  Status 500         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-500.txt")

PORT SCANNING:
  Open Ports         : $(count_lines "$OUTPUT_DIR/phase4-portscan/open-ports.txt")
  Web on Alt Ports   : $(count_lines "$OUTPUT_DIR/phase4-portscan/services-on-ports.txt")

URL DISCOVERY:
  Total URLs         : $(count_lines "$OUTPUT_DIR/phase5-urls/all-urls.txt")
  API Endpoints      : $(count_lines "$OUTPUT_DIR/phase5-urls/api-endpoints.txt")
  Sensitive Endpoints: $(count_lines "$OUTPUT_DIR/phase5-urls/sensitive-endpoints.txt")
  Live JS Files      : $(count_lines "$OUTPUT_DIR/phase5-urls/live-js-files.txt")

ASSET SCORING:
  Hosts Scored       : $(count_lines "$OUTPUT_DIR/asset-scoring/scored-targets.txt")
  Top Targets (25%)  : $(count_lines "$OUTPUT_DIR/asset-scoring/top-targets.txt")

NUCLEI FINDINGS:
  Critical           : $(count_lines "$OUTPUT_DIR/phase7-vulns/critical-findings.txt")
  High / Medium      : $(count_lines "$OUTPUT_DIR/phase7-vulns/high-medium-findings.txt")
  CVEs               : $(count_lines "$OUTPUT_DIR/phase7-vulns/cve-findings.txt")
  Exposures          : $(count_lines "$OUTPUT_DIR/phase7-vulns/exposure-findings.txt")
  Subdomain Takeover : $(count_lines "$OUTPUT_DIR/phase2-validation/takeover-findings.txt")

CLOUD STORAGE:
  S3 Buckets Found       : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/s3/exists.txt")
  S3 Readable            : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/s3/readable.txt")
  S3 WRITABLE (CRITICAL) : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/s3/writable.txt")
  GCS Buckets Found      : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/gcs/exists.txt")
  GCS Readable           : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/gcs/readable.txt")
  Azure Accounts Found   : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/azure/exists.txt")
  Azure Readable         : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/azure/readable.txt")
  Total Exposed          : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/exposed/all-exposed-buckets.txt")

JAVASCRIPT SECRETS:
  TruffleHog Verified: $(count_lines "$OUTPUT_DIR/phase8-javascript/trufflehog-summary.txt")
  AWS Access Keys    : $(count_lines "$OUTPUT_DIR/phase8-javascript/aws-access-keys.txt")
  Google API Keys    : $(count_lines "$OUTPUT_DIR/phase8-javascript/google-api-keys.txt")
  GitHub Tokens      : $(count_lines "$OUTPUT_DIR/phase8-javascript/github-tokens.txt")
  Slack Tokens       : $(count_lines "$OUTPUT_DIR/phase8-javascript/slack-tokens.txt")
  Stripe Keys        : $(count_lines "$OUTPUT_DIR/phase8-javascript/stripe-keys.txt")
  Private Keys       : $(count_lines "$OUTPUT_DIR/phase8-javascript/private-keys.txt")

PATTERN HUNTING:
  SSRF Candidates    : $(count_lines "$OUTPUT_DIR/phase9-patterns/ssrf-candidates.txt")
  Open Redirects     : $(count_lines "$OUTPUT_DIR/phase9-patterns/redirect-candidates.txt")
  XSS Candidates     : $(count_lines "$OUTPUT_DIR/phase9-patterns/xss-candidates.txt")
  XSS Confirmed      : $(count_lines "$OUTPUT_DIR/phase9-patterns/dalfox-xss-confirmed.txt")
  SQLi Candidates    : $(count_lines "$OUTPUT_DIR/phase9-patterns/sqli-candidates.txt")
  LFI Candidates     : $(count_lines "$OUTPUT_DIR/phase9-patterns/lfi-candidates.txt")
  IDOR Candidates    : $(count_lines "$OUTPUT_DIR/phase9-patterns/idor-candidates.txt")
  CORS Issues        : $(count_lines "$OUTPUT_DIR/phase9-patterns/cors-findings.txt")
  Host Header Inject : $(count_lines "$OUTPUT_DIR/phase9-patterns/host-injection-findings.txt")

DIRECTORY FUZZING:
  Paths Discovered   : $(count_lines "$OUTPUT_DIR/phase11-fuzzing/dirs/all-found-paths.txt")

ACTIVE CONFIRMATION:
  SSRF Confirmed     : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/ssrf-confirmed.txt")
  Redirects Confirmed: $(count_lines "$OUTPUT_DIR/phase12-active-vulns/redirect-confirmed.txt")
  LFI Confirmed      : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/lfi-confirmed.txt")
  403 Bypasses       : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/403-bypass-confirmed.txt")
  GraphQL Issues     : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/graphql-findings.txt")

================================================================================
                         CRITICAL / HIGH FINDINGS
================================================================================

EOF

    for findings_file in \
        "$OUTPUT_DIR/phase7-vulns/critical-findings.txt" \
        "$OUTPUT_DIR/phase7-vulns/high-medium-findings.txt" \
        "$OUTPUT_DIR/phase2-validation/takeover-findings.txt" \
        "$OUTPUT_DIR/phase2.5-cloud/exposed/critical-writable.txt" \
        "$OUTPUT_DIR/phase2.5-cloud/exposed/all-exposed-buckets.txt" \
        "$OUTPUT_DIR/phase9-patterns/dalfox-xss-confirmed.txt" \
        "$OUTPUT_DIR/phase9-patterns/cors-findings.txt" \
        "$OUTPUT_DIR/phase12-active-vulns/ssrf-confirmed.txt" \
        "$OUTPUT_DIR/phase12-active-vulns/403-bypass-confirmed.txt" \
        "$OUTPUT_DIR/phase12-active-vulns/graphql-findings.txt"; do
        if [ -s "$findings_file" ]; then
            echo "--- $(basename "$findings_file") ---" >> "$report_file"
            cat "$findings_file" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    # ── Top scored targets ───────────────────────────────────────────────────
    if [ -s "$OUTPUT_DIR/asset-scoring/scored-targets.txt" ]; then
        cat >> "$report_file" << EOF

================================================================================
                        TOP SCORED TARGETS (by attack potential)
================================================================================

EOF
        head -25 "$OUTPUT_DIR/asset-scoring/scored-targets.txt" >> "$report_file"
        echo "" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

================================================================================
                         SECRETS FOUND IN JAVASCRIPT
================================================================================

EOF

    for secret_file in \
        "$OUTPUT_DIR/phase8-javascript/trufflehog-summary.txt" \
        "$OUTPUT_DIR/phase8-javascript/aws-access-keys.txt" \
        "$OUTPUT_DIR/phase8-javascript/google-api-keys.txt" \
        "$OUTPUT_DIR/phase8-javascript/github-tokens.txt" \
        "$OUTPUT_DIR/phase8-javascript/slack-tokens.txt" \
        "$OUTPUT_DIR/phase8-javascript/stripe-keys.txt" \
        "$OUTPUT_DIR/phase8-javascript/private-keys.txt"; do
        if [ -s "$secret_file" ]; then
            echo "--- $(basename "$secret_file") ---" >> "$report_file"
            cat "$secret_file" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF

================================================================================
                              END OF REPORT
================================================================================

Report generated by the NullSec Framework
Happy Hunting! 🐛

================================================================================
EOF

    success "Report generated: $report_file"
}

#==============================================================================#
#                               MAIN EXECUTION                                 #
#==============================================================================#

main() {
    local RESUME_DIR=""
    while getopts "d:o:m:surc:h" opt; do
        case $opt in
            d) TARGET="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            m) SCAN_MODE="$OPTARG" ;;
            s) SKIP_TOOL_CHECK=true ;;
            u) UPDATE_NUCLEI=true ;;
            r) RATE_LIMIT=true ;;
            c) RESUME_DIR="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [ -z "$TARGET" ]; then
        error "Target domain is required!"
        usage
    fi

    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./recon-$TARGET-$(date +%Y%m%d-%H%M%S)"
    fi

    # ── Resume / checkpoint setup ──────────────────────────────────────────
    # NOTE: CHECKPOINT_FILE is intentionally set *after* create_structure() below
    # so it always uses the absolute-resolved OUTPUT_DIR path.  Here we only
    # read the checkpoint if resuming — the file reference is valid because the
    # resume dir must already exist (validated above).
    if [ -n "$RESUME_DIR" ]; then
        if [ ! -d "$RESUME_DIR" ]; then
            error "Resume directory not found: $RESUME_DIR"
            exit 1
        fi
        OUTPUT_DIR="$RESUME_DIR"
        local early_checkpoint="$OUTPUT_DIR/.checkpoint"
        if [ -f "$early_checkpoint" ]; then
            RESUME_FROM=$(cat "$early_checkpoint")
            info "Resuming scan from checkpoint — phases 1-$RESUME_FROM already completed."
        else
            warn "No checkpoint file found in $RESUME_DIR — starting from Phase 1."
            RESUME_FROM=0
        fi
    else
        RESUME_FROM=0
    fi

    # Record scan start time for duration tracking
    local START_TIME
    START_TIME=$(date +%s)

    # Validate and apply scan mode (sets all RUN_* variables)
    apply_scan_mode

    print_banner

    info "Target          : $TARGET"
    info "Output Directory: $OUTPUT_DIR"
    info "Scan Mode       : $SCAN_MODE"
    info "Nuclei Update   : $UPDATE_NUCLEI"
    info "Rate Limiting   : $RATE_LIMIT"
    echo ""

    [ "$SKIP_TOOL_CHECK" = false ] && check_tools

    # ── Connectivity check ─────────────────────────────────────────────
    info "Checking internet connectivity..."
    
    # Using curl instead of 'host' or 'ping' to bypass UDP/53 or ICMP 
    # filtering common in strict firewalls and VPN tunnels.
    if ! curl -s --max-time 5 -o /dev/null -k https://1.1.1.1; then
        error "No internet connectivity detected. Check your network/VPN and try again."
        exit 1
    fi
    success "Internet connectivity OK"

    create_structure

    CHECKPOINT_FILE="$OUTPUT_DIR/.checkpoint"

    phase1_subdomain_discovery
    phase2_validation
    phase2_5_cloud_enum
    phase3_probing
    phase4_portscan
    phase5_url_discovery
    phase6_parameters
    phase_asset_scoring
    phase7_vulnerability_scanning

    # Phases 8-11 are independent — run in parallel.
    # Phase 9 and Phase 11 are individually wrapped in `timeout` to enforce the
    # per-mode wall-clock ceilings configured in apply_scan_mode().  This is the
    # structural fix for the 3-hour hang observed when dalfox was fed a large
    # candidate set with no upper bound.
    #
    # We use a subshell wrapper ( timeout ... sh -c "..." ) rather than
    # `bash -c 'function_name'` because shell functions are not exported to child
    # bash processes by default.  Instead we run the function directly inside a
    # subshell of the current process via ( ... ) which inherits all functions and
    # variables, then wrap that subshell in timeout via the outer & background job.
    #
    # _PARALLEL_PIDS is exposed globally so the SIGINT/SIGTERM trap can kill and
    # drain children before merging .bak files (BUG-4).
    local parallel_pids=()

    phase8_javascript_analysis &
    parallel_pids+=($!)

    # Phase 9 — wrap in PHASE9_WALL_TIMEOUT so a stuck dalfox/sqlmap sub-step
    # cannot block the parallel group indefinitely.  The subshell inherits all
    # functions and variables.  timeout sends SIGTERM to the subshell PID and then
    # SIGKILL after 60 s if it hasn't exited cleanly.
    ( trap '' INT; phase9_pattern_hunting ) &
    local _p9_pid=$!
    ( sleep "${PHASE9_WALL_TIMEOUT}"
      if kill -0 "$_p9_pid" 2>/dev/null; then
          warn "Phase 9 hit the ${PHASE9_WALL_TIMEOUT}s wall-clock timeout — stopping."
          kill -TERM "$_p9_pid" 2>/dev/null
          sleep 60
          kill -KILL "$_p9_pid" 2>/dev/null
      fi ) &
    local _p9_watchdog=$!
    parallel_pids+=($_p9_pid)

    phase10_screenshots &
    parallel_pids+=($!)

    # Phase 11 — same wall-clock watchdog pattern.
    ( trap '' INT; phase11_fuzzing ) &
    local _p11_pid=$!
    ( sleep "${PHASE11_WALL_TIMEOUT}"
      if kill -0 "$_p11_pid" 2>/dev/null; then
          warn "Phase 11 hit the ${PHASE11_WALL_TIMEOUT}s wall-clock timeout — stopping."
          kill -TERM "$_p11_pid" 2>/dev/null
          sleep 60
          kill -KILL "$_p11_pid" 2>/dev/null
      fi ) &
    local _p11_watchdog=$!
    parallel_pids+=($_p11_pid)

    # Expose PID list to the SIGINT/SIGTERM trap (BUG-4 / BUG-7).
    _PARALLEL_PIDS=("${parallel_pids[@]}" "$_p9_watchdog" "$_p11_watchdog")

    # Wait for all parallel phase PIDs and record failures (BUG-8).
    local phase_failed=false
    for pid in "${parallel_pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            local exit_code=$?
            if [ $exit_code -eq 143 ]; then
                # 143 = 128+SIGTERM — killed by watchdog timeout
                warn "A parallel phase (PID $pid) was stopped by its wall-clock timeout — partial results preserved."
            else
                warn "A parallel phase (PID $pid) exited with errors (code $exit_code) — continuing."
            fi
            phase_failed=true
        fi
    done

    # Clean up watchdog processes if phase finished before timeout.
    kill -TERM "$_p9_watchdog"  2>/dev/null; wait "$_p9_watchdog"  2>/dev/null || true
    kill -TERM "$_p11_watchdog" 2>/dev/null; wait "$_p11_watchdog" 2>/dev/null || true

    # All children have exited — clear global so trap doesn't try to kill reaped PIDs.
    _PARALLEL_PIDS=()
    [ "$phase_failed" = false ] && success "Phases 8–11 completed in parallel."

    # Only advance the checkpoint when every parallel phase succeeded (BUG-6).
    # A failed/timed-out run leaves the checkpoint at 7 so resume re-runs 8–11
    # rather than skipping to Phase 12 with incomplete Phase 9 findings.
    if [ "$phase_failed" = false ]; then
        save_checkpoint 11
    else
        warn "One or more parallel phases failed or timed out — checkpoint NOT advanced to 11."
        warn "Re-run with -c '$OUTPUT_DIR' after investigating to resume from Phase 8."
    fi

    # Phase 12 depends on Phase 9 findings — must run after parallel block
    phase12_active_vulns

    local END_TIME ELAPSED_SECS elapsed_mins elapsed_secs
    END_TIME=$(date +%s)
    ELAPSED_SECS=$(( END_TIME - START_TIME ))
    elapsed_mins=$(( ELAPSED_SECS / 60 ))
    elapsed_secs=$(( ELAPSED_SECS % 60 ))

    generate_report "$elapsed_mins" "$elapsed_secs"

    # ── Scan complete notification ─────────────────────────────────────────────
    # Build a compact summary from the same counters used in the report so the
    # Telegram alert gives you the headline numbers without opening the report.
    local nc_subs nc_live nc_crit nc_high nc_buckets nc_secrets
    nc_subs=$(count_lines "$OUTPUT_DIR/phase1-subdomains/all-subdomains.txt")
    nc_live=$(count_lines "$OUTPUT_DIR/phase3-probing/live-hosts.txt")
    nc_crit=$(count_lines "$OUTPUT_DIR/phase7-vulns/critical-findings.txt")
    nc_high=$(count_lines "$OUTPUT_DIR/phase7-vulns/high-medium-findings.txt")
    nc_buckets=$(count_lines "$OUTPUT_DIR/phase2.5-cloud/exposed/all-exposed-buckets.txt")
    nc_secrets=$(count_lines "$OUTPUT_DIR/phase8-javascript/trufflehog-summary.txt")
    notify "✅ Scan Complete — ${TARGET}" \
        "All 12 phases finished in *${elapsed_mins}m ${elapsed_secs}s*\n\nSubdomains: *${nc_subs}* | Live: *${nc_live}*\nCritical vulns: *${nc_crit}* | High/Med: *${nc_high}*\nExposed buckets: *${nc_buckets}* | JS secrets: *${nc_secrets}*\n\nReport: \`${OUTPUT_DIR}/reports/recon-report.txt\`"

    print_phase "🎉 RECONNAISSANCE COMPLETE!"

    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║                    RECONNAISSANCE COMPLETED SUCCESSFULLY!                    ║"
    echo "║                             NullSec Framework                                ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    info "Output Directory : $OUTPUT_DIR"
    info "Report           : $OUTPUT_DIR/reports/recon-report.txt"
    info "Total Scan Time  : ${elapsed_mins}m ${elapsed_secs}s"
    info ""
    info "Happy Hunting! 🐛"
}

main "$@"
