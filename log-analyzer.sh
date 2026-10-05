#!/usr/bin/env bash
# log-analyzer.sh
# Name:    Raul Melendez
# Userid:  janayame
# Purpose: Summarize an Apache combined-format access log (totals, status
#          codes, top URLs/IPs, 404s, suspicious probes, user agents) and
#          optionally email the report, for a daily cron job. 95-799 Lab 6.
#
# Usage: log-analyzer.sh [-s minigolf|portal|portfolio|all] [-f /path/to/access.log]
#                        [-d today|yesterday] [-n 10] [--anonymize] [--mail] [--out file]
#        With no arguments, prompts interactively.  -h for help.
#
# Read-only against the server: reads logs, writes only under $HOME (or --out).
# Mail credentials live in ~/.config/log-analyzer/mail.env, never in this file.

set -u
export LC_ALL=C      # consistent sort/comm/uniq ordering regardless of login locale

# --- Defaults ---------------------------------------------------------------
SITE=""
LOGFILE=""
DAY="today"
TOPN=10
ANONYMIZE=0
MAIL=0
OUTFILE=""
LOG_DIR=${LOG_DIR:-/var/log/apache2}                 # override for testing
MAIL_ENV=${MAIL_ENV:-$HOME/.config/log-analyzer/mail.env}
SITES_ALL="minigolf portal portfolio"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/log-analyzer.XXXXXX") || exit 1
trap 'rm -rf "$WORKDIR"' EXIT

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    cat <<USAGE

Options:
  -s SITE       minigolf | portal | portfolio | all   (log paths under $LOG_DIR)
  -f FILE       analyze this log file instead (e.g. an instructor sample)
  -d DAY        today (live log) | yesterday (rotated *.log.1)   [default: today]
  -n N          show top N entries per table                     [default: 10]
  -a, --anonymize   mask IPs in the report (IPv4 last octet, IPv6 tail)
  -m, --mail        email the report (implies --anonymize); needs $MAIL_ENV
  -o, --out FILE    also write the report to FILE
  -h, --help        this help
USAGE
}

die() { echo "log-analyzer: $*" >&2; exit 1; }

# --- Site map ---------------------------------------------------------------
# case: translate a site name into its Apache access log.
site_log() {
    local site=$1 suffix=""
    [[ $DAY == yesterday ]] && suffix=".1"
    case $site in
        minigolf)  echo "$LOG_DIR/access.log$suffix" ;;
        portal)    echo "$LOG_DIR/portal-access.log$suffix" ;;
        portfolio) echo "$LOG_DIR/portfolio-access.log$suffix" ;;
        *)         die "unknown site '$site' (use minigolf, portal, portfolio, all)" ;;
    esac
}

# --- Parsing ----------------------------------------------------------------
# Convert an Apache "combined" log into a tab-separated file (file format
# conversion), one record per request, so every section below can work from
# the same clean columns:
#   1 ip  2 timestamp  3 method  4 path  5 status  6 bytes  7 user-agent
# Splitting on the double quote is more robust than splitting on spaces
# because the request line and user agent contain spaces themselves.
parse_log() {
    local logfile=$1 tsv=$2
    awk '
    {
        # Apache writes embedded quotes as \" ; hide them before splitting on
        # the quote character, then restore them inside the fields.
        line = $0
        gsub(/\\"/, "\001", line)
        nf = split(line, f, "\"")
        if (nf < 6) next
        for (i = 1; i <= nf; i++) gsub(/\001/, "\"", f[i])

        # f[1] = `ip - user [dd/Mon/yyyy:hh:mm:ss zone] `
        split(f[1], a, " ")
        ip = a[1]
        ts = a[4]; sub(/^\[/, "", ts)

        # f[2] = `METHOD /path HTTP/1.1` (may be garbage from port scanners)
        split(f[2], r, " ")
        method = (r[1] == "") ? "-" : r[1]
        path   = (r[2] == "") ? "-" : r[2]

        # f[3] = ` status bytes `
        split(f[3], s, " ")
        status = s[1]
        bytes  = (s[2] == "-" || s[2] == "") ? 0 : s[2]

        ua = (f[6] == "") ? "-" : f[6]
        gsub(/\t/, " ", ua); gsub(/\t/, " ", path)

        # Apache pings itself ("OPTIONS *") to wake worker processes; not a visitor.
        if (index(ua, "(internal dummy connection)")) next

        if (status ~ /^[0-9][0-9][0-9]$/)
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ip, ts, method, path, status, bytes, ua
    }' "$logfile" > "$tsv"
}

# --- Helpers ----------------------------------------------------------------
# Pretty-print "count<TAB>value" lines as a right-aligned table.
print_counts() {
    awk -F'\t' 'BEGIN { n = 0 } { n++; printf "  %8d  %s\n", $1, $2 }
                END { if (n == 0) print "  (none)" }'
}

# Top-N of one column of a TSV (or of stdin when file is "-"):
# cut | sort | uniq -c | sort -rn | head is the classic pipeline.
top_n() {
    local tsv=$1 col=$2 n=$3
    cut -f"$col" "$tsv" | sort | uniq -c | sort -rn | head -n "$n" \
        | awk '{ c = $1; $1 = ""; sub(/^ /, ""); printf "%d\t%s\n", c, $0 }'
}

human_bytes() {
    awk -v b="$1" 'BEGIN {
        split("B KB MB GB TB", u, " "); i = 1
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        printf (i == 1 ? "%d %s" : "%.1f %s"), b, u[i]
    }'
}

# Mask IP addresses in a text stream (visitor privacy for anything that
# leaves the server).  Only whitespace-bounded tokens are considered, so
# timestamps like 03/Oct/2026:00:04:16 and version strings like
# Safari/13.0.0.0 are untouched, and column alignment is preserved.
#   IPv4  203.0.113.57            -> 203.0.113.x
#   IPv6  2a06:98c0:3600::103     -> 2a06:98c0:3600:xxxx
mask_ips() {
    awk '
    function mask(tok,    h) {
        if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
            sub(/\.[0-9]+$/, ".x", tok)
        } else if (tok ~ /^[0-9a-fA-F:]+$/ && tok ~ /:.*:/) {
            split(tok, h, ":")
            tok = h[1] ":" h[2] ":" h[3] ":xxxx"
        }
        return tok
    }
    {
        out = ""; rest = $0
        # Walk the line: copy whitespace runs verbatim, mask each word.
        while (match(rest, /[^ \t]+/)) {
            out = out substr(rest, 1, RSTART - 1) mask(substr(rest, RSTART, RLENGTH))
            rest = substr(rest, RSTART + RLENGTH)
        }
        print out rest
    }'
}

# --- Report sections (one function each) ------------------------------------
section_header() { printf '\n== %s ==\n' "$1"; }

section_totals() {
    local tsv=$1
    local requests unique_ips bytes first last
    requests=$(wc -l < "$tsv" | tr -d ' ')
    unique_ips=$(cut -f1 "$tsv" | sort -u | wc -l | tr -d ' ')
    bytes=$(awk -F'\t' '{ b += $6 } END { print b + 0 }' "$tsv")
    first=$(head -n1 "$tsv" | cut -f2)
    last=$(tail -n1 "$tsv" | cut -f2)

    section_header "Totals"
    printf '  %-16s %s\n' "Requests:"    "$requests"
    printf '  %-16s %s\n' "Unique IPs:"  "$unique_ips"
    printf '  %-16s %s (%s)\n' "Bytes sent:" "$bytes" "$(human_bytes "$bytes")"
    printf '  %-16s %s\n' "First entry:" "${first:--}"
    printf '  %-16s %s\n' "Last entry:"  "${last:--}"
}

section_status() {
    local tsv=$1
    section_header "Responses by status class"
    awk -F'\t' '
        { cls = substr($5, 1, 1) "xx"; n[cls]++; total++ }
        END { for (c in n) printf "%s\t%d\t%.1f\n", c, n[c], 100 * n[c] / total }
    ' "$tsv" | sort | awk -F'\t' '{ printf "  %-4s %8d  (%5.1f%%)\n", $1, $2, $3 }'

    section_header "Top status codes"
    top_n "$tsv" 5 "$TOPN" | print_counts
}

section_top_urls() {
    local tsv=$1
    section_header "Top $TOPN requested paths"
    top_n "$tsv" 4 "$TOPN" | print_counts
}

section_top_ips() {
    local tsv=$1
    section_header "Top $TOPN client IPs"
    top_n "$tsv" 1 "$TOPN" | print_counts
}

section_404s() {
    local tsv=$1
    section_header "Top $TOPN paths returning 404"
    awk -F'\t' '$5 == "404"' "$tsv" > "$WORKDIR/404.tsv"
    top_n "$WORKDIR/404.tsv" 4 "$TOPN" | print_counts
}

# Paths and user agents that are almost always vulnerability scanners.
# (lower-case: they are matched against lower-cased fields; exported so awk
# reads them via ENVIRON and does not mangle the backslashes)
export PROBE_PATHS='/wp-login\.php|/wp-admin|/xmlrpc\.php|/\.env|/\.git|/phpmyadmin|/cgi-bin|/\.aws|/actuator|/\.ds_store|/vendor/phpunit|/boaform|/hnap1|/shell\?|\.php$'
export PROBE_UAS='sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan|acunetix|nessus|openvas|censys|internetmeasurement|l9explore|paloaltonetworks'

section_probes() {
    local tsv=$1 probes="$WORKDIR/probes.tsv"
    awk -F'\t' 'tolower($4) ~ ENVIRON["PROBE_PATHS"] || tolower($7) ~ ENVIRON["PROBE_UAS"]' \
        "$tsv" > "$probes"
    local count ips
    count=$(wc -l < "$probes" | tr -d ' ')
    ips=$(cut -f1 "$probes" | sort -u | wc -l | tr -d ' ')

    section_header "Suspicious probes (scanner paths / user agents)"
    printf '  %-16s %s\n' "Probe requests:" "$count"
    printf '  %-16s %s\n' "Probing IPs:"    "$ips"
    if [[ $count -gt 0 ]]; then
        echo "  Top probed paths:"
        top_n "$probes" 4 "$TOPN" | print_counts | sed 's/^/  /'
        echo "  Top probing IPs:"
        top_n "$probes" 1 "$TOPN" | print_counts | sed 's/^/  /'
    fi

    # The one line that matters: a probe that got a 2xx means the thing
    # being probed for actually exists and was served.  Should always be none.
    echo "  !! Probes that SUCCEEDED (2xx):"
    # (path matches only: a scanner UA fetching "/" is not a finding)
    awk -F'\t' '$5 ~ /^2/ && tolower($4) ~ ENVIRON["PROBE_PATHS"]' "$probes" > "$WORKDIR/probes-ok.tsv"
    top_n "$WORKDIR/probes-ok.tsv" 4 "$TOPN" | print_counts | sed 's/^/  /'
}

# Login attempts: many POSTs to a login path from one IP is password guessing;
# a POST followed by a 302 is a successful login (check the IP is yours).
section_logins() {
    local tsv=$1 logins="$WORKDIR/logins.tsv"
    awk -F'\t' '$3 == "POST" && tolower($4) ~ /login|wp-login|signin|auth/' "$tsv" > "$logins"
    section_header "Login POSTs (password guessing / successful sign-ins)"
    printf '  %-16s %s\n' "Login POSTs:" "$(wc -l < "$logins" | tr -d ' ')"
    if [[ -s $logins ]]; then
        echo "  By IP, with outcome (302 = accepted, 419/422/401 = rejected):"
        awk -F'\t' '{ printf "%s %s\n", $1, $5 }' "$logins" | sort | uniq -c | sort -rn \
            | head -n "$TOPN" | awk '{ printf "  %8d  %s  -> %s\n", $1, $2, $3 }'
    fi
}

section_user_agents() {
    local tsv=$1
    section_header "Top $TOPN user agents"
    top_n "$tsv" 7 "$TOPN" | cut -c1-110 | print_counts
}

# Mini golf site only: the marketing page fires tracking pixels when a
# visitor taps "Call" or "Get a quote".
section_conversions() {
    local tsv=$1
    section_header "Mini golf conversions (tracking pixels)"
    for pixel in call quote; do
        awk -F'\t' -v p="/track/$pixel.gif" -v name="$pixel" '
            index($4, p) == 1 { hits++; ip[$1] = 1 }
            END { n = 0; for (k in ip) n++
                  printf "  %-7s taps: %4d   unique visitors: %4d\n", name, hits + 0, n }
        ' "$tsv"
    done
}

# Set operations across sites: which visitors touched more than one site?
section_cross_site() {
    local sites=("$@") a b
    section_header "Cross-site visitors (set intersection of unique IPs)"
    for ((i = 0; i < ${#sites[@]}; i++)); do
        for ((j = i + 1; j < ${#sites[@]}; j++)); do
            a=${sites[i]}; b=${sites[j]}
            printf '  %-10s and %-10s %4d shared IPs\n' "$a" "$b" \
                "$(comm -12 "$WORKDIR/ips.$a" "$WORKDIR/ips.$b" | wc -l | tr -d ' ')"
        done
    done
    echo "  IPs seen on 2+ sites (top $TOPN by request count):"
    sort "$WORKDIR"/ips.* | uniq -d > "$WORKDIR/ips.multi"
    if [[ -s "$WORKDIR/ips.multi" ]]; then
        # Join the multi-site IP set back to all requests to rank them.
        awk -F'\t' 'NR == FNR { keep[$1] = 1; next } ($1 in keep) { n[$1]++ }
                    END { for (k in n) printf "%d\t%s\n", n[k], k }' \
            "$WORKDIR/ips.multi" "$WORKDIR"/*.site.tsv \
            | sort -rn | head -n "$TOPN" | print_counts | sed 's/^/  /'
    else
        echo "    (none)"
    fi
}

# --- Driver -----------------------------------------------------------------
analyze_file() {
    local logfile=$1 label=$2 site=${3:-}
    local tsv="$WORKDIR/$label.site.tsv"

    printf '\n######## %s ########\n' "$label"
    printf 'Log file: %s\n' "$logfile"
    if [[ ! -r "$logfile" ]]; then
        echo "  ERROR: cannot read $logfile"
        return 1
    fi
    parse_log "$logfile" "$tsv"
    if [[ ! -s "$tsv" ]]; then
        echo "  (no parseable requests)"
        return 0
    fi
    cut -f1 "$tsv" | sort -u > "$WORKDIR/ips.$label"

    section_totals      "$tsv"
    section_status      "$tsv"
    section_top_urls    "$tsv"
    section_top_ips     "$tsv"
    section_404s        "$tsv"
    section_probes      "$tsv"
    section_logins      "$tsv"
    section_user_agents "$tsv"
    [[ $site == minigolf ]] && section_conversions "$tsv"
    return 0
}

# Printed at the top of every report so the daily habit is in the email itself.
print_daily_read() {
    cat <<'CHECK'

-- The 30-second daily read --------------------------------------------
  1. "Probes that SUCCEEDED" says none on every site.
  2. "Login POSTs" is zero, or only your own IP prefix with a 302.
  3. The status class table has no 5xx line.
  4. Totals and top IPs look roughly like the day before.
  If all four hold, the day was normal. Everything else in the report is
  context for when one of them doesn't.
------------------------------------------------------------------------
CHECK
}

build_report() {
    local report=$1 targets=() s rc=0
    {
        printf 'Apache Log Report  (generated %s on %s)\n' \
            "$(date '+%Y-%m-%d %H:%M %Z')" "$(hostname)"
        printf 'Covering: %s\n' "$DAY"
        print_daily_read

        if [[ -n $LOGFILE ]]; then
            analyze_file "$LOGFILE" "$(basename "$LOGFILE")" || rc=1
        else
            [[ $SITE == all ]] && targets=($SITES_ALL) || targets=("$SITE")
            for s in "${targets[@]}"; do
                analyze_file "$(site_log "$s")" "$s" "$s" || rc=1
            done
            [[ ${#targets[@]} -gt 1 ]] && section_cross_site "${targets[@]}"
        fi
        printf '\n-- end of report --\n'
    } > "$report"
    if [[ $ANONYMIZE -eq 1 ]]; then
        mask_ips < "$report" > "$report.masked" && mv "$report.masked" "$report"
    fi
    return $rc
}

# --- Mail -------------------------------------------------------------------
# The server has no MTA, so talk SMTP to Gmail directly with curl.  The
# credentials file (chmod 600) defines MAIL_FROM, MAIL_APP_PASSWORD and
# optionally MAIL_TO (defaults to MAIL_FROM).
send_mail() {
    local report=$1 msg="$WORKDIR/message.eml" subject
    [[ -r $MAIL_ENV ]] || die "mail: $MAIL_ENV not found or unreadable"
    local perms
    perms=$(stat -c '%a' "$MAIL_ENV" 2>/dev/null || stat -f '%Lp' "$MAIL_ENV")
    [[ $perms == 600 ]] || echo "warning: $MAIL_ENV should be chmod 600 (is $perms)" >&2
    # Read KEY=VALUE lines ourselves instead of sourcing the file, so a value
    # with spaces (Google shows app passwords as "xxxx xxxx xxxx xxxx") or odd
    # characters can never be executed as shell.
    local key val
    while IFS='=' read -r key val || [[ -n $key ]]; do
        key=${key//[[:space:]]/}
        [[ -z $key || $key == \#* ]] && continue
        val=${val%\"}; val=${val#\"}; val=${val%\'}; val=${val#\'}
        case $key in
            MAIL_FROM)         MAIL_FROM=${val//[[:space:]]/} ;;
            MAIL_TO)           MAIL_TO=${val//[[:space:]]/} ;;
            MAIL_APP_PASSWORD) MAIL_APP_PASSWORD=${val//[[:space:]]/} ;;
            MAIL_SMTP)         MAIL_SMTP=${val//[[:space:]]/} ;;
        esac
    done < "$MAIL_ENV"
    [[ -n ${MAIL_FROM:-} ]]         || die "mail: MAIL_FROM missing in $MAIL_ENV"
    [[ -n ${MAIL_APP_PASSWORD:-} ]] || die "mail: MAIL_APP_PASSWORD missing in $MAIL_ENV"
    MAIL_TO=${MAIL_TO:-$MAIL_FROM}          # default: send the report to yourself

    subject="Apache log report: ${LOGFILE:+$(basename "$LOGFILE")}${SITE} ($DAY, $(date +%Y-%m-%d))"
    {
        printf 'From: %s\nTo: %s\nSubject: %s\nDate: %s\n' \
            "$MAIL_FROM" "$MAIL_TO" "$subject" "$(date -R 2>/dev/null || date '+%a, %d %b %Y %T %z')"
        printf 'MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n'
        cat "$report"
    } > "$msg"

    if curl --silent --show-error --ssl-reqd --url "${MAIL_SMTP:-smtps://smtp.gmail.com:465}" \
            --mail-from "$MAIL_FROM" --mail-rcpt "$MAIL_TO" \
            --user "$MAIL_FROM:$MAIL_APP_PASSWORD" --upload-file "$msg"; then
        echo "$(date '+%F %T') mail: report sent to $MAIL_TO"
        # Keep a copy of exactly what was sent (headers included) under $HOME.
        local sent_dir="$HOME/log-analyzer/sent"
        mkdir -p "$sent_dir" && cp "$msg" "$sent_dir/report-$(date +%Y-%m-%d-%H%M).eml" \
            && echo "mail: copy saved in $sent_dir"
    else
        die "mail: sending failed"
    fi
}

# --- Interactive mode (typed input) -----------------------------------------
prompt_user() {
    local ans
    echo "No options given; answer a few questions (Enter accepts the default)."
    read -r -p "Site [minigolf/portal/portfolio/all] (all): " ans
    SITE=${ans:-all}
    read -r -p "Day [today/yesterday] (today): " ans
    DAY=${ans:-today}
    read -r -p "How many entries per table? (10): " ans
    TOPN=${ans:-10}
    read -r -p "Mask IP addresses? [y/N]: " ans
    [[ $ans =~ ^[Yy] ]] && ANONYMIZE=1
}

# --- Argument handling ------------------------------------------------------
parse_args() {
    local args=() a
    # getopts only knows single letters, so fold the long forms first.
    for a in "$@"; do
        case $a in
            --anonymize) args+=(-a) ;;
            --mail)      args+=(-m) ;;
            --out)       args+=(-o) ;;
            --help)      args+=(-h) ;;
            --*)         die "unknown option $a (try -h)" ;;
            *)           args+=("$a") ;;
        esac
    done
    set -- "${args[@]}"

    local opt
    while getopts ":s:f:d:n:amo:h" opt; do
        case $opt in
            s) SITE=$OPTARG ;;
            f) LOGFILE=$OPTARG ;;
            d) DAY=$OPTARG ;;
            n) TOPN=$OPTARG ;;
            a) ANONYMIZE=1 ;;
            m) MAIL=1; ANONYMIZE=1 ;;
            o) OUTFILE=$OPTARG ;;
            h) usage; exit 0 ;;
            :) die "option -$OPTARG needs a value (try -h)" ;;
            \?) die "unknown option -$OPTARG (try -h)" ;;
        esac
    done
    shift $((OPTIND - 1))
    [[ $# -eq 0 ]] || die "unexpected argument '$1' (use -f for a log file)"
}

validate() {
    [[ $TOPN =~ ^[1-9][0-9]*$ ]] || die "-n must be a positive integer, got '$TOPN'"
    case $DAY in today|yesterday) ;; *) die "-d must be today or yesterday" ;; esac
    if [[ -n $LOGFILE ]]; then
        [[ -r $LOGFILE ]] || die "cannot read log file $LOGFILE"
        SITE=""
    else
        [[ -n $SITE ]] || die "give -s SITE or -f FILE (or run with no arguments)"
        [[ $SITE == all ]] || site_log "$SITE" > /dev/null || exit 1
    fi
}

main() {
    if [[ $# -eq 0 ]]; then
        prompt_user
    else
        parse_args "$@"
    fi
    validate

    local report="$WORKDIR/report.txt" rc
    build_report "$report"; rc=$?

    if [[ -n $OUTFILE ]]; then
        mkdir -p "$(dirname "$OUTFILE")" && cp "$report" "$OUTFILE" \
            && echo "report written to $OUTFILE" >&2
    fi
    if [[ $MAIL -eq 1 ]]; then
        send_mail "$report"
    fi
    if [[ -z $OUTFILE && $MAIL -eq 0 ]]; then
        cat "$report"
    fi
    return $rc
}

main "$@"
