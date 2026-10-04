#!/usr/bin/env bash
# log-analyzer.sh
# Name:    Raul Melendez
# Userid:  rmelendez
# Purpose: Summarize an Apache combined-format access log (totals, status
#          codes, top URLs/IPs, 404s, suspicious probes, user agents) and
#          optionally email the report, for a daily cron job. 95-799 Lab 6.
#
# Usage: log-analyzer.sh [-s minigolf|portal|portfolio|all] [-f /path/to/access.log]
#                        [-d today|yesterday] [-n 10] [--anonymize] [--mail] [--out file]
#        With no arguments, prompts interactively.

set -euo pipefail

# --- Defaults ---------------------------------------------------------------
SITE=""
LOGFILE=""
DAY="today"
TOPN=10
ANONYMIZE=0
MAIL=0
OUTFILE=""

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/log-analyzer.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT

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
        NF = split(line, f, "\"")
        if (NF < 6) next
        for (i = 1; i <= NF; i++) gsub(/\001/, "\"", f[i])
        $1 = f[1]; $2 = f[2]; $3 = f[3]; $6 = f[6]

        # $1 = `ip - user [dd/Mon/yyyy:hh:mm:ss zone] `
        n = split($1, a, " ")
        ip = a[1]
        ts = a[4]; sub(/^\[/, "", ts)

        # $2 = `METHOD /path HTTP/1.1` (may be garbage from port scanners)
        split($2, r, " ")
        method = (r[1] == "") ? "-" : r[1]
        path   = (r[2] == "") ? "-" : r[2]

        # $3 = ` status bytes `
        split($3, s, " ")
        status = s[1]
        bytes  = (s[2] == "-" || s[2] == "") ? 0 : s[2]

        ua = ($6 == "") ? "-" : $6
        gsub(/\t/, " ", ua); gsub(/\t/, " ", path)

        if (status ~ /^[0-9][0-9][0-9]$/)
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ip, ts, method, path, status, bytes, ua
    }' "$logfile" > "$tsv"
}

# Pretty-print "count<TAB>value" lines as a right-aligned table.
print_counts() {
    awk -F'\t' '{ printf "  %8d  %s\n", $1, $2 }'
}

# Top-N of a single column: cut | sort | uniq -c is the classic pipeline.
top_n() {
    local tsv=$1 col=$2 n=$3
    cut -f"$col" "$tsv" | sort | uniq -c | sort -rn | head -n "$n" \
        | awk '{ c=$1; $1=""; sub(/^ /, ""); printf "%d\t%s\n", c, $0 }'
}

human_bytes() {
    awk -v b="$1" 'BEGIN {
        split("B KB MB GB TB", u, " "); i = 1
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        printf (i == 1 ? "%d %s" : "%.1f %s"), b, u[i]
    }'
}

# --- Report sections --------------------------------------------------------
section_header() {
    printf '\n== %s ==\n' "$1"
}

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
        END {
            for (c in n) printf "%s\t%d\t%.1f\n", c, n[c], 100 * n[c] / total
        }' "$tsv" | sort | awk -F'\t' '{ printf "  %-4s %8d  (%5.1f%%)\n", $1, $2, $3 }'

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

# --- Driver -----------------------------------------------------------------
analyze_file() {
    local logfile=$1 label=$2
    local tsv="$WORKDIR/$(basename "$logfile").tsv"

    [[ -r "$logfile" ]] || { echo "error: cannot read $logfile" >&2; return 1; }
    parse_log "$logfile" "$tsv"

    printf '\n######## %s ########\n' "$label"
    printf 'Log file: %s\n' "$logfile"
    if [[ ! -s "$tsv" ]]; then
        echo "  (no parseable requests)"
        return 0
    fi

    section_totals   "$tsv"
    section_status   "$tsv"
    section_top_urls "$tsv"
    section_top_ips  "$tsv"
}

main() {
    # Temporary: step 2 only accepts a log path; getopts arrives in step 3.
    LOGFILE=${1:-}
    [[ -n "$LOGFILE" ]] || { echo "usage: $0 /path/to/access.log" >&2; exit 2; }

    printf 'Apache Log Report  (generated %s on %s)\n' "$(date '+%Y-%m-%d %H:%M %Z')" "$(hostname)"
    analyze_file "$LOGFILE" "$(basename "$LOGFILE")"
}

main "$@"
