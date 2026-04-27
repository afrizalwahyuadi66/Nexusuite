#!/usr/bin/env bash

set -u

_POLICY_FILE_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config/risk_policy.yaml"
RISK_POLICY_FILE="${RISK_POLICY_FILE:-${AI_RISK_POLICY_FILE:-$_POLICY_FILE_DEFAULT}}"

policy_get() {
    local key="$1"
    local default="${2:-}"
    local line=""
    if [[ ! -f "$RISK_POLICY_FILE" ]]; then
        printf '%s' "$default"
        return 0
    fi
    line="$(grep -E "^[[:space:]]*${key}:[[:space:]]*" "$RISK_POLICY_FILE" | head -n 1 || true)"
    if [[ -z "$line" ]]; then
        printf '%s' "$default"
        return 0
    fi
    line="${line#*:}"
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    printf '%s' "$line"
}

_csv_has_token() {
    local csv="$1"
    local token="$2"
    IFS=',' read -r -a _arr <<< "$csv"
    local t=""
    for t in "${_arr[@]}"; do
        t="$(echo "$t" | xargs)"
        [[ -z "$t" ]] && continue
        [[ "$t" == "$token" ]] && return 0
    done
    return 1
}

classify_command_tier() {
    local cmd="$1"
    local tok=""
    read -r tok _ <<< "$cmd"
    [[ -z "$tok" ]] && { printf 'high'; return 0; }

    local low_tokens medium_tokens high_tokens
    low_tokens="$(policy_get tier_low_tokens 'curl,httpx,wafw00f,nikto,searchsploit,gau,subfinder')"
    medium_tokens="$(policy_get tier_medium_tokens 'nmap,nuclei,ffuf,katana,arjun,paramspider')"
    high_tokens="$(policy_get tier_high_tokens 'sqlmap,dalfox,wapiti')"

    if _csv_has_token "$high_tokens" "$tok"; then
        printf 'high'; return 0
    fi
    if _csv_has_token "$medium_tokens" "$tok"; then
        printf 'medium'; return 0
    fi
    if _csv_has_token "$low_tokens" "$tok"; then
        printf 'low'; return 0
    fi
    printf 'high'
}

is_flag_blocked_by_policy() {
    local cmd="$1"
    local blocked flags f
    blocked="$(policy_get blocked_flags '--os-shell,--sql-shell,--os-pwn,--file-write,--file-dest,msfconsole')"
    IFS=',' read -r -a flags <<< "$blocked"
    for f in "${flags[@]}"; do
        f="$(echo "$f" | xargs)"
        [[ -z "$f" ]] && continue
        if [[ "$cmd" == *"$f"* ]]; then
            return 0
        fi
    done
    return 1
}

target_in_allowlist() {
    local target="$1"
    local allowlist
    allowlist="$(policy_get scope_allowlist '')"
    [[ -z "$allowlist" ]] && return 0

    IFS=',' read -r -a entries <<< "$allowlist"
    local e=""
    for e in "${entries[@]}"; do
        e="$(echo "$e" | xargs)"
        [[ -z "$e" ]] && continue
        if [[ "$target" == "$e" || "$target" == *".${e}" ]]; then
            return 0
        fi
    done
    return 1
}

_normalize_target_host() {
    local t="$1"
    t="${t#http://}"
    t="${t#https://}"
    t="${t%%/*}"
    t="${t,,}"

    # [ipv6]:port or [ipv6]
    if [[ "$t" =~ ^\[([0-9a-fA-F:]+)\](:[0-9]+)?$ ]]; then
        t="${BASH_REMATCH[1]}"
    # host:port (non-IPv6 literal)
    elif [[ "$t" =~ ^[^:]+:[0-9]+$ ]]; then
        t="${t%%:*}"
    fi

    printf '%s' "$t"
}

_is_ipv4_literal() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

_is_ipv6_literal() {
    local ip="$1"
    [[ "$ip" == *:* ]]
}

_is_private_ipv4() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"

    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1

    # RFC1918 + loopback + link-local + CGNAT
    [[ "$a" -eq 10 ]] && return 0
    [[ "$a" -eq 127 ]] && return 0
    [[ "$a" -eq 192 && "$b" -eq 168 ]] && return 0
    [[ "$a" -eq 172 && "$b" -ge 16 && "$b" -le 31 ]] && return 0
    [[ "$a" -eq 169 && "$b" -eq 254 ]] && return 0
    [[ "$a" -eq 100 && "$b" -ge 64 && "$b" -le 127 ]] && return 0

    return 1
}

_is_private_ipv6() {
    local ip="${1,,}"

    [[ "$ip" == "::1" ]] && return 0
    # Unique local addresses fc00::/7
    [[ "$ip" =~ ^f[c-d] ]] && return 0
    # Link-local addresses fe80::/10
    [[ "$ip" =~ ^fe[89ab] ]] && return 0

    return 1
}

_resolve_target_ips() {
    local host="$(_normalize_target_host "$1")"
    [[ -n "$host" ]] || return 0

    if _is_ipv4_literal "$host" || _is_ipv6_literal "$host"; then
        printf '%s\n' "$host"
        return 0
    fi

    if [[ "$host" == "localhost" || "$host" == *".localhost" ]]; then
        printf '%s\n' "127.0.0.1" "::1"
        return 0
    fi

    if command -v getent >/dev/null 2>&1; then
        getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u
        return 0
    fi

    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$host" 2>/dev/null | awk '/^Address: /{print $2}' | sort -u
        return 0
    fi
}

_csv_trimmed_iter() {
    local csv="$1"
    local raw
    IFS=',' read -r -a _csv_arr <<< "$csv"
    for raw in "${_csv_arr[@]}"; do
        raw="$(echo "$raw" | xargs)"
        [[ -n "$raw" ]] && printf '%s\n' "$raw"
    done
}

target_blocked_by_scope_policy() {
    local host="$(_normalize_target_host "$1")"
    local item blocklist blocked_suffixes
    [[ -n "$host" ]] || return 1

    blocklist="$(policy_get scope_blocklist '')"
    blocked_suffixes="$(policy_get scope_blocked_suffixes '.internal,.corp,.lan,.local,home.arpa')"

    # Explicit blocklist: exact host or wildcard patterns (e.g. *.internal, admin.*)
    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        item="${item,,}"
        if [[ "$item" == *"*"* ]]; then
            [[ "$host" == $item ]] && return 0
        else
            [[ "$host" == "$item" ]] && return 0
        fi
    done < <(_csv_trimmed_iter "$blocklist")

    # Blocked suffixes: token can be ".internal" or "internal"
    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        item="${item,,}"
        item="${item#.}"
        [[ -z "$item" ]] && continue

        if [[ "$host" == "$item" || "$host" == *".${item}" ]]; then
            return 0
        fi
    done < <(_csv_trimmed_iter "$blocked_suffixes")

    return 1
}

target_is_private_or_local() {
    local host ip
    host="$(_normalize_target_host "$1")"

    [[ "$host" == "localhost" || "$host" == *".localhost" ]] && return 0

    if _is_ipv4_literal "$host" && _is_private_ipv4 "$host"; then
        return 0
    fi
    if _is_ipv6_literal "$host" && _is_private_ipv6 "$host"; then
        return 0
    fi

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        if _is_ipv4_literal "$ip" && _is_private_ipv4 "$ip"; then
            return 0
        fi
        if _is_ipv6_literal "$ip" && _is_private_ipv6 "$ip"; then
            return 0
        fi
    done < <(_resolve_target_ips "$host")

    return 1
}
