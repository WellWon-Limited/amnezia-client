#!/bin/bash -p
# Root-side OpenVPN DNS hook. This file is part of the sealed Tribe service
# payload; the daemon rejects a substituted/writable hook before spawning
# OpenVPN. Bash privileged mode prevents BASH_ENV/exported-function startup
# injection before this script can sanitize its environment.
set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
IFS=$' \t\n'
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH GLOBIGNORE
readonly PATH LC_ALL

script_action="${script_type:-}"
tunnel_device="${dev:-}"
case "$script_action" in up|down) ;; *) exit 1 ;; esac
case "$tunnel_device" in
    utun[0-9]|utun[0-9][0-9]|utun[0-9][0-9][0-9]) ;;
    *) exit 1 ;;
esac

dns_servers=()
search_domains=()
network_services=()

# Values remain ordinary quoted argv elements, but validate them as a second
# containment layer against option confusion and pathological input.
valid_dns_token() {
    local value="$1"
    [ -n "$value" ] && [ "${#value}" -le 64 ] || return 1
    case "$value" in
        -*|*[!0-9A-Fa-f:.%]*) return 1 ;;
        *.*|*:*) return 0 ;;
        *) return 1 ;;
    esac
}

valid_domain_token() {
    local value="$1"
    [ -n "$value" ] && [ "${#value}" -le 253 ] || return 1
    case "$value" in
        -*|.*|*..*|*-.|*-|*[!A-Za-z0-9._-]*) return 1 ;;
        *) return 0 ;;
    esac
}

while IFS= read -r service; do
    [ -n "$service" ] || continue
    case "$service" in
        "An asterisk ("*|\**) continue ;;
    esac
    [ "${#service}" -le 255 ] || continue
    network_services[${#network_services[@]}]="$service"
done < <(/usr/sbin/networksetup -listallnetworkservices 2>/dev/null)

[ "${#network_services[@]}" -gt 0 ] || exit 1

if [ "$script_action" = up ]; then
    # ${!prefix@}, quoted, expands to parameter names only. Never eval data.
    for option_name in "${!foreign_option_@}"; do
        case "$option_name" in
            foreign_option_[0-9]|foreign_option_[0-9][0-9]|\
            foreign_option_[0-9][0-9][0-9]) ;;
            *) continue ;;
        esac
        option_value="${!option_name}"
        [ "${#option_value}" -le 512 ] || continue
        option_directive=""
        option_kind=""
        option_data=""
        option_extra=""
        IFS=' ' read -r option_directive option_kind option_data option_extra \
            <<< "$option_value"
        [ "$option_directive" = dhcp-option ] && [ -z "$option_extra" ] \
            || continue
        case "$option_kind" in
            DNS)
                if valid_dns_token "$option_data"; then
                    dns_servers[${#dns_servers[@]}]="$option_data"
                fi
                ;;
            DOMAIN|DOMAIN-SEARCH)
                if valid_domain_token "$option_data"; then
                    search_domains[${#search_domains[@]}]="$option_data"
                fi
                ;;
        esac
    done

    operation_failed=0
    for service in "${network_services[@]}"; do
        if [ "${#search_domains[@]}" -gt 0 ]; then
            /usr/sbin/networksetup -setsearchdomains \
                "$service" "${search_domains[@]}" >/dev/null 2>&1 \
                || operation_failed=1
        fi
        if [ "${#dns_servers[@]}" -gt 0 ]; then
            /usr/sbin/networksetup -setdnsservers \
                "$service" "${dns_servers[@]}" >/dev/null 2>&1 \
                || operation_failed=1
        fi
    done
    exit "$operation_failed"
fi

operation_failed=0
for service in "${network_services[@]}"; do
    /usr/sbin/networksetup -setdnsservers "$service" empty >/dev/null 2>&1 \
        || operation_failed=1
    /usr/sbin/networksetup -setsearchdomains "$service" empty >/dev/null 2>&1 \
        || operation_failed=1
done
exit "$operation_failed"
