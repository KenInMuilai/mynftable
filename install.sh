#!/usr/bin/env bash
## nftables 端口转发管理工具 v1.2 (Alpine 适配版)
## 交互式管理 DNAT 端口转发规则

# ============== 常量定义 ==============
CONF_DIR="/etc/nftables.d"
CONF_FILE="${CONF_DIR}/port-forward.conf"
BACKUP_DIR="${CONF_DIR}/backups"
MAIN_CONF="/etc/nftables.conf"
SYSCTL_CONF="/etc/sysctl.d/99-nft-forward.conf"
LOG_FILE="/var/log/nft-forward.log"
LOGROTATE_CONF="/etc/logrotate.d/nft-forward"
TABLE_NAME="port_forward"

# ============== 日志函数 ==============
log_action() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

# ============== 输出辅助 ==============
info()    { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
warn()    { printf '\033[33m[警告]\033[0m %s\n' "$1"; }
err()     { printf '\033[31m[错误]\033[0m %s\n' "$1"; }

# ============== root 权限检查 ==============
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "此脚本需要 root 权限运行，请使用 sudo 或 root 用户执行。"
        exit 1
    fi
}

# ============== 输入验证 ==============
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^0[0-9] ]]; then
        return 1
    fi
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    if [[ "$ip" =~ (^|\.)0[0-9] ]]; then
        return 1
    fi
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet > 255 )); then
            return 1
        fi
    done
    return 0
}

# ============== 自动获取本机 IP ==============
get_local_ip() {
    local ip
    # 适配 Alpine/BusyBox 的 awk 提取法
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
}

# ============== 发行版检测 ==============
detect_pkg_manager() {
    if command -v apk &>/dev/null; then
        echo "apk"
    elif command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

has_iptables() {
    command -v iptables &>/dev/null && iptables -S &>/dev/null
}

try_persist_iptables() {
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null && return 0
        fi
    fi
    return 1
}

dest_still_used() {
    local check_ip="$1" check_dport="$2" exclude_lport="$3"
    local rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        [[ "$lport" == "$exclude_lport" ]] && continue
        if [[ "$dip" == "$check_ip" && "$dport" == "$check_dport" ]]; then
            return 0
        fi
    done
    return 1
}

# ============== 端口放行 ==============
firewall_open_port() {
    local lport="$1" dest_ip="$2" dport="$3"

    if has_iptables; then
        iptables -C INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        info "已在 iptables 中开通对应放行规则。"
        try_persist_iptables || true
    fi
}

firewall_close_port() {
    local lport="$1" dest_ip="$2" dport="$3" force="${4:-}"

    if has_iptables; then
        iptables -D INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            iptables -D FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        fi
        try_persist_iptables || true
    fi
}

check_port_conflict() {
    local port="$1"
    local conflict=""
    if command -v ss &>/dev/null; then
        if ss -tlnp 2>/dev/null | grep -qE ":${port}\b"; then conflict="TCP"; fi
        if ss -ulnp 2>/dev/null | grep -qE ":${port}\b"; then
            conflict=$([[ -n "$conflict" ]] && echo "TCP+UDP" || echo "UDP")
        fi
    fi
    if [[ -n "$conflict" ]]; then
        warn "本机端口 ${port} 已被其他服务占用（${conflict}）。"
        read -rp "是否仍要继续添加转发规则？[y/N]: " ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then return 1; fi
    fi
    return 0
}

# ============== 初始化配置 ==============
init_conf() {
    mkdir -p "${CONF_DIR}" "${BACKUP_DIR}" 2>/dev/null || return 1
    touch "${LOG_FILE}" 2>/dev/null || true

    if [[ ! -f "${MAIN_CONF}" ]]; then
        cat > "${MAIN_CONF}" <<'NFTCONF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.conf"
NFTCONF
    elif ! grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
        echo 'include "/etc/nftables.d/*.conf"' >> "${MAIN_CONF}"
    fi

    if [[ ! -f "${CONF_FILE}" ]]; then
        write_conf_file || return 1
    fi
}

declare -a RULES=()
sanitize_note() {
    local note="${1:-}"
    note="${note//$'\r'/ }"
    note="${note//$'\n'/ }"
    note="${note//|/ }"
    printf "%s" "$note"
}

get_conf_local_ip() {
    [[ -f "${CONF_FILE}" ]] || return
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*define[[:space:]]+LOCAL_IP[[:space:]]*=[[:space:]]*([0-9.]+) ]]; then
            printf "%s" "${BASH_REMATCH[1]}"
            return
        fi
    done < "${CONF_FILE}"
}

load_rules() {
    RULES=()
    [[ -f "${CONF_FILE}" ]] || return
    local pending_note=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*备注:[[:space:]]*(.*)$ ]]; then
            pending_note=$(sanitize_note "${BASH_REMATCH[1]}")
            continue
        fi
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ tcp\ dport\ ([0-9]+)\ dnat\ to\ ([0-9.]+):([0-9]+) ]]; then
            RULES+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|${BASH_REMATCH[3]}|${pending_note}")
            pending_note=""
        fi
    done < "${CONF_FILE}"
}

write_conf_file() {
    local local_ip
    local_ip=$(get_local_ip)
    [[ -z "$local_ip" ]] && local_ip=$(get_conf_local_ip)
    if [[ -z "$local_ip" ]]; then
        err "无法获取本机 IP 地址，请检查网络配置。"
        return 1
    fi

    local tmp_file="${CONF_FILE}.tmp.$$"
    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f
define LOCAL_IP = ${local_ip}
table ip ${TABLE_NAME} {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    local rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        [[ -n "$note" ]] && echo "        # 备注: ${note}" >> "${tmp_file}"
        echo "        tcp dport ${lport} dnat to ${dip}:${dport}" >> "${tmp_file}"
        echo "        udp dport ${lport} dnat to ${dip}:${dport}" >> "${tmp_file}"
    done

    cat >> "${tmp_file}" <<EOF
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF

    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        echo "        ip daddr ${dip} tcp dport ${dport} ct status dnat snat to \$LOCAL_IP" >> "${tmp_file}"
        echo "        ip daddr ${dip} udp dport ${dport} ct status dnat snat to \$LOCAL_IP" >> "${tmp_file}"
    done

    echo -e "    }\n}" >> "${tmp_file}"
    mv -f "${tmp_file}" "${CONF_FILE}" 2>/dev/null
}

reload_rules() {
    nft flush table ip "${TABLE_NAME}" 2>/dev/null || true
    nft delete table ip "${TABLE_NAME}" 2>/dev/null || true
    nft -f "${CONF_FILE}"
}

backup_conf() {
    if [[ -f "${CONF_FILE}" ]]; then
        cp "${CONF_FILE}" "${BACKUP_DIR}/port-forward.conf.$(date '+%Y%m%d_%H%M%S')" 2>/dev/null || true
    fi
}

enable_ip_forward() {
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    fi
    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    echo "net.ipv4.ip_forward=1" > "${SYSCTL_CONF}" 2>/dev/null || true
    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
}

enable_bbr_fq() {
    # 针对 Alpine 优化 BBR 检测与开启
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        warn "当前内核未加载 BBR 模块，跳过配置。"
        return 0
    fi
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    echo -e "net.core.default_qdisc=fq\net.ipv4.tcp_congestion_control=bbr" > "${SYSCTL_CONF}" 2>/dev/null || true
    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
    info "BBR + fq 优化参数已应用。"
}

# ============== 诊断/自检 (适配 OpenRC) ==============
do_diagnose() {
    echo -e "\n========================================\n           诊断 / 自检 (Alpine)\n========================================"
    [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]] && info "IPv4 转发: 已开启" || err "IPv4 转发: 未开启"
    command -v nft &>/dev/null && info "nftables: 已安装" || err "nftables: 未安装"

    # OpenRC 状态检测
    if rc-service nftables status 2>/dev/null | grep -q "started"; then
        info "nftables 服务状态: 运行中"
    else
        warn "nftables 服务状态: 未运行"
    fi

    if rc-status default 2>/dev/null | grep -q "nftables"; then
        info "nftables 开机启动: 是"
    else
        warn "nftables 开机启动: 否"
    fi

    nft list table ip "${TABLE_NAME}" &>/dev/null && info "转发规则表: 已成功加载" || warn "转发规则表: 未加载"
    echo ""
}

# ============== 安装 nftables ==============
do_install() {
    echo ""
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    if [[ "$pkg_mgr" == "apk" ]]; then
        info "检测到 Alpine 系统，正在通过 apk 补全环境 (bash, grep, iproute2, nftables)..."
        apk update && apk add bash grep iproute2 nftables iptables
    else
        # 兜底其他系统
        case "$pkg_mgr" in
            apt) apt-get update -y && apt-get install -y nftables ;;
            dnf|yum) ${pkg_mgr} install -y nftables ;;
            *) err "未知发行版，请手动安装依赖。"; return ;;
        esac
    fi

    if ! command -v nft &>/dev/null; then
        err "nftables 安装失败。"
        return
    fi

    enable_ip_forward
    enable_bbr_fq
    init_conf

    # Alpine OpenRC 服务激活与开机自启
    if command -v rc-update &>/dev/null; then
        rc-update add nftables default >/dev/null 2>&1
        rc-service nftables start >/dev/null 2>&1
        info "已激活 OpenRC nftables 服务并设置开机自启。"
    fi

    info "安装与初始化完成。"
}

# ============== 其余菜单交互逻辑 ==============
edit_rule_note() {
    local ans
    read -rp "是否添加/修改备注？[y/N]: " ans
    [[ ! "$ans" =~ ^[Yy]$ ]] && return
    local choice
    read -rp "请输入序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" || ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#RULES[@]} )); then
        err "输入无效。"; return
    fi
    local target="${RULES[$((choice-1))]}"
    local lport dip dport old_note note
    IFS='|' read -r lport dip dport old_note <<< "$target"
    read -rp "请输入新备注: " note
    note=$(sanitize_note "$note")
    backup_conf
    RULES[$((choice-1))]="${lport}|${dip}|${dport}|${note}"
    write_conf_file && info "备注已更新。"
}

do_list() {
    echo ""
    load_rules
    if [[ ${#RULES[@]} -eq 0 ]]; then info "当前没有端口转发规则。"; return; fi
    printf "\n\033[1m%-6s %-10s %-10s    %-22s %s\033[0m\n" "序号" "协议" "本机端口" "目标地址" "备注"
    echo "────────────────────────────────────────────────────────────────────────"
    local idx=1 rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        printf "%-6s %-10s %-10s -> %-22s %s\n" "$idx" "tcp+udp" "$lport" "${dip}:${dport}" "${note:--}"
        ((idx++))
    done
    echo ""
    edit_rule_note
}

do_add() {
    echo ""
    if ! command -v nft &>/dev/null; then err "请先选择 [1] 安装环境。"; return; fi
    init_conf || return
    enable_ip_forward
    load_rules

    local lport dip dport note
    while true; do
        read -rp "请输入本机监听端口 (1-65535): " lport
        validate_port "$lport" && break || err "端口无效。"
    done

    local rule rp
    for rule in "${RULES[@]}"; do
        IFS='|' read -r rp _ _ _ <<< "$rule"
        if [[ "$rp" == "$lport" ]]; then err "该端口已存在转发规则。"; return; fi
    done

    check_port_conflict "$lport" || return

    while true; do
        read -rp "请输入目标 IP 地址: " dip
        validate_ip "$dip" && break || err "IP 格式错误。"
    done

    while true; do
        read -rp "请输入目标端口 [默认: ${lport}]: " dport
        dport="${dport:-$lport}"
        validate_port "$dport" && break || err "端口无效。"
    done

    read -rp "请输入备注（可留空）: " note
    note=$(sanitize_note "$note")

    backup_conf
    RULES+=("${lport}|${dip}|${dport}|${note}")
    if write_conf_file && reload_rules; then
        firewall_open_port "$lport" "$dip" "$dport"
        info "规则添加成功！"
    else
        err "应用配置失败。"
    fi
}

do_delete() {
    echo ""
    load_rules
    if [[ ${#RULES[@]} -eq 0 ]]; then info "没有可供删除的规则。"; return; fi
    
    local idx=1 rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        echo "  ${idx}) 本机:${lport} -> ${dip}:${dport} (${note:--})"
        ((idx++))
    done

    local choice
    read -rp "请选择要删除的序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" || ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#RULES[@]} )); then
        return
    fi

    local target="${RULES[$((choice-1))]}"
    IFS='|' read -r lport dip dport note <<< "$target"

    backup_conf
    unset 'RULES[$((choice-1))]'
    RULES=("${RULES[@]}")

    if write_conf_file && reload_rules; then
        firewall_close_port "$lport" "$dip" "$dport"
        info "规则删除成功。"
    fi
}

do_clear_all() {
    echo ""
    load_rules
    [[ ${#RULES[@]} -eq 0 ]] && return
    read -rp "确认清空全部规则？[y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && return

    backup_conf
    local rule lport dip dport note
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport note <<< "$rule"
        firewall_close_port "$lport" "$dip" "$dport" "force"
    done

    RULES=()
    if write_conf_file && reload_rules; then
        info "已清空所有转发规则。"
    fi
}

main_menu() {
    while true; do
        echo -e "\n========================================\n   nftables 端口转发工具 v1.2 (Alpine)\n========================================"
        echo "  1) 安装/补全 Alpine 环境"
        echo "  2) 查看现有端口转发"
        echo "  3) 新增端口转发"
        echo "  4) 删除端口转发"
        echo "  5) 一键清空所有转发"
        echo "  6) 诊断/自检"
        echo "  7) 退出"
        echo "========================================"
        read -rp "请选择操作 [1-7]: " choice
        case "$choice" in
            1) do_install ;;
            2) do_list ;;
            3) do_add ;;
            4) do_delete ;;
            5) do_clear_all ;;
            6) do_diagnose ;;
            7) info "再见！"; exit 0 ;;
            *) err "无效选择。" ;;
        esac
    done
}

# ============== 入口 ==============
check_root
main_menu
