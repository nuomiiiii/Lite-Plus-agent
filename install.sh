#!/bin/bash

# Color definitions for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${NC} $1"
}

log_success() {
    echo -e "${GREEN}${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${NC} $1"
}

log_config() {
    echo -e "${CYAN}[CONFIG]${NC} $1"
}

redact_agent_args() {
    local args="$1"
    local out="" prev="" token
    # shellcheck disable=SC2086
    for token in $args; do
        if [ "$prev" = "-t" ] || [ "$prev" = "--token" ] || [ "$prev" = "--cf-access-client-secret" ]; then
            out="$out ***"
            prev="$token"
            continue
        fi
        case "$token" in
            --token=*)
                out="$out --token=***"
                prev=""
                continue
                ;;
            --cf-access-client-secret=*)
                out="$out --cf-access-client-secret=***"
                prev=""
                continue
                ;;
        esac
        out="$out $token"
        prev="$token"
    done
    echo "${out# }"
}

# Default values
service_name="lite-plus-agent"
target_dir="/opt/lite-plus-agent"
github_proxy=""
install_version="" # New parameter for specifying version
lite_service_name="lite-agent"
legacy_service_name="komari-agent"
github_repo="nuomiiiii/Lite-Plus-agent"
custom_layout=false

 

# Detect OS
os_type=$(uname -s)
case $os_type in
    Darwin)
        os_name="darwin"
        target_dir="/usr/local/lite-plus-agent"  # Use /usr/local on macOS
        # Check if we can write to /usr/local, fallback to user directory
        if [ ! -w "/usr/local" ] && [ "$EUID" -ne 0 ]; then
            target_dir="$HOME/.lite-plus-agent"
            log_info "No write permission to /usr/local, using user directory: $target_dir"
        fi
        ;;
    Linux)
        os_name="linux"
        ;;
    FreeBSD)
        os_name="freebsd"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        os_name="windows"
        target_dir="/c/lite-plus-agent"  # Use C:\lite-plus-agent on Windows
        ;;
    *)
        log_error "Unsupported operating system: $os_type"
        exit 1
        ;;
esac

# Parse install-specific arguments
agent_args=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir)
            target_dir="$2"
            custom_layout=true
            shift 2
            ;;
        --install-service-name)
            service_name="$2"
            custom_layout=true
            shift 2
            ;;
        --install-ghproxy)
            github_proxy="$2"
            shift 2
            ;;
        --install-version)
            install_version="$2"
            shift 2
            ;;
        --install*)
            log_warning "Unknown install parameter: $1"
            shift
            ;;
        *)
            # Non-install arguments go to agent_args
            agent_args="$agent_args $1"
            shift
            ;;
    esac
done

# Remove leading space from agent_args if present
agent_args="${agent_args# }"

args_have_flag() {
    local args="$1"
    local name="$2"
    local token
    # shellcheck disable=SC2086
    for token in $args; do
        case "$token" in
            --"$name"|--"$name"=*)
                return 0
                ;;
        esac
    done
    return 1
}

flag_bool_value() {
    local args="$1"
    local name="$2"
    local token
    # shellcheck disable=SC2086
    for token in $args; do
        case "$token" in
            --"$name")
                echo "true"
                return
                ;;
            --"$name"=*)
                echo "${token#--$name=}"
                return
                ;;
        esac
    done
    echo "true"
}

strip_remote_control_flags() {
    local args="$1"
    local token out=""
    # shellcheck disable=SC2086
    for token in $args; do
        case "$token" in
            --enable-remote-control|--enable-remote-control=*|--disable-web-ssh|--disable-web-ssh=*)
                continue
                ;;
        esac
        out="$out $token"
    done
    echo "${out# }"
}

bool_flag_is_true() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        false|0|no|off) return 1 ;;
        *) return 0 ;;
    esac
}

managed_service_unit_exists() {
    local name="$1"
    [ -f "/etc/systemd/system/${name}.service" ] && return 0
    [ -f "/etc/init.d/${name}" ] && return 0
    [ -f "/etc/init/${name}.conf" ] && return 0
    if [ "$os_name" = "darwin" ]; then
        [ -f "/Library/LaunchDaemons/com.liteplus.${name}.plist" ] && return 0
        [ -f "/Library/LaunchDaemons/com.lite.${name}.plist" ] && return 0
        [ -f "/Library/LaunchDaemons/com.komari.${name}.plist" ] && return 0
        [ -f "$HOME/Library/LaunchAgents/com.liteplus.${name}.plist" ] && return 0
        [ -f "$HOME/Library/LaunchAgents/com.lite.${name}.plist" ] && return 0
        [ -f "$HOME/Library/LaunchAgents/com.komari.${name}.plist" ] && return 0
    fi
    return 1
}

extract_args_after_binary() {
    local line="$1"
    line="${line#ExecStart=}"
    line="${line#exec }"
    line="${line#\"}"
    line="${line%\"}"
    # shellcheck disable=SC2086
    set -- $line
    shift
    printf '%s' "$*"
}

read_service_args_from_unit() {
    local name="$1"
    local unit line
    if [ -f "/etc/systemd/system/${name}.service" ]; then
        line=$(grep -E '^ExecStart=' "/etc/systemd/system/${name}.service" | head -n1)
        if [ -n "$line" ]; then
            extract_args_after_binary "$line"
            return 0
        fi
    fi
    if [ -f "/etc/init.d/${name}" ]; then
        line=$(grep -E '^(ARGS|command_args)=' "/etc/init.d/${name}" | head -n1)
        if [ -n "$line" ]; then
            line="${line#ARGS=}"
            line="${line#command_args=}"
            line="${line#\"}"
            line="${line%\"}"
            printf '%s' "$line"
            return 0
        fi
    fi
    if [ -f "/etc/init/${name}.conf" ]; then
        line=$(grep -E '^exec ' "/etc/init/${name}.conf" | head -n1)
        if [ -n "$line" ]; then
            extract_args_after_binary "$line"
            return 0
        fi
    fi
    return 1
}

flag_path_value() {
    local args="$1"
    local name="$2"
    local prev=""
    local token
    # shellcheck disable=SC2086
    for token in $args; do
        if [ "$prev" = "--$name" ]; then
            echo "$token"
            return
        fi
        case "$token" in
            --"$name"=*)
                echo "${token#--$name=}"
                return
                ;;
        esac
        prev="$token"
    done
}

preserve_existing_config_arg() {
    if args_have_flag "$agent_args" "config"; then
        return
    fi
    local existing=""
    existing=$(read_existing_managed_service_args) || return 0
    local cfg
    cfg=$(flag_path_value "$existing" "config")
    [ -n "$cfg" ] || return 0
    [ -f "$cfg" ] || return 0
    mkdir -p "$target_dir"
    local dest="$target_dir/$(basename "$cfg")"
    if [ "$cfg" != "$dest" ] && [ ! -f "$dest" ]; then
        log_info "Copying config $(basename "$cfg") to $target_dir"
        cp -a "$cfg" "$dest"
    fi
    if [ -f "$dest" ]; then
        agent_args="${agent_args} --config ${dest}"
        agent_args="${agent_args# }"
        log_info "Keeping existing --config ${dest}"
    fi
}

read_existing_managed_service_args() {
    if managed_service_unit_exists "$service_name"; then
        read_service_args_from_unit "$service_name" || true
        return 0
    fi
    if [ "$custom_layout" != true ]; then
        if managed_service_unit_exists "$lite_service_name"; then
            read_service_args_from_unit "$lite_service_name" || true
            return 0
        fi
        if managed_service_unit_exists "$legacy_service_name"; then
            read_service_args_from_unit "$legacy_service_name" || true
            return 0
        fi
    fi
    return 1
}

apply_remote_control_install_args() {
    local existing=""
    local managed=false
    if args_have_flag "$agent_args" "enable-remote-control"; then
        return
    fi
    if args_have_flag "$agent_args" "disable-web-ssh"; then
        if bool_flag_is_true "$(flag_bool_value "$agent_args" "disable-web-ssh")"; then
            agent_args="$(strip_remote_control_flags "$agent_args") --enable-remote-control=false"
        else
            agent_args="$(strip_remote_control_flags "$agent_args") --enable-remote-control=true"
        fi
        agent_args="${agent_args# }"
        return
    fi
    if existing=$(read_existing_managed_service_args); then
        managed=true
    fi
    if [ "$managed" != true ]; then
        agent_args="${agent_args} --enable-remote-control=false"
        agent_args="${agent_args# }"
        return
    fi
    if args_have_flag "$existing" "enable-remote-control"; then
        if bool_flag_is_true "$(flag_bool_value "$existing" "enable-remote-control")"; then
            agent_args="${agent_args} --enable-remote-control=true"
        else
            agent_args="${agent_args} --enable-remote-control=false"
        fi
        agent_args="${agent_args# }"
        return
    fi
    if args_have_flag "$existing" "disable-web-ssh"; then
        if bool_flag_is_true "$(flag_bool_value "$existing" "disable-web-ssh")"; then
            agent_args="${agent_args} --enable-remote-control=false"
        else
            agent_args="${agent_args} --enable-remote-control=true"
        fi
        agent_args="${agent_args# }"
        return
    fi
    agent_args="${agent_args} --enable-remote-control=true"
    agent_args="${agent_args# }"
}

apply_remote_control_install_args


agent_path="${target_dir}/Lite-Plus-agent"
if [ "$os_name" = "darwin" ] && command -v brew >/dev/null 2>&1; then
    # On macOS with Homebrew, we can run without root for dependencies
    require_root_for_deps=false
else
    require_root_for_deps=true
fi

if [ "$EUID" -ne 0 ] && [ "$require_root_for_deps" = true ]; then
    log_error "Please run as root"
    exit 1
fi

echo -e "${WHITE}===========================================${NC}"
echo -e "${WHITE}    Lite-Plus Agent Installation Script     ${NC}"
echo -e "${WHITE}===========================================${NC}"
echo ""
log_config "Installation configuration:"
log_config "  Service name: ${GREEN}$service_name${NC}"
log_config "  Install directory: ${GREEN}$target_dir${NC}"
log_config "  GitHub proxy: ${GREEN}${github_proxy:-"(direct)"}${NC}"
log_config "  Binary: ${GREEN}$agent_path${NC}"
log_config "  Binary arguments: ${GREEN}$(redact_agent_args "$agent_args")${NC}"
if [ -n "$install_version" ]; then
    log_config "  Specified agent version: ${GREEN}$install_version${NC}"
else
    log_config "  Agent version: ${GREEN}Latest${NC}"
fi
echo ""

# Function to uninstall the previous installation
uninstall_named_service() {
    local name="$1"
    local unit_file="/etc/systemd/system/${name}.service"
    local drop_in="/etc/systemd/system/${name}.service.d"
    local wants_link="/etc/systemd/system/multi-user.target.wants/${name}.service"
    local has_unit=false
    local cleaned=false
    if command -v systemctl >/dev/null 2>&1; then
        if [ -f "$unit_file" ] || [ -L "$unit_file" ]; then
            has_unit=true
        fi
        if systemctl is-active --quiet "${name}.service" 2>/dev/null; then
            systemctl stop "${name}.service" >/dev/null 2>&1 || true
        fi
        if [ "$has_unit" = true ]; then
            log_info "Stopping and disabling existing systemd service ${name}..."
            systemctl stop "${name}.service" >/dev/null 2>&1 || true
            systemctl disable "${name}.service" >/dev/null 2>&1 || true
        fi
        if [ "$has_unit" = true ] || [ -e "$wants_link" ] || [ -d "$drop_in" ]; then
            rm -f "$wants_link"
            rm -f "$unit_file"
            rm -rf "$drop_in"
            systemctl daemon-reload >/dev/null 2>&1 || true
            cleaned=true
        fi
    fi
    if [ "$has_unit" = true ] || [ "$cleaned" = true ]; then
        return
    fi
    if command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${name}" ]; then
        log_info "Stopping and disabling existing OpenRC service ${name}..."
        rc-service ${name} stop
        rc-update del ${name} default
        rm -f "/etc/init.d/${name}"
    elif command -v uci >/dev/null 2>&1 && [ -f "/etc/init.d/${name}" ]; then
        log_info "Stopping and disabling existing procd service ${name}..."
        /etc/init.d/${name} stop
        /etc/init.d/${name} disable
        rm -f "/etc/init.d/${name}"
    elif command -v initctl >/dev/null 2>&1 && [ -f "/etc/init/${name}.conf" ]; then
        log_info "Stopping and removing existing upstart service ${name}..."
        initctl stop ${name}
        rm -f "/etc/init/${name}.conf"
    elif [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        for prefix in com.liteplus com.lite com.komari; do
            system_plist="/Library/LaunchDaemons/${prefix}.${name}.plist"
            user_plist="$HOME/Library/LaunchAgents/${prefix}.${name}.plist"
            if [ -f "$system_plist" ]; then
                log_info "Stopping and removing existing system launchd service ${prefix}.${name}..."
                launchctl bootout system "$system_plist" 2>/dev/null || true
                rm -f "$system_plist"
            fi
            if [ -f "$user_plist" ]; then
                log_info "Stopping and removing existing user launchd service ${prefix}.${name}..."
                launchctl bootout gui/$(id -u) "$user_plist" 2>/dev/null || true
                rm -f "$user_plist"
            fi
        done
    fi
}

copy_sidecars_from() {
    local src="$1"
    if [ ! -d "$src" ] || [ "$src" = "$target_dir" ]; then
        return
    fi
    mkdir -p "$target_dir"
    local name
    for name in auto-discovery.json net_static.json net_static.json.bak node.json remote-control.state config.json; do
        if [ -f "$src/$name" ] && [ ! -f "$target_dir/$name" ]; then
            log_info "Copying $name from $src to $target_dir"
            cp -a "$src/$name" "$target_dir/$name"
        fi
    done
}

prevent_service_restart() {
    local name="$1"
    if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/${name}.service" ]; then
        mkdir -p "/etc/systemd/system/${name}.service.d"
        printf '[Service]\nRestart=no\n' > "/etc/systemd/system/${name}.service.d/restart.conf"
        systemctl daemon-reload
    fi
}

new_service_running() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "${service_name}.service"
        return $?
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service "${service_name}" status >/dev/null 2>&1
        return $?
    fi
    if [ -x "/etc/init.d/${service_name}" ]; then
        "/etc/init.d/${service_name}" status >/dev/null 2>&1
        return $?
    fi
    if [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        launchctl print "system/com.liteplus.${service_name}" >/dev/null 2>&1 && return 0
        launchctl print "gui/$(id -u)/com.liteplus.${service_name}" >/dev/null 2>&1 && return 0
        launchctl print "system/com.lite.${service_name}" >/dev/null 2>&1 && return 0
        launchctl print "gui/$(id -u)/com.lite.${service_name}" >/dev/null 2>&1 && return 0
        return 1
    fi
    if command -v initctl >/dev/null 2>&1; then
        initctl status "${service_name}" 2>/dev/null | grep -q "start/running"
        return $?
    fi
    return 1
}

wait_new_service() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if new_service_running; then
            return 0
        fi
        sleep 1
    done
    return 1
}

legacy_install_detected() {
    if managed_service_unit_exists "$lite_service_name" || managed_service_unit_exists "$legacy_service_name"; then
        return 0
    fi
    local src
    for src in \
        "/opt/lite-agent" "/usr/local/lite-agent" "$HOME/.lite-agent" "/c/lite-agent" \
        "/opt/komari" "/usr/local/komari" "$HOME/.komari" "/c/komari"; do
        if [ -d "$src" ] && [ "$src" != "$target_dir" ]; then
            return 0
        fi
    done
    return 1
}

retire_named_previous_service() {
    local name="$1"
    if [ "$custom_layout" = true ]; then
        return
    fi
    if [ "$service_name" = "$name" ]; then
        return
    fi
    if ! managed_service_unit_exists "$name"; then
        return
    fi
    log_step "Retiring previous service ${name} after Lite-Plus-agent is running..."
    prevent_service_restart "$name"
    uninstall_named_service "$name"
}

retire_legacy_service() {
    retire_named_previous_service "$lite_service_name"
    retire_named_previous_service "$legacy_service_name"
}

# Keep existing komari-agent / lite-agent processes running until Plus is up.
# Nothing is printed when no previous service or directory is present.
# Custom --install-dir / --install-service-name installs do not migrate default paths.
if [ "$custom_layout" != true ]; then
    copy_sidecars_from "/opt/lite-agent"
    copy_sidecars_from "/usr/local/lite-agent"
    copy_sidecars_from "$HOME/.lite-agent"
    copy_sidecars_from "/c/lite-agent"
    copy_sidecars_from "/opt/komari"
    copy_sidecars_from "/usr/local/komari"
    copy_sidecars_from "$HOME/.komari"
    copy_sidecars_from "/c/komari"
else
    if legacy_install_detected; then
        log_step "Custom install layout; leaving lite-agent and komari-agent in place."
    fi
    uninstall_named_service "$service_name"
fi
preserve_existing_config_arg

install_dependencies() {
    log_step "Checking and installing dependencies..."

    local deps="curl"
    local missing_deps=""
    for cmd in $deps; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps="$missing_deps $cmd"
        fi
    done

    if [ -n "$missing_deps" ]; then
        # Check package manager and install dependencies
        if command -v apt >/dev/null 2>&1; then
            log_info "Using apt to install dependencies..."
            apt update
            apt install -y $missing_deps
        elif command -v yum >/dev/null 2>&1; then
            log_info "Using yum to install dependencies..."
            yum install -y $missing_deps
        elif command -v apk >/dev/null 2>&1; then
            log_info "Using apk to install dependencies..."
            apk add $missing_deps
        elif command -v brew >/dev/null 2>&1; then
            log_info "Using Homebrew to install dependencies..."
            brew install $missing_deps
        else
            log_error "No supported package manager found (apt/yum/apk/brew)"
            exit 1
        fi
        
        # Verify installation
        for cmd in $missing_deps; do
            if ! command -v $cmd >/dev/null 2>&1; then
                log_error "Failed to install $cmd"
                exit 1
            fi
        done
        log_success "Dependencies installed successfully"
    else
        log_success "Dependencies already satisfied"
    fi
}

 
# Install dependencies
install_dependencies

 

# Architecture detection with platform-specific support
arch=$(uname -m)
case $arch in
    x86_64)
        arch="amd64"
        ;;
    aarch64|arm64)
        arch="arm64"
        ;;
    loongarch64|loong64)
        arch="loong64"
        ;;
    i386|i686)
        # x86 (32-bit) support
        case $os_name in
            freebsd|linux|windows)
                arch="386"
                ;;
            *)
                log_error "32-bit x86 architecture not supported on $os_name"
                exit 1
                ;;
        esac
        ;;
    armv7*|armv6*)
        # ARM 32-bit support
        case $os_name in
            freebsd|linux)
                arch="arm"
                ;;
            *)
                log_error "32-bit ARM architecture not supported on $os_name"
                exit 1
                ;;
        esac
        ;;
    *)
        log_error "Unsupported architecture: $arch on $os_name"
        exit 1
        ;;
esac
log_info "Detected OS: ${GREEN}$os_name${NC}, Architecture: ${GREEN}$arch${NC}"

version_to_install="latest"
if [ -n "$install_version" ]; then
    log_info "Attempting to install specified version: ${GREEN}$install_version${NC}"
    version_to_install="$install_version"
else
    log_info "No version specified, installing the latest version."
fi

# Construct download URL
file_name="Lite-Plus-agent-${os_name}-${arch}"
if [ "$version_to_install" = "latest" ]; then
    download_path="latest/download"
else
    download_path="download/${version_to_install}"
fi

build_download_url() {
    local repo="$1"
    local name="$2"
    if [ -n "$github_proxy" ]; then
        echo "${github_proxy%/}/https://github.com/${repo}/releases/${download_path}/${name}"
    else
        echo "https://github.com/${repo}/releases/${download_path}/${name}"
    fi
}

log_step "Creating installation directory: ${GREEN}$target_dir${NC}"
mkdir -p "$target_dir"

# curl -o cannot overwrite a running executable (ETXTBSY / "Text file busy").
# Write a new inode, then replace the name so a live Lite-Plus-agent can keep running
# until the service is restarted.
download_path_tmp="${agent_path}.new"
rm -f "$download_path_tmp"

download_ok=false
for candidate in \
    "${github_repo}|${file_name}"; do
    repo="${candidate%%|*}"
    name="${candidate##*|}"
    download_url="$(build_download_url "$repo" "$name")"
    if [ -n "$github_proxy" ]; then
        log_step "Downloading $name via proxy..."
    else
        log_step "Downloading $name directly..."
    fi
    log_info "URL: ${CYAN}$download_url${NC}"
    if curl --fail --show-error -L -A "Lite-Plus-agent-install (+https://github.com/nuomiiiii/Lite-Plus-agent)" -o "$download_path_tmp" "$download_url"; then
        download_ok=true
        break
    fi
    rm -f "$download_path_tmp"
    log_warning "Download from $repo/$name failed, trying next source..."
done

if [ "$download_ok" != true ]; then
    log_error "Download failed"
    exit 1
fi

chmod +x "$download_path_tmp"
if ! mv -f "$download_path_tmp" "$agent_path"; then
    log_error "Failed to replace ${agent_path}"
    rm -f "$download_path_tmp"
    exit 1
fi
log_success "Lite-Plus-agent installed to ${GREEN}$agent_path${NC}"

# Detect init system and configure service
log_step "Configuring system service..."

# Function to detect actual init system
detect_init_system() {
    # Check if running on NixOS (special case)
    if [ -f /etc/NIXOS ]; then
        echo "nixos"
        return
    fi
    
    # Alpine Linux MUST be checked first
    # Alpine always uses OpenRC, even in containers where PID 1 might be different
    if [ -f /etc/alpine-release ]; then
        if command -v rc-service >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
            echo "openrc"
            return
        fi
    fi
    
    # Get PID 1 process for other detection
    local pid1_process=$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')
    
    # If PID 1 is systemd, use systemd
    if [ "$pid1_process" = "systemd" ] || [ -d /run/systemd/system ]; then
        if command -v systemctl >/dev/null 2>&1; then
            # Additional verification that systemd is actually functioning
            if systemctl list-units >/dev/null 2>&1; then
                echo "systemd"
                return
            fi
        fi
    fi
    
    # Check for Gentoo OpenRC (PID 1 is openrc-init)
    if [ "$pid1_process" = "openrc-init" ]; then
        if command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
    fi
    
    # Check for other OpenRC systems (not Alpine, already handled)
    # Some systems use traditional init with OpenRC
    if [ "$pid1_process" = "init" ] && [ ! -f /etc/alpine-release ]; then
        # Check if OpenRC is actually managing services
        if [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
        # Check for OpenRC files
        if [ -f /sbin/openrc ] && command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
    fi
    
    # Check for OpenWrt's procd
    if command -v uci >/dev/null 2>&1 && [ -f /etc/rc.common ]; then
        echo "procd"
        return
    fi
    
    # Check for macOS launchd
    if [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        echo "launchd"
        return
    fi
    
    # Fallback: if systemctl exists and appears functional, assume systemd
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-units >/dev/null 2>&1; then
            echo "systemd"
            return
        fi
    fi
    
    # Last resort: check for OpenRC without other indicators
    if command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
        echo "openrc"
        return
    fi

    # check for Upstart (CentOS 6)
    if command -v initctl >/dev/null 2>&1 && [ -d /etc/init ]; then
        echo "upstart"
        return
    fi
    
    echo "unknown"
}

init_system=$(detect_init_system)
log_info "Detected init system: ${GREEN}$init_system${NC}"

# Handle each init system
if [ "$init_system" = "nixos" ]; then
    log_warning "NixOS detected. System services must be configured declaratively."
    log_info "Please add the following to your NixOS configuration:"
    echo ""
    echo -e "${CYAN}systemd.services.${service_name} = {${NC}"
    echo -e "${CYAN}  description = \"Lite-Plus Agent Service\";${NC}"
    echo -e "${CYAN}  after = [ \"network.target\" ];${NC}"
    echo -e "${CYAN}  wantedBy = [ \"multi-user.target\" ];${NC}"
    echo -e "${CYAN}  serviceConfig = {${NC}"
    echo -e "${CYAN}    Type = \"simple\";${NC}"
    echo -e "${CYAN}    ExecStart = \"${agent_path} ${agent_args}\";${NC}"
    echo -e "${CYAN}    WorkingDirectory = \"${target_dir}\";${NC}"
    echo -e "${CYAN}    Restart = \"always\";${NC}"
    echo -e "${CYAN}    User = \"root\";${NC}"
    echo -e "${CYAN}    Environment = [ \"GODEBUG=disablethp=1\" ];${NC}"
    echo -e "${CYAN}  };${NC}"
    echo -e "${CYAN}};${NC}"
    echo ""
    log_info "Then run: sudo nixos-rebuild switch"
    log_warning "Service not started automatically on NixOS. Please rebuild your configuration."
elif [ "$init_system" = "openrc" ]; then
    # OpenRC service configuration
    log_info "Using OpenRC for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/sbin/openrc-run

name="Lite-Plus Agent Service"
description="Lite monitoring agent"
command="${agent_path}"
command_args="${agent_args}"
command_user="root"
directory="${target_dir}"
# Keep Go heap off Linux transparent huge pages so idle RSS can return.
supervise_daemon_args="--env GODEBUG=disablethp=1"
pidfile="/run/${service_name}.pid"
retry="SIGTERM/30"
supervisor=supervise-daemon

depend() {
    need net
    after network
}
EOF

    # Set permissions and enable service
    chmod +x "$service_file"
    rc-update add ${service_name} default
    rc-service ${service_name} restart || rc-service ${service_name} start
    log_success "OpenRC service configured and started"
elif [ "$init_system" = "systemd" ]; then
    # Systemd service configuration
    log_info "Using systemd for service management"
    service_file="/etc/systemd/system/${service_name}.service"
    cat > "$service_file" << EOF
[Unit]
Description=Lite-Plus Agent Service
After=network.target

[Service]
Type=simple
ExecStart=${agent_path} ${agent_args}
WorkingDirectory=${target_dir}
Restart=always
User=root
Environment=GODEBUG=disablethp=1

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and start service
    systemctl daemon-reload
    systemctl enable ${service_name}.service
    systemctl restart ${service_name}.service
    log_success "Systemd service configured and started"
elif [ "$init_system" = "procd" ]; then
    # procd service configuration (OpenWrt)
    log_info "Using procd for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

PROG="${agent_path}"
ARGS="${agent_args}"

start_service() {
    procd_open_instance
    procd_set_param command \$PROG \$ARGS
    procd_set_param env GODEBUG=disablethp=1
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param user root
    procd_close_instance
}

stop_service() {
    killall \$(basename \$PROG)
}

reload_service() {
    stop
    start
}
EOF

    # Set permissions and enable service
    chmod +x "$service_file"
    /etc/init.d/${service_name} enable
    /etc/init.d/${service_name} restart || /etc/init.d/${service_name} start
    log_success "procd service configured and started"
elif [ "$init_system" = "launchd" ]; then
    # macOS launchd service configuration
    log_info "Using launchd for service management"
    
    # Determine if this should be a system or user service based on installation directory
    if [[ "$target_dir" =~ ^/Users/.* ]] || [ "$EUID" -ne 0 ]; then
        # User-level service (LaunchAgent)
        plist_dir="$HOME/Library/LaunchAgents"
        plist_file="$plist_dir/com.liteplus.${service_name}.plist"
        log_info "Installing as user-level service (LaunchAgent)"
        mkdir -p "$plist_dir"
        service_user="$(whoami)"
        log_dir="$HOME/Library/Logs"
    else
        # System-level service (LaunchDaemon)
        plist_dir="/Library/LaunchDaemons"
        plist_file="$plist_dir/com.liteplus.${service_name}.plist"
        log_info "Installing as system-level service (LaunchDaemon)"
        service_user="root"
        log_dir="/var/log"
    fi
    
    # Create the launchd plist file
    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.liteplus.${service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${agent_path}</string>
EOF
    
    # Add program arguments if provided
    if [ -n "$agent_args" ]; then
        echo "$agent_args" | xargs -n1 printf "        <string>%s</string>\n" >> "$plist_file"
    fi
    
    cat >> "$plist_file" << EOF
    </array>
    <key>WorkingDirectory</key>
    <string>${target_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>${service_user}</string>
    <key>StandardOutPath</key>
    <string>${log_dir}/${service_name}.log</string>
    <key>StandardErrorPath</key>
    <string>${log_dir}/${service_name}.log</string>
</dict>
</plist>
EOF
    
    # Load and start the service
    if [[ "$target_dir" =~ ^/Users/.* ]] || [ "$EUID" -ne 0 ]; then
        launchctl bootout gui/$(id -u) "$plist_file" 2>/dev/null || true
        if launchctl bootstrap gui/$(id -u) "$plist_file"; then
            log_success "User-level launchd service configured and started"
        else
            log_error "Failed to load user-level launchd service"
            exit 1
        fi
    else
        launchctl bootout system "$plist_file" 2>/dev/null || true
        if launchctl bootstrap system "$plist_file"; then
            log_success "System-level launchd service configured and started"
        else
            log_error "Failed to load system-level launchd service"
            exit 1
        fi
    fi
elif [ "$init_system" = "upstart" ]; then
    # Upstart service configuration
    log_info "Using upstart for service management"
    service_file="/etc/init/${service_name}.conf"
    cat > "$service_file" << EOF
# Lite-Plus Agent
description "Lite-Plus Agent Service"

chdir ${target_dir}
start on filesystem or runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5
umask 022

console none

pre-start script
    test -x ${agent_path} || { stop; exit 0; }
end script

# Start
script
    exec ${agent_path} ${agent_args}
end script
EOF
    # enable Upstart unit
    initctl reload-configuration
    initctl restart ${service_name} 2>/dev/null || initctl start ${service_name}
    log_success "Upstart service configured and started"
else
    log_error "Unsupported or unknown init system detected: $init_system"
    log_error "Supported init systems: systemd, openrc, procd, launchd"
    exit 1
fi

if [ "$init_system" != "nixos" ]; then
    if ! wait_new_service; then
        if managed_service_unit_exists "$lite_service_name" || managed_service_unit_exists "$legacy_service_name"; then
            log_error "Lite-Plus-agent service ${service_name} did not become running; leaving previous agents in place"
        else
            log_error "Lite-Plus-agent service ${service_name} did not become running"
        fi
        exit 1
    fi
    retire_legacy_service
fi

echo ""
echo -e "${WHITE}===========================================${NC}"
if [ -f /etc/NIXOS ]; then
    log_success "Lite-Plus-agent binary installed!"
    log_warning "NixOS requires declarative service configuration."
    log_info "Please add the service configuration to your NixOS config and rebuild."
else
    log_success "Lite-Plus-agent installation completed!"
fi
log_config "Service: ${GREEN}$service_name${NC}"
log_config "Process: ${GREEN}$agent_path${NC}"
log_config "Arguments: ${GREEN}$(redact_agent_args "$agent_args")${NC}"
echo -e "${WHITE}===========================================${NC}"
