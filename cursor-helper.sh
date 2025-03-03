#!/bin/bash

# Set error handling
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Get current user
get_current_user() {
    if [ "$EUID" -eq 0 ]; then
        echo "$SUDO_USER"
    else
        echo "$USER"
    fi
}

CURRENT_USER=$(get_current_user)
if [ -z "$CURRENT_USER" ]; then
    log_error "Unable to retrieve username"
fi

# Define paths
STORAGE_FILE="$HOME/Library/Application Support/Cursor/User/globalStorage/storage.json"
BACKUP_DIR="$HOME/Library/Application Support/Cursor/User/globalStorage/backups"
CURSOR_APP_PATH="/Applications/Cursor.app"

# Check permissions
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run this script with sudo\nExample: sudo $0"
    fi
}

# Check and close Cursor process
check_and_kill_cursor() {
    log_info "Checking Cursor process..."
    local attempt=1
    local max_attempts=5

    get_process_details() {
        local process_name="$1"
        log_debug "Getting $process_name process details:"
        ps aux | grep -i "$process_name" | grep -v grep || true
    }

    while [ $attempt -le $max_attempts ]; do
        CURSOR_PIDS=$(pgrep -i "cursor" || true)
        if [ -z "$CURSOR_PIDS" ]; then
            log_info "No running Cursor process found"
            return 0
        fi

        log_warn "Cursor process is running"
        get_process_details "cursor"
        log_warn "Attempting to close Cursor process..."

        if [ $attempt -eq $max_attempts ]; then
            log_warn "Attempting to force-kill process..."
            kill -9 "$CURSOR_PIDS" 2>/dev/null || true
        else
            kill "$CURSOR_PIDS" 2>/dev/null || true
        fi

        sleep 1
        if ! pgrep -i "cursor" >/dev/null 2>&1; then
            log_info "Cursor process successfully closed"
            return 0
        fi

        log_warn "Waiting for process to close, attempt $attempt/$max_attempts..."
        ((attempt++))
    done

    log_error "Unable to close Cursor process after $max_attempts attempts\n$(get_process_details "cursor")\nPlease close it manually and try again"
}

# Backup system ID
backup_system_id() {
    log_info "Backing up system ID..."
    local system_id_file="$BACKUP_DIR/system_id.backup_$(date +%Y%m%d_%H%M%S)"

    mkdir -p "$BACKUP_DIR" || log_error "Unable to create backup directory"
    {
        echo "# Original System ID Backup" >"$system_id_file"
        echo "## IOPlatformExpertDevice Info:" >>"$system_id_file"
        ioreg -rd1 -c IOPlatformExpertDevice >>"$system_id_file"
        chmod 444 "$system_id_file"
        chown "$CURRENT_USER" "$system_id_file"
        log_info "System ID backed up to: $system_id_file"
    } || log_error "Failed to backup system ID"
}

# Backup configuration file
backup_config() {
    if [ ! -f "$STORAGE_FILE" ]; then
        log_warn "Configuration file does not exist, skipping backup"
        return 0
    fi

    mkdir -p "$BACKUP_DIR" || log_error "Unable to create backup directory"
    local backup_file="$BACKUP_DIR/storage.json.backup_$(date +%Y%m%d_%H%M%S)"

    cp "$STORAGE_FILE" "$backup_file" || log_error "Backup failed"
    chmod 644 "$backup_file"
    chown "$CURRENT_USER" "$backup_file"
    log_info "Configuration backed up to: $backup_file"
}

# Generate random ID
generate_random_id() {
    openssl rand -hex 32
}

# Generate random UUID
generate_uuid() {
    uuidgen | tr '[:upper:]' '[:lower:]'
}

# Modify or add config
modify_or_add_config() {
    local key="$1"
    local value="$2"
    local file="$3"

    [ ! -f "$file" ] && log_error "File does not exist: $file"
    chmod 644 "$file" || log_error "Unable to modify file permissions: $file"

    local temp_file=$(mktemp)
    if grep -q "\"$key\":" "$file"; then
        sed "s/\"$key\":[[:space:]]*\"[^\"]*\"/\"$key\": \"$value\"/" "$file" >"$temp_file" || {
            rm -f "$temp_file"
            log_error "Failed to modify configuration: $key"
        }
    else
        sed "s/}$/,\n    \"$key\": \"$value\"\n}/" "$file" >"$temp_file" || {
            rm -f "$temp_file"
            log_error "Failed to add configuration: $key"
        }
    fi

    [ ! -s "$temp_file" ] && {
        rm -f "$temp_file"
        log_error "Generated temporary file is empty"
    }

    cat "$temp_file" >"$file" || {
        rm -f "$temp_file"
        log_error "Unable to write to file: $file"
    }
    rm -f "$temp_file"
    chmod 444 "$file"
}

# Generate new configuration
generate_new_config() {
    log_info "Modifying system ID..."
    backup_system_id

    local new_system_uuid=$(uuidgen)
    nvram SystemUUID="$new_system_uuid" || log_error "Failed to update SystemUUID"
    log_info "System UUID updated to: $new_system_uuid"
    log_warn "Please restart your system for the changes to take effect"

    local prefix_hex=$(echo -n "auth0|user_" | xxd -p)
    local random_part=$(generate_random_id)
    local machine_id="${prefix_hex}${random_part}"
    local mac_machine_id=$(generate_random_id)
    local device_id=$(generate_uuid)
    local sqm_id="{$(generate_uuid | tr '[:lower:]' '[:upper:]')}"

    log_info "Modifying configuration file..."
    [ ! -f "$STORAGE_FILE" ] && {
        log_error "Configuration file not found: $STORAGE_FILE\nPlease install and run Cursor once before using this script"
    }

    mkdir -p "$(dirname "$STORAGE_FILE")" || log_error "Unable to create configuration directory"
    [ ! -s "$STORAGE_FILE" ] && echo '{}' >"$STORAGE_FILE" || log_error "Unable to initialize configuration file"

    modify_or_add_config "telemetry.machineId" "$machine_id" "$STORAGE_FILE"
    modify_or_add_config "telemetry.macMachineId" "$mac_machine_id" "$STORAGE_FILE"
    modify_or_add_config "telemetry.devDeviceId" "$device_id" "$STORAGE_FILE"
    modify_or_add_config "telemetry.sqmId" "$sqm_id" "$STORAGE_FILE"

    chown "$CURRENT_USER" "$STORAGE_FILE"
    log_info "Updated configuration: $STORAGE_FILE"
    log_debug "machineId: $machine_id"
    log_debug "macMachineId: $mac_machine_id"
    log_debug "devDeviceId: $device_id"
    log_debug "sqmId: $sqm_id"
}

# Main function
main() {
    [[ $(uname) != "Darwin" ]] && log_error "This script only supports macOS systems"

    clear
    echo -e "
    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
    "
    echo -e "${BLUE}================================${NC}"
    echo -e "${GREEN}   Cursor Device ID Modification Tool          ${NC}"
    echo -e "${YELLOW}  Follow our public account [Pancake Roll AI]     ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo -e "${YELLOW}[Important]${NC} This tool supports Cursor v0.45.x"
    echo

    check_permissions
    check_and_kill_cursor
    backup_config
    generate_new_config

    log_info "Script completed successfully!"
}

# Execute main function
main
