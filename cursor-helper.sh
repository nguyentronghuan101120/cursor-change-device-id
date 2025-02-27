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
    echo -e "${RED}[ERROR]${NC} $1"
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
    exit 1
fi

# Define configuration file path
STORAGE_FILE="$HOME/Library/Application Support/Cursor/User/globalStorage/storage.json"
BACKUP_DIR="$HOME/Library/Application Support/Cursor/User/globalStorage/backups"

# Define Cursor application path
CURSOR_APP_PATH="/Applications/Cursor.app"

# Check permissions
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run this script with sudo"
        echo "Example: sudo $0"
        exit 1
    fi
}

# Check and close Cursor process
check_and_kill_cursor() {
    log_info "Checking Cursor process..."
    
    local attempt=1
    local max_attempts=5
    
    # Function: Get process details
    get_process_details() {
        local process_name="$1"
        log_debug "Getting $process_name process details:"
        ps aux | grep -i "$process_name" | grep -v grep
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
            kill -9 $CURSOR_PIDS 2>/dev/null || true
        else
            kill $CURSOR_PIDS 2>/dev/null || true
        fi
        
        sleep 1
        
        if ! pgrep -i "cursor" > /dev/null; then
            log_info "Cursor process successfully closed"
            return 0
        fi
        
        log_warn "Waiting for process to close, attempt $attempt/$max_attempts..."
        ((attempt++))
    done
    
    log_error "Unable to close Cursor process after $max_attempts attempts"
    get_process_details "cursor"
    log_error "Please close the process manually and try again"
    exit 1
}

# Backup system ID
backup_system_id() {
    log_info "Backing up system ID..."
    local system_id_file="$BACKUP_DIR/system_id.backup_$(date +%Y%m%d_%H%M%S)"
    
    # Get and backup IOPlatformExpertDevice info
    {
        echo "# Original System ID Backup" > "$system_id_file"
        echo "## IOPlatformExpertDevice Info:" >> "$system_id_file"
        ioreg -rd1 -c IOPlatformExpertDevice >> "$system_id_file"
        
        chmod 444 "$system_id_file"
        chown "$CURRENT_USER" "$system_id_file"
        log_info "System ID backed up to: $system_id_file"
    } || {
        log_error "Failed to backup system ID"
        return 1
    }
}

# Backup configuration file
backup_config() {
    if [ ! -f "$STORAGE_FILE" ]; then
        log_warn "Configuration file does not exist, skipping backup"
        return 0
    fi
    
    mkdir -p "$BACKUP_DIR"
    local backup_file="$BACKUP_DIR/storage.json.backup_$(date +%Y%m%d_%H%M%S)"
    
    if cp "$STORAGE_FILE" "$backup_file"; then
        chmod 644 "$backup_file"
        chown "$CURRENT_USER" "$backup_file"
        log_info "Configuration backed up to: $backup_file"
    else
        log_error "Backup failed"
        exit 1
    fi
}

# Generate random ID
generate_random_id() {
    # Generate a 32-byte (64 hexadecimal characters) random number
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
    
    if [ ! -f "$file" ]; then
        log_error "File does not exist: $file"
        return 1
    fi
    
    # Ensure the file is writable
    chmod 644 "$file" || {
        log_error "Unable to modify file permissions: $file"
        return 1
    }
    
    # Create temporary file
    local temp_file=$(mktemp)
    
    # Check if key exists
    if grep -q "\"$key\":" "$file"; then
        # Key exists, perform replacement
        sed "s/\"$key\":[[:space:]]*\"[^\"]*\"/\"$key\": \"$value\"/" "$file" > "$temp_file" || {
            log_error "Failed to modify configuration: $key"
            rm -f "$temp_file"
            return 1
        }
    else
        # Key does not exist, add new key-value pair
        sed "s/}$/,\n    \"$key\": \"$value\"\n}/" "$file" > "$temp_file" || {
            log_error "Failed to add configuration: $key"
            rm -f "$temp_file"
            return 1
        }
    fi
    
    # Check if temporary file is empty
    if [ ! -s "$temp_file" ]; then
        log_error "Generated temporary file is empty"
        rm -f "$temp_file"
        return 1
    fi
    
    # Replace original file content with cat
    cat "$temp_file" > "$file" || {
        log_error "Unable to write to file: $file"
        rm -f "$temp_file"
        return 1
    }
    
    rm -f "$temp_file"
    
    # Restore file permissions
    chmod 444 "$file"
    
    return 0
}

# Generate new configuration
generate_new_config() {
  
    # Modify system ID
    log_info "Modifying system ID..."
    
    # Backup current system ID
    backup_system_id
    
    # Generate new system UUID
    local new_system_uuid=$(uuidgen)
    
    # Modify system UUID
    sudo nvram SystemUUID="$new_system_uuid"
    printf "${YELLOW}System UUID updated to: $new_system_uuid${NC}\n"
    printf "${YELLOW}Please restart your system for the changes to take effect${NC}\n"
    
    # Convert auth0|user_ to hexadecimal byte array
    local prefix_hex=$(echo -n "auth0|user_" | xxd -p)
    local random_part=$(generate_random_id)
    local machine_id="${prefix_hex}${random_part}"
    
    local mac_machine_id=$(generate_random_id)
    local device_id=$(generate_uuid | tr '[:upper:]' '[:lower:]')
    local sqm_id="{$(generate_uuid | tr '[:lower:]' '[:upper:]')}"
    
    log_info "Modifying configuration file..."
    # Check if the configuration file exists
    if [ ! -f "$STORAGE_FILE" ]; then
        log_error "Configuration file not found: $STORAGE_FILE"
        log_warn "Please install and run Cursor once before using this script"
        exit 1
    fi
    
    # Ensure configuration directory exists
    mkdir -p "$(dirname "$STORAGE_FILE")" || {
        log_error "Unable to create configuration directory"
        exit 1
    }
    
    # If file doesn't exist, create a basic JSON structure
    if [ ! -s "$STORAGE_FILE" ]; then
        echo '{}' > "$STORAGE_FILE" || {
            log_error "Unable to initialize configuration file"
            exit 1
        }
    fi
    
    # Modify existing file
    modify_or_add_config "telemetry.machineId" "$machine_id" "$STORAGE_FILE" || exit 1
    modify_or_add_config "telemetry.macMachineId" "$mac_machine_id" "$STORAGE_FILE" || exit 1
    modify_or_add_config "telemetry.devDeviceId" "$device_id" "$STORAGE_FILE" || exit 1
    modify_or_add_config "telemetry.sqmId" "$sqm_id" "$STORAGE_FILE" || exit 1
    
    # Set file permissions and owner
    chmod 444 "$STORAGE_FILE"  # Change to read-only permissions
    chown "$CURRENT_USER" "$STORAGE_FILE"
    
    # Verify permission settings
    if [ -w "$STORAGE_FILE" ]; then
        log_warn "Unable to set read-only permissions, attempting other methods..."
        chattr +i "$STORAGE_FILE" 2>/dev/null || true
    else
        log_info "Successfully set file to read-only"
    fi
    
    echo
    log_info "Updated configuration: $STORAGE_FILE"
    log_debug "machineId: $machine_id"
    log_debug "macMachineId: $mac_machine_id"
    log_debug "devDeviceId: $device_id"
    log_debug "sqmId: $sqm_id"
}

# Modify Cursor main program files (safe mode)
modify_cursor_app_files() {
    log_info "Safely modifying Cursor main program files..."
    
    # Verify application exists
    if [ ! -d "$CURSOR_APP_PATH" ]; then
        log_error "Cursor.app not found, please confirm installation path: $CURSOR_APP_PATH"
        return 1
    fi

    # Define target files
    local target_files=(
        "${CURSOR_APP_PATH}/Contents/Resources/app/out/main.js"
        "${CURSOR_APP_PATH}/Contents/Resources/app/out/vs/code/node/cliProcessMain.js"
    )
    
    # Check if files exist and are already modified
    local need_modification=false
    local missing_files=false
    
    for file in "${target_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_warn "File does not exist: ${file/$CURSOR_APP_PATH\//}"
            missing_files=true
            continue
        fi
        
        if ! grep -q "return crypto.randomUUID()" "$file" 2>/dev/null; then
            log_info "File needs modification: ${file/$CURSOR_APP_PATH\//}"
            need_modification=true
            break
        else
            log_info "File already modified: ${file/$CURSOR_APP_PATH\//}"
        fi
    done
    
    # If all files are already modified or do not exist, exit
    if [ "$missing_files" = true ]; then
        log_error "Some target files do not exist, please confirm Cursor installation is complete"
        return 1
    fi
    
    if [ "$need_modification" = false ]; then
        log_info "All target files have already been modified, no need to repeat the operation"
        return 0
    fi

    # Create temporary working directory
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local temp_dir="/tmp/cursor_reset_${timestamp}"
    local temp_app="${temp_dir}/Cursor.app"
    local backup_app="/tmp/Cursor.app.backup_${timestamp}"
    
    # Clean up any existing temporary directories
    if [ -d "$temp_dir" ]; then
        log_info "Cleaning up existing temporary directory..."
        rm -rf "$temp_dir"
    fi
    
    # Create new temporary directory
    mkdir -p "$temp_dir" || {
        log_error "Unable to create temporary directory: $temp_dir"
        return 1
    }

    # Backup original application
    log_info "Backing up original application..."
    cp -R "$CURSOR_APP_PATH" "$backup_app" || {
        log_error "Unable to create application backup"
        rm -rf "$temp_dir" "$backup_app"
        return 1
    }

    # Copy application to temporary directory
    log_info "Creating temporary working copy..."
    cp -R "$CURSOR_APP_PATH" "$temp_dir" || {
        log_error "Unable to copy application to temporary directory"
        rm -rf "$temp_dir" "$backup_app"
        return 1
    }

    # Ensure correct permissions for temporary directory
    chown -R "$CURRENT_USER:staff" "$temp_dir"
    chmod -R 755 "$temp_dir"

    # Remove signature (for improved compatibility)
    log_info "Removing application signature..."
    codesign --remove-signature "$temp_app" || {
        log_warn "Failed to remove application signature"
    }

    # Remove signatures for all related components
    local components=(
        "$temp_app/Contents/Frameworks/Cursor Helper.app"
        "$temp_app/Contents/Frameworks/Cursor Helper (GPU).app"
        "$temp_app/Contents/Frameworks/Cursor Helper (Plugin).app"
        "$temp_app/Contents/Frameworks/Cursor Helper (Renderer).app"
    )

    for component in "${components[@]}"; do
        if [ -e "$component" ]; then
            log_info "Removing signature: $component"
            codesign --remove-signature "$component" || {
                log_warn "Failed to remove component signature: $component"
            }
        fi
    done
    
    # Modify target files
    local modified_count=0
    local files=(
        "${temp_app}/Contents/Resources/app/out/main.js"
        "${temp_app}/Contents/Resources/app/out/vs/code/node/cliProcessMain.js"
    )
    
    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            log_warn "File does not exist: ${file/$temp_dir\//}"
            continue
        fi
        
        log_debug "Processing file: ${file/$temp_dir\//}"
        
        # Create file backup
        cp "$file" "${file}.bak" || {
            log_error "Unable to create file backup: ${file/$temp_dir\//}"
            continue
        }

        # Read file content
        local content=$(cat "$file")
        
        # Find the location of IOPlatformUUID
        local uuid_pos=$(printf "%s" "$content" | grep -b -o "IOPlatformUUID" | cut -d: -f1)
        if [ -z "$uuid_pos" ]; then
            log_warn "IOPlatformUUID not found in $file"
            continue
        fi

        # Find switch before UUID position
        local before_uuid=${content:0:$uuid_pos}
        local switch_pos=$(printf "%s" "$before_uuid" | grep -b -o "switch" | tail -n1 | cut -d: -f1)
        if [ -z "$switch_pos" ]; then
            log_warn "switch keyword not found in $file"
            continue
        fi

        # Build new file content
        if printf "%sreturn crypto.randomUUID();\n%s" "${content:0:$switch_pos}" "${content:$switch_pos}" > "$file"; then
            ((modified_count++))
            log_info "Successfully modified file: ${file/$temp_dir\//}"
        else
            log_error "Failed to write to file: ${file/$temp_dir\//}"
            mv "${file}.bak" "$file"
        fi
        
        # Clean up backup
        rm -f "${file}.bak"
    done
    
    if [ "$modified_count" -eq 0 ]; then
        log_error "Failed to modify any files"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Re-sign application (add retry mechanism)
    local max_retry=3
    local retry_count=0
    local sign_success=false
    
    while [ $retry_count -lt $max_retry ]; do
        ((retry_count++))
        log_info "Attempting to sign (attempt $retry_count)..."
        
        # Use more detailed signing parameters
        if codesign --sign - --force --deep --preserve-metadata=entitlements,identifier,flags "$temp_app" 2>&1 | tee /tmp/codesign.log; then
            # Verify signature
            if codesign --verify -vvvv "$temp_app" 2>/dev/null; then
                sign_success=true
                log_info "Application signature verification passed"
                break
            else
                log_warn "Signature verification failed, error log:"
                cat /tmp/codesign.log
            fi
        else
            log_warn "Signing failed, error log:"
            cat /tmp/codesign.log
        fi
        
        sleep 1
    done

    if ! $sign_success; then
        log_error "Unable to complete signing after $max_retry attempts"
        log_error "Please manually execute the following command to complete signing:"
        echo -e "${BLUE}sudo codesign --sign - --force --deep '${temp_app}'${NC}"
        echo -e "${YELLOW}After completion, please manually copy the application to the original path:${NC}"
        echo -e "${BLUE}sudo cp -R '${temp_app}' '/Applications/'${NC}"
        log_info "Temporary files are retained in: ${temp_dir}"
        return 1
    fi

    # Replace original application
    log_info "Installing modified application..."
    if ! sudo rm -rf "$CURSOR_APP_PATH" || ! sudo cp -R "$temp_app" "/Applications/"; then
        log_error "Application replacement failed, restoring..."
        sudo rm -rf "$CURSOR_APP_PATH"
        sudo cp -R "$backup_app" "$CURSOR_APP_PATH"
        rm -rf "$temp_dir" "$backup_app"
        return 1
    fi
    
    # Clean up temporary files
    rm -rf "$temp_dir" "$backup_app"
    
    # Set permissions
    sudo chown -R "$CURRENT_USER:staff" "$CURSOR_APP_PATH"
    sudo chmod -R 755 "$CURSOR_APP_PATH"
    
    log_info "Cursor main program file modification complete! Original backup is in: ${backup_app/$HOME/\~}"
    return 0
}

# Show file tree structure
show_file_tree() {
    local base_dir=$(dirname "$STORAGE_FILE")
    echo
    log_info "File structure:"
    echo -e "${BLUE}$base_dir${NC}"
    echo "├── globalStorage"
    echo "│   ├── storage.json (modified)"
    echo "│   └── backups"
    
    # List backup files
    if [ -d "$BACKUP_DIR" ]; then
        local backup_files=("$BACKUP_DIR"/*)
        if [ ${#backup_files[@]} -gt 0 ]; then
            for file in "${backup_files[@]}"; do
                if [ -f "$file" ]; then
                    echo "│       └── $(basename "$file")"
                fi
            done
        else
            echo "│       └── (empty)"
        fi
    fi
    echo
}

# Show follow information
show_follow_info() {
    echo
    echo -e "${GREEN}================================${NC}"
    echo -e "${YELLOW}  Follow our public account [Pancake Roll AI] to exchange more Cursor skills and AI knowledge (script is free, follow our public account and join the group for more skills and experts) ${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
}

# Disable auto-update
disable_auto_update() {
    local updater_path="$HOME/Library/Application Support/Caches/cursor-updater"
    local app_update_yml="/Applications/Cursor.app/Contents/Resources/app-update.yml"
    
    echo
    log_info "Disabling Cursor auto-update..."
    
    # Backup and clear app-update.yml
    if [ -f "$app_update_yml" ]; then
        log_info "Backing up and modifying app-update.yml..."
        if ! sudo cp "$app_update_yml" "${app_update_yml}.bak" 2>/dev/null; then
            log_warn "Failed to backup app-update.yml, continuing..."
        fi
        
        if sudo bash -c "echo '' > \"$app_update_yml\"" && \
           sudo chmod 444 "$app_update_yml"; then
            log_info "Successfully disabled app-update.yml"
        else
            log_error "Failed to modify app-update.yml, please execute the following commands manually:"
            echo -e "${BLUE}sudo cp \"$app_update_yml\" \"${app_update_yml}.bak\"${NC}"
            echo -e "${BLUE}sudo bash -c 'echo \"\" > \"$app_update_yml\"'${NC}"
            echo -e "${BLUE}sudo chmod 444 \"$app_update_yml\"${NC}"
        fi
    else
        log_warn "app-update.yml file not found"
    fi
    
    # Also handle cursor-updater
    log_info "Handling cursor-updater..."
    if sudo rm -rf "$updater_path" && \
       sudo touch "$updater_path" && \
       sudo chmod 444 "$updater_path"; then
        log_info "Successfully disabled cursor-updater"
    else
        log_error "Failed to disable cursor-updater, please execute the following commands manually:"
        echo -e "${BLUE}sudo rm -rf \"$updater_path\" && sudo touch \"$updater_path\" && sudo chmod 444 \"$updater_path\"${NC}"
    fi
    
    echo
    log_info "Verification method:"
    echo "1. Run command: ls -l \"$updater_path\""
    echo "   Confirm file permissions display as: r--r--r--"
    echo "2. Run command: ls -l \"$app_update_yml\""
    echo "   Confirm file permissions display as: r--r--r--"
    echo
    log_info "Please restart Cursor after completion"
}

# Generate random MAC address
generate_random_mac() {
    # Generate random MAC address, keeping the second bit of the first byte at 0 (guaranteeing it is a unicast address)
    printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

# Get network interface list
get_network_interfaces() {
    networksetup -listallhardwareports | awk '/Hardware Port|Ethernet Address/ {print $NF}' | paste - - | grep -v 'N/A'
}

# Backup MAC addresses
backup_mac_addresses() {
    log_info "Backing up MAC addresses..."
    local backup_file="$BACKUP_DIR/mac_addresses.backup_$(date +%Y%m%d_%H%M%S)"
    
    {
        echo "# Original MAC Addresses Backup - $(date)" > "$backup_file"
        echo "## Network Interfaces:" >> "$backup_file"
        networksetup -listallhardwareports >> "$backup_file"
        
        chmod 444 "$backup_file"
        chown "$CURRENT_USER" "$backup_file"
        log_info "MAC addresses backed up to: $backup_file"
    } || {
        log_error "Failed to backup MAC addresses"
        return 1
    }
}

# Modify MAC address
modify_mac_address() {
    log_info "Getting network interface information..."
    
    # Backup current MAC address
    backup_mac_addresses
    
    # Get all network interfaces
    local interfaces=$(get_network_interfaces)
    
    if [ -z "$interfaces" ]; then
        log_error "No available network interfaces found"
        return 1
    fi
    
    echo
    log_info "Found the following network interfaces:"
    echo "$interfaces" | nl -w2 -s') '
    echo
    
    echo -n "Please select the interface number to modify (press Enter to skip): "
    read -r choice
    
    if [ -z "$choice" ]; then
        log_info "Skipping MAC address modification"
        return 0
    fi
    
    # Get the selected interface name
    local selected_interface=$(echo "$interfaces" | sed -n "${choice}p" | awk '{print $1}')
    
    if [ -z "$selected_interface" ]; then
        log_error "Invalid selection"
        return 1
    fi
    
    # Generate new MAC address
    local new_mac=$(generate_random_mac)
    
    log_info "Modifying MAC address of interface $selected_interface..."
    
    # Close network interface
    sudo ifconfig "$selected_interface" down || {
        log_error "Unable to close network interface"
        return 1
    }
    
    # Modify MAC address
    if sudo ifconfig "$selected_interface" ether "$new_mac"; then
        # Re-enable network interface
        sudo ifconfig "$selected_interface" up
        log_info "Successfully modified MAC address to: $new_mac"
        echo
        log_warn "Please note: MAC address modification may require reconnecting to the network for it to take effect"
    else
        log_error "Failed to modify MAC address"
        # Attempt to restore network interface
        sudo ifconfig "$selected_interface" up
        return 1
    fi
}

# Add restore functionality option
restore_feature() {
    # Check if the backup directory exists
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warn "Backup directory does not exist"
        return 1
    fi

    # Use the find command to get the list of backup files and store it in an array
    backup_files=()
    while IFS= read -r file; do
        [ -f "$file" ] && backup_files+=("$file")
    done < <(find "$BACKUP_DIR" -name "*.backup_*" -type f 2>/dev/null | sort)
    
    # Check if any backup files were found
    if [ ${#backup_files[@]} -eq 0 ]; then
        log_warn "No backup files found"
        return 1
    fi
    
    echo
    log_info "Available backup files:"
    echo "0) Exit (default)"
    
    # Display the list of backup files
    for i in "${!backup_files[@]}"; do
        echo "$((i+1))) $(basename "${backup_files[$i]}")"
    done
    
    echo
    echo -n "Please select the backup file number to restore [0-${#backup_files[@]}] (default: 0): "
    read -r choice
    
    # Process user input
    if [ -z "$choice" ] || [ "$choice" = "0" ]; then
        log_info "Skipping restore operation"
        return 0
    fi
    
    # Validate input
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt "${#backup_files[@]}" ]; then
        log_error "Invalid selection"
        return 1
    fi
    
    # Get the selected backup file
    local selected_backup="${backup_files[$((choice-1))]}"
    
    # Verify file existence and readability
    if [ ! -f "$selected_backup" ] || [ ! -r "$selected_backup" ]; then
        log_error "Unable to access the selected backup file"
        return 1
    fi
    
    # Attempt to restore configuration
    if cp "$selected_backup" "$STORAGE_FILE"; then
        chmod 644 "$STORAGE_FILE"
        chown "$CURRENT_USER" "$STORAGE_FILE"
        log_info "Configuration restored from backup file: $(basename "$selected_backup")"
        return 0
    else
        log_error "Failed to restore configuration"
        return 1
    fi
}

# Main function
main() {
    
    # Add environment check
    if [[ $(uname) != "Darwin" ]]; then
        log_error "This script only supports macOS systems"
        exit 1
    fi
    
    
    clear
    # Display Logo
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
    echo -e "${YELLOW}  Exchange more Cursor skills and AI knowledge together (script is free, follow our public account and join the group for more skills and experts)  ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
    echo -e "${YELLOW}[Important]${NC} This tool supports Cursor v0.45.x"
    echo -e "${YELLOW}[Important]${NC} This tool is free, if it helps you, please follow our public account [Pancake Roll AI]"
    echo
    
    check_permissions
    check_and_kill_cursor
    backup_config
    generate_new_config
    modify_cursor_app_files
    
    # Add MAC address modification option
    echo
    log_warn "Do you want to modify the MAC address?"
    echo "0) No - Keep default settings (default)"
    echo "1) Yes - Modify MAC address"
    echo -n "Enter your choice [0-1] (default 0): "
    read -r choice
    
    # Process user input (including empty and invalid input)
    case "$choice" in
        1)
            if modify_mac_address; then
                log_info "MAC address modification complete!"
            else
                log_error "MAC address modification failed"
            fi
            ;;
        *)
            log_info "MAC address modification skipped"
            ;;
    esac
    
    show_file_tree
    show_follow_info
  
    # Directly execute disable auto-update
    disable_auto_update

    log_info "Please restart Cursor to apply the new configuration"

    # Add restore functionality option
    #restore_feature

    # Show final prompt information
    show_follow_info

    
}

# Execute main function
main
