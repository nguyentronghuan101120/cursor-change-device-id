#!/bin/bash

# Set error handling
set -e

# Define log file path
LOG_FILE="/tmp/cursor_mac_id_modifier.log"

# Initialize log file
initialize_log() {
    echo "========== Cursor ID Modifier Tool Log Start $(date) ==========" > "$LOG_FILE"
    chmod 644 "$LOG_FILE"
}

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function - outputs to both terminal and log file
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
    echo "[DEBUG] $(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

# Record command output to log file
log_cmd_output() {
    local cmd="$1"
    local msg="$2"
    echo "[CMD] $(date '+%Y-%m-%d %H:%M:%S') Executing command: $cmd" >> "$LOG_FILE"
    echo "[CMD] $msg:" >> "$LOG_FILE"
    eval "$cmd" 2>&1 | tee -a "$LOG_FILE"
    echo "" >> "$LOG_FILE"
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
    log_error "Cannot get username"
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
        log_error "Please run this script using sudo"
        echo "Example: sudo $0"
        exit 1
    fi
}

# Check and kill Cursor process
check_and_kill_cursor() {
    log_info "Checking Cursor process..."

    local attempt=1
    local max_attempts=5

    # Function: Get process details
    get_process_details() {
        local process_name="$1"
        log_debug "Getting $process_name process details:"
        ps aux | grep -i "/Applications/Cursor.app" | grep -v grep
    }

    while [ $attempt -le $max_attempts ]; do
        # Use more precise matching to get Cursor processes
        CURSOR_PIDS=$(ps aux | grep -i "/Applications/Cursor.app" | grep -v grep | awk '{print $2}')

        if [ -z "$CURSOR_PIDS" ]; then
            log_info "No running Cursor process found"
            return 0
        fi

        log_warn "Found Cursor process running"
        get_process_details "cursor"

        log_warn "Attempting to close Cursor process..."

        if [ $attempt -eq $max_attempts ]; then
            log_warn "Attempting to force terminate process..."
            kill -9 $CURSOR_PIDS 2>/dev/null || true
        else
            kill $CURSOR_PIDS 2>/dev/null || true
        fi

        sleep 1

        # Also use more precise matching to check if the process is still running
        if ! ps aux | grep -i "/Applications/Cursor.app" | grep -v grep > /dev/null; then
            log_info "Cursor process successfully closed"
            return 0
        fi

        log_warn "Waiting for process to close, attempt $attempt/$max_attempts..."
        ((attempt++))
    done

    log_error "Failed to close Cursor process after $max_attempts attempts"
    get_process_details "cursor"
    log_error "Please manually close the process and retry"
    exit 1
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
    # Generate 32 bytes (64 hexadecimal characters) of random data
    openssl rand -hex 32
}

# Generate random UUID
generate_uuid() {
    uuidgen | tr '[:upper:]' '[:lower:]'
}

# Modify existing file or add config
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
        log_error "Cannot modify file permissions: $file"
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
        # Note: This simple sed might fail on complex JSON. A more robust JSON tool (like jq) would be better.
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

    # Use cat to replace original file content (safer than mv for permissions/links)
    cat "$temp_file" > "$file" || {
        log_error "Cannot write to file: $file"
        rm -f "$temp_file"
        return 1
    }

    rm -f "$temp_file"

    # Restore file permissions (read-only)
    chmod 444 "$file"

    return 0
}

# Generate new configuration (or handle existing)
generate_new_config() {
    echo
    log_warn "Machine ID handling"

    # Default: do not reset machine ID
    reset_choice=0

    # Log for debugging
    echo "[INPUT_DEBUG] Machine ID reset option: Do not reset (default)" >> "$LOG_FILE"

    # Handling - Default is not to reset
    log_info "Defaulting to not resetting machine ID, will only modify js files"

    # Ensure configuration file directory exists (or handle if file exists)
    if [ -f "$STORAGE_FILE" ]; then
        log_info "Found existing configuration file: $STORAGE_FILE"

        # Backup existing configuration (just in case)
        backup_config
    else
        log_warn "Configuration file not found, this is normal, script will skip ID modification in storage.json"
    fi

    echo
    log_info "Configuration processing complete"
}

# Clean up previous Cursor modifications
clean_cursor_app() {
    log_info "Attempting to clean up previous Cursor modifications..."

    # If a backup exists, restore it directly
    local latest_backup=""

    # Find the latest backup
    latest_backup=$(find /tmp -name "Cursor.app.backup_*" -type d -print 2>/dev/null | sort -r | head -1)

    if [ -n "$latest_backup" ] && [ -d "$latest_backup" ]; then
        log_info "Found existing backup: $latest_backup"
        log_info "Restoring original version..."

        # Stop Cursor process (already done before calling this, but good practice)
        check_and_kill_cursor

        # Restore backup
        sudo rm -rf "$CURSOR_APP_PATH"
        sudo cp -R "$latest_backup" "$CURSOR_APP_PATH"
        sudo chown -R "$CURRENT_USER:staff" "$CURSOR_APP_PATH"
        sudo chmod -R 755 "$CURSOR_APP_PATH"

        log_info "Original version restored"
        return 0
    else
        log_warn "No existing backup found, cannot automatically restore."
        log_warn "Suggesting reinstalling Cursor..."
        echo "You can download and reinstall Cursor from https://cursor.sh"
        echo "Or, if you proceed, the script will attempt to modify the current installation."
        # Logic for redownloading and installing can be added here
        return 1 # Indicate failure to restore
    fi
}

# Modify Cursor main program files (safe mode)
modify_cursor_app_files() {
    log_info "Safely modifying Cursor main program files..."
    log_info "Detailed logs will be recorded in: $LOG_FILE"

    # First, try to clean up/restore from previous modifications if possible
    # clean_cursor_app # Removed from here, called explicitly in main menu flow

    # Verify application exists
    if [ ! -d "$CURSOR_APP_PATH" ]; then
        log_error "Cursor.app not found, please confirm installation path: $CURSOR_APP_PATH"
        return 1
    fi

    # Define target files - put extensionHostProcess.js first for priority processing
    local target_files=(
        "${CURSOR_APP_PATH}/Contents/Resources/app/out/vs/workbench/api/node/extensionHostProcess.js"
        "${CURSOR_APP_PATH}/Contents/Resources/app/out/main.js"
        "${CURSOR_APP_PATH}/Contents/Resources/app/out/vs/code/node/cliProcessMain.js"
    )

    # Check if files exist and if they have been modified
    local need_modification=false
    local missing_files=false

    log_debug "Checking target files..."
    for file in "${target_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_warn "File does not exist: ${file/$CURSOR_APP_PATH\//}"
            echo "[FILE_CHECK] File does not exist: $file" >> "$LOG_FILE"
            missing_files=true
            continue # Check next file even if one is missing
        fi

        echo "[FILE_CHECK] File exists: $file ($(wc -c < "$file") bytes)" >> "$LOG_FILE"

        # Check if the primary modification (randomUUID call) is already present
        if grep -q "return crypto.randomUUID()" "$file" 2>/dev/null; then
            log_info "File appears already modified (contains randomUUID): ${file/$CURSOR_APP_PATH\//}"
        # Check if the checksum modification is present in the specific file
        elif [[ "$file" == *"extensionHostProcess.js"* ]] && grep -q 'i.header.set("x-cursor-checksum",e===void 0?`${p}${t}`:`${p}${t}\/${p}`)' "$file" 2>/dev/null; then
            log_info "File appears already modified (contains checksum fix): ${file/$CURSOR_APP_PATH\//}"
        else
             log_info "File likely needs modification: ${file/$CURSOR_APP_PATH\//}"
             # Log relevant lines for debugging if modification is needed
             grep -n "IOPlatformUUID" "$file" | head -3 >> "$LOG_FILE" || echo "[FILE_CHECK] IOPlatformUUID not found in $file" >> "$LOG_FILE"
             if [[ "$file" == *"extensionHostProcess.js"* ]]; then
                 grep -n 'i.header.set("x-cursor-checksum' "$file" | head -3 >> "$LOG_FILE" || echo "[FILE_CHECK] x-cursor-checksum not found in $file" >> "$LOG_FILE"
             fi
             need_modification=true
             # No need to break, check all files first
        fi
    done

    if [ "$missing_files" = true ]; then
        log_error "Some target files do not exist. Please ensure Cursor installation is complete or try reinstalling."
        return 1
    fi

    if [ "$need_modification" = false ]; then
        log_info "All target files seem to be already modified or don't require the specific changes checked. No further action taken on app files."
        return 0 # Indicate success as no modification was needed
    fi

    log_info "Proceeding with modification..."

    # Create temporary working directory
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local temp_dir="/tmp/cursor_reset_${timestamp}"
    local temp_app="${temp_dir}/Cursor.app"
    local backup_app="/tmp/Cursor.app.backup_${timestamp}" # Backup location

    log_debug "Creating temporary directory: $temp_dir"
    echo "[TEMP_DIR] Creating temporary directory: $temp_dir" >> "$LOG_FILE"

    # Clean up potentially existing old temporary directories (less likely with timestamp but safe)
    if [ -d "$temp_dir" ]; then
        log_info "Cleaning up potentially existing temporary directory..."
        rm -rf "$temp_dir"
    fi

    # Create new temporary directory
    mkdir -p "$temp_dir" || {
        log_error "Cannot create temporary directory: $temp_dir"
        echo "[ERROR] Cannot create temporary directory: $temp_dir" >> "$LOG_FILE"
        return 1
    }

    # Backup original application to a timestamped location
    log_info "Backing up original application..."
    echo "[BACKUP] Starting backup: $CURSOR_APP_PATH -> $backup_app" >> "$LOG_FILE"

    cp -R "$CURSOR_APP_PATH" "$backup_app" || {
        log_error "Cannot create application backup at $backup_app"
        echo "[ERROR] Backup failed: $CURSOR_APP_PATH -> $backup_app" >> "$LOG_FILE"
        rm -rf "$temp_dir" # Clean up temp dir on backup failure
        return 1
    }

    echo "[BACKUP] Backup complete to $backup_app" >> "$LOG_FILE"

    # Copy application to temporary directory for modification
    log_info "Creating temporary working copy..."
    echo "[COPY] Starting copy: $CURSOR_APP_PATH -> $temp_dir" >> "$LOG_FILE"

    cp -R "$CURSOR_APP_PATH" "$temp_dir" || {
        log_error "Cannot copy application to temporary directory $temp_dir"
        echo "[ERROR] Copy failed: $CURSOR_APP_PATH -> $temp_dir" >> "$LOG_FILE"
        # Attempt to clean up temp dir and potentially the incomplete backup
        rm -rf "$temp_dir" "$backup_app"
        return 1
    }

    echo "[COPY] Copy complete" >> "$LOG_FILE"

    # Ensure temporary directory permissions are correct (script runs as sudo, but good practice)
    chown -R "$CURRENT_USER:staff" "$temp_dir"
    chmod -R 755 "$temp_dir"

    # Remove signature (enhance compatibility, needed before modification)
    log_info "Removing application signature..."
    echo "[CODESIGN] Removing signature: $temp_app" >> "$LOG_FILE"

    codesign --remove-signature "$temp_app" 2>> "$LOG_FILE" || {
        log_warn "Failed to remove application signature (might be unsigned already)"
        echo "[WARN] Failed to remove signature: $temp_app (continuing...)" >> "$LOG_FILE"
    }

    # Remove signatures from all related components
    local components=(
        "$temp_app/Contents/Frameworks/Cursor Helper.app"
        "$temp_app/Contents/Frameworks/Cursor Helper (GPU).app"
        "$temp_app/Contents/Frameworks/Cursor Helper (Plugin).app"
        "$temp_app/Contents/Frameworks/Cursor Helper (Renderer).app"
    )

    for component in "${components[@]}"; do
        if [ -e "$component" ]; then
            log_info "Removing signature: $(basename "$component")"
            codesign --remove-signature "$component" 2>> "$LOG_FILE" || {
                log_warn "Failed to remove component signature: $(basename "$component") (continuing...)"
            }
        fi
    done

    # Modify target files - prioritize js files
    local modified_count=0
    # Re-list files pointing to the temp directory
    local files_to_modify=(
        "${temp_app}/Contents/Resources/app/out/vs/workbench/api/node/extensionHostProcess.js"
        "${temp_app}/Contents/Resources/app/out/main.js"
        "${temp_app}/Contents/Resources/app/out/vs/code/node/cliProcessMain.js"
    )

    for file in "${files_to_modify[@]}"; do
        if [ ! -f "$file" ]; {
            log_warn "File not found in temp dir (should not happen): ${file/$temp_dir\//}"
            continue
        }

        log_debug "Processing file: ${file/$temp_dir\//}"
        echo "[PROCESS] Starting to process file: $file" >> "$LOG_FILE"
        echo "[PROCESS] File size: $(wc -c < "$file") bytes" >> "$LOG_FILE"

        # Output part of the file content to the log for debugging
        echo "[FILE_CONTENT] File header first 50 non-empty lines:" >> "$LOG_FILE"
        head -100 "$file" 2>/dev/null | grep -v "^$" | head -50 >> "$LOG_FILE"
        echo "[FILE_CONTENT] ..." >> "$LOG_FILE"

        # Create file backup within the temp dir before modification
        cp "$file" "${file}.bak" || {
            log_error "Cannot create file backup in temp dir: ${file/$temp_dir\//}"
            echo "[ERROR] Cannot create file backup: $file" >> "$LOG_FILE"
            continue # Skip this file if backup fails
        }

        local file_modified_in_loop=false

        # Use sed for replacement
        # --- Handle extensionHostProcess.js checksum ---
        if [[ "$file" == *"extensionHostProcess.js"* ]]; then
            log_debug "Processing extensionHostProcess.js file for checksum..."
            echo "[PROCESS_DETAIL] Starting checksum processing for extensionHostProcess.js" >> "$LOG_FILE"

            # Check if the specific target code exists
            if grep -q 'i.header.set("x-cursor-checksum' "$file"; then
                log_debug "Found x-cursor-checksum setting code line"
                echo "[FOUND] Found x-cursor-checksum setting code line" >> "$LOG_FILE"
                grep -n 'i.header.set("x-cursor-checksum' "$file" >> "$LOG_FILE" # Log the line found

                # Check if it's already modified
                if grep -q 'i.header.set("x-cursor-checksum",e===void 0?`${p}${t}`:`${p}${t}\/${p}`)' "$file"; then
                    log_info "Checksum modification already applied to extensionHostProcess.js"
                    file_modified_in_loop=true # Count as modified for overall success check
                else
                    # Perform the specific replacement
                    # Using comma as sed delimiter to avoid issues with slashes in the pattern
                    if sed -i.tmp 's,i\.header\.set("x-cursor-checksum",e===void 0?`${p}${t}`:`${p}${t}\/${e}`),i.header.set("x-cursor-checksum",e===void 0?`${p}${t}`:`${p}${t}\/${p}`),' "$file"; then
                        log_info "Successfully modified x-cursor-checksum setting code in extensionHostProcess.js"
                        echo "[SUCCESS] Successfully completed x-cursor-checksum setting code replacement" >> "$LOG_FILE"
                        grep -n 'i.header.set("x-cursor-checksum' "$file" >> "$LOG_FILE" # Log the modified line
                        file_modified_in_loop=true
                    else
                        log_error "Failed to modify x-cursor-checksum setting code in extensionHostProcess.js"
                        echo "[ERROR] Failed replacement for x-cursor-checksum setting code" >> "$LOG_FILE"
                        cp "${file}.bak" "$file" # Restore from backup on failure
                    fi
                fi
            else
                log_warn "Did not find the expected x-cursor-checksum setting code line in extensionHostProcess.js"
                echo "[FILE_CHECK] Expected x-cursor-checksum setting code not found" >> "$LOG_FILE"
                # Log related lines for easier debugging if structure changed
                echo "[FILE_CONTENT] Lines containing 'header.set' in extensionHostProcess.js:" >> "$LOG_FILE"
                grep -n "header.set" "$file" | head -20 >> "$LOG_FILE"
                echo "[FILE_CONTENT] Lines containing 'checksum' in extensionHostProcess.js:" >> "$LOG_FILE"
                grep -n "checksum" "$file" | head -20 >> "$LOG_FILE"
            fi
            echo "[PROCESS_DETAIL] Finished checksum processing for extensionHostProcess.js" >> "$LOG_FILE"
        fi # End of extensionHostProcess.js specific handling

        # --- Handle IOPlatformUUID / Device ID ---
        # Check if already modified with randomUUID
        if grep -q "return crypto.randomUUID()" "$file"; then
             log_info "File already contains randomUUID modification, skipping further ID changes: ${file/$temp_dir\//}"
             # If the checksum was also modified above, file_modified_in_loop will be true.
             # If only randomUUID was found, mark it as modified for the count.
             if ! $file_modified_in_loop; then
                 file_modified_in_loop=true
             fi
        # Check for IOPlatformUUID keyword for primary modification strategy
        elif grep -q "IOPlatformUUID" "$file"; then
            log_debug "Found IOPlatformUUID keyword in: ${file/$temp_dir\//}"
            echo "[FOUND] Found IOPlatformUUID keyword" >> "$LOG_FILE"
            grep -n "IOPlatformUUID" "$file" | head -5 >> "$LOG_FILE"

            # Attempt modification based on known function patterns
            local id_modified=false
            if grep -q "function a\$" "$file"; then
                # Target specific structure in main.js (example)
                if sed -i.tmp 's/function a\$(t){switch/function a\$(t){return crypto.randomUUID(); switch/' "$file"; then
                    log_debug "Successfully injected randomUUID call into a\$ function"
                    id_modified=true
                else
                    log_error "Failed to modify a\$ function, restoring backup"
                    cp "${file}.bak" "$file"
                fi
            elif grep -q "async function v5" "$file"; then
                # Alternative target function (example)
                if sed -i.tmp 's/async function v5(t){let e=/async function v5(t){return crypto.randomUUID(); let e=/' "$file"; then
                    log_debug "Successfully injected randomUUID call into v5 function"
                    id_modified=true
                else
                    log_error "Failed to modify v5 function, restoring backup"
                    cp "${file}.bak" "$file"
                fi
            # Add more specific patterns here if discovered
            # ...

            # Fallback if specific patterns fail or aren't found, but IOPlatformUUID is present
            elif ! $id_modified; then
                 log_warn "IOPlatformUUID found, but known function patterns (a$, v5) didn't match or failed. Attempting broader replacement (less precise)."
                 # Example: Replace the first occurrence of a pattern likely related to its usage
                 # This is more brittle and needs careful testing/adjustment based on actual file content
                 # sed -i.tmp '0,/IOPlatformUUID/{s/some_pattern_before/replacement_including_randomUUID/}' "$file"
                 # For now, just log that a more generic approach would be needed
                 log_warn "Generic replacement for IOPlatformUUID usage not implemented yet. Manual inspection might be needed if specific patterns fail."
                 # Keep id_modified as false
            fi

            if $id_modified; then
                log_info "Successfully modified file for device ID: ${file/$temp_dir\//}"
                file_modified_in_loop=true
            fi

        else
            # IOPlatformUUID not found, maybe structure changed drastically
            log_warn "IOPlatformUUID keyword not found in ${file/$temp_dir\//}. Cannot apply primary ID modification strategy."
            echo "[FILE_CHECK] IOPlatformUUID keyword not found" >> "$LOG_FILE"
            # Could add checks for other potential identifiers or functions here if needed
            # e.g., getMachineId, getDeviceId etc.
        fi # End of IOPlatformUUID / Device ID handling

        # Increment overall modified count if this file was changed in the loop
        if $file_modified_in_loop; then
            ((modified_count++))
            echo "[MODIFIED] File content after potential modification:" >> "$LOG_FILE"
            # Log lines relevant to the modifications made
            grep -n "return crypto.randomUUID()" "$file" | head -3 >> "$LOG_FILE"
            if [[ "$file" == *"extensionHostProcess.js"* ]]; then
                grep -n 'i.header.set("x-cursor-checksum' "$file" | head -3 >> "$LOG_FILE"
            fi
        fi

        # Clean up temporary files for this specific file
        rm -f "${file}.tmp" "${file}.bak"
        echo "[PROCESS] File processing complete: $file" >> "$LOG_FILE"
    done # End of file processing loop

    # Check if any modifications were successfully applied across all files
    if [ "$modified_count" -eq 0 ]; then
        log_error "Failed to apply necessary modifications to any target file."
        log_error "Check the log file for details: $LOG_FILE"
        # Clean up temp dir and restore original backup if modification failed
        log_info "Restoring original application from backup due to modification failure..."
        sudo rm -rf "$CURSOR_APP_PATH"
        sudo cp -R "$backup_app" "$CURSOR_APP_PATH" || log_error "Failed to restore backup!"
        rm -rf "$temp_dir" # Keep backup file ($backup_app) for manual recovery if needed
        return 1
    fi

    log_info "Successfully modified $modified_count target file(s)."

    # Re-sign the application (with retry mechanism)
    local max_retry=3
    local retry_count=0
    local sign_success=false

    while [ $retry_count -lt $max_retry ]; do
        ((retry_count++))
        log_info "Attempting to sign (Attempt $retry_count/$max_retry)..."

        # Use ad-hoc signing (-) with force and deep options
        # Log codesign output to a temporary file for inspection on failure
        if sudo codesign --sign - --force --deep --preserve-metadata=entitlements,identifier,flags "$temp_app" &> /tmp/codesign.log; then
            # Verify the signature immediately
            if sudo codesign --verify -vvvv "$temp_app" &> /tmp/codesign_verify.log; then
                sign_success=true
                log_info "Application signing verification passed."
                rm -f /tmp/codesign.log /tmp/codesign_verify.log # Clean up logs on success
                break # Exit retry loop
            else
                log_warn "Signature verification failed after signing (Attempt $retry_count). Error details:"
                cat /tmp/codesign_verify.log >> "$LOG_FILE" # Append verification error to main log
                cat /tmp/codesign_verify.log # Show verification error in console
                # Optionally, remove the failed signature before retrying?
                # codesign --remove-signature "$temp_app"
            fi
        else
            log_warn "Signing failed (Attempt $retry_count). Error details:"
            cat /tmp/codesign.log >> "$LOG_FILE" # Append signing error to main log
            cat /tmp/codesign.log # Show signing error in console
        fi

        if [ $retry_count -lt $max_retry ]; then
             log_info "Waiting 1 second before retrying signing..."
             sleep 1
        fi
    done

    # Clean up temporary signing logs if they still exist
    rm -f /tmp/codesign.log /tmp/codesign_verify.log

    if ! $sign_success; then
        log_error "Failed to sign the application after $max_retry attempts."
        log_error "The modified app is in: ${temp_app}"
        log_error "The original backup is in: ${backup_app}"
        log_error "You might need to manually sign or troubleshoot."
        echo -e "${YELLOW}To manually sign (ad-hoc):${NC}"
        echo -e "${BLUE}sudo codesign --sign - --force --deep '${temp_app}'${NC}"
        echo -e "${YELLOW}Then, manually replace the application:${NC}"
        echo -e "${BLUE}sudo rm -rf '/Applications/Cursor.app' && sudo cp -R '${temp_app}' '/Applications/'${NC}"
        # Don't automatically clean up $temp_dir or $backup_app on signing failure
        return 1
    fi

    log_info "Application successfully signed."

    # Replace original application with modified one
    log_info "Installing modified application..."
    # Use sudo for rm and cp as target is /Applications
    if ! sudo rm -rf "$CURSOR_APP_PATH" || ! sudo cp -R "$temp_app" "/Applications/"; then
        log_error "Application replacement failed! Restoring from backup..."
        # Attempt to restore the backup created earlier
        sudo rm -rf "$CURSOR_APP_PATH" # Clean up potentially partially copied app
        sudo cp -R "$backup_app" "$CURSOR_APP_PATH" || log_error "CRITICAL: Failed to restore backup $backup_app!"
        # Clean up temp dir, but keep the backup for safety
        rm -rf "$temp_dir"
        return 1
    fi

    # Clean up temporary directory and the now-obsolete backup copy in /tmp
    rm -rf "$temp_dir"
    # Keep the backup ($backup_app) for a while? Or remove it now?
    # rm -rf "$backup_app" # Uncomment if you want to clean up the backup immediately after success
    log_info "Temporary directory $temp_dir cleaned up."
    log_info "Original application backup remains at: $backup_app (can be manually deleted later)"


    # Set final permissions on the installed application
    sudo chown -R "$CURRENT_USER:staff" "$CURSOR_APP_PATH"
    sudo chmod -R 755 "$CURSOR_APP_PATH"

    log_info "Cursor main program file modification complete!"
    return 0
}

# Display file tree structure
show_file_tree() {
    local base_dir=$(dirname "$STORAGE_FILE")
    echo
    log_info "File structure:"
    echo -e "${BLUE}$base_dir${NC}"
    echo "├── globalStorage"
    # Check if storage.json exists before claiming modification
    if [ -f "$STORAGE_FILE" ]; then
        echo "│   ├── storage.json (Processing attempted)" # More accurate than "Modified" if it wasn't actually changed
    else
         echo "│   ├── storage.json (Not Found)"
    fi
    echo "│   └── backups"

    # List backup files
    if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR")" ]; then
        # Use find for potentially many files, limit output for display
        find "$BACKUP_DIR" -maxdepth 1 -name 'storage.json.backup_*' -print0 | xargs -0 -I {} basename {} | sort | head -n 5 | while read -r file; do
             echo "│       └── $file"
        done
        if [ $(find "$BACKUP_DIR" -maxdepth 1 -name 'storage.json.backup_*' | wc -l) -gt 5 ]; then
            echo "│       └── ..."
        fi
    else
        echo "│       └── (Empty or No Backups)"
    fi
    echo
}

# Display public account information
show_follow_info() {
    echo
    echo -e "${GREEN}================================${NC}"
    echo -e "${YELLOW}  Follow the public account [JianbingGuoziJuanAI] ${NC}"
    echo -e "${YELLOW}  to discuss more Cursor tips and AI knowledge ${NC}"
    echo -e "${YELLOW}  (Script is free, follow public account & join group for more tips/experts) ${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
}

# Disable auto-update
disable_auto_update() {
    local updater_path="$HOME/Library/Application Support/Caches/cursor-updater"
    local app_update_yml="/Applications/Cursor.app/Contents/Resources/app-update.yml"

    echo
    log_info "Attempting to disable Cursor auto-update..."

    # Backup and modify app-update.yml (make read-only)
    if [ -f "$app_update_yml" ]; then
        log_info "Backing up and modifying $app_update_yml..."
        # Use sudo for backup and modification in /Applications
        if ! sudo cp "$app_update_yml" "${app_update_yml}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null; then
            log_warn "Failed to back up $app_update_yml, continuing..."
        else
            log_info "Backup created: ${app_update_yml}.bak_..."
        fi

        # Make the file read-only for all to prevent updates writing to it
        # Emptying it might cause issues, making read-only is safer
        if sudo chmod 444 "$app_update_yml"; then
            log_info "Successfully made $app_update_yml read-only."
        else
            log_error "Failed to make $app_update_yml read-only. Please manually execute:"
            echo -e "${BLUE}sudo chmod 444 \"$app_update_yml\"${NC}"
        fi
    else
        log_warn "$app_update_yml file not found. Skipping."
    fi

    # Also handle cursor-updater cache directory/file (make inaccessible)
    log_info "Handling cursor-updater cache..."
    # We need sudo because the script runs with sudo, but path is in $HOME
    # Ensure the parent directory exists before trying to remove/touch
    mkdir -p "$(dirname "$updater_path")"
    # Remove if exists, then create an empty *file* and make read-only
    if sudo rm -rf "$updater_path" && \
       sudo touch "$updater_path" && \
       sudo chmod 444 "$updater_path"; then
        log_info "Successfully disabled cursor-updater by replacing with read-only file."
    else
        log_error "Failed to disable cursor-updater. Please manually execute:"
        echo -e "${BLUE}sudo rm -rf \"$updater_path\" && sudo touch \"$updater_path\" && sudo chmod 444 \"$updater_path\"${NC}"
    fi

    echo
    log_info "Verification method:"
    echo "1. Run command: ls -l \"$updater_path\""
    echo "   Confirm it is a FILE with permissions like: -r--r--r--"
    echo "2. Run command: ls -l \"$app_update_yml\""
    echo "   Confirm permissions show read-only, e.g.: -r--r--r--"
    echo
    log_info "Changes should take effect after restarting Cursor."
}

# Added restore feature option (for storage.json)
restore_feature() {
    log_info "Checking for storage.json backups..."
    # Check if backup directory exists
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warn "Backup directory $BACKUP_DIR does not exist. Cannot restore."
        return 1
    fi

    # Use find command to get list of backup files and store in an array
    local backup_files=()
    while IFS= read -r file; do
        [ -f "$file" ] && backup_files+=("$file")
    done < <(find "$BACKUP_DIR" -name "storage.json.backup_*" -type f 2>/dev/null | sort)

    # Check if any backup files were found
    if [ ${#backup_files[@]} -eq 0 ]; then
        log_warn "No storage.json backup files found in $BACKUP_DIR."
        return 1
    fi

    echo
    log_info "Available storage.json backups:"

    # Build menu options string
    local menu_options="Exit - Do not restore any file"
    for i in "${!backup_files[@]}"; do
        menu_options="$menu_options|$(basename "${backup_files[$i]}")"
    done

    # Use menu selection function
    select_menu_option "Use arrow keys to select the backup file to restore, press Enter to confirm:" "$menu_options" 0
    local choice=$? # Get return code which is the selected index

    # Handle user input
    if [ "$choice" -eq 0 ]; then # Index 0 is "Exit"
        log_info "Skipping restore operation."
        return 0
    fi

    # Get the selected backup file (adjust index: choice 1 maps to array index 0)
    local selected_backup_index=$((choice - 1))
    # Bounds check (shouldn't be necessary with select_menu_option but good practice)
     if [ "$selected_backup_index" -lt 0 ] || [ "$selected_backup_index" -ge ${#backup_files[@]} ]; then
        log_error "Invalid selection index."
        return 1
     fi
    local selected_backup="${backup_files[$selected_backup_index]}"


    # Verify file existence and readability (should exist based on find)
    if [ ! -f "$selected_backup" ] || [ ! -r "$selected_backup" ]; then
        log_error "Cannot access the selected backup file: $selected_backup"
        return 1
    fi

    log_info "Attempting to restore $STORAGE_FILE from $(basename "$selected_backup")..."
    # Attempt to restore configuration
    # Ensure permissions allow writing to the target file first
    # The target might not exist, so check parent dir write perms if needed,
    # but cp should handle creation. We need to ensure correct owner/perms after copy.
    # Make writable temporarily if exists
    [ -f "$STORAGE_FILE" ] && chmod 644 "$STORAGE_FILE" 2>/dev/null

    if cp "$selected_backup" "$STORAGE_FILE"; then
        # Set correct permissions and ownership after copy
        chmod 644 "$STORAGE_FILE" # User RW, Group R, Other R
        chown "$CURRENT_USER" "$STORAGE_FILE" # Own by the user running Cursor
        log_info "Successfully restored configuration from backup: $(basename "$selected_backup")"
        log_info "Restart Cursor for changes to take effect."
        return 0
    else
        log_error "Failed to restore configuration from $selected_backup"
        # Try to restore original permissions if file existed
        [ -f "$STORAGE_FILE" ] && chmod 444 "$STORAGE_FILE" 2>/dev/null
        return 1
    fi
}

# Fix "Application is damaged and cannot be opened" issue
fix_damaged_app() {
    log_info "Attempting to fix \"Application is damaged\" issue for Cursor.app..."

    # Check if Cursor application exists
    if [ ! -d "$CURSOR_APP_PATH" ]; then
        log_error "Cursor application not found: $CURSOR_APP_PATH. Cannot apply fix."
        return 1
    fi

    log_info "Attempting to remove quarantine attribute..."
    # Use sudo as the script runs with sudo
    if sudo xattr -rd com.apple.quarantine "$CURSOR_APP_PATH" &> /dev/null; then
        log_info "Successfully removed quarantine attribute (if it existed)."
    else
        # This command might fail if the attribute doesn't exist, which is fine.
        # Only log as warning if it fails for other reasons (permission denied unlikely with sudo)
        log_warn "Could not remove quarantine attribute (might not have existed or other error)."
    fi

    log_info "Attempting to re-sign the application with ad-hoc signature..."
    # Re-signing can often fix corruption issues perceived by Gatekeeper
    if sudo codesign --force --deep --sign - "$CURSOR_APP_PATH" &> /tmp/fix_damaged_codesign.log; then
        log_info "Application re-signed successfully (ad-hoc)."
        rm -f /tmp/fix_damaged_codesign.log
    else
        log_warn "Application re-signing failed. Check details below and in log."
        cat /tmp/fix_damaged_codesign.log
        cat /tmp/fix_damaged_codesign.log >> "$LOG_FILE"
        rm -f /tmp/fix_damaged_codesign.log
        # Don't return failure here, as removing quarantine might have been enough
    fi

    echo
    log_info "Fix attempt complete! Please try opening the Cursor application again."
    echo
    echo -e "${YELLOW}If it still cannot be opened, you can try:${NC}"
    echo "1. In System Preferences -> Security & Privacy -> General, look for an \"Open Anyway\" button for Cursor."
    echo "2. Temporarily allow apps from anywhere (use with caution and revert afterwards):"
    echo "   sudo spctl --master-disable  (To re-enable: sudo spctl --master-enable)"
    echo "3. Re-download and install the Cursor application from the official website."
    echo
    echo -e "${BLUE}Reference link (general macOS issue): https://sysin.org/blog/macos-if-crashes-when-opening/${NC}"

    return 0
}


# New: General menu selection function
# Parameters:
# $1 - Prompt message
# $2 - Options string, format "Option1|Option2|Option3"
# $3 - Default option index (0-based)
# Returns: Selected option index (0-based) via exit code
select_menu_option() {
    local prompt="$1"
    IFS='|' read -ra options <<< "$2"
    local default_index=${3:-0}
    local selected_index=$default_index
    local key_input
    # Terminfo capabilities (safer than hardcoded escapes)
    local cursor_up=$(tput cuu1)
    local cursor_down=$(tput cud1) # Or ind
    local enter_key=$'\n' # Standard newline for Enter
    local erase_line=$(tput el)

    # Hide cursor during selection
    tput civis

    # Function to cleanup cursor visibility on exit/interrupt
    cleanup_cursor() {
        tput cnorm # Make cursor visible again
    }
    trap cleanup_cursor EXIT INT TERM

    # Save cursor position
    tput sc

    # Display prompt message
    echo -e "$prompt"

    # Function to display the menu
    display_menu() {
        # Restore cursor position to overwrite previous menu
        tput rc
        # Move down one line past the prompt
        # tput cud1 # Not needed if prompt is simple echo

        for i in "${!options[@]}"; do
            # Erase the line before writing
            echo -n "${erase_line}"
            if [ $i -eq $selected_index ]; then
                echo -e " ${GREEN}►${NC} ${options[$i]}"
            else
                echo -e "   ${options[$i]}"
            fi
        done
    }

    # Initial display
    display_menu

    # Loop to handle keyboard input
    while true; do
        # Read up to 3 bytes to capture arrow keys
        read -rsn3 key_input

        # Detect key press
        case "$key_input" in
            # Up arrow key (ESC [ A)
            $'\e[A')
                if [ $selected_index -gt 0 ]; then
                    ((selected_index--))
                else
                    # Wrap around to the bottom
                    selected_index=$((${#options[@]}-1))
                fi
                display_menu
                ;;
            # Down arrow key (ESC [ B)
            $'\e[B')
                if [ $selected_index -lt $((${#options[@]}-1)) ]; then
                    ((selected_index++))
                else
                    # Wrap around to the top
                    selected_index=0
                fi
                display_menu
                ;;
            # Enter key (empty string for -s, or \n depending on terminal)
            ""|$'\n')
                echo # Move to a new line after selection
                log_info "User selected: ${options[$selected_index]}"
                cleanup_cursor # Ensure cursor is visible before returning
                trap - EXIT INT TERM # Remove trap
                return $selected_index # Return index via exit code
                ;;
            # Handle potential ESC key press alone (optional)
            $'\e')
                # Could potentially exit or ignore
                ;;
        esac
    done
}


# Main function
main() {

    # Initialize log file
    initialize_log
    log_info "Script starting..."

    # Log system information
    log_info "System information: $(uname -a)"
    log_info "Current user: $CURRENT_USER (Effective EUID: $EUID)"
    log_cmd_output "sw_vers" "macOS version information"
    log_cmd_output "which codesign" "codesign path"
    log_cmd_output "ls -ld \"$CURSOR_APP_PATH\"" "Cursor application path info" # Use -ld for directory info


    # Added environment check
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
    echo -e "${GREEN}   Cursor Helper Tool         ${NC}" # Renamed slightly
    echo -e "${YELLOW}  Follow Public Account [JianbingGuoziJuanAI] ${NC}"
    echo -e "${YELLOW}  Discuss Cursor tips & AI (Script free, join group for more) ${NC}" # Shortened
    echo -e "${BLUE}================================${NC}"
    echo
    echo -e "${YELLOW}[Important Note]${NC} This tool primarily modifies JS files for safety."
    echo -e "${YELLOW}[Important Note]${NC} This tool is free. If it helps, please follow [JianbingGuoziJuanAI]."
    echo

    # --- Main Workflow ---

    # 1. Check Permissions
    check_permissions

    # 2. Check and Kill Cursor
    check_and_kill_cursor # Will exit if it fails

    # 3. Backup config (if exists) - Done inside generate_new_config or restore_feature
    # backup_config # Call explicitly if needed outside other functions

    # 4. Handle configuration file (storage.json) - currently just logs and ensures backup
    generate_new_config

    # 5. Modify Application Files
    log_info "Attempting main application file modification..."
    local modification_successful=false
    # Use a subshell or check return status carefully
    if modify_cursor_app_files; then
        log_info "Main application file modification process completed successfully."
        modification_successful=true
    else
        log_error "Main application file modification process failed."
        # Decide whether to continue or exit based on severity.
        # Since signing failure already handles backup restore, we might continue to offer other options.
        modification_successful=false # Explicitly set
    fi

    # Restore error handling in case subshell changed it (unlikely here)
    set -e

    # 6. Show File Structure (Reflects state after potential modifications)
    show_file_tree

    # 7. Disable Auto Update (Run regardless of modification success)
    disable_auto_update

    # 8. Show Follow Info
    show_follow_info

    # 9. Final messages and options
    if $modification_successful; then
         log_info "Modifications applied. Please restart Cursor."
    else
         log_warn "Modification process encountered errors. Check logs. Cursor might not function correctly."
         log_warn "Original application backup should be at /tmp/Cursor.app.backup_*"
    fi


    # --- Optional Post-Actions ---

    # Restore storage.json from backup?
    echo
    log_warn "Optional: Restore storage.json"
    select_menu_option "Do you want to restore an older storage.json config from backup?" "No - Keep current state|Yes - Choose a backup to restore" 0
    local restore_choice=$?
    echo "[INPUT_DEBUG] Restore storage.json choice: $restore_choice" >> "$LOG_FILE"
    set +e # Allow potential errors in restore_feature without exiting main script
    if [ "$restore_choice" = "1" ]; then
        log_info "Proceeding with storage.json restore..."
        if ! restore_feature; then
             log_warn "storage.json restoration failed or was cancelled."
        fi
    else
        log_info "Skipping storage.json restore."
    fi
    set -e


    # Offer to restore original Cursor.app from the backup made *by this run*?
    echo
    log_warn "Optional: Revert App Modification"
    # Check if a backup was successfully created during *this* execution
    if [ -n "$backup_app" ] && [ -d "$backup_app" ]; then
        select_menu_option "Do you want to revert Cursor.app to the state BEFORE this script ran? (Using backup: $(basename "$backup_app"))" "No - Keep modified version|Yes - Revert to original backup" 0
        local revert_choice=$?
        echo "[INPUT_DEBUG] Revert app choice: $revert_choice" >> "$LOG_FILE"
        set +e
        if [ "$revert_choice" = "1" ]; then
            log_info "Reverting Cursor.app from backup: $backup_app"
            check_and_kill_cursor # Ensure Cursor is not running before revert
            sudo rm -rf "$CURSOR_APP_PATH"
            if sudo cp -R "$backup_app" "$CURSOR_APP_PATH"; then
                sudo chown -R "$CURRENT_USER:staff" "$CURSOR_APP_PATH"
                sudo chmod -R 755 "$CURSOR_APP_PATH"
                log_info "Cursor.app successfully reverted from backup."
            else
                log_error "Failed to revert Cursor.app from backup $backup_app!"
                log_error "Original application might be missing or corrupted."
            fi
        else
            log_info "Skipping revert operation. Keeping potentially modified Cursor.app."
        fi
        set -e
    else
        log_info "No backup location recorded from this run, cannot offer automatic revert."
    fi


    # Offer to fix "damaged app" issue
    echo
    log_warn "Optional: Fix 'Damaged App' Issue"
    select_menu_option "If Cursor shows 'Application is damaged', try this fix:" "No - Skip fix|Yes - Attempt fix (remove quarantine, re-sign)" 0
    local damaged_choice=$?
    echo "[INPUT_DEBUG] Fix damaged app choice: $damaged_choice" >> "$LOG_FILE"
    set +e
    if [ "$damaged_choice" = "1" ]; then
        log_info "Attempting to fix 'damaged app' issue..."
        if fix_damaged_app; then
            log_info "'Damaged app' fix attempt completed."
        else
            log_warn "'Damaged app' fix attempt encountered errors."
        fi
    else
        log_info "Skipping 'damaged app' fix."
    fi
    set -e

    # --- Final Log Messages ---
    log_info "Script execution finished."
    echo "========== Cursor ID Modifier Tool Log End $(date) ==========" >> "$LOG_FILE"

    # Display log file location
    echo
    log_info "Detailed log saved to: $LOG_FILE"
    echo "If you encounter problems, please provide this log file for assistance."
    echo

    # Final follow reminder
    show_follow_info

}

# Execute main function
main
