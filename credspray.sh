#!/bin/bash

# NetExec Credential Validation Script
# Checks credentials against multiple protocols with local and domain auth

# Remove set -e to handle errors manually
set +e

# Default values
TARGET=""
PASSWORD=""
HASH=""
USER_INPUT=""
COMBINED_FILE=""
PROTOCOLS=()

# Global variables for process management
CURRENT_PID=""
SKIP_CURRENT=false
LAST_INTERRUPT_TIME=0
INTERRUPT_TIMEOUT=1  # seconds - if Ctrl+C pressed again within this time, exit

# Color definitions
BLUE='\033[38;5;39m'
CYAN='\033[38;5;51m'
GREEN='\033[38;5;46m'
YELLOW='\033[38;5;226m'
RED='\033[38;5;196m'
PURPLE='\033[38;5;129m'
ORANGE='\033[38;5;208m'
WHITE='\033[38;5;231m'
SKIN='\033[38;5;223m'
BOLD='\033[1m'
NC='\033[0m'

clear
# Banner
echo -e "${BLUE}"
cat << "EOF"

             ▏▌▌▊▁▊▋▃▊▊▍
            ▊▇▅▃▃▂▁▅▄█▅▉▌
           ▊█▇▊▋▌▉▄████▅▃▋▌▁▁▊▌▎
          ▏▇█▅▋▄██████▁▅▉▁▋▋▃▂▅▁▁▌▎
          ▌██▄▇███████▄▌▏▏▋▋ ▏▎▎▌▏▎▍▏
          ▋██████████▄▏▏▋▆▌▏▉▁▋ ▍▍▍▍▌▎
          ▎██████████▂▄▅█▇▅█▆▇▃▊▃▁▄▍▃▌
          ▏▇██████████████▇▇▁▃███▄▇▅█▃▌
        ▏▏▍▇█████▇▁██████▇▅▂▃▆██▇▄██▆▆▊
         ▉▇███████▄████▄▁▁▊▎▏▊▉▆▅▇██▃▆▌
          ▏▂███████████▅▍    ▎▌▌▌███▁▋▏
          ▉██████████▁█▄▊▏ ▎▍▎ ▎▄███▃
       ▎▋▅███████████▋▅▇█▃▊▌▋▉▃███▄▂▄▎
       ▏▌▉▂██▃▉▁▆▄████▂█▂▊▃▇▆█████▅▆▇▊                    ▏▏▏▏
        ▏▂█▄▁▆█▃▎▏▋▆████▋▎▏▍▌▊▅████▌▁▅▁▌▏               ▏▌▁▃▂▊▍▏
     ▏▉▆▇▄▁▃▃▎▉▇█▃▉▎▄██▆▎▏▏▍▍▏▎▁██▅▁█▃▌▊▁▁▌▌▌▍▌▌▌▎     ▏▋▌███▂▃▊▎
   ▎▁▇█▄▊▋▂▂▊▋▉▇███▆▋▄▇▍      ▎▍▎▆▅██▅▃▂▁▊▄▆▂▍  ▏▊▄▎▏▏▍▍▋▊▃▌▍▏▃▊▋
  ▉███▃▋▃▅▂▃█▆███████▂▆▊▏       ▍▄█▇██▇▇██▆█▊▉▍▃█▇▁▊▁▄▋ ▅██▅▅▅▆▁▊
 ▁█▆█▅▍▉▃▃▄██████████▆██▃▁▉▉▊▋▉▋▍▇█▅█████████▆▁██▇▃▅▆▁▌▎▅██▅▊▌▅▁▉         _____              _    _____
 ▃███▄▇▅▍ ▏▋▄▁▊███████████▆▉▊▋▍▏▌▅████████████████████▌▋▁▆█▇▏▏▉▃▎        / ____|            | |  / ____|
 ▎▇██████▄▅▃▃█████████████▋▌▋▋▉▂▃▄███▊▉▄███████████▃▃▋   ▉██▋▍▉▅▏       | |     ____ ___  __| | | (___  ____  ____ ____ _   _
  ▍▅████████▅▆▆████████▆▉▋▋▌▍▏▌▍ ▋███▉  ▏▎▍▊▁▄▅▅▅▁▎      ▎██████▋       | |    |  __/ _ \/ _  |  \___ \|  _ \| __/  _  | | | |
    ▎▆██████▅▅▄▉▉▄████▅▌▏     ▍▌ ▏▂██▇                    ▊▄▅▄▃▊        | |____| | |  __/ (_| |  ____) | |_) | | | (_| | |_| |
     ▏▋▉▁▄██▇▎▏  ▍▍▉▄▆▎       ▏▏  ▏▇█▂                                   \_____|_|  \___|\____| |_____/|  __/|_|  \____|\___ |
          ▎▋▃▌  ▍▌▃▊▂█▇▄▂▊▉▋▋▌▍▌▊▁▄█▇▎                                                                 | |               __/ |
             ▋▅▆▉▁▂▃▆█████████▅▇████▂▏                                                                 |_|              |___/
             ▏▆██▇███████████████▇▅▃▃▉
              ▌██▆███▄▄▃▄▃▃▇████▅▁▊▏ ▊
               ▎▎▏█▄▎  ▎▍▍▋▋▂█▇▋     ▌▎
                  ▃▏  ▏     ▉▆▍  ▏    ▋
                  ▍▋       ▎▌▍▊       ▋
                   ▉▏      ▋  ▍▋      ▋
                   ▌▍ ▏   ▍▍   ▌▌ ▏   ▋▏
                   ▏▋     ▊     ▊▎▏▌▏ ▋▎
                   ▉▏ ▂▍▎▊▊     ▍▍ ▉▍▋▃▏
                  ▊▍  ▌▃▂▉▏     ▉▏ ▏▏▍▊
                 ▏▊     ▎▋      ▁▏    ▎▍
                 ▏▉     ▌▏      ▍▌  ▏ ▎▌
                  ▊▎ ▏  ▊        ▊▌   ▎▋
                  ▏▁ ▏  ▋         ▊▎▏▏▎▋
                   ▌▋▎  ▊         ▏▉   ▋
                   ▏▁▏▍▍▁▏        ▋▆▁▂▆█▆
                   ▊█▆███▃        ▂████▅▄▉
                   ▉█▇▇▂▄▅        ▄█▂▌▆▆▃▃▋▏
                   ▇█▅█▄▂▅▁      ▍████▉▂▇▃▄▄▉▏
                   ▇█▂▄▇▂▂▃▉▏    ▏▉▃▇█▂▅█▃▎  ▋▌
EOF
echo -e "${NC}"

echo ""
echo -e "${YELLOW}${BOLD}              ════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}                         Developer: ${WHITE}Strikoder${NC}"
echo -e "${GREEN}${BOLD}                         Version: ${WHITE}1.0.0${NC}"
echo -e "${YELLOW}${BOLD}              ════════════════════════════════════════════════════${NC}"
echo -e ""

# Function to display usage
usage() {
    echo "Usage: $0 -t <target> -u <username|userfile> [-p <password|passfile>] [-H <hash|hashfile>] [-c <combined_file>] [-a <auth_type>] [--spray|--no-spray]"
    echo ""
    echo "Options:"
    echo "  -t <target>      Target IP or hostname (required)"
    echo "  -u <user>        Username or file with usernames (required)"
    echo "  -p <password>    Password or file with ONLY passwords"
    echo "  -H <hash>        NTLM hash or file with ONLY hashes"
    echo "  -c <file>        Combined file with mixed format (user:pass, user:hash, etc.)"
    echo "  -a <auth_type>   Authentication type: both (default), local, domain"
    echo "  --spray          Spray mode: test all users with all passwords (DEFAULT)"
    echo "  --no-spray       No-spray mode: pair credentials (user1:pass1, user2:pass2)"
    echo ""
    echo "Note: Use either (-p OR -H) OR -c, but not multiple credential options together"
    echo ""
    echo "File Formats for -c (combined file):"
    echo "  Spray mode extracts ALL users and ALL credentials separately:"
    echo "    user:pass       → extracts user + password"
    echo "    user:hash       → extracts user + hash"
    echo "    user:           → extracts user only"
    echo "    :pass           → extracts password only"
    echo "    :hash           → extracts hash only"
    echo "    username        → extracts as user"
    echo "    credential      → smart detection (hash vs password)"
    echo ""
    echo "  No-spray mode pairs credentials:"
    echo "    user:pass       → paired (auto-detects password)"
    echo "    user:hash       → paired (auto-detects hash)"
    echo "    Lines without credentials are skipped"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100 -u administrator -p 'Password123'"
    echo "  $0 -t 192.168.1.100 -u users.txt -p passwords.txt --spray"
    echo "  $0 -t 192.168.1.100 -u users.txt -c creds.txt --spray"
    echo "  $0 -t 192.168.1.100 -u users.txt -c creds.txt --no-spray"
    echo "  $0 -t 192.168.1.100 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'"
    exit 1
}

# Function to detect if a string is an NTLM hash
is_hash() {
    local cred=$1
    # NTLM hash patterns:
    # - 32 hex chars (LM or NTLM hash)
    # - 65 hex chars with colon (LM:NTLM format)
    if [[ "$cred" =~ ^[a-fA-F0-9]{32}$ ]] || [[ "$cred" =~ ^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$ ]]; then
        return 0
    fi
    return 1
}

# Check for --help or --version before getopts
SPRAY_MODE=true
for arg in "$@"; do
    if [[ "$arg" == "--help" || "$arg" == "-help" ]]; then
        usage
    elif [[ "$arg" == "--no-spray" ]]; then
        SPRAY_MODE=false
    elif [[ "$arg" == "--spray" ]]; then
        SPRAY_MODE=true
    fi
done

# Parse command line arguments
AUTH_TYPE="both"
while getopts "t:p:u:H:c:a:h-:" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        u) USER_INPUT="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        H) HASH="$OPTARG" ;;
        c) COMBINED_FILE="$OPTARG" ;;
        a) AUTH_TYPE="$OPTARG" ;;
        h) usage ;;
        -) ;; # Ignore long options (already processed above)
        *) usage ;;
    esac
done

# Validate required arguments
if [[ -z "$TARGET" || -z "$USER_INPUT" ]]; then
    echo -e "${RED}[!] Error: Target and username/userfile are required${NC}\n"
    usage
fi

# Check that either password, hash, or combined file is provided
if [[ -z "$PASSWORD" && -z "$HASH" && -z "$COMBINED_FILE" ]]; then
    echo -e "${RED}[!] Error: You must provide either -p (password), -H (hash), or -c (combined file)${NC}\n"
    usage
fi

# Ensure only one credential option is used
cred_option_count=0
[[ -n "$PASSWORD" ]] && ((cred_option_count++))
[[ -n "$HASH" ]] && ((cred_option_count++))
[[ -n "$COMBINED_FILE" ]] && ((cred_option_count++))

if [[ $cred_option_count -gt 1 ]]; then
    echo -e "${RED}[!] Error: Use only ONE of: -p (password), -H (hash), or -c (combined file)${NC}\n"
    usage
fi

# Validate auth type
if [[ "$AUTH_TYPE" != "both" && "$AUTH_TYPE" != "local" && "$AUTH_TYPE" != "domain" ]]; then
    echo -e "${RED}[!] Error: Invalid auth type. Use: both, local, or domain${NC}\n"
    usage
fi

# Create temporary file for results
RESULTS_FILE=$(mktemp)

# Handle Ctrl+C - skip on first press, exit on second press within timeout
handle_interrupt() {
    local current_time=$(date +%s)
    local time_diff=$((current_time - LAST_INTERRUPT_TIME))
    
    if [[ $time_diff -le $INTERRUPT_TIMEOUT && $LAST_INTERRUPT_TIME -gt 0 ]]; then
        # Second Ctrl+C within timeout - exit
        echo -e "\n${RED}[!] Second Ctrl+C detected - Exiting script...${NC}"
        cleanup_and_exit
    else
        # First Ctrl+C or timeout expired - skip current test
        echo -e "\n${YELLOW}[!] Ctrl+C detected - Skipping current test...${NC}"
        echo -e "${YELLOW}[!] Press Ctrl+C again within ${INTERRUPT_TIMEOUT}s to exit script${NC}"
        SKIP_CURRENT=true
        LAST_INTERRUPT_TIME=$current_time
        
        # Kill the entire process group of nxc command
        if [[ -n "$CURRENT_PID" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
            # Kill process group (negative PID)
            kill -TERM -"$CURRENT_PID" 2>/dev/null || true
            sleep 0.5
            # Force kill if still running
            kill -KILL -"$CURRENT_PID" 2>/dev/null || true
        fi
        
        # Also kill any orphaned nxc processes
        pkill -9 -f "nxc.*$TARGET" 2>/dev/null || true
    fi
}

# Cleanup function
cleanup_and_exit() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    
    # Kill any remaining nxc processes
    pkill -9 -f "nxc.*$TARGET" 2>/dev/null || true
    
    # Cleanup temp files
    [[ -n "$TEMP_USER_FILE" && -f "$TEMP_USER_FILE" ]] && rm -f "$TEMP_USER_FILE"
    [[ -n "$TEMP_PASS_FILE" && -f "$TEMP_PASS_FILE" ]] && rm -f "$TEMP_PASS_FILE"
    [[ -n "$TEMP_HASH_FILE" && -f "$TEMP_HASH_FILE" ]] && rm -f "$TEMP_HASH_FILE"
    [[ -f "$RESULTS_FILE" ]] && rm -f "$RESULTS_FILE"
    
    echo -e "${YELLOW}[*] Script terminated${NC}"
    exit 1
}

trap handle_interrupt SIGINT
trap cleanup_and_exit EXIT

# Function to parse credential file with auto-detection (--no-spray mode)
parse_credential_file_smart() {
    local file=$1
    local temp_users=$(mktemp)
    local temp_passes=$(mktemp)
    local temp_hashes=$(mktemp)
    local skipped=0
    local pass_count=0
    local hash_count=0
    
    echo -e "${YELLOW}[*] Processing credential file with auto-detection (no-spray mode)...${NC}" >&2
    
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Trim whitespace
        line=$(echo "$line" | xargs)
        
        # Check if line contains colon
        if [[ "$line" == *:* ]]; then
            local user=$(echo "$line" | cut -d':' -f1 | xargs)
            local cred=$(echo "$line" | cut -d':' -f2- | xargs)
            
            # Skip if line starts with : (no username)
            if [[ -z "$user" ]]; then
                ((skipped++))
                echo -e "${YELLOW}[*] Skipping line with no username: :$cred${NC}" >&2
                continue
            fi
            
            # Skip if no credential after colon (user: with nothing after)
            if [[ -z "$cred" ]]; then
                ((skipped++))
                echo -e "${YELLOW}[*] Skipping line with no credential: $user:${NC}" >&2
                continue
            fi
            
            # Detect if credential is hash or password
            if is_hash "$cred"; then
                echo "$user" >> "$temp_users"
                echo "$cred" >> "$temp_hashes"
                ((hash_count++))
            else
                echo "$user" >> "$temp_users"
                echo "$cred" >> "$temp_passes"
                ((pass_count++))
            fi
        else
            # Line with only username (no colon, no credential)
            # In --no-spray mode, skip users without credentials
            ((skipped++))
            echo -e "${YELLOW}[*] Skipping username without credential: $line${NC}" >&2
        fi
    done < "$file"
    
    if [[ $skipped -gt 0 ]]; then
        echo -e "${YELLOW}[*] Skipped $skipped line(s) with missing or incomplete credentials${NC}" >&2
    fi
    
    echo -e "${GREEN}[*] Detected: $pass_count password(s), $hash_count hash(es)${NC}" >&2
    
    echo "$temp_users:$temp_passes:$temp_hashes:$pass_count:$hash_count"
}

# Function to parse credential file for spray mode (extracts all users and all creds separately)
parse_credential_file_spray() {
    local file=$1
    local temp_users=$(mktemp)
    local temp_passes=$(mktemp)
    local temp_hashes=$(mktemp)
    local pass_count=0
    local hash_count=0
    local user_count=0
    
    echo -e "${YELLOW}[*] Processing credential file for spray mode...${NC}" >&2
    echo -e "${YELLOW}[*] Extracting ALL users and ALL credentials separately...${NC}" >&2
    
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Trim whitespace
        line=$(echo "$line" | xargs)
        
        # Check if line contains colon
        if [[ "$line" == *:* ]]; then
            local user=$(echo "$line" | cut -d':' -f1 | xargs)
            local cred=$(echo "$line" | cut -d':' -f2- | xargs)
            
            # Add user if present (even if no credential)
            if [[ -n "$user" ]]; then
                echo "$user" >> "$temp_users"
                ((user_count++))
            fi
            
            # Add credential if present (even if no user)
            if [[ -n "$cred" ]]; then
                if is_hash "$cred"; then
                    echo "$cred" >> "$temp_hashes"
                    ((hash_count++))
                else
                    echo "$cred" >> "$temp_passes"
                    ((pass_count++))
                fi
            fi
        else
            # Line with no colon - could be username OR credential
            # In spray mode, we try to detect what it is
            
            # Check if it looks like a hash
            if is_hash "$line"; then
                echo "$line" >> "$temp_hashes"
                ((hash_count++))
            # Check if it looks like a password (contains non-alphanumeric, spaces, or is long)
            elif [[ "$line" =~ [^a-zA-Z0-9] ]] || [[ ${#line} -gt 20 ]]; then
                # Likely a password
                echo "$line" >> "$temp_passes"
                ((pass_count++))
            else
                # Assume it's a username (short alphanumeric string)
                echo "$line" >> "$temp_users"
                ((user_count++))
            fi
        fi
    done < "$file"
    
    echo -e "${GREEN}[*] Spray mode: Extracted $user_count user(s), $pass_count password(s), $hash_count hash(es)${NC}" >&2
    
    echo "$temp_users:$temp_passes:$temp_hashes:$pass_count:$hash_count"
}

# Function to parse simple credential file (spray mode or same type)
parse_credential_file_simple() {
    local file=$1
    local temp_users=$(mktemp)
    local temp_creds=$(mktemp)
    local is_combined=false
    local skipped=0
    
    # Check if file contains colon-separated format
    if grep -q ':' "$file"; then
        is_combined=true
        echo -e "${YELLOW}[*] Detected combined format (user:credential) in file${NC}" >&2
        
        while IFS=: read -r user cred; do
            # Skip empty lines
            [[ -z "$user" && -z "$cred" ]] && continue
            
            # Trim whitespace
            user=$(echo "$user" | xargs)
            cred=$(echo "$cred" | xargs)
            
            if [[ -z "$user" || -z "$cred" ]]; then
                ((skipped++))
                continue
            fi
            
            echo "$user" >> "$temp_users"
            echo "$cred" >> "$temp_creds"
        done < "$file"
        
        if [[ $skipped -gt 0 ]]; then
            echo -e "${YELLOW}[*] Skipped $skipped line(s) with missing user or credential${NC}" >&2
        fi
    else
        # Simple list format - just copy the file
        cp "$file" "$temp_users"
        cp "$file" "$temp_creds"
    fi
    
    echo "$temp_users:$temp_creds:$is_combined"
}

# Process input files
TEMP_USER_FILE=""
TEMP_PASS_FILE=""
TEMP_HASH_FILE=""
USE_TEMP_FILES=false
HAS_PASSWORDS=false
HAS_HASHES=false

# Handle combined file (-f option)
if [[ -n "$COMBINED_FILE" ]]; then
    if [[ ! -f "$COMBINED_FILE" ]]; then
        echo -e "${RED}[!] Error: Combined file not found: $COMBINED_FILE${NC}"
        exit 1
    fi
    
    if [[ "$SPRAY_MODE" == false ]]; then
        # No-spray mode: pair credentials with auto-detection
        echo -e "${BLUE}[*] No-spray mode: Processing combined credential file...${NC}"
        
        result=$(parse_credential_file_smart "$COMBINED_FILE")
        TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
        TEMP_PASS_FILE=$(echo "$result" | cut -d: -f2)
        TEMP_HASH_FILE=$(echo "$result" | cut -d: -f3)
        pass_count=$(echo "$result" | cut -d: -f4)
        hash_count=$(echo "$result" | cut -d: -f5)
        
        USE_TEMP_FILES=true
        USER_INPUT="$TEMP_USER_FILE"
        
        if [[ $pass_count -gt 0 ]]; then
            HAS_PASSWORDS=true
            PASSWORD="$TEMP_PASS_FILE"
        fi
        if [[ $hash_count -gt 0 ]]; then
            HAS_HASHES=true
            HASH="$TEMP_HASH_FILE"
        fi
    else
        # Spray mode: extract all users and all credentials separately
        echo -e "${BLUE}[*] Spray mode: Extracting users and credentials from combined file...${NC}"
        
        result=$(parse_credential_file_spray "$COMBINED_FILE")
        TEMP_USER_FILE=$(echo "$result" | cut -d: -f1)
        TEMP_PASS_FILE=$(echo "$result" | cut -d: -f2)
        TEMP_HASH_FILE=$(echo "$result" | cut -d: -f3)
        pass_count=$(echo "$result" | cut -d: -f4)
        hash_count=$(echo "$result" | cut -d: -f5)
        
        USE_TEMP_FILES=true
        USER_INPUT="$TEMP_USER_FILE"
        
        if [[ $pass_count -gt 0 ]]; then
            HAS_PASSWORDS=true
            PASSWORD="$TEMP_PASS_FILE"
        fi
        if [[ $hash_count -gt 0 ]]; then
            HAS_HASHES=true
            HASH="$TEMP_HASH_FILE"
        fi
    fi
# Handle separate -p or -H options
else
    if [[ -n "$PASSWORD" ]]; then
        HAS_PASSWORDS=true
    fi
    if [[ -n "$HASH" ]]; then
        HAS_HASHES=true
    fi
fi

# Cleanup function for temp files
cleanup_temp_files() {
    if [[ "$USE_TEMP_FILES" == true ]]; then
        [[ -n "$TEMP_USER_FILE" && -f "$TEMP_USER_FILE" ]] && rm -f "$TEMP_USER_FILE"
        [[ -n "$TEMP_PASS_FILE" && -f "$TEMP_PASS_FILE" ]] && rm -f "$TEMP_PASS_FILE"
        [[ -n "$TEMP_HASH_FILE" && -f "$TEMP_HASH_FILE" ]] && rm -f "$TEMP_HASH_FILE"
    fi
}

# Protocol selection menu
echo -e "${BLUE}[*] Select protocols to test (comma-separated, ranges, or 'all'):${NC}"
echo -e "  ${YELLOW}1${NC}  - SMB"
echo -e "  ${YELLOW}2${NC}  - WinRM"
echo -e "  ${YELLOW}3${NC}  - RDP"
echo -e "  ${YELLOW}4${NC}  - SSH"
echo -e "  ${YELLOW}5${NC}  - MSSQL"
echo -e "  ${YELLOW}6${NC}  - LDAP"
echo -e "  ${YELLOW}7${NC}  - FTP"
echo -e "  ${YELLOW}8${NC}  - WMI"
echo -e "  ${YELLOW}9${NC}  - VNC"
echo -e "  ${YELLOW}10${NC} - NFS"
echo -e "\nExample: 1,2,3 or 1-5 or all\n"
read -p "Selection: " protocol_choice

# Map selections to protocols
declare -A PROTOCOL_MAP
PROTOCOL_MAP[1]="smb"
PROTOCOL_MAP[2]="winrm"
PROTOCOL_MAP[3]="rdp"
PROTOCOL_MAP[4]="ssh"
PROTOCOL_MAP[5]="mssql"
PROTOCOL_MAP[6]="ldap"
PROTOCOL_MAP[7]="ftp"
PROTOCOL_MAP[8]="wmi"
PROTOCOL_MAP[9]="vnc"
PROTOCOL_MAP[10]="nfs"

if [[ "$protocol_choice" == "all" ]]; then
    PROTOCOLS=("smb" "winrm" "rdp" "ssh" "mssql" "ldap" "ftp" "wmi" "vnc" "nfs")
else
    # Parse selection string to handle ranges and comma-separated values
    declare -A selected_nums
    
    # Split by comma
    IFS=',' read -ra parts <<< "$protocol_choice"
    for part in "${parts[@]}"; do
        part=$(echo "$part" | tr -d ' ')
        
        # Check if it's a range (e.g., 1-5)
        if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            
            # Validate range
            if [[ $start -gt $end ]]; then
                echo -e "${RED}[!] Warning: Invalid range '$part' (start > end) - ignored${NC}"
                continue
            fi
            
            # Add all numbers in range
            for ((i=start; i<=end; i++)); do
                if [[ $i -ge 1 && $i -le 10 ]]; then
                    selected_nums[$i]=1
                else
                    echo -e "${RED}[!] Warning: Number '$i' in range '$part' is out of bounds (1-10) - ignored${NC}"
                fi
            done
        # Check if it's a single number
        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            if [[ $part -ge 1 && $part -le 10 ]]; then
                selected_nums[$part]=1
            else
                echo -e "${RED}[!] Warning: Invalid selection '$part' (out of bounds) - ignored${NC}"
            fi
        else
            echo -e "${RED}[!] Warning: Invalid selection '$part' - ignored${NC}"
        fi
    done
    
    # Convert selected numbers to protocols in order
    for num in $(echo "${!selected_nums[@]}" | tr ' ' '\n' | sort -n); do
        PROTOCOLS+=("${PROTOCOL_MAP[$num]}")
    done
fi

if [[ ${#PROTOCOLS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] Error: No valid protocols selected${NC}"
    exit 1
fi

# Function to test credentials with improved process handling
test_credentials() {
    local protocol=$1
    local target=$2
    local user_param=$3
    local cred_param=$4
    local cred_flag=$5
    local local_auth=$6
    
    # Reset skip flag and current PID at the start of each test
    SKIP_CURRENT=false
    CURRENT_PID=""
    
    local auth_type="Domain"
    local flag=""
    
    # FTP and SSH don't support --local-auth flag
    if [[ "$local_auth" == "true" && "$protocol" != "ftp" && "$protocol" != "ssh" ]]; then
        auth_type="Local"
        flag="--local-auth"
    elif [[ "$local_auth" == "true" && ( "$protocol" == "ftp" || "$protocol" == "ssh" ) ]]; then
        auth_type="Local/Domain (${protocol^^})"
    fi
    
    echo -e "\n${YELLOW}[*] Testing: ${protocol} | Auth: ${auth_type}${NC}"
    
    # Build and display the command
    local cmd="nxc $protocol $target -u $user_param $cred_flag $cred_param $flag --continue-on-success"
    echo -e "${BLUE}[CMD] $cmd${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Create temporary file for output
    local output_file=$(mktemp)
    
    # Check if we're in no-spray mode with files (need to pair credentials)
    if [[ "$SPRAY_MODE" == false && -f "$user_param" && -f "$cred_param" ]]; then
        # No-spray mode: test paired credentials one by one
        local user_array=()
        local cred_array=()
        
        # Read users and credentials into arrays
        mapfile -t user_array < "$user_param"
        mapfile -t cred_array < "$cred_param"
        
        # Test each pair
        for i in "${!user_array[@]}"; do
            local user="${user_array[$i]}"
            local cred="${cred_array[$i]}"
            
            # Skip empty lines
            [[ -z "$user" || -z "$cred" ]] && continue
            
            # Check if we should skip
            if [[ "$SKIP_CURRENT" == true ]]; then
                break
            fi
            
            # Run nxc for this specific pair
            echo -e "${YELLOW}[*] Testing pair: $user : $cred${NC}"
            script -q -c "nxc $protocol $target -u '$user' $cred_flag '$cred' $flag 2>&1" /dev/null | tee -a "$output_file"
        done
        
        CURRENT_PID=""
        
    else
        # Spray mode OR single credentials: run normally
        (
            # Create new process group
            set -m
            # Force colored output using script command
            script -q -c "nxc $protocol $target -u $user_param $cred_flag $cred_param $flag --continue-on-success 2>&1" /dev/null | tee "$output_file"
        ) &
        
        CURRENT_PID=$!
    fi
    
    
    # Wait for process to finish with skip handling
    while kill -0 "$CURRENT_PID" 2>/dev/null; do
        if [[ "$SKIP_CURRENT" == true ]]; then
            kill -TERM -"$CURRENT_PID" 2>/dev/null || true
            sleep 0.2
            kill -KILL -"$CURRENT_PID" 2>/dev/null || true
            wait "$CURRENT_PID" 2>/dev/null || true
            break
        fi
        sleep 0.1
    done
    
    # Wait for process to finish if not killed
    if [[ "$SKIP_CURRENT" == false ]]; then
        wait "$CURRENT_PID" 2>/dev/null || true
    fi
    
    # Save [+] lines to results file
    if [[ "$SKIP_CURRENT" == false && -f "$output_file" ]]; then
        grep '\[+\]' "$output_file" >> "$RESULTS_FILE" 2>/dev/null || true
    fi

    # If skipped, clean up and return early
    if [[ "$SKIP_CURRENT" == true ]]; then
        rm -f "$output_file"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}[*] Test skipped by user${NC}\n"
        CURRENT_PID=""
        return 0
    fi
    
    # Check for status_not_supported error
    if grep -qi "status_not_supported" "$output_file"; then
        rm -f "$output_file"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        echo -e "${RED}[!] ERROR DETECTED: status_not_supported${NC}\n"
        
        echo -e "${YELLOW}[!] This error typically indicates a Kerberos authentication problem.${NC}\n"
        
        echo -e "${BLUE}SOLUTION 1: Use Manual Kerberos Enumeration${NC}"
        echo -e "${GREEN}Add the '-k' flag to manually specify Kerberos authentication:${NC}\n"
        echo -e "  ${YELLOW}nxc smb HOST_NAME -u $USER_INPUT -p '$PASSWORD' -k${NC}\n"
        
        echo -e "${BLUE}SOLUTION 2: Fix Time Synchronization (if you see KRB_AP_ERR_SKEW)${NC}"
        echo -e "${GREEN}Kerberos requires time sync within 5 minutes. Run these commands:${NC}\n"
        echo -e "  ${YELLOW}sudo systemctl restart systemd-timesyncd.service${NC}  ${BLUE}# If using systemd-timesyncd${NC}"
        echo -e "  ${YELLOW}sudo timedatectl set-ntp no${NC}                      ${BLUE}# Disable automatic NTP${NC}"
        echo -e "  ${YELLOW}sudo ntpdate -u $TARGET${NC}                          ${BLUE}# Sync with target${NC}\n"
        
        echo -e "${BLUE}Note:${NC} The first 2 commands depend on your VM configuration."
        echo -e "      You might not need them if you're not using systemd-timesyncd.\n"
        
        echo -e "${RED}[!] Script stopped to prevent further errors.${NC}\n"
        cleanup_temp_files
        exit 1
    fi
    
    rm -f "$output_file"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    CURRENT_PID=""
    return 0
}

# Main execution
echo -e "\n${BLUE}[*] Target: $TARGET${NC}"
echo -e "${BLUE}[*] User(s): $USER_INPUT${NC}"

if [[ "$HAS_PASSWORDS" == true ]]; then
    echo -e "${BLUE}[*] Password(s): $PASSWORD${NC}"
fi
if [[ "$HAS_HASHES" == true ]]; then
    echo -e "${BLUE}[*] Hash(es): $HASH${NC}"
fi

# Display authentication mode
if [[ "$AUTH_TYPE" == "both" ]]; then
    echo -e "${GREEN}[*] Auth Mode: BOTH (Domain + Local)${NC}"
elif [[ "$AUTH_TYPE" == "local" ]]; then
    echo -e "${GREEN}[*] Auth Mode: LOCAL ONLY${NC}"
else
    echo -e "${GREEN}[*] Auth Mode: DOMAIN ONLY${NC}"
fi

# Display spray mode
if [[ "$SPRAY_MODE" == true ]]; then
    echo -e "${GREEN}[*] Credential Mode: SPRAY (all users x all passwords)${NC}"
else
    echo -e "${YELLOW}[*] Credential Mode: NO-SPRAY (paired credentials only)${NC}"
fi

echo -e "${BLUE}[*] Protocols: ${PROTOCOLS[*]}${NC}"
echo -e "${BLUE}[*] Starting credential validation...${NC}"
echo -e "${YELLOW}[*] Press Ctrl+C once to skip current test, twice within ${INTERRUPT_TIMEOUT}s to exit${NC}\n"

# Test each protocol
for protocol in "${PROTOCOLS[@]}"; do
    # Reset skip flag for new protocol
    SKIP_CURRENT=false
    
    echo -e "\n${BLUE}========== Testing protocol: $protocol ==========${NC}"
    
    # Test with passwords if we have them
    if [[ "$HAS_PASSWORDS" == true ]]; then
        # Determine which auth types to test
        if [[ "$AUTH_TYPE" == "both" ]]; then
            # Test domain auth
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "false"
            
            sleep 1
            
            # Test local auth (skip for FTP and SSH)
            if [[ "$SKIP_CURRENT" == false ]]; then
                if [[ "$protocol" != "ftp" && "$protocol" != "ssh" ]]; then
                    test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "true"
                    
                    sleep 1
                else
                    echo -e "${YELLOW}[*] Note: ${protocol^^} protocol tested without --local-auth flag (not supported)${NC}"
                fi
            fi
        elif [[ "$AUTH_TYPE" == "local" ]]; then
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "true"
            
            sleep 1
        else
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$PASSWORD" "-p" "false"
            
            sleep 1
        fi
        
        # Reset skip flag for next credential type
        SKIP_CURRENT=false
    fi
    
    # Test with hashes if we have them
    if [[ "$HAS_HASHES" == true ]]; then
        # Check if protocol supports hash authentication
        # FTP, SSH, VNC, and NFS don't support hash authentication
        if [[ "$protocol" == "ftp" || "$protocol" == "ssh" || "$protocol" == "vnc" || "$protocol" == "nfs" ]]; then
            echo -e "${YELLOW}[!] Warning: ${protocol^^} does not support hash authentication - skipping${NC}"
            continue
        fi
        
        # Determine which auth types to test
        if [[ "$AUTH_TYPE" == "both" ]]; then
            # Test domain auth
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "false"
            
            sleep 1
            
            # Test local auth
            if [[ "$SKIP_CURRENT" == false ]]; then
                test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "true"
                
                sleep 1
            fi
        elif [[ "$AUTH_TYPE" == "local" ]]; then
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "true"
            
            sleep 1
        else
            test_credentials "$protocol" "$TARGET" "$USER_INPUT" "$HASH" "-H" "false"
            
            sleep 1
        fi
        
        # Reset skip flag for next protocol
        SKIP_CURRENT=false
    fi
done

# Cleanup temp files before displaying results
cleanup_temp_files

# Display results summary
echo -e "\n${BLUE}================================${NC}"
echo -e "${BLUE}     Results Summary${NC}"
echo -e "${BLUE}================================${NC}\n"

if [[ -s "$RESULTS_FILE" ]]; then
    # Extract and display valid credentials
    if grep -E '\[\+\]' "$RESULTS_FILE" 2>/dev/null; then
        echo -e "\n${GREEN}[+] Valid credentials found above!${NC}"
    else
        echo -e "${YELLOW}[*] No valid credentials found${NC}"
    fi
    
    echo -e "\n${GREEN}[+] Testing completed!${NC}"
    echo -e "${YELLOW}[*] Results file: $RESULTS_FILE${NC}"
    echo -e "${YELLOW}[*] Copy results before script exits to preserve them${NC}"
    
    # Ask if user wants to save results
    echo -e "\n${BLUE}[?] Save results to a file? (y/n):${NC} "
    read -t 10 -n 1 save_choice
    echo""
    
    if [[ "$save_choice" == "y" || "$save_choice" == "Y" ]]; then
        timestamp=$(date +%Y%m%d_%H%M%S)
        output_file="nxc_results_${timestamp}.txt"
        cp "$RESULTS_FILE" "$output_file"
        echo -e "${GREEN}[+] Results saved to: $output_file${NC}"
    fi
else
    echo -e "${YELLOW}[*] No results captured - check output above${NC}"
fi

echo ""
