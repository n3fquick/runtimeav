#!/bin/bash

# Script version
VERSION="1.1.1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/clamd.d"
LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"
RUN_DIR="/var/run/clamd.scan"
QUARANTINE_DIR="/var/quarantine/clamav"

# Debug mode (set to true for verbose output)
DEBUG=true

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_DIR/install.log"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_DIR/install.log" >&2
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_DIR/install.log"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_DIR/install.log"
}

debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG: $1" >> "$LOG_DIR/debug.log"
    fi
}

# Function to check system requirements
check_system_requirements() {
    log "Checking system requirements..."
    
    # Check memory
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 1024 ]; then
        error "Insufficient memory. Minimum 1GB required, found ${total_mem}MB"
        exit 1
    fi
    
    # Check disk space
    local free_space=$(df -m "$INSTALL_DIR" | awk 'NR==2 {print $4}')
    if [ "$free_space" -lt 5120 ]; then
        error "Insufficient disk space. Minimum 5GB required, found ${free_space}MB"
        exit 1
    fi
    
    # Check if systemd is present
    if ! command -v systemctl >/dev/null 2>&1; then
        error "systemd is required but not found"
        exit 1
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS=$(cat /etc/redhat-release | cut -d' ' -f1)
    else
        error "Unsupported operating system"
        exit 1
    fi
    
    OS=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
    log "Detected OS: $OS $VERSION"
    
    # Verify supported OS version
    case $OS in
        *"centos"*|*"rhel"*|*"rocky"*|*"almalinux"*)
            if [ "${VERSION%%.*}" -lt 7 ]; then
                error "Unsupported OS version. Minimum required: 7"
                exit 1
            fi
            ;;
        *"ubuntu"*)
            if [ "${VERSION%%.*}" -lt 18 ]; then
                error "Unsupported OS version. Minimum required: 18.04"
                exit 1
            fi
            ;;
        *)
            warn "OS not explicitly supported, attempting installation anyway..."
            ;;
    esac
}

# Function to configure SELinux
configure_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_status=$(getenforce)
        log "SELinux status: $selinux_status"
        
        if [ "$selinux_status" != "Disabled" ]; then
            log "Configuring SELinux..."
            
            # Install SELinux utilities if needed
            case $OS in
                *"centos"*|*"rhel"*|*"fedora"*|*"rocky"*|*"almalinux"*)
                    dnf install -y policycoreutils-python-utils selinux-policy-targeted
                    ;;
            esac
            
            # Set appropriate contexts
            semanage fcontext -a -t antivirus_db_t "$DB_DIR(/.*)?" || true
            semanage fcontext -a -t antivirus_var_run_t "$RUN_DIR(/.*)?" || true
            semanage fcontext -a -t antivirus_var_log_t "$LOG_DIR(/.*)?" || true
            
            # Apply contexts
            restorecon -R "$DB_DIR" || true
            restorecon -R "$RUN_DIR" || true
            restorecon -R "$LOG_DIR" || true
            
            # Add necessary SELinux booleans
            setsebool -P antivirus_can_scan_system 1 || true
            setsebool -P clamd_use_jit 1 || true
        fi
    fi
}

# Function to verify Node.js installation
verify_nodejs() {
    log "Verifying Node.js installation..."
    
    # Check if Node.js exists and is at least version 16
    if command -v node >/dev/null 2>&1; then
        NODE_VERSION=$(node -v | cut -d. -f1 | tr -d 'v')
        if [ "$NODE_VERSION" -lt 16 ]; then
            log "Node.js version too old. Installing latest LTS version..."
            need_install=true
        else
            log "Node.js $(node -v) is already installed"
            return 0
        fi
    else
        need_install=true
    fi
    
    if [ "$need_install" = true ]; then
        case $OS in
            *"ubuntu"*|*"debian"*)
                curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
                apt-get install -y nodejs build-essential
                ;;
            *"centos"*|*"rhel"*|*"fedora"*|*"rocky"*|*"almalinux"*)
                curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
                dnf install -y nodejs gcc-c++ make
                ;;
            *)
                error "Unsupported OS for Node.js installation"
                exit 1
                ;;
        esac
        
        # Verify installation
        if ! command -v node >/dev/null 2>&1; then
            error "Node.js installation failed"
            exit 1
        fi
    fi
    
    # Update npm to latest version
    npm install -g npm@latest
    
    log "Node.js $(node -v) is installed with npm $(npm -v)"
}

# Function to verify and install PM2
verify_pm2() {
    log "Verifying PM2 installation..."
    
    # First, ensure npm prefix is set correctly
    npm config set prefix /usr/local
    
    # Add /usr/local/bin to PATH if not already present
    if ! echo $PATH | grep -q "/usr/local/bin"; then
        export PATH="/usr/local/bin:$PATH"
        echo 'export PATH="/usr/local/bin:$PATH"' >> /root/.bashrc
        echo 'export PATH="/usr/local/bin:$PATH"' >> /etc/profile
    fi
    
    # Clean any existing problematic installations
    rm -f /usr/local/bin/pm2
    rm -f /usr/bin/pm2
    npm uninstall -g pm2 2>/dev/null || true
    
    log "Installing PM2 globally..."
    if npm install -g pm2@latest; then
        # Force create symlink
        if [ -f "/usr/local/lib/node_modules/pm2/bin/pm2" ]; then
            ln -sf "/usr/local/lib/node_modules/pm2/bin/pm2" /usr/local/bin/pm2
        elif [ -f "/usr/lib/node_modules/pm2/bin/pm2" ]; then
            ln -sf "/usr/lib/node_modules/pm2/bin/pm2" /usr/local/bin/pm2
        fi
        
        # Source profile to ensure PATH is updated
        source /etc/profile
        export PATH="/usr/local/bin:$PATH"
        
        # Verify PM2 is available
        if ! command -v pm2 >/dev/null 2>&1; then
            error "PM2 installation succeeded but binary not found in PATH"
            debug "PATH: $PATH"
            debug "PM2 locations:"
            ls -l /usr/local/lib/node_modules/pm2/bin/pm2 2>/dev/null || debug "Not found in /usr/local/lib"
            ls -l /usr/lib/node_modules/pm2/bin/pm2 2>/dev/null || debug "Not found in /usr/lib"
            ls -l /usr/local/bin/pm2 2>/dev/null || debug "No symlink in /usr/local/bin"
            exit 1
        fi
        
        log "PM2 installed successfully: $(pm2 -v)"
        
        # Setup PM2 startup script properly
        local startup_cmd=$(pm2 startup systemd -u root --hp /root | grep "sudo" | sed 's/sudo //')
        debug "PM2 startup command: $startup_cmd"
        
        if [ ! -z "$startup_cmd" ]; then
            eval "$startup_cmd"
            systemctl daemon-reload
            systemctl enable pm2-root || warn "Failed to enable PM2 startup service"
        else
            warn "Could not generate PM2 startup command"
        fi
        
        return 0
    else
        error "Failed to install PM2"
        exit 1
    fi
}

# Function to clean existing installation
clean_existing() {
    log "Cleaning existing installation..."
    
    # Stop services gracefully
    systemctl stop clamd@scan 2>/dev/null || true
    systemctl stop clamav-freshclam 2>/dev/null || true
    systemctl stop clamav-update.timer 2>/dev/null || true
    
    if command -v pm2 >/dev/null 2>&1; then
        pm2 delete clamav-monitor 2>/dev/null || true
        pm2 save 2>/dev/null || true
        systemctl stop pm2-root 2>/dev/null || true
    fi
    
    # Remove packages based on OS
    case $OS in
        *"ubuntu"*|*"debian"*)
            apt-get remove -y clamav clamav-daemon clamav-freshclam
            apt-get autoremove -y
            ;;
        *"centos"*|*"rhel"*|*"fedora"*|*"rocky"*|*"almalinux"*)
            dnf remove -y clamav clamav-update clamd
            dnf autoremove -y
            ;;
    esac
    
    # Clean directories
    rm -rf "$CONFIG_DIR"/*
    rm -rf "$LOG_DIR"/*
    rm -rf "$DB_DIR"/*
    rm -rf "$RUN_DIR"/*
    rm -rf "$QUARANTINE_DIR"
    rm -f "$INSTALL_DIR/clamav-monitor"
    rm -f "$INSTALL_DIR/clamav-update"
    rm -f "/root/clamav-monitor-ecosystem.config.js"
    rm -f "/etc/systemd/system/clamav-update.service"
    rm -f "/etc/systemd/system/clamav-update.timer"
    
    # Reload systemd
    systemctl daemon-reload
}

# Function to install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    case $OS in
        *"ubuntu"*|*"debian"*)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y clamav clamav-daemon inotify-tools curl
            ;;
        *"centos"*|*"rhel"*|*"fedora"*|*"rocky"*|*"almalinux"*)
            dnf install -y epel-release
            dnf makecache
            dnf install -y clamav clamav-update clamd inotify-tools curl
            ;;
        *)
            error "Unsupported OS for package installation"
            exit 1
            ;;
    esac
    
    if [ $? -ne 0 ]; then
        error "Failed to install required packages"
        exit 1
    fi
}

# Function to setup directories and permissions
setup_directories() {
    log "Setting up directories and permissions..."
    
    # Create directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$DB_DIR"
    mkdir -p "$RUN_DIR"
    mkdir -p "$QUARANTINE_DIR"
    
    # Create clamav user if it doesn't exist
    if ! id -u clamav >/dev/null 2>&1; then
        useradd -r -d "$DB_DIR" clamav
    fi
    
    # Set ownership and permissions
    chown -R clamav:clamav "$LOG_DIR"
    chown -R clamav:clamav "$DB_DIR"
    chown -R clamav:clamav "$RUN_DIR"
    chown -R clamav:clamav "$QUARANTINE_DIR"
    
    chmod 750 "$LOG_DIR"
    chmod 750 "$DB_DIR"
    chmod 750 "$RUN_DIR"
    chmod 750 "$QUARANTINE_DIR"
    
    # Ensure run directory exists and has correct permissions
    mkdir -p /var/run/clamd.scan
    chown clamav:clamav /var/run/clamd.scan
    chmod 750 /var/run/clamd.scan
}

# Function to configure ClamAV
configure_clamav() {
    log "Configuring ClamAV..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Create ClamAV configuration
    cat > "$CONFIG_DIR/scan.conf" << EOL
LogFile $LOG_DIR/clamd.log
LogTime yes
LogSyslog yes
LogVerbose yes
PidFile $RUN_DIR/clamd.pid
TemporaryDirectory /var/tmp
DatabaseDirectory $DB_DIR
LocalSocket $RUN_DIR/clamd.sock
FixStaleSocket yes
MaxConnectionQueueLength 30
MaxThreads 50
ReadTimeout 300
User clamav
ScanPE yes
ScanELF yes
DetectBrokenExecutables yes
ScanOLE2 yes
ScanPDF yes
ScanHTML yes
AlertBrokenExecutables yes
TCPSocket 3310
TCPAddr 127.0.0.1
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
LocalSocketGroup clamav
LocalSocketMode 660
EOL

    # Set permissions for config
    chown root:clamav "$CONFIG_DIR/scan.conf"
    chmod 644 "$CONFIG_DIR/scan.conf"
    
    # Configure freshclam
    cat > "/etc/freshclam.conf" << EOL
DatabaseDirectory $DB_DIR
UpdateLogFile $LOG_DIR/freshclam.log
LogTime yes
LogSyslog yes
Foreground false
Debug false
MaxAttempts 5
DatabaseMirror database.clamav.net
ConnectTimeout 30
ReceiveTimeout 30
TestDatabases yes
ScriptedUpdates yes
CompressLocalDatabase no
DatabaseOwner clamav
Checks 24
NotifyClamd $CONFIG_DIR/scan.conf
EOL

    chown root:clamav "/etc/freshclam.conf"
    chmod 644 "/etc/freshclam.conf"
    
    # Create systemd override for clamd@scan
    mkdir -p /etc/systemd/system/clamd@scan.service.d/
    cat > /etc/systemd/system/clamd@scan.service.d/override.conf << EOL
[Service]
ExecStartPre=
ExecStartPre=/bin/mkdir -p /var/run/clamd.scan
ExecStartPre=/bin/chown clamav:clamav /var/run/clamd.scan
Restart=always
RestartSec=3
EOL

    systemctl daemon-reload
}

# Function to configure automatic database updates
configure_auto_updates() {
    log "Configuring automatic database updates..."
    
    # Create update script
    cat > "$INSTALL_DIR/clamav-update" << 'EOL'
#!/bin/bash
LOG_FILE="/var/log/clamav/freshclam.log"
DB_DIR="/var/lib/clamav"

# Stop freshclam daemon if running
systemctl stop clamav-freshclam 2>/dev/null || true

# Update virus definitions
freshclam --quiet
UPDATE_EXIT=$?

if [ $UPDATE_EXIT -eq 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Database updated successfully" >> "$LOG_FILE"
    # Restart ClamAV daemon to use new definitions
    systemctl restart clamd@scan
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Database update failed with exit code $UPDATE_EXIT" >> "$LOG_FILE"
fi

# Start freshclam daemon again
systemctl start clamav-freshclam 2>/dev/null || true
EOL

    chmod +x "$INSTALL_DIR/clamav-update"
    chown root:root "$INSTALL_DIR/clamav-update"
    
    # Create systemd timer for updates
    cat > "/etc/systemd/system/clamav-update.service" << EOL
[Unit]
Description=ClamAV Database Update
After=network.target
ConditionPathExists=$INSTALL_DIR/clamav-update

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/clamav-update
User=root
IOSchedulingClass=idle
CPUSchedulingPolicy=idle
Restart=no

[Install]
WantedBy=multi-user.target
EOL

    cat > "/etc/systemd/system/clamav-update.timer" << EOL
[Unit]
Description=Run ClamAV Database Update Every 4 Hours

[Timer]
OnBootSec=15min
OnUnitActiveSec=4h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOL

    chmod 644 "/etc/systemd/system/clamav-update.service"
    chmod 644 "/etc/systemd/system/clamav-update.timer"
    
    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable clamav-update.timer
    systemctl start clamav-update.timer
    
    log "Automatic updates configured successfully"
}

create_monitor_script() {
    log "Creating file monitor script..."
    
    cat > "$INSTALL_DIR/clamav-monitor" << 'EOL'
#!/bin/bash

# Configuration
declare -A WATCH_DIRS
QUARANTINE_DIR="/var/quarantine/clamav"
LOG_FILE="/var/log/clamav/monitor.log"
MONITOR_PID=""

# Create directories
mkdir -p "$QUARANTINE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Quarantine function
quarantine_file() {
    local file="$1"
    local reason="$2"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local filename=$(basename "$file")
    local quarantine_path="$QUARANTINE_DIR/${timestamp}_${filename}"
    
    if [ ! -f "$file" ]; then
        log "ERROR: Cannot quarantine: File not found - $file"
        return 1
    fi
    
    mv "$file" "$quarantine_path" 2>/dev/null || {
        log "ERROR: Failed to quarantine file: $file"
        return 1
    }
    
    chmod 600 "$quarantine_path"
    
    # Save metadata
    cat > "${quarantine_path}.meta" << EOF
Original Path: $file
Quarantine Time: $(date '+%Y-%m-%d %H:%M:%S')
Reason: $reason
File Size: $(stat -c%s "$quarantine_path")
EOF
    
    log "QUARANTINED: $file -> $quarantine_path ($reason)"
}

# File scanning function
scan_file() {
    local file="$1"
    
    # Skip if not a regular file or empty
    [[ ! -f "$file" ]] && return
    [[ ! -s "$file" ]] && return
    
    log "SCANNING: $file"
    
    # Ensure clamd is running
    if ! systemctl is-active --quiet clamd@scan; then
        log "ERROR: ClamD is not running, restarting..."
        systemctl restart clamd@scan
        sleep 5
    fi
    
    # Scan with clamdscan
    if clamdscan --fdpass --quiet "$file"; then
        log "CLEAN: $file"
    else
        local scan_exit=$?
        if [ $scan_exit -eq 1 ]; then
            local virus=$(clamdscan --fdpass "$file" 2>&1 | grep FOUND | awk -F: '{print $NF}' | tr -d '[:space:]')
            log "INFECTED: $file ($virus)"
            quarantine_file "$file" "$virus"
        else
            log "ERROR: Scan failed for $file (exit code: $scan_exit)"
        fi
    fi
}

# Function to find all public_html directories
find_public_html_dirs() {
    log "Finding public_html directories..."
    while IFS= read -r dir; do
        if [ -d "$dir" ]; then
            WATCH_DIRS["$dir"]=1
            log "Added watch directory: $dir"
        fi
    done < <(find /home -type d -name "public_html")
}

# Function to monitor for new public_html directories
monitor_new_dirs() {
    while true; do
        # Get current list of directories
        while IFS= read -r dir; do
            if [ -d "$dir" ] && [ -z "${WATCH_DIRS[$dir]}" ]; then
                WATCH_DIRS["$dir"]=1
                log "New public_html directory detected: $dir"
                find "$dir" -type f -exec bash -c 'scan_file "$0"' {} \;
                if [ ! -z "$MONITOR_PID" ]; then
                    pkill -f "inotifywait -m"
                fi
            fi
        done < <(find /home -type d -name "public_html")
        sleep 60
    done
}

# Main function
main() {
    log "Starting ClamAV file monitor..."
    
    # Find all public_html directories
    find_public_html_dirs
    
    # Start directory monitoring in background
    monitor_new_dirs &
    
    # Monitor all public_html directories for file changes
    while true; do
        if [ ${#WATCH_DIRS[@]} -gt 0 ]; then
            inotifywait -m "${!WATCH_DIRS[@]}" -r -e close_write,moved_to --format '%w%f' | while read file; do
                scan_file "$file"
            done &
            MONITOR_PID=$!
            wait $MONITOR_PID
        else
            log "No directories to monitor, waiting..."
            sleep 60
        fi
        sleep 5
    done
}

# Cleanup function
cleanup() {
    log "Shutting down monitor..."
    pkill -f "inotifywait -m"
    [ ! -z "$MONITOR_PID" ] && kill $MONITOR_PID 2>/dev/null
    exit 0
}

# Register cleanup
trap cleanup INT TERM

# Start the monitor
main
EOL

    chmod +x "$INSTALL_DIR/clamav-monitor"
}

# Function to create PM2 ecosystem file
create_pm2_config() {
    log "Creating PM2 ecosystem config..."
    
    cat > "/root/clamav-monitor-ecosystem.config.js" << EOL
module.exports = {
  apps: [{
    name: 'clamav-monitor',
    script: '$INSTALL_DIR/clamav-monitor',
    interpreter: 'bash',
    autorestart: true,
    watch: false,
    max_memory_restart: '200M',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    error_file: '$LOG_DIR/monitor-error.log',
    out_file: '$LOG_DIR/monitor-out.log',
    merge_logs: true,
    kill_timeout: 10000,
    wait_ready: true,
    max_restarts: 10,
    restart_delay: 4000,
    env: {
      NODE_ENV: 'production'
    }
  }]
}
EOL
}

# Function to update virus database
update_database() {
    log "Updating virus database..."
    
    # Stop freshclam and any running processes
    systemctl stop clamav-freshclam 2>/dev/null || true
    pkill -f freshclam
    
    # Wait for processes to stop
    sleep 5
    
    # Remove any stale lock files
    rm -f /var/log/clamav/freshclam.log.* 2>/dev/null
    rm -f /var/run/clamav/freshclam.pid 2>/dev/null
    
    # Initialize database directory
    mkdir -p "$DB_DIR"
    chown clamav:clamav "$DB_DIR"
    
    # Ensure log file exists and has correct permissions
    touch "$LOG_DIR/freshclam.log"
    chown clamav:clamav "$LOG_DIR/freshclam.log"
    chmod 600 "$LOG_DIR/freshclam.log"
    
    # Update virus definitions
    log "Running freshclam..."
    sudo -u clamav freshclam --quiet
    local update_exit=$?
    
    if [ $update_exit -ne 0 ]; then
        error "Initial database update failed (exit code: $update_exit), retrying..."
        # Clear log file and try again
        cat /dev/null > "$LOG_DIR/freshclam.log"
        sleep 5
        sudo -u clamav freshclam
        update_exit=$?
        if [ $update_exit -ne 0 ]; then
            error "Database update retry failed"
            return 1
        fi
    fi
    
    log "Database update completed successfully"
    return 0
}

# Function to start services
start_services() {
    log "Starting services..."
    
    # Ensure required directories exist
    mkdir -p /var/run/clamd.scan
    chown clamav:clamav /var/run/clamd.scan
    chmod 750 /var/run/clamd.scan
    
    # Start and enable freshclam daemon
    systemctl enable clamav-freshclam
    systemctl start clamav-freshclam
    sleep 3
    
    # Start ClamAV daemon
    systemctl enable clamd@scan
    systemctl start clamd@scan
    sleep 5
    
    if ! systemctl is-active --quiet clamd@scan; then
        error "Failed to start ClamAV daemon"
        log "Checking ClamAV daemon status..."
        systemctl status clamd@scan --no-pager
        log "Checking ClamAV daemon logs..."
        journalctl -xe --unit=clamd@scan.service --no-pager | tail -n 50
        exit 1
    fi
    
    # Source updated PATH
    source /etc/profile
    export PATH="/usr/local/bin:$PATH"
    
    # Start monitor with PM2
    if ! command -v pm2 >/dev/null 2>&1; then
        error "PM2 not found in PATH after installation"
        exit 1
    fi
    
    log "Starting ClamAV monitor with PM2..."
    pm2 delete clamav-monitor 2>/dev/null || true
    if ! pm2 start /root/clamav-monitor-ecosystem.config.js; then
        error "Failed to start monitor with PM2"
        exit 1
    fi
    
    pm2 save
    
    # Verify PM2 startup is configured
    if ! systemctl is-enabled --quiet pm2-root; then
        log "Configuring PM2 startup..."
        pm2 startup systemd -u root --hp /root || warn "Failed to setup PM2 startup script"
        systemctl enable pm2-root || warn "Failed to enable PM2 startup service"
    fi
}

# Function to verify installation
verify_installation() {
    log "Verifying installation..."
    
    # Export PATH again to ensure PM2 is available
    export PATH="/usr/local/bin:$PATH"
    
    # Check ClamAV daemon
    if ! pgrep clamd >/dev/null; then
        error "ClamAV daemon is not running"
        return 1
    fi
    
    # Check freshclam daemon
    if ! systemctl is-active --quiet clamav-freshclam; then
        warn "Freshclam daemon is not running"
    fi
    
    # Verify PM2 installation
    if ! command -v pm2 >/dev/null 2>&1; then
        error "PM2 not found in PATH"
        return 1
    fi
    
    # Check PM2 process
    if ! pm2 list | grep -q "clamav-monitor"; then
        error "Monitor is not running under PM2"
        return 1
    fi
    
    # Test virus detection
    log "Testing virus detection..."
    local test_dir="/home/test/public_html"
    mkdir -p "$test_dir"
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$test_dir/test-virus.txt"
    
    # Wait for detection and quarantine
    local timeout=60
    local count=0
    while [ -f "$test_dir/test-virus.txt" ] && [ $count -lt $timeout ]; do
        sleep 1
        count=$((count + 1))
    done
    
    if [ -f "$test_dir/test-virus.txt" ]; then
        error "Test virus file was not quarantined within $timeout seconds"
        return 1
    fi
    
    # Clean up test directory
    rm -rf "$test_dir"
    
    # Additional checks
    if ! systemctl is-enabled --quiet clamd@scan; then
        warn "ClamAV daemon not enabled at startup"
    fi
    
    if ! systemctl is-enabled --quiet clamav-update.timer; then
        warn "Database updates not enabled at startup"
    fi
    
    log "Installation verified successfully"
    return 0
}

# Function to display status report
show_status_report() {
    echo -e "\n${GREEN}=== ClamAV Monitor Status Report ===${NC}"
    echo -e "\nService Status:"
    systemctl status clamd@scan --no-pager
    systemctl status clamav-freshclam --no-pager
    systemctl status clamav-update.timer --no-pager
    
    echo -e "\nPM2 Process Status:"
    pm2 list
    
    echo -e "\nMonitored Directories:"
    find /home -type d -name "public_html" -exec echo "- {}" \;
    
    echo -e "\nImportant Paths:"
    echo "Monitor Script: $INSTALL_DIR/clamav-monitor"
    echo "Configuration: $CONFIG_DIR/scan.conf"
    echo "Logs Directory: $LOG_DIR"
    echo "Quarantine Directory: $QUARANTINE_DIR"
    
    echo -e "\nDatabase Information:"
    sigtool --info "$DB_DIR/main.cvd" 2>/dev/null || sigtool --info "$DB_DIR/main.cld"
    
    echo -e "\nSystem Resources:"
    echo "Memory Usage:"
    free -h
    echo -e "\nDisk Usage:"
    df -h "$DB_DIR"
}

# Main function
main() {
    echo -e "${GREEN}ClamAV Monitor Installation Script v${VERSION}${NC}"
    echo -e "${GREEN}=====================================${NC}"
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Check if root
    check_root
    
    # Check system requirements
    check_system_requirements
    
    # Detect OS
    detect_os
    
    # Configure SELinux if needed
    configure_selinux
    
    # Verify Node.js installation
    verify_nodejs
    
    # Verify/Install PM2
    verify_pm2
    
    # Clean existing installation
    clean_existing
    
    # Install dependencies
    install_dependencies
    
    # Setup directories and permissions
    setup_directories
    
    # Configure ClamAV
    configure_clamav
    
    # Configure automatic updates
    configure_auto_updates
    
    # Create monitor script
    create_monitor_script
    
    # Create PM2 config
    create_pm2_config
    
 # Update virus database
    if ! update_database; then
        error "Failed to update virus database, but continuing with installation..."
        sleep 5
    fi
    
    # Start services
    start_services
    
    # Verify installation
    if verify_installation; then
        log "Installation completed successfully!"
        
        # Show status report
        show_status_report
        
        log "ClamAV Monitor is now running and watching all public_html directories"
        
        exit 0
    else
        error "Installation verification failed"
        exit 1
    fi
}

# Register cleanup function for script interruption
trap cleanup INT TERM

# Run main function
main

exit 0
