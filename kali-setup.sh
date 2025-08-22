#!/usr/bin/env bash
# kali-setup.sh — One-shot personalization for fresh Kali VMs.

set -euo pipefail

# =====================================================
#  WHAT THIS DOES
#   • apt update/upgrade, then installs base packages
#   • TIME: sets timezone to Europe/Berlin + enables NTP
#   • TERMINAL: font size 16 (QTerminal + Xfce + GNOME)
#   • WALLPAPER: sets your chosen image (QTerminal + Xfce + GNOME)
# =====================================================

# --------- EDITABLE SETTINGS ---------------------------------
APT_PACKAGES=(
  openssh-server
  curl
  jq
  git
  open-vm-tools-desktop
  dbus-x11
  kali-community-wallpapers
  open-vm-tools
  open-vm-tools-desktop
  burpsuite
  seclists
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
sudo apt update -y
sudo apt upgrade -y

echo "[*] Installing base packages..."
sudo apt install -y "${APT_PACKAGES[@]}"

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

# ===== Tools: create ~/www and pull helpers ==================================
echo "[*] Preparing ~/www with common tools..."
# ===== Tools: ~/www + local-copy-or-download =================================
echo "[*] Preparing ~/www with common tools (prefer local copies)..."
WWW_DIR="$HOME/www"
mkdir -p "$WWW_DIR"

need() { command -v "$1" >/dev/null 2>&1 || { echo "    -> installing $1..."; sudo apt install -y "$1"; }; }
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
curlget() { curl -fL --retry 3 --retry-delay 2 -A "$UA" "$@"; }

# Helper: try to copy first match from /usr/share, else curl it
copy_or_get() {
  local pattern="$1" dest="$2" url="$3"
  local found
  found="$(sudo find /usr/share -maxdepth 8 -type f -iname "$pattern" 2>/dev/null | head -n1 || true)"
  if [[ -n "$found" ]]; then
    echo "  - Found local: $found -> $dest"
    sudo cp -f "$found" "$dest"
  else
    echo "  - Downloading -> $dest"
    curlget -o "$dest" "$url"
  fi
}

# --- Sysinternals Suite (Windows binaries, ZIP) ---
if [[ ! -d "$WWW_DIR/sysinternals" ]]; then
  echo "  - Downloading Sysinternals Suite..."
  need unzip
  TMPZ="/tmp/sysinternals.zip"
  curlget -o "$TMPZ" "https://download.sysinternals.com/files/SysinternalsSuite.zip"
  mkdir -p "$WWW_DIR/sysinternals"
  unzip -oq "$TMPZ" -d "$WWW_DIR/sysinternals"
  rm -f "$TMPZ"
else
  echo "  ✓ Sysinternals already present"
fi

# --- linpeas.sh ---
copy_or_get "linpeas.sh" "$WWW_DIR/linpeas.sh" \
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
chmod +x "$WWW_DIR/linpeas.sh" || true

# --- LinEnum.sh ---
copy_or_get "LinEnum.sh" "$WWW_DIR/LinEnum.sh" \
  "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
chmod +x "$WWW_DIR/LinEnum.sh" || true

# --- mimikatz.exe ---
copy_or_get "mimikatz.exe" "$WWW_DIR/mimikatz.exe" \
  "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
if file "$WWW_DIR/mimikatz.exe" 2>/dev/null | grep -qi zip; then
  need unzip
  TMPZ="$WWW_DIR/mimikatz_trunk.zip"
  mv -f "$WWW_DIR/mimikatz.exe" "$TMPZ"
  unzip -oq "$TMPZ" -d "$WWW_DIR/mimikatz_extracted"
  CAND="$(find "$WWW_DIR/mimikatz_extracted" -iname mimikatz.exe | sort | head -n1 || true)"
  if [[ -n "$CAND" ]]; then mv -f "$CAND" "$WWW_DIR/mimikatz.exe"; fi
  rm -rf "$WWW_DIR/mimikatz_extracted" "$TMPZ"
fi

# --- SharpHound.ps1 ---
copy_or_get "SharpHound.ps1" "$WWW_DIR/SharpHound.ps1" \
  "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1"

# --- WinPEASx64.exe ---
copy_or_get "winpeasx64.exe" "$WWW_DIR/WinPEASx64.exe" \
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"

# --- PowerUp.ps1 ---
copy_or_get "PowerUp.ps1" "$WWW_DIR/PowerUp.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"

# --- PowerView.ps1 ---
copy_or_get "PowerView.ps1" "$WWW_DIR/PowerView.ps1" \
  "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"

# Final touches
chmod +x "$WWW_DIR/"*.sh 2>/dev/null || true
echo "✅ Tools staged in $WWW_DIR"

# ===== DONE ================================================================
echo
echo "✅ kali-setup finished."
echo
echo "Installed apt packages: ${APT_PACKAGES[*]}"
echo "Timezone now: $(timedatectl | grep 'Time zone' || true)"
echo "SSH: enabled and running (systemctl status ssh)"
echo "Terminal: font set to 16 (QTerminal/Xfce/GNOME if present)"
echo "You still have to install Firefox extensions, e.g. FoxyProxy, Wappalyzer"
echo "⚠️  Reminder: change your local password:  passwd"
echo
