#!/usr/bin/env bash
# kali-setup.sh — One-shot personalization for fresh Kali VMs.

set -euo pipefail

# =====================================================
#  WHAT THIS DOES
#   • apt update/upgrade, then installs base packages
#   • TIME: sets timezone to Europe/Berlin + enables NTP
#   • FIREFOX: installs FoxyProxy + Wappalyzer; sets Burp proxy 127.0.0.1:8080
#   • TERMINAL: font size 16 (QTerminal + Xfce + GNOME)
#   • BURP: dark UI + font size 16
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
