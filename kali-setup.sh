#!/usr/bin/env bash
# kali-setup.sh — One-shot personalization for fresh Kali VMs.

set -euo pipefail
# -e: exit on first error
# -u: error on unset variables
# -o pipefail: pipeline fails if any command fails

# =====================================================
#  WHAT THIS DOES
#   • APT: installs your base packages (edit list below)
#   • TIME: sets timezone to Europe/Berlin + enables NTP
#   • FIREFOX: installs FoxyProxy + sets Burp proxy 127.0.0.1:8080
#   • TERMINAL: font size 16 (Xfce + GNOME)
#   • BURP: dark UI + font size 16
#   • WALLPAPER: sets your chosen image (Xfce + GNOME)
#
#  HOW TO RUN
#   chmod +x kali-setup.sh
#   ./kali-setup.sh
#
#  HOW TO EXTEND
#   • Add/remove apt packages in APT_PACKAGES
#   • Change TIMEZONE
#   • Change WALLPAPER_SRC to a URL or local path
# =====================================================

# --------- EDITABLE SETTINGS ---------------------------------

# Add any apt packages you want installed on every VM here:
APT_PACKAGES=(
  openssh-server        # SSH server
  curl                  # HTTP client/downloader
  jq                    # JSON processor
  git                   # Version control
  open-vm-tools-desktop # VMware guest additions (clipboard/display)
  dbus-x11              # DBus for GUI sessions
  kali-community-wallpapers # Kali wallpaper pack
)

# Timezone for the VM:
TIMEZONE="Europe/Berlin"

# Wallpaper source: URL or local absolute path. We’ll copy/download to $WALLPAPER_DST.
WALLPAPER_SRC="/usr/share/backgrounds/kali-16x9/kali-nord-3840x2160.png"
WALLPAPER_DST="$HOME/Pictures/kali-setup-wallpaper.jpg"  # we’ll store a copy here

# -------------------------------------------------------------

# Helper to run root commands succinctly
as_root() { sudo sh -c "$*"; }

echo "[*] Updating apt metadata and installing packages..."
sudo apt update -y
sudo apt install -y "${APT_PACKAGES[@]}" || true
# Tip: remove '|| true' if you prefer the script to stop on any failed package.

echo "[*] Enabling and (re)starting SSH service..."
as_root "systemctl enable ssh"
as_root "systemctl restart ssh"

# =====================================================
#  TIME / TIMEZONE
# =====================================================
echo "[*] Setting timezone to ${TIMEZONE} and enabling NTP..."
as_root "timedatectl set-timezone '${TIMEZONE}'"
as_root "timedatectl set-ntp true" || true
as_root "hwclock --systohc" || true

# =====================================================
#  FIREFOX ENTERPRISE POLICIES (FoxyProxy + Burp proxy)
#  We write to both firefox-esr and firefox paths for safety.
# =====================================================
echo "[*] Configuring Firefox enterprise policies (FoxyProxy + proxy)..."
for POL_DIR in /usr/lib/firefox-esr/distribution /usr/lib/firefox/distribution; do
  if [[ -d "$(dirname "$POL_DIR")" ]]; then
    as_root "mkdir -p '$POL_DIR'"
    as_root "cat > '$POL_DIR/policies.json' <<'JSON'
{
  \"policies\": {
    \"DisableAppUpdate\": true,               // You’ll update via apt
    \"Extensions\": {
      \"Install\": [
        \"https://addons.mozilla.org/firefox/downloads/latest/2464/addon-2464-latest.xpi\"
      ]
    },
    \"Proxy\": {
      \"Mode\": \"manual\",
      \"HTTPProxy\": \"127.0.0.1:8080\",
      \"SSLProxy\": \"127.0.0.1:8080\",
      \"UseProxyForDNS\": true,
      \"NoProxy\": \"localhost, 127.0.0.1\"
    }
  }
}
JSON"
    echo "    -> Wrote policies to: $POL_DIR/policies.json"
  fi
done

# =====================================================
#  TERMINAL FONT SIZE = 16 (QTerminal + Xfce + GNOME)
# =====================================================
echo "[*] Setting terminal font size to 16..."

# =====================================================
#  TERMINAL FONT: QTerminal -> keep FiraCode, set 16pt
# =====================================================
echo "[*] Setting QTerminal font size to 16..."

QCONF="$HOME/.config/qterminal.org/qterminal.ini"
pkill -x qterminal 2>/dev/null || true      # close QTerminal so it can't overwrite changes
mkdir -p "$(dirname "$QCONF")"
[[ -f "$QCONF" ]] || printf "[General]\n" > "$QCONF"

# force useSystemFont=false
if grep -q '^[Uu]se[Ss]ystem[Ff]ont=' "$QCONF"; then
  sed -i 's/^[Uu]se[Ss]ystem[Ff]ont=.*/useSystemFont=false/' "$QCONF"
else
  echo "useSystemFont=false" >> "$QCONF"
fi

# force fontSize=16
if grep -q '^[Ff]ont[Ss]ize=' "$QCONF"; then
  sed -i 's/^[Ff]ont[Ss]ize=.*/fontSize=16/' "$QCONF"
else
  echo "fontSize=16" >> "$QCONF"
fi

echo "    ✓ QTerminal font size set to 16 (family stays $(grep -m1 '^fontFamily=' "$QCONF" | cut -d= -f2))"

# --- Xfce Terminal (if present) ---
if command -v xfconf-query >/dev/null 2>&1; then
  xfconf-query -c xfce4-terminal -p /general/use-system-font -s false || true
  xfconf-query -c xfce4-terminal -p /general/fontName -s "Monospace 16" || true
fi

# --- GNOME Terminal (if present) ---
if command -v gsettings >/dev/null 2>&1 && gsettings list-schemas | grep -q 'org.gnome.Terminal.ProfilesList'; then
  PROFILE_ID=$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d \')
  BASE="org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$PROFILE_ID/"
  gsettings set "$BASE" use-system-font false || true
  gsettings set "$BASE" font "Monospace 16" || true
fi

# =====================================================
#  BURP SUITE: Dark theme + font size 16
#  Burp will read/merge this on startup if present.
# =====================================================
echo "[*] Writing Burp user options (dark theme, font 16)..."
mkdir -p "$HOME/.BurpSuite"
cat > "$HOME/.BurpSuite/user-options.json" <<'JSON'
{
  "user_options": {
    "display": {
      "user_interface": {
        "look_and_feel": "Dark",
        "font_size": 16
      }
    }
  }
}
JSON

# =====================================================
#  WALLPAPER (Xfce + GNOME)
#   • If WALLPAPER_SRC is a URL: download to $WALLPAPER_DST
#   • If local path: copy to $WALLPAPER_DST
#   • Apply to both DEs if available
# =====================================================
echo "[*] Preparing wallpaper..."
mkdir -p "$(dirname "$WALLPAPER_DST")"

apply_wallpaper=false
if [[ -n "${WALLPAPER_SRC}" ]]; then
  if [[ "$WALLPAPER_SRC" =~ ^https?:// ]]; then
    echo "    -> Downloading from URL..."
    if curl -fsSL "$WALLPAPER_SRC" -o "$WALLPAPER_DST"; then
      apply_wallpaper=true
    else
      echo "    !! Download failed: $WALLPAPER_SRC"
    fi
  else
    # Local file
    if [[ -f "$WALLPAPER_SRC" ]]; then
      cp "$WALLPAPER_SRC" "$WALLPAPER_DST"
      apply_wallpaper=true
    else
      echo "    !! Local path not found: $WALLPAPER_SRC"
    fi
  fi
else
  echo "    -> No wallpaper source set; skipping."
fi

if $apply_wallpaper; then
  echo "[*] Applying wallpaper to desktop environments..."

  # Xfce: set all 'last-image' props to the new file; style 5 = Zoomed
  if command -v xfconf-query >/dev/null 2>&1; then
    while read -r prop; do
      xfconf-query -c xfce4-desktop -p "$prop" -s "$WALLPAPER_DST" || true
    done < <(xfconf-query -c xfce4-desktop -l | grep last-image || true)

    while read -r prop; do
      xfconf-query -c xfce4-desktop -p "$prop" -s 5 || true
    done < <(xfconf-query -c xfce4-desktop -l | grep image-style || true)
  fi

  # GNOME: set picture URIs + zoom mode
  if command -v gsettings >/dev/null 2>&1 && gsettings list-schemas | grep -q 'org.gnome.desktop.background'; then
    uri="file://$WALLPAPER_DST"
    gsettings set org.gnome.desktop.background picture-uri "$uri" || true
    gsettings set org.gnome.desktop.background picture-uri-dark "$uri" || true
    gsettings set org.gnome.desktop.background picture-options "zoom" || true
  fi
else
  echo "[*] Skipping wallpaper apply; file not present."
fi

# =====================================================
#  DONE
# =====================================================
echo
echo "✅ kali-setup finished."
echo
echo "Installed apt packages: ${APT_PACKAGES[*]}"
echo "Timezone now: $(timedatectl | grep 'Time zone' || true)"
echo "SSH: enabled and running (systemctl status ssh)"
echo "Firefox: FoxyProxy via policy; HTTP/HTTPS proxy 127.0.0.1:8080"
echo "Terminal: font set to 16 (Xfce/GNOME if present)"
if [[ -f "$WALLPAPER_DST" ]]; then
  echo "Wallpaper: $WALLPAPER_DST (source: $WALLPAPER_SRC)"
else
  echo "Wallpaper: not applied"
fi
echo
echo "Tip: add more APT packages by editing the APT_PACKAGES array near the top."
echo
