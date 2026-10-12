#!/bin/sh
# Lag Lens installer. POSIX sh; works as "curl -fsSL .../get.sh | sh" or "| bash".
#
#   LAGLENS_BASE  where to download from (default https://magitekzed.github.io/lag-lens)
#   LAGLENS_DIR   where to install       (default $HOME/lag-lens)
#
# Downloads lag-lens.zip and its .sha256, verifies the checksum, unpacks it and
# installs it to LAGLENS_DIR. A previous install is kept as <dir>.old; your
# config.json and sessions/ are carried over. Needs python3 and any one of
# curl / wget / python3 for the download, and unzip or python3 to extract.
#
# Your data is never staged in a temporary directory: the previous install is
# renamed to <dir>.old first and config.json / sessions/ are moved from there
# into the new tree. If any step fails they are still in <dir>.old.
set -eu

BASE="${LAGLENS_BASE:-https://magitekzed.github.io/lag-lens}"
BASE="${BASE%/}"
DEST="${LAGLENS_DIR:-$HOME/lag-lens}"
case "$DEST" in
  */) DEST="${DEST%/}" ;;
esac
OLD="$DEST.old"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required (macOS: run 'xcode-select --install'; Linux: install python3)" >&2
  exit 1
fi

# $TMP only ever holds the download and the unpacked archive, never user data,
# so removing it on exit is always safe. INT/TERM exit instead of continuing.
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t laglens)"
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fetch() { # fetch URL OUTFILE
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --max-time 600 --retry 2 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=30 --tries=3 "$1" -O "$2"
  else
    python3 -c 'import sys, socket, urllib.request; socket.setdefaulttimeout(30); urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$1" "$2"
  fi
}

sha256_of() { # sha256_of FILE -> hex on stdout
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    python3 -c 'import sys, hashlib; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
  fi
}

echo "Downloading Lag Lens from $BASE ..."
fetch "$BASE/lag-lens.zip" "$TMP/lag-lens.zip" || { echo "download failed: $BASE/lag-lens.zip" >&2; exit 1; }
fetch "$BASE/lag-lens.zip.sha256" "$TMP/sum" || { echo "download failed: $BASE/lag-lens.zip.sha256" >&2; exit 1; }

WANT="$(cut -d' ' -f1 "$TMP/sum" | tr -d '[:space:]')"
GOT="$(sha256_of "$TMP/lag-lens.zip")"
if [ -z "$WANT" ] || [ "$WANT" != "$GOT" ]; then
  echo "checksum mismatch: expected '$WANT' got '$GOT'" >&2
  exit 1
fi
echo "Checksum OK ($GOT)"

mkdir -p "$TMP/x"
if command -v unzip >/dev/null 2>&1; then
  unzip -q "$TMP/lag-lens.zip" -d "$TMP/x"
else
  python3 -m zipfile -e "$TMP/lag-lens.zip" "$TMP/x"
fi
if [ ! -f "$TMP/x/lag-lens/start.sh" ]; then
  echo "unexpected archive layout (no lag-lens/start.sh inside the zip)" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"

# Everything below must not lose user data. Order of operations:
#   1. remove the stale <dir>.old; if that is impossible, stop before touching <dir>
#   2. rename <dir> -> <dir>.old           (same filesystem: a pure rename)
#   3. move the new tree into place         (a failure here restores <dir>.old -> <dir>)
#   4. move config.json and sessions/ from <dir>.old into the new <dir> (pure renames)
HAD_PREVIOUS=0
if [ -e "$DEST" ]; then
  if [ -e "$OLD" ]; then
    rm -rf "$OLD" 2>/dev/null || true
    if [ -e "$OLD" ]; then
      echo "cannot remove the previous backup $OLD (permissions?)." >&2
      echo "Remove or rename it, then run the installer again. $DEST was not touched." >&2
      exit 1
    fi
  fi
  mv "$DEST" "$OLD"
  HAD_PREVIOUS=1
fi

if ! mv "$TMP/x/lag-lens" "$DEST"; then
  echo "could not move the new install into $DEST" >&2
  if [ "$HAD_PREVIOUS" = 1 ]; then
    rm -rf "$DEST" 2>/dev/null || true
    if [ ! -e "$DEST" ] && mv "$OLD" "$DEST" 2>/dev/null; then
      echo "Restored the previous install at $DEST." >&2
    else
      echo "Your previous install (with config.json and sessions/) is at $OLD." >&2
    fi
  fi
  exit 1
fi

if [ "$HAD_PREVIOUS" = 1 ]; then
  for keep in config.json sessions; do
    if [ -e "$OLD/$keep" ]; then
      if ! mv "$OLD/$keep" "$DEST/$keep"; then
        echo "could not move $keep into the new install; it is still at $OLD/$keep" >&2
        exit 1
      fi
    fi
  done
  echo "Previous install kept as $OLD"
fi

chmod +x "$DEST/start.sh" "$DEST/get.sh" "$DEST/run.py" 2>/dev/null || true

VER="unknown"
if [ -f "$DEST/VERSION" ]; then
  VER="$(tr -d '[:space:]' < "$DEST/VERSION")"
fi

echo
echo "Installed Lag Lens $VER to $DEST"
echo
echo "Next:"
echo "  cd \"$DEST\" && bash start.sh"
echo
echo "Then open the dashboard URL it prints (or scan the QR code with your phone)."
case "$(uname -s 2>/dev/null)" in
  Darwin) echo "macOS: if the gateway shows as unreachable, allow Local Network for your terminal app in System Settings > Privacy & Security > Local Network." ;;
esac
