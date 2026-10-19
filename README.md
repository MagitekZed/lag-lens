# Lag Lens

Lag Lens watches a home network from one computer and tells you, in plain
English, whether the lag you felt was your LAN, your cable modem, Comcast, or
the internet.

**Status: v1.** ICMP/DNS/TCP/NTP/CDN probes, path discovery, Xbox presence,
host/Wi-Fi/WAN/DOCSIS/IGD collectors, the detection engine (episodes,
classification, verdict, Tell-Comcast block), the dashboard + phone pages,
`report.html`, exports and the sessions index. See `docs/INTERFACES.md` for
the module contracts.

## Install

From the public download site (no login needed):

```sh
curl -fsSL https://magitekzed.github.io/lag-lens/get.sh | sh
cd ~/lag-lens && bash start.sh
```

Or download `lag-lens.zip` from https://magitekzed.github.io/lag-lens/ , unzip it anywhere and run
`bash start.sh` inside the folder. Re-running the installer upgrades in place and keeps `config.json`
and `sessions/`. `bash start.sh --update` does the same from inside the tool.

Works on Linux (including immutable distributions such as Bazzite: run it in Desktop Mode from your
home folder) and macOS. On macOS the first run asks for **Local Network** access for your terminal
app; allow it, or the gateway cannot be probed.

## What it does

Lag Lens is a parallel witness: it runs on a computer plugged into the same Xfinity XB7 as the Xbox
and, several times a second, probes the XB7 itself, the first Comcast hop, a mid-path hop and the
internet over IPv4 and IPv6 (ICMP), plus DNS, TCP connects to Xbox Live, NTP (which also tells
upstream from downstream trouble) and a small CDN fetch. It watches its own link, Wi-Fi, the WAN
address, optionally the XB7's DOCSIS signal and event log (with the admin password) and the UPnP
byte counters. Episodes are detected automatically, classified with evidence (LAN / XB7 / Comcast
access network / upstream / IPv6-only / upload saturation / DNS / this computer), and summed into a
plain-English verdict with a "Tell Comcast" block. Everything is saved every 30 s into a single
self-contained `report.html` you can keep or send.

## Quick start

```sh
bash start.sh                      # run: fast doctor, then monitor (restart loop); opens the dashboard
bash start.sh --no-browser --label "xbox on port 2"
bash start.sh --doctor             # full environment check table
bash start.sh --report sessions/<id>      # rebuild report.html offline
bash start.sh --export sessions/<id> [--pack comcast]
bash start.sh --index              # rebuild sessions/index.html
bash start.sh --stop               # stop the running instance
bash start.sh --update --check     # look for a newer release
bash start.sh --version
```

While it runs: dashboard at `http://<your LAN IP>:8787`, phone page at
`/phone` (QR code on the dashboard), press **Enter** in the terminal, `L` on
the dashboard or the big button on the phone when the lag happens. Stop with
Ctrl-C; the session folder under `sessions/` then holds `report.html`,
`comcast_evidence.txt` and everything needed for `--report`/`--export`.

## Gateway (XB7) password

Modem signal levels and the XB7 event log are the strongest evidence for a cable-line fault, but
reading them needs the gateway's admin login. Lag Lens never asks for it in the browser; you put it
in the config file once:

1. Open `config.json` in the Lag Lens folder (it is created next to `start.sh` on the first run).
2. In the `"docsis"` section replace `null` after `"password"` with the XB7 admin password in
   quotes, e.g. `"password": "your-gateway-password"`. Leave `"username": "admin"` unless you changed it.
3. Save and restart Lag Lens (Ctrl-C, then `bash start.sh`). The doctor line `xb7_login` and the
   XB7 panel on the dashboard confirm it worked; `bash start.sh --docsis-dump` saves the raw pages
   if a table is not recognised.

The file is kept private (mode 600) and the password is only sent to the gateway address in
`docsis.url` (default `http://10.0.0.1`). It is redacted from reports, exports and logs.

Other optional settings: `targets.xbox_ip` (or choose the Xbox on `/setup`) to watch the console,
`notify.ntfy_topic` for phone notifications, `link.up_mbps` for your plan's upload speed.

## Plex mode

For stutter when streaming from a Plex server to a player at home (traffic that never passes this
computer), start with `bash start.sh --plex`, or turn it on under **Setup → Plex mode**. Lag Lens then
finds the server on the LAN (or uses the IP you give it), watches it on its port 32400 (this works
even when Windows' firewall drops pings) and watches each player, and a stutter press tells you which
side dropped. With your Plex token it also reads what the server is doing: Direct Play or Transcode
and its speed, server CPU, background tasks (scans, thumbnails, intro detection) and when a player
reports buffering, so a server that cannot keep up is told apart from the network.

To find the token, open Plex in a browser, open any movie or episode and choose ⋯ → Get Info →
View XML: the address of the page that opens ends in `X-Plex-Token=…`. Paste the part after the `=`
into the token field on the Setup page. Like the XB7 password, it is stored only in `config.json`
(mode 600), sent only to your Plex server and redacted from reports, exports and logs. Run Lag Lens
on a wired computer for this; on Wi-Fi the readings mostly measure the Wi-Fi.

## Updating

```sh
cd ~/lag-lens && bash start.sh --update
```

This downloads the latest release from the download site, verifies its checksum, replaces the
files in place and keeps your `config.json` and `sessions/`. The folder itself stays where it is,
so you can run `bash start.sh` straight afterwards from the same terminal. The previous files are
kept next to it as `lag-lens.old-<version>` (delete that folder whenever you like). `bash start.sh --update --check` only reports whether a newer version
exists; the dashboard shows an update chip when one is available.

Requirements: Python 3.9+ standard library only. No pip, no root.
