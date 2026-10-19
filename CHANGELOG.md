# Changelog

All notable changes to Lag Lens are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and versions follow SemVer.

## [1.0.16] - 2026-10-18

### Added
- Plex mode (`bash start.sh --plex`, or Setup → Plex mode) for stutter streaming between two devices at
  home. Lag Lens finds the Plex Media Server on the LAN by GDM (or uses `plex.server`), watches it on
  port 32400 at 2 Hz (a TCP connect, so Windows' firewall dropping pings does not matter) and watches
  each player by ping (`plex.players`, plus every player seen in a session; a player that stops
  answering while it is not playing is taken as asleep).
- With the Plex token (`plex.token`, entered on the Setup page, write-only, kept in `config.json` and
  redacted like the XB7 password) it reads the server's sessions (Direct Play / Direct Stream /
  Transcode, transcoder speed and throttling, bitrate, local or remote), CPU and background tasks, and
  notes when a player reports buffering, when the transcoder falls under real time, CPU above 90 %, a
  background task starting, a stream leaving the LAN, and the server going offline.
- New episode classes: the Plex server alone, a player alone, and both together while the router is
  fine (the switch or cabling they share), with next steps. Episodes and "Lag happened" presses carry
  what Plex reported at that moment (for example "HTPC transcode at 0.7x; server CPU 96%"), the
  verdict adds a Plex summary sentence, and the dashboard has a Plex panel. "Plex" joins the
  activities, and the doctor checks the server and the token.

### Changed
- The TCP prober honours a faster rate when a target asks for one (the Plex server's 2 Hz); every
  other TCP target keeps one connect every 2 s.

## [1.0.15] - 2026-10-12

### Fixed
- Behind a router of your own (the XB7 in bridge mode), Lag Lens no longer calls that router "the XB7".
  Verdict sentences, the top bar, episode evidence, "Lag happened" summaries, next steps and doctor hints
  name it "your router", and a gateway that stops answering is reported as a home problem with router steps.
  The gateway counts as your own router when its address differs from the modem's admin address
  (`docsis.url`); with the XB7 as the router nothing changes.
- The Tell-Comcast evidence lists only episodes that point at Comcast's side (cable line, Comcast network,
  upload delay past the modem) and says how many others were left out. Home episodes (the Xbox's cable, a
  home upload, this computer, your own router) are no longer listed under a heading that says they are not
  caused by the home. Behind your own router it shows the router and "Modem: XB7 in bridge mode".
- When the modem hides its event log from the customer login (the XB7 on current firmware), the evidence
  says "T3/T4 not visible" instead of "T3 ×0, T4 ×0", which read as "no timeouts", and drops the log clock
  offset line. The request also asks Comcast for the modem's T3 timeouts and notes how many episodes were in
  the upload direction.

## [1.0.14] - 2026-10-12

### Fixed
- A gateway upload counter that failed a check stays untrusted for the rest of the session. Other devices'
  traffic can only add to what the counter shows, so an undercount is proof; a later upload that happened to
  overlap other devices' uploads (85 % of 1 MB on an Arris TG4482A whose self-check had counted 6 %) no
  longer flips the counter to trusted.
- A passing check must hold up after taking off what the counter adds on its own while this computer is
  quiet (other devices' uploads), and the one-time self-check still runs after a passive pass.
- The Tell-Comcast table read IPv6 targets' loss from the wrong part of the evidence line, showing
  figures like "2390%" in the internet column. The Comcast hop column now falls back to the IPv6 hop when
  the IPv4 hop does not answer, instead of "n/a".
- The load test's download phase moved nothing: speed.cloudflare.com now refuses 100 MB downloads (HTTP 403),
  so the test asked for 100 MB and was graded on the upload alone. Downloads are now 25 MB requests repeated
  for the phase; a refused request stops that worker instead of retrying in a tight loop, and a load phase
  that moves under 1 Mb/s is reported as failed (with the reason, also on the dashboard) and gets no grade.

## [1.0.13] - 2026-10-11

### Fixed
- Only one monitor runs per install folder: `bash start.sh` now says which session is already running
  (pid, session, dashboard port) and exits instead of starting a second copy that fights the first over
  the gateway login and the session pointers. A stale pidfile from a crash is ignored.
- A monitor's shutdown no longer deletes the pidfile of another monitor.

## [1.0.12] - 2026-10-11

### Added
- New episode class "upload delay past the modem": the XB7 answers normally while the first Comcast hop and
  everything past it slow down in the upload direction, and the household upload cannot be measured. It
  names both possible causes (a device at home uploading, such as a game clip, or Comcast's upstream) and
  the experiments that tell them apart. With a verified gateway counter showing low household upload, the
  same pattern is attributed to Comcast's upstream (`docsis_access/upstream`); with a high one, to upload
  saturation.
- The gateway's UPnP traffic counters are trusted only after they account for a known upload from this
  computer: passively (this computer uploaded at least 1 MB) or by a one-time 1.5 MB check at about 3 Mb/s,
  a minute after the gateway is found and never during an episode (`igd.verify_upload`, default on).

### Fixed
- When Comcast's first IPv4 hop ignores pings (the 10.60.x.x hop on Xfinity), the IPv6 Comcast hop is used
  for classification, so these episodes are no longer "unclear".
- Moving gateway counters are no longer taken as trustworthy: on the Arris TG4482A the upload counter
  moves but counts about 4 to 9 % of real traffic.
- Xbox discovery no longer sends discovery broadcasts when the computer has no LAN address.

## [1.0.11] - 2026-10-11

### Fixed
- After the Xbox address changes, the previous address's silence no longer shows up as a short
  "Xbox cable/port" episode: only samples sent to the new address count.
- Saving the same Xbox address again on the setup page no longer resets the console's awake state.

## [1.0.10] - 2026-10-11

### Added
- Xbox discovery asks every device on the local network (and the broadcast address) the same question
  the Xbox app uses to find consoles, so the console is found whatever its hardware prefix; the
  Microsoft-prefix list is now only the fallback.
- When the console at the known address goes quiet and a console answers at another address (its
  DHCP lease changed), Lag Lens follows it and saves the new address in `config.json`. An address given
  with `--xbox` is never overridden; Lag Lens logs the new address instead.

## [1.0.9] - 2026-10-11

### Changed
- Dashboard tiles use smaller text and pack a little tighter.
- Tile addresses appear only while hovering the tile (a strip over the name, clipped with "…"); the
  tooltip always has the full label and address. Long labels are clipped instead of overflowing.
- The phone page's big numbers no longer show addresses (long IPv6 addresses overflowed there).

## [1.0.8] - 2026-10-11

### Fixed
- No more "the Xbox stopped answering" / "Xbox cable/port" alarm in the first half minute when the
  console is off or in standby: only an awake console's losses count (as designed). A console that
  answers at least half of its probes is considered awake even if it never answers 10 in a row, so a
  bad cable is still caught.
- The doctor no longer reports the dashboard port as busy right after a previous run closed it.

## [1.0.7] - 2026-10-11

### Fixed
- XB7 log timestamps in the TG4482A's `2026/9/30 02:41:54` format are understood, and the trailing
  newlines the firmware appends to every log field are removed.
- `--docsis-dump` says plainly when the gateway's event or system log is empty (the TG4482A firmware
  does not show DOCSIS events to the admin login), instead of printing an empty count.

## [1.0.6] - 2026-10-11

### Added
- XB7 event and system logs (T3/T4 timeouts and other DOCSIS events) are read from the JSON endpoint the
  gateway's troubleshooting page loads by script: a week of history at start (kept as history, never
  turned into events), then today's lines every poll, including the lines from just before midnight.
- `bash start.sh --docsis-dump` fetches a month of event and system log, saves it as JSON and prints a
  summary with every T3/T4/ranging line.
- The gateway's clock offset is measured from its own "Local time" line (the TG4482A runs an hour behind).

### Fixed
- Firmware version is read from the TG4482A's "Download Version" field.
- The dump no longer fetches the `.jsp` page names once the `.jst` pages work.

## [1.0.5] - 2026-10-11

### Fixed
- XB7 login was reported as rejected even though it succeeded: logged-in pages on the Arris TG4482A
  contain a Logout link and an inactivity timer that mention `home_loggedout.jst`, which the
  logged-out check mistook for the redirect page. A page now counts as logged out only when it is the
  login form or a bare redirect script, and never when it carries the Logout link.
- The unused channel "0" column on the XB7's channel and codeword tables is ignored (DOCSIS channel
  ids start at 1).

## [1.0.4] - 2026-10-11

### Changed
- XB7 login: the username is lower-cased like the gateway's own login page does, a browser-like
  User-Agent is sent, and every login attempt is logged with the HTTP status and what the reply
  looked like. `bash start.sh --docsis-dump` now saves the login reply pages (`login_response_*.html`)
  and explains the usual causes of a rejection.

## [1.0.3] - 2026-10-11

### Fixed
- UPnP: a WAN byte counter that the gateway firmware clamps at the 32-bit maximum (the Arris TG4482A
  XB7 does this for the download direction) is reported as unavailable instead of a 0 Mb/s rate; the
  upload counter and the saturation witness keep working.

## [1.0.2] - 2026-10-11

### Changed
- `bash start.sh --update` now replaces the files inside the install folder instead of swapping the
  folder itself, so a terminal that is already in the folder (and the restart loop) keeps working
  right after the update. The previous files are still kept as `lag-lens.old-<version>`.

## [1.0.1] - 2026-10-11

### Fixed
- Dashboard target tiles no longer dim and brighten every second (a class was flipped on each tick).
- Phone page: the big button and the bottom sheet are clamped to the screen width; the status pill wraps.
- Episodes on a Wi-Fi probe host where the gateway degrades together with everything beyond it are
  classified as the probe host's Wi-Fi link instead of "unknown".
- The dashboard no longer polls the modem endpoint while the DOCSIS collector is disabled.

### Changed
- Setup page and README say exactly where the XB7 admin password goes (config.json, docsis.password).

## [1.0.0] - 2026-10-11

### Added
- Initial release: shared `State`/`Store` contracts, configuration, logging,
  thread supervisor, platform layer (Linux/macOS), target table, rollup
  engine, CLI and application wiring with a clean SIGINT/SIGTERM shutdown
  sequence.
- ICMP engine (v4+v6, 250 ms grid, ping-binary fallback), path discovery with
  hop roles and route-change events, DNS/TCP/NTP/CDN probes, Xbox presence.
- Host, Wi-Fi, WAN, DOCSIS (XB7) and UPnP IGD collectors; keep-awake; doctor.
- Detection engine: baselines, episodes, simultaneity matrix, classification
  rules, session verdict, Tell-Comcast block, health score, marks.
- Dashboard, phone page, sessions and setup pages; SSE; `report.html`;
  export packs; `sessions/index.html`; load test; ntfy/webhook notify;
  `--update`.
- Integration: NTP probe wired, Enter-to-mark in the terminal, doctor lines in
  the startup box, update check, session rotation after `rotate_hours`,
  Xbox IP chosen on `/setup` persisted to `config.json`, static sessions index
  rebuilt at every shutdown, `dns_gw` prefers the home gateway over a VPN
  resolver, IPv4-mapped AAAA answers rejected.
