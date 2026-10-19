/* Lag Lens — dashboard (live mode) and report renderer (static mode).
 *
 * Live mode runs on `/`: it paints from GET /api/state, follows SSE /events (polling
 * fallback), keeps the uPlot timeline stack fed from /api/series and handles the
 * Lag-happened button, episode evidence cards, load test, activity, stop and export.
 *
 * Static mode is chosen when <script id="laglens-data"> exists (report.html): the
 * whole report (SPEC §9.1 sections 1–13) is rendered from that blob and the page never
 * touches the network.
 */
(function (root) {
  'use strict';
  var doc = (typeof document !== 'undefined') ? document : null;
  var LL = root.LL;
  if (!doc || !LL) return;
  var h = LL.h, $ = LL.$, fmt = LL.fmt, esc = LL.esc;

  var ICMP_ORDER = ['gw4', 'xbox', 'isp_hop4', 'mid_hop4', 'inet4_cf', 'inet4_g', 'gw6', 'isp_hop6', 'inet6_cf', 'inet6_g'];
  var CARD_LABELS = { gw4: 'Gateway', gw6: 'Gateway v6', xbox: 'Xbox', isp_hop4: 'Comcast hop', isp_hop6: 'Comcast hop v6', mid_hop4: 'Mid-path',
    inet4_cf: 'Internet v4', inet4_g: 'Internet v4 (G)', inet6_cf: 'Internet v6', inet6_g: 'Internet v6 (G)' };
  var CLASS_LIST = ['docsis_access', 'upstream_delay', 'comcast_network', 'xb7_gateway', 'xbox_lan', 'plex_server', 'plex_player', 'home_lan', 'xb7_cpu', 'internet', 'ipv6_only',
    'ipv4_only', 'upload_saturation', 'probe_host', 'probe_link', 'probe_wifi', 'single_destination', 'dns', 'cdn', 'unknown'];

  function targetLabel(t) { return CARD_LABELS[t.key] || t.label || t.key; }
  function isIcmp(t) { return t.kind === 'icmp'; }
  function sortTargets(list) {
    return list.slice().sort(function (a, b) {
      var ia = ICMP_ORDER.indexOf(a.key), ib = ICMP_ORDER.indexOf(b.key);
      if (ia < 0) ia = 100 + a.id; if (ib < 0) ib = 100 + b.id;
      return ia - ib;
    });
  }
  function confClass(c) { return c >= 0.75 ? 'hi' : (c >= 0.5 ? 'mid' : 'lo'); }
  // why a load test has no grade: its load phases that moved no traffic ("down: … HTTP 403 …")
  function ltFailed(l) {
    var p = (l && l.phases) || {};
    return ['down', 'up'].filter(function (k) { return p[k] && p[k].failed; }).map(function (k) { return k + ': ' + p[k].failed; }).join('; ');
  }
  function kv(pairs) {
    var dl = h('dl', { class: 'kvlist' });
    pairs.forEach(function (p) { if (p[1] == null || p[1] === '') return; dl.appendChild(h('dt', null, p[0])); dl.appendChild(h('dd', null, p[1])); });
    return dl;
  }

  // =====================================================================================
  // Shared chart stack (live dashboard + static report section 6)
  // =====================================================================================
  function buildStack(container, targets, opts) {
    opts = opts || {};
    var group = new LL.ChartGroup({ range: opts.range || 600, follow: opts.follow !== false, sessionStart: opts.sessionStart, onZoom: opts.onZoom, onFollow: opts.onFollow });
    LL._groups.push(group);
    var byId = {}; targets.forEach(function (t) { byId[t.id] = t; });
    var icmp = sortTargets(targets.filter(isIcmp));
    var app = sortTargets(targets.filter(function (t) { return !isIcmp(t); }));
    var colors = {}; targets.forEach(function (t) { colors[t.id] = LL.roleColor(t); });
    LL.clear(container);
    function panel(id, title, legend) {
      var lg = h('span', { class: 'legend' });
      (legend || []).forEach(function (l) { var s = h('span', null, l[0]); s.style.setProperty('--sw', l[1]); lg.appendChild(s); });
      var wrap = h('div', { class: 'chart', id: id }, h('div', { class: 'title' }, h('span', null, title), lg));
      var el = h('div');
      wrap.appendChild(el);
      container.appendChild(wrap);
      return el;
    }
    var charts = {};
    function tg(id, key) { return function (S) { return S.targets && S.targets[String(id)] ? S.targets[String(id)][key] : null; }; }
    charts.latency = group.add(panel('ch-latency', 'Latency (p50 per target)', icmp.map(function (t) { return [targetLabel(t), colors[t.id]]; })), {
      height: 220, logToggle: true, raw: true, markIcons: true, lateMarkers: true, yLabel: 'ms',
      series: icmp.map(function (t) { return { label: targetLabel(t), stroke: colors[t.id], width: t.role === 'gateway' ? 2 : 1.5, spanGaps: false }; })
    });
    charts.latency.pick = icmp.map(function (t) { return tg(t.id, 'p50'); });
    charts.loss = group.add(panel('ch-loss', 'Loss (lost probes per window)', icmp.map(function (t) { return [targetLabel(t), colors[t.id]]; })), {
      height: 130, yLabel: 'lost', series: icmp.map(function (t) { return { label: targetLabel(t), stroke: colors[t.id], fill: LL.shade(colors[t.id], 0.35), width: 1, bars: true }; })
    });
    charts.loss.pick = icmp.map(function (t) { return tg(t.id, 'lost'); });
    charts.jitter = group.add(panel('ch-jitter', 'Jitter + late replies', icmp.map(function (t) { return [targetLabel(t), colors[t.id]]; }).concat([['late', LL.cssVar('--warn')]])), {
      height: 130, yLabel: 'ms / late',
      series: icmp.map(function (t) { return { label: targetLabel(t), stroke: colors[t.id], width: 1 }; }).concat([{ label: 'late', stroke: LL.cssVar('--warn'), width: 1.5, dash: [4, 4] }])
    });
    charts.jitter.pick = icmp.map(function (t) { return tg(t.id, 'jit'); }).concat([function (S) {
      var sum = S.t.map(function () { return null; });
      icmp.forEach(function (t) { var a = tg(t.id, 'late')(S); if (a) a.forEach(function (v, i) { if (v != null) sum[i] = (sum[i] || 0) + v; }); });
      return sum;
    }]);
    var segCols = [['LAN', LL.cssVar('--c-gw')], ['DOCSIS', LL.cssVar('--c-isp')], ['Comcast', LL.cssVar('--c-mid')], ['Internet', LL.cssVar('--c-inet4')]];
    charts.segments = group.add(panel('ch-segments', 'Segments (approximate, 10 s medians)', segCols), {
      height: 130, yLabel: 'ms', series: segCols.map(function (c) { return { label: c[0], stroke: c[1], width: 1.5, fill: LL.shade(c[1], 0.12), spanGaps: true }; })
    });
    charts.segments.pick = ['lan', 'docsis', 'comcast', 'internet'].map(function (k) { return function (S) { return S.segments ? S.segments[k] : null; }; });
    if (app.length) {
      charts.app = group.add(panel('ch-app', 'UDP / TCP / DNS / CDN', app.map(function (t) { return [t.label || t.key, colors[t.id]]; }).concat([['NTP offset shift', LL.cssVar('--c-udp')]])), {
        height: 150, yLabel: 'ms', series: app.map(function (t) { return { label: t.label || t.key, stroke: colors[t.id], width: 1.2, spanGaps: true, points: { show: true, size: 4 } }; })
          .concat([{ label: 'NTP offset shift', stroke: LL.cssVar('--c-udp'), width: 1, dash: [2, 3], spanGaps: true }])
      });
      charts.app.pick = app.map(function (t) { return tg(t.id, 'p50'); }).concat([function (S) { return S.ntp ? S.ntp.offset_shift : null; }]);
    }
    var upMbps = opts.linkUp || null;
    charts.traffic = group.add(panel('ch-traffic', 'Traffic (host, WAN via IGD, upstream limit)', [['host rx', LL.cssVar('--c-inet4')], ['host tx', LL.cssVar('--c-gw')], ['WAN rx', LL.cssVar('--c-inet6')], ['WAN tx', LL.cssVar('--c-isp')], ['up limit', LL.cssVar('--fg-3')]]), {
      height: 130, yLabel: 'Mb/s', series: [
        { label: 'host rx', stroke: LL.cssVar('--c-inet4'), width: 1, spanGaps: true }, { label: 'host tx', stroke: LL.cssVar('--c-gw'), width: 1, spanGaps: true },
        { label: 'WAN rx', stroke: LL.cssVar('--c-inet6'), width: 1.5, spanGaps: true }, { label: 'WAN tx', stroke: LL.cssVar('--c-isp'), width: 1.5, spanGaps: true },
        { label: 'up limit', stroke: LL.cssVar('--fg-3'), width: 1, dash: [6, 4], spanGaps: true }]
    });
    charts.traffic.pick = [function (S) { return S.iface ? S.iface.rx_mbps : null; }, function (S) { return S.iface ? S.iface.tx_mbps : null; },
      function (S) { return S.wan ? S.wan.rx_mbps : null; }, function (S) { return S.wan ? S.wan.tx_mbps : null; },
      function (S) { return upMbps ? S.t.map(function () { return upMbps; }) : null; }];
    charts.link = group.add(panel('ch-link', 'Link & modem (iface errors/drops, carrier, mcast; DOCSIS SNR/US power/uncorrectables; Wi-Fi RSSI)',
      [['errors', LL.cssVar('--bad')], ['drops', LL.cssVar('--warn')], ['carrier', LL.cssVar('--fg')], ['mcast pps', LL.cssVar('--fg-3')], ['DS SNR', LL.cssVar('--c-gw')], ['US pwr', LL.cssVar('--c-isp')], ['uncorr', LL.cssVar('--c-mid')], ['RSSI', LL.cssVar('--c-inet6')]]), {
      height: 150, yLabel: 'count / dB', series: [
        { label: 'errors', stroke: LL.cssVar('--bad'), width: 1.5, spanGaps: true }, { label: 'drops', stroke: LL.cssVar('--warn'), width: 1, spanGaps: true },
        { label: 'carrier', stroke: LL.cssVar('--fg'), width: 1, spanGaps: true }, { label: 'mcast pps', stroke: LL.cssVar('--fg-3'), width: 1, spanGaps: true },
        { label: 'DS SNR', stroke: LL.cssVar('--c-gw'), width: 1.5, spanGaps: true }, { label: 'US pwr', stroke: LL.cssVar('--c-isp'), width: 1.5, spanGaps: true },
        { label: 'uncorr', stroke: LL.cssVar('--c-mid'), width: 1.5, spanGaps: true, points: { show: true, size: 4 } }, { label: 'RSSI', stroke: LL.cssVar('--c-inet6'), width: 1, spanGaps: true }],
      yRange: function (u, min, max) { return [min == null ? 0 : Math.min(min, 0), max == null ? 1 : max * 1.05]; }
    });
    charts.link.pick = [function (S) { return S.iface ? S.iface.err : null; }, function (S) { return S.iface ? S.iface.drop : null; }, function (S) { return S.iface ? S.iface.carrier_changes : null; },
      function (S) { return S.iface ? S.iface.mcast_pps : null; }, function (S) { return S.docsis ? S.docsis.ds_snr_min : null; }, function (S) { return S.docsis ? S.docsis.us_pwr_max : null; },
      function (S) { return S.docsis ? S.docsis.uncorr_delta : null; }, function (S) { return S.wifi ? S.wifi.rssi : null; }];
    var ribbonEl = h('div', { class: 'ribbon', id: 'ribbon' });
    container.appendChild(h('div', { class: 'chart' }, h('div', { class: 'title' }, h('span', null, 'Events (click a block) · marks (dashed) · Xbox asleep / host stall shading')), ribbonEl));
    var ribbon = new LL.Ribbon(group, ribbonEl, { onEpisode: opts.onEpisode, onMark: opts.onMark });
    return { group: group, charts: charts, ribbon: ribbon, colors: colors, icmp: icmp, app: app, byId: byId,
      feed: function (S) {
        if (!S || !S.t) return;
        Object.keys(charts).forEach(function (k) { var c = charts[k]; if (c.pick) c.setData(LL.seriesData(S, c.pick)); });
        group.overlays.sleep = LL.spans(S.t, S.xbox_state, function (v) { return v === 'asleep'; });
        group.overlays.stall = LL.spans(S.t, S.stall, function (v) { return v === 1; });
        var late = [];
        icmp.forEach(function (t) {
          var l = tg(t.id, 'late')(S), p = tg(t.id, 'p50')(S);
          if (l) l.forEach(function (v, i) { if (v && p && p[i] != null) late.push([S.t[i], p[i]]); });
        });
        group.overlays.late = late;
        group.redraw();
      },
      setEpisodes: function (eps, selectedId) {
        group.overlays.episodes = eps.map(function (e) { var c = Object.assign({}, e); c.selected = e.id === selectedId; return c; });
        group.redraw();
      },
      setMarks: function (marks) { group.overlays.marks = marks.slice(); group.redraw(); }
    };
  }

  function chartTools(container, stack, opts) {
    opts = opts || {};
    var tools = h('div', { class: 'chart-tools' });
    var seg = h('div', { class: 'seg' });
    var rangeBtns = {};
    LL.RANGES.forEach(function (r) {
      var b = h('button', { type: 'button', onclick: function () { stack.group.setRange(r[0]); setOn(r[0]); if (opts.onRange) opts.onRange(r[0]); } }, r[1]);
      rangeBtns[String(r[0])] = b; seg.appendChild(b);
    });
    function setOn(v) { Object.keys(rangeBtns).forEach(function (k) { rangeBtns[k].classList.toggle('on', k === String(v)); }); }
    setOn(stack.group.range);
    var follow = h('button', { type: 'button', class: stack.group.follow ? 'on' : '', onclick: function () { stack.group.setFollow(!stack.group.follow); } }, 'Live');
    stack.group.onFollow = function (on) { follow.classList.toggle('on', on); if (!on) setOn('none'); else setOn(stack.group.range); if (opts.onFollow) opts.onFollow(on); };
    var logy = h('button', { type: 'button', onclick: function () { stack.group.setLogY(!stack.group.logY); logy.classList.toggle('on', stack.group.logY); } }, 'log-y');
    var raw = null;
    if (opts.rawToggle) raw = h('button', { type: 'button', onclick: function () { var on = !raw.classList.contains('on'); raw.classList.toggle('on', on); opts.rawToggle(on); } }, 'Raw');
    tools.appendChild(seg);
    tools.appendChild(h('div', { class: 'seg' }, follow));
    tools.appendChild(h('div', { class: 'seg' }, logy, raw));
    tools.appendChild(h('span', { class: 'hint' }, 'drag to zoom · double-click to reset'));
    container.appendChild(tools);
    return tools;
  }

  // Locus mini heatmap from episode.locus.cond ({"isp_hop4|inet4_cf": 0.91})
  function locusHeat(locus) {
    if (!locus || !locus.cond) return null;
    var keys = Object.keys(locus.cond);
    if (!keys.length) return null;
    var grid = h('div', { class: 'heat' });
    grid.style.gridTemplateColumns = 'repeat(' + Math.min(4, keys.length) + ', max-content)';
    keys.forEach(function (k) {
      var v = Number(locus.cond[k]) || 0;
      var c = h('div', { class: 'cell', title: k }, k.replace('|', ' | ') + ' ' + Math.round(v * 100) + '%');
      c.style.setProperty('--v', String(v));
      grid.appendChild(c);
    });
    return grid;
  }
  function sweepTable(sweep) {
    if (!sweep || !sweep.hops || !sweep.hops.length) return null;
    var tb = h('tbody');
    sweep.hops.forEach(function (hp) {
      var rtts = (hp.rtt || []).map(function (v) { return v == null ? '*' : fmt.num(v, 1); }).join(' / ');
      tb.appendChild(h('tr', null, h('td', null, String(hp.ttl)), h('td', { class: 'mono' }, hp.ip || '*'), h('td', null, rtts), h('td', { class: 'num' }, hp.loss == null ? '—' : fmt.pct(hp.loss, 0))));
    });
    return h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'ttl'), h('th', null, 'hop'), h('th', null, 'rtt ms'), h('th', { class: 'num' }, 'loss'))), tb));
  }
  function docsisPrePost(d) {
    if (!d) return null;
    var pre = d.pre_uncorr || {}, post = d.post_uncorr || {}, rows = [];
    Object.keys(post).forEach(function (ch) {
      var a = Number(pre[ch] || 0), b = Number(post[ch] || 0);
      if (b - a !== 0) rows.push('ch ' + ch + ': +' + (b - a) + ' uncorrectables');
    });
    var lines = (d.log_lines || []).slice(0, 6);
    if (!rows.length && !lines.length) return h('div', { class: 'muted' }, 'DOCSIS: no change around the episode');
    return h('div', null, rows.length ? h('div', null, rows.join(', ')) : null, lines.length ? h('div', { class: 'log-lines' }, lines.join('\n')) : null);
  }
  function evidenceCard(ep, marks, similar, extra) {
    var card = h('div', { class: 'panel evidence' });
    var head = (ep.evidence && ep.evidence.length) ? ep.evidence[0] : (fmt.cls(ep['class']) + ' for ' + fmt.durShort(ep.dur_s));
    card.appendChild(h('div', { class: 'head' }, fmt.clock(ep.t0) + ' — ' + fmt.cls(ep['class']) + (ep.subclass ? ' / ' + fmt.cls(ep.subclass) : ''), ' ',
      h('span', { class: 'conf ' + confClass(ep.confidence) }, fmt.conf(ep.confidence)), extra || null));
    card.appendChild(h('div', null, head));
    var ul = h('ul'); (ep.evidence || []).forEach(function (e) { ul.appendChild(h('li', null, e)); });
    card.appendChild(ul);
    var pairs = [];
    if (ep.alt && ep.alt['class']) pairs.push(['Rejected alternative', fmt.cls(ep.alt['class']) + (ep.alt.why_rejected ? ' — ' + ep.alt.why_rejected : '')]);
    if (ep.locus && ep.locus.shallowest) pairs.push(['Loss locus', 'shallowest target lost in step with deeper ones: ' + ep.locus.shallowest]);
    pairs.push(['Direction', ep.direction || 'n/a']);
    pairs.push(['Xbox', ep.xbox_state || 'unknown']);
    pairs.push(['Activity', LL.actLabel(ep.activity)]);
    if (ep.host_tags && ep.host_tags.length) pairs.push(['Host tags', ep.host_tags.join(', ') + ' (not Comcast-relevant)']);
    if (ep.onset_order && ep.onset_order.length) pairs.push(['Onset order', ep.onset_order.join(' → ')]);
    pairs.push(['Duration', fmt.durShort(ep.dur_s) + (ep.t1 == null ? ' (open)' : '')]);
    var linked = (ep.marks || []).map(function (id) { var m = marks.filter(function (x) { return x.id === id; })[0]; return m ? (id + ' ' + fmt.clock(m.t_est) + (m.note ? ' "' + m.note + '"' : '')) : id; });
    pairs.push(['Linked marks', linked.length ? linked.join('; ') : 'none']);
    if (similar != null) pairs.push(['Similar episodes', similar + ' other' + (similar === 1 ? '' : 's') + ' of this class']);
    card.appendChild(kv(pairs));
    var heat = locusHeat(ep.locus); if (heat) card.appendChild(h('div', null, h('h3', null, 'Co-loss heatmap'), heat));
    var sw = sweepTable(ep.sweep); if (sw) card.appendChild(h('div', null, h('h3', null, 'Sweep (mini-MTR)'), sw));
    var dp = docsisPrePost(ep.docsis); if (dp) card.appendChild(h('div', null, h('h3', null, 'DOCSIS pre/post'), dp));
    return card;
  }

  // A small raw ±window chart from rows [[ts_ms,id,kind,flags,value_us],...]
  function rawChart(container, rows, targets, colors, t0, t1) {
    var el = h('div', { class: 'chart' }, h('div', { class: 'title' }, h('span', null, 'Raw probes (filled = received, hollow = late, red tick = lost)')));
    var plot = h('div'); el.appendChild(plot); container.appendChild(el);
    var g = new LL.ChartGroup({ follow: false });
    g.overlays.raw = { rows: rows, colors: colors };
    g.overlays.episodes = [{ t0: t0, t1: t1 }];
    var c = g.add(plot, { height: 180, raw: true, yLabel: 'ms', series: [{ label: 'ref', stroke: 'rgba(0,0,0,0)', width: 0 }], opts: { cursor: { sync: { key: 'raw-' + Math.random() }, drag: { x: true, setScale: true } } } });
    var tmin = Infinity, tmax = -Infinity, vmax = 1;
    rows.forEach(function (r) { var t = r[0] / 1000; if (t < tmin) tmin = t; if (t > tmax) tmax = t; if (r[4] > 0 && !(r[3] & 5)) vmax = Math.max(vmax, r[4] / 1000); });
    if (!isFinite(tmin)) { tmin = t0 - 90; tmax = t1 + 90; }
    c.setData([[tmin, tmax], [vmax * 1.1, vmax * 1.1]]);
    g.setX(tmin, tmax, false);
    return g;
  }

  // =====================================================================================
  // LIVE DASHBOARD
  // =====================================================================================
  function Dashboard() {
    this.state = null;
    this.targets = [];
    this.targetSig = '';
    this.stack = null;
    this.S = null;              // current /api/series body
    this.episodes = {};         // id -> episode (brief)
    this.marks = [];
    this.selected = null;       // selected episode id
    this.online = true;
    this.lastData = null;
    this.rawOn = false;
    this.loading = false;
    this.cards = {};
    this.stopped = false;
  }
  var D = Dashboard.prototype;

  D.boot = function () {
    var self = this;
    this.bindButtons();
    LL.api.get('/api/state').then(function (st) {
      self.applyState(st, true);
      self.lastData = st.now;
      return Promise.all([LL.api.get('/api/episodes?limit=200').catch(function () { return { episodes: [] }; }), LL.api.get('/api/marks').catch(function () { return { marks: [] }; })]);
    }).then(function (res) {
      (res[0].episodes || []).forEach(function (e) { self.episodes[e.id] = e; });
      self.marks = res[1].marks || [];
      self.renderEpisodes();
      self.stack.setEpisodes(self.episodeList(), null);
      self.stack.setMarks(self.marks);
      self.loadSeriesForRange();
      self.setOnline(true);
    }).catch(function (err) {
      self.setOnline(false, err);
    });
    this.sse = LL.sse.connect({
      onEvent: function (name, data) { self.onEvent(name, data); },
      onStatus: function (s) { self.setOnline(s === 'live' || s === 'polling'); if (s === 'live') self.resync(); },
      onPoll: function (st) { self.applyState(st); self.lastData = st.now; }
    });
    setInterval(function () { self.tickClock(); }, 1000);
    setInterval(function () { if (self.online && !self.stopped) self.refreshTail(); }, 5000);
    setInterval(function () { if (self.online && !self.stopped && self.plexOn) self.loadPlex(); }, 5000);
    setInterval(function () { if (self.online && !self.stopped) LL.api.get('/api/state').then(function (st) { self.applyState(st); }).catch(function () { /* SSE/polling handle it */ }); }, 30000);
    doc.addEventListener('keydown', function (ev) {
      if ((ev.key === 'l' || ev.key === 'L') && !ev.metaKey && !ev.ctrlKey && !ev.altKey) {
        var tag = (ev.target && ev.target.tagName) || '';
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        ev.preventDefault(); self.lagPressed();
      }
    });
  };

  D.bindButtons = function () {
    var self = this;
    $('btn-lag').addEventListener('click', function () { self.lagPressed(); });
    $('activity-sel').addEventListener('change', function (ev) { self.setActivity(ev.target.value); });
    $('btn-loadtest').addEventListener('click', function () { self.loadtest(); });
    $('btn-stop').addEventListener('click', function () { self.stop(); });
    $('btn-copy-comcast').addEventListener('click', function () { LL.api.text('/api/comcast.txt').then(LL.copy).catch(function () { LL.copy((self.state && self.state.verdict && self.state.verdict.comcast) || ''); }); });
    $('btn-rediscover').addEventListener('click', function () { LL.api.post('/api/path/rediscover').then(function (r) { LL.toast(r.running ? 'Path discovery already running' : 'Rediscovering the path…', 'ok'); }).catch(function (e) { LL.toast(e.message, 'bad'); }); });
    $('btn-doctor').addEventListener('click', function () { LL.api.post('/api/doctor/run').then(function (r) { self.renderDoctor(r.checks || []); LL.toast('Doctor re-ran', 'ok'); }).catch(function (e) { LL.toast(e.message, 'bad'); }); });
    $('btn-docsis').addEventListener('click', function () { LL.api.post('/api/docsis/refresh').then(function () { LL.toast('Modem refresh requested', 'ok'); self.loadDocsis(); }).catch(function (e) { LL.toast(e.message, 'bad'); }); });
    $('ep-class').addEventListener('change', function () { self.renderEpisodes(); });
    $('ep-conf').addEventListener('change', function () { self.renderEpisodes(); });
    $('btn-label').addEventListener('click', function () {
      var cur = (self.state && self.state.session && self.state.session.label) || '';
      var v = root.prompt('Experiment label for this session', cur);
      if (v == null) return;
      LL.api.post('/api/session/label', { label: v }).then(function () { LL.toast('Label saved', 'ok'); }).catch(function (e) { LL.toast(e.message, 'bad'); });
    });
  };

  D.setOnline = function (on, err) {
    var was = this.online;
    this.online = !!on;
    var banner = $('banner');
    if (!on) {
      $('pill').className = 'pill UNREACHABLE'; $('pill').textContent = 'UNREACHABLE';
      banner.textContent = 'Lag Lens is not reachable — last data ' + (this.lastData ? fmt.clock(this.lastData) : 'never') + '. Presses are saved locally and sent when it is back.';
      banner.classList.remove('hidden');
      $('btn-lag').textContent = 'Lag happened (will send when reconnected)';
    } else {
      banner.classList.add('hidden');
      $('btn-lag').textContent = 'Lag happened  (L)';
      if (this.state) this.paintPill(this.state.state, this.state.pill);
      if (!was) this.flushQueue();
    }
  };
  D.flushQueue = function () {
    var self = this;
    if (!LL.queue.size()) return;
    LL.queue.flush().then(function (n) { if (n) { LL.toast('Sent ' + n + ' queued press' + (n > 1 ? 'es' : ''), 'ok'); self.refreshMarks(); } });
  };
  D.resync = function () {
    var self = this;
    LL.api.get('/api/state').then(function (st) { self.applyState(st); self.refreshMarks(); self.refreshEpisodes(); self.loadSeriesForRange(); }).catch(function () { /* handled by status */ });
  };
  D.refreshMarks = function () { var self = this; LL.api.get('/api/marks').then(function (r) { self.marks = r.marks || []; self.stack.setMarks(self.marks); }).catch(function () { /* ignore */ }); };
  D.refreshEpisodes = function () { var self = this; LL.api.get('/api/episodes?limit=200').then(function (r) { (r.episodes || []).forEach(function (e) { self.episodes[e.id] = e; }); self.renderEpisodes(); self.stack.setEpisodes(self.episodeList(), self.selected); }).catch(function () { /* ignore */ }); };

  D.paintPill = function (state, text) {
    var p = $('pill');
    p.className = 'pill ' + (state || 'STARTING');
    p.textContent = text || state || '';
  };
  D.tickClock = function () {
    if (!this.state || !this.state.session) return;
    var started = this.state.session.started;
    if (started && this.online && !this.stopped) $('elapsed').textContent = fmt.dur(Date.now() / 1000 - started);
    if (this.stack && this.stack.group.follow && this.online && !this.stopped) this.stack.group.followNow();
  };

  D.applyState = function (st, first) {
    var self = this;
    this.state = st;
    this.paintPill(st.state, st.pill);
    var health = (st.health && st.health.now != null) ? st.health.now : null;
    var dial = $('dial');
    dial.style.setProperty('--pct', String(health == null ? 0 : health));
    dial.className = 'dial ' + (health == null ? '' : (health >= 80 ? '' : (health >= 50 ? 'warn' : 'bad')));
    $('dial-v').textContent = health == null ? '—' : String(Math.round(health));
    dial.title = 'Health now ' + (health == null ? '—' : health) + ' · session ' + ((st.health && st.health.session != null) ? st.health.session : '—');
    if (st.headline) {
      var hl = $('headline');
      LL.clear(hl);
      hl.appendChild(doc.createTextNode('Is it my network? '));
      hl.appendChild(h('b', null, st.headline.text || 'Can’t tell yet'));
      if (st.headline.action) hl.appendChild(h('span', { class: 'action' }, st.headline.action));
    }
    // URLs + QR of the PHONE url
    var lan = st.host && st.host.lan_ip;
    var port = root.location.port || '8787';
    var base = 'http://' + (lan || root.location.hostname) + ':' + port;
    $('url-text').textContent = base + '  ·  phone: ' + base + '/phone';
    if (first || this._qrFor !== base) { this._qrFor = base; try { if (root.LagLensQR) root.LagLensQR.render($('qr'), base + '/phone', 2); } catch (e) { /* ignore */ } }
    // activity selector
    var sel = $('activity-sel'), acts = (st.activities || (st.config && st.config.activities)) || LL.activities;
    if (sel.options.length !== acts.length) { LL.clear(sel); acts.forEach(function (a) { sel.appendChild(h('option', { value: a }, 'Now: ' + LL.actLabel(a))); }); }
    if (st.activity && st.activity.current) sel.value = st.activity.current;
    // targets + cards + charts
    var targets = st.targets || [];
    var sig = targets.map(function (t) { return t.id + ':' + t.key + ':' + t.kind; }).join(',');
    if (sig !== this.targetSig) { this.targetSig = sig; this.targets = targets; this.buildCharts(); }
    this.renderCards(targets, st);
    this.renderCollectors(st.collectors || {});
    this.renderDoctor(st.doctor || []);
    this.renderPath(st.path || {});
    this.renderVerdict(st.verdict || {});
    this.renderLoadtest(st.loadtest || {});
    this.renderUpdate(st.update || {});
    this.renderDisk(st.disk || {});
    this.renderXbox(st.xbox || {});
    (st.episodes_recent || []).forEach(function (e) { self.episodes[e.id] = e; });
    if (st.marks_recent) { var ids = {}; this.marks.forEach(function (m) { ids[m.id] = 1; }); st.marks_recent.forEach(function (m) { if (!ids[m.id]) self.marks.push(m); }); }
    this.renderEpisodes();
    if (this.stack) { this.stack.setEpisodes(this.episodeList(), this.selected); this.stack.setMarks(this.marks); }
    if (st.state === 'STOPPED') this.markStopped();
    if (first) { this.loadDocsis(); this.loadIgd(); }
    var plexCol = (st.collectors || {}).plex;
    this.plexOn = !!(plexCol && plexCol.status !== 'disabled');
    var pp = $('plex-panel'); if (pp) pp.hidden = !this.plexOn;
    if (first && this.plexOn) this.loadPlex();
    $('a-report').href = '/report.html';
    $('a-export').href = '/export.zip?pack=full&raw=1';
  };

  D.buildCharts = function () {
    var self = this;
    if (this.stack) { this.stack.group.destroy(); LL._groups = LL._groups.filter(function (g) { return g !== self.stack.group; }); }
    var tools = $('chart-tools'); LL.clear(tools);
    var container = $('charts'); LL.clear(container);
    var linkUp = this.state && this.state.host ? this.state.host.link_up_mbps : null;
    this.stack = buildStack(container, this.targets, {
      range: this.stack ? this.stack.group.range : 600, sessionStart: this.state && this.state.session ? this.state.session.started : null, linkUp: linkUp,
      onZoom: function (min, max, byUser) { if (byUser) self.onZoom(min, max); },
      onEpisode: function (ep) { self.selectEpisode(ep.id); },
      onMark: function (m) { self.zoomTo(m.t_est - 60, m.t_est + 60, m.id); }
    });
    chartTools(tools, this.stack, { onRange: function () { self.selected = null; self.closeEvidence(); self.loadSeriesForRange(); }, rawToggle: function (on) { self.rawOn = on; if (on) self.loadRaw(self.stack.group.xmin, self.stack.group.xmax); else { self.stack.group.overlays.raw = null; self.stack.group.redraw(); } } });
    this.stack.group.followNow();
    if (this.S) this.stack.feed(this.S);
  };

  D.renderCards = function (targets, st) {
    var self = this, wrap = $('cards');
    var openTargets = {};
    (st.episodes_open || []).forEach(function (id) { var e = self.episodes[id]; if (e) (e.targets || []).forEach(function (t) { openTargets[t] = e['class']; }); });
    var order = sortTargets(targets);
    var byKey = {}; targets.forEach(function (t) { byKey[t.key] = t; });
    order.forEach(function (t) {
      var card = self.cards[t.id];
      if (!card) {
        card = h('div', { class: 'card', onclick: function () { self.toggleTarget(t); } },
          h('div', { class: 'name' }, h('span', { class: 'lbl' }), h('small', { class: 'addr' })),
          h('div', { class: 'big' }), h('div', { class: 'stats' }), h('div', { class: 'reason' }), h('canvas', { class: 'spark' }));
        self.cards[t.id] = card; wrap.appendChild(card);
      }
      card.style.setProperty('--swatch', LL.roleColor(t));
      card.querySelector('.lbl').textContent = targetLabel(t);
      card.querySelector('.addr').textContent = (t.addr || 'unresolved') + (t.backend === 'pingbin' ? ' (ping)' : '');
      var last = t.last && t.last.rtt != null ? t.last.rtt : null, w = t.w5m || {};
      var big = card.querySelector('.big'); LL.clear(big);
      big.appendChild(doc.createTextNode(last == null ? '—' : fmt.num(last, last >= 100 ? 0 : 1)));
      big.appendChild(h('small', null, ' ms'));
      var statsEl = card.querySelector('.stats'); LL.clear(statsEl);
      statsEl.appendChild(h('span', null, 'p95 ', h('b', null, fmt.num(w.p95))));
      statsEl.appendChild(h('span', { class: (w.loss_pct || 0) > 1 ? 'bad' : '' }, 'loss ', h('b', null, fmt.pct(w.loss_pct))));
      statsEl.appendChild(h('span', null, 'late ', h('b', null, fmt.pct(w.late_pct))));
      if (t.family === 6) {
        var v4 = byKey[t.key.replace('6', '4')];
        if (v4 && v4.w5m && v4.w5m.p50 != null && w.p50 != null) statsEl.appendChild(h('span', null, 'v6−v4 ', h('b', null, fmt.num(w.p50 - v4.w5m.p50, 1) + ' ms')));
      }
      card.querySelector('.reason').textContent = t.enabled ? '' : (t.reason || 'disabled');
      card.classList.toggle('off', !t.enabled || !!(self.hiddenTargets && self.hiddenTargets[t.id]));  // always a boolean: toggle() with undefined flips the class every tick
      card.classList.toggle('event', !!openTargets[t.id]);
      var where = targetLabel(t) + ' · ' + (t.addr || 'unresolved');
      card.title = where + '\n' + (openTargets[t.id] ? 'Open episode: ' + fmt.cls(openTargets[t.id]) : 'Click to toggle this target on the charts');
      LL.sparkline(card.querySelector('canvas'), t.spark || [], LL.roleColor(t));
    });
  };
  D.toggleTarget = function (t) {
    this.hiddenTargets = this.hiddenTargets || {};
    this.hiddenTargets[t.id] = !this.hiddenTargets[t.id];
    var show = !this.hiddenTargets[t.id], label = isIcmp(t) ? targetLabel(t) : (t.label || t.key);
    Object.keys(this.stack.charts).forEach(function (k) { this.stack.charts[k].toggle(label, show); }, this);
    if (this.cards[t.id]) this.cards[t.id].classList.toggle('off', !show || !t.enabled);
  };

  D.renderCollectors = function (cols) {
    var wrap = $('collectors'); LL.clear(wrap);
    Object.keys(cols).sort().forEach(function (name) {
      var c = cols[name] || {};
      var chip = h('span', { class: 'chip ' + (c.status || ''), title: c.reason || '' }, name, c.reason ? h('span', { class: 'why' }, ' ' + c.reason) : null);
      wrap.appendChild(chip);
    });
  };
  D.renderDoctor = function (checks) {
    var wrap = $('doctor'); LL.clear(wrap);
    if (!checks.length) { wrap.appendChild(h('div', { class: 'muted' }, 'not run yet')); return; }
    var tb = h('tbody');
    checks.forEach(function (c) { tb.appendChild(h('tr', null, h('td', { class: c.status }, c.status), h('td', null, c.check), h('td', { class: 'small' }, (c.detail || '') + (c.fallback ? ' → ' + c.fallback : '')))); });
    wrap.appendChild(h('div', { class: 'table-wrap doctor' }, h('table', null, tb)));
  };
  D.renderPath = function (path) {
    var wrap = $('path-ladder'); LL.clear(wrap);
    var self = this;
    var byAddr = {}; (this.targets || []).forEach(function (t) { if (t.addr) byAddr[t.addr] = t; });
    [['v4', path.v4], ['v6', path.v6]].forEach(function (fam) {
      var hops = fam[1] || [];
      if (!hops.length) return;
      wrap.appendChild(h('div', { class: 'small muted' }, 'IPv' + fam[0].slice(1) + (path.discovered_at ? ' · discovered ' + fmt.clock(path.discovered_at) : '') + (path.changes ? ' · ' + path.changes + ' route change' + (path.changes > 1 ? 's' : '') : '')));
      hops.forEach(function (hp) {
        var t = hp.ip ? byAddr[hp.ip] : null, w = t && t.w5m || {};
        var probed = t && t.enabled;
        wrap.appendChild(h('div', { class: 'hop ' + (probed ? 'probed' : 'silent'), title: probed ? 'probed continuously' : 'listed only (does not answer direct echo)' },
          h('span', { class: 'ttl' }, String(hp.ttl)),
          h('span', { class: 'ip' }, (hp.ip || '*') + (hp.rdns ? ' ' + hp.rdns : ''), h('div', { class: 'role' }, hp.role || '')),
          h('span', { class: 'num' }, probed ? fmt.ms(t.last && t.last.rtt, 1) : '—'),
          h('span', { class: 'num ' + ((w.loss_pct || 0) > 1 ? 'bad' : '') }, probed ? fmt.pct(w.loss_pct) : '')));
      });
    });
    if (!wrap.childNodes.length) wrap.appendChild(h('div', { class: 'muted' }, 'path not discovered yet'));
  };
  D.renderVerdict = function (v) {
    var box = $('verdict-text');
    box.textContent = v.text || 'Verdict forms after warm-up and the first few minutes of data.';
    var top = $('verdict-top'); LL.clear(top);
    (v.top || []).forEach(function (t) { top.appendChild(h('div', null, h('b', null, fmt.cls(t['class'])), ' ' + Math.round((t.share || 0) * 100) + '% · ' + (t.episodes || 0) + ' episodes · ' + fmt.dur(t.seconds || 0))); });
    if (v.marks && v.marks.total) top.appendChild(h('div', { class: 'small muted' }, v.marks.linked + ' of ' + v.marks.total + ' presses line up with episodes'));
    (v.next || []).slice(0, 3).forEach(function (n) { top.appendChild(h('div', { class: 'small' }, h('b', null, 'Try: '), n.try || '', n.confirm_if ? h('span', { class: 'muted' }, ' — confirmed if ' + n.confirm_if) : null)); });
    $('btn-copy-comcast').disabled = !(v.comcast || (v.top && v.top.length));
  };
  D.renderLoadtest = function (lt) {
    var b = $('btn-loadtest');
    b.textContent = lt.running ? ('Load test: ' + (lt.phase || 'running') + ' — stop') : 'Load test';
    b.classList.toggle('on', !!lt.running);
    if (lt.last && lt.last.grade && !lt.running) b.title = 'Last grade ' + lt.last.grade;
    else if (lt.last && ltFailed(lt.last) && !lt.running) b.title = 'Last load test failed (' + ltFailed(lt.last) + ')';
  };
  D.renderUpdate = function (u) {
    var chip = $('update-chip');
    if (u && u.available) { chip.textContent = 'Update ' + (u.latest || '') + ' — bash start.sh --update'; chip.classList.remove('hidden'); } else chip.classList.add('hidden');
  };
  D.renderDisk = function (d) {
    var b = $('disk-banner');
    if (d && d.writing === false) { b.textContent = 'Disk: writing stopped' + (d.reason ? ' — ' + d.reason : '') + (d.free_mb != null ? ' (free ' + Math.round(d.free_mb) + ' MB)' : ''); b.classList.remove('hidden'); } else b.classList.add('hidden');
  };
  D.renderXbox = function (x) {
    var el = $('xbox-line');
    if (!el) return;
    el.textContent = x.ip ? ('Xbox ' + x.ip + ' · ' + (x.state || 'unknown') + (x.link_mbps ? ' · ' + x.link_mbps + ' Mb/s' : '')) : 'Xbox: not found (set it on /setup)';
  };
  D.loadDocsis = function () {
    var wrap = $('xb7'); if (!wrap) return;
    var col = (this.state && this.state.collectors && this.state.collectors.docsis) || null;
    if (col && col.status === 'disabled') {  // do not poll a collector that is off (it only answers 503)
      LL.clear(wrap); wrap.appendChild(h('div', { class: 'muted' }, 'modem data not collected' + (col.reason ? ' (' + col.reason + ')' : ''))); return;
    }
    LL.api.get('/api/docsis?last=20').then(function (d) {
      LL.clear(wrap);
      var polls = d.polls || [], last = polls.length ? polls[polls.length - 1] : null;
      if (!last) { wrap.appendChild(h('div', { class: 'muted' }, 'no modem poll yet')); return; }
      var ds = last.ds || [], us = last.us || [];
      var snr = ds.map(function (c) { return c.snr_db; }).filter(function (v) { return v != null; }), usp = us.map(function (c) { return c.pwr_dbmv; }).filter(function (v) { return v != null; });
      var unc = ds.reduce(function (a, c) { return a + (c.uncorr || 0); }, 0);
      wrap.appendChild(kv([['Uptime', last.uptime_s != null ? fmt.dur(last.uptime_s) : null], ['Firmware', last.fw], ['DS channels', ds.length ? ds.length + ' · SNR min ' + fmt.num(Math.min.apply(null, snr), 1) + ' dB' : null],
        ['US channels', us.length ? us.length + ' · power max ' + fmt.num(Math.max.apply(null, usp), 1) + ' dBmV' : null], ['Uncorrectables', String(unc)], ['Flags', (last.flags || []).join(', ') || 'none'],
        ['Log clock offset', last.log_clock_offset_s != null ? last.log_clock_offset_s + ' s' : null]]));
      var lines = (d.log || []).slice(-20).map(function (l) { return (l.ts || '') + ' ' + (l.class ? '[' + l.class + '] ' : '') + (l.text || ''); });
      if (lines.length) wrap.appendChild(h('div', { class: 'log-lines' }, lines.join('\n')));
    }).catch(function (e) { LL.clear(wrap); wrap.appendChild(h('div', { class: 'muted' }, e.message || 'modem data not available')); });
  };
  D.loadIgd = function () {
    var wrap = $('igd'); if (!wrap) return;
    LL.api.get('/api/igd').then(function (d) {
      LL.clear(wrap);
      wrap.appendChild(kv([['Status', d.status + (d.trusted === false ? ' (counters not trusted)' : (d.trusted === true ? ' (counters verified)' : ' (counters not verified yet)'))], ['Counter check', d.verification ? (d.verification.method + ': counted ' + Math.round(d.verification.ratio * 100) + '% of ' + (d.verification.bytes / 1e6).toFixed(1) + ' MB') : null], ['WAN uptime', d.uptime_s != null ? fmt.dur(d.uptime_s) : null], ['External IP', d.ext_ip],
        ['WAN rx/tx', (d.rx_pegged ? 'n/a (counter clamped by firmware)' : (d.rx_mbps != null ? fmt.mbps(d.rx_mbps) : '—')) + ' / ' + (d.tx_pegged ? 'n/a' : (d.tx_mbps != null ? fmt.mbps(d.tx_mbps) : '—'))],
        ['Mappings', (d.mappings || []).length ? d.mappings.map(function (m) { return m.proto + ' ' + m.ext + '→' + m.int + (m.desc ? ' (' + m.desc + ')' : ''); }).join('; ') : 'none']]));
    }).catch(function (e) { LL.clear(wrap); wrap.appendChild(h('div', { class: 'muted' }, e.message || 'IGD not available')); });
  };

  D.loadPlex = function () {
    var wrap = $('plex'); if (!wrap) return;
    LL.api.get('/api/plex').then(function (p) {
      LL.clear(wrap);
      var srv = p.server && typeof p.server === 'object' ? p.server : null;
      var cnt = p.counts || {}, res = p.resources || {};
      wrap.appendChild(kv([
        ['Server', srv ? (srv.name || srv.ip) + ' ' + srv.ip + ':' + (srv.port || 32400) + (p.reachable === false ? ' — not answering' : '') : (p.reason || 'looking…')],
        ['Status', p.token_set ? (p.token_rejected ? 'token rejected (Setup)' : 'reading server status') : 'no token: probes only (add it in Setup)'],
        ['Server CPU', res.host_cpu != null ? Math.round(res.host_cpu) + '% host · ' + Math.round(res.plex_cpu || 0) + '% Plex' : null],
        ['Tasks', (p.activities || []).length ? p.activities.map(function (a) { return a.title + (a.progress != null ? ' ' + Math.round(a.progress) + '%' : ''); }).join('; ') : (p.token_set ? 'none' : null)],
        ['Players', (p.players || []).length ? p.players.map(function (x) { return (x.name ? x.name + ' ' : '') + x.ip + (x.pingable === false ? ' (no ping)' : x.asleep ? ' (asleep)' : ''); }).join(' · ') : 'none yet'],
        ['Seen', 'buffering ' + (cnt.buffering || 0) + ' · slow transcode ' + (cnt.transcode_slow || 0) + ' · CPU high ' + (cnt.cpu_high || 0) + ' · server offline ' + (cnt.offline || 0)]]));
      var ss = p.sessions || [];
      if (ss.length) {
        var tb = h('tbody');
        ss.forEach(function (s) {
          var tc = s.transcode || {};
          var dec = (s.decision || '—') + (s.decision !== 'direct play' && tc.speed != null ? ' ' + tc.speed.toFixed(1) + '×' + (tc.throttled ? ' (ahead)' : '') : '');
          tb.appendChild(h('tr', { class: s.state === 'buffering' || (tc.speed != null && tc.speed < 1 && !tc.throttled) ? 'bad' : '' },
            h('td', null, s.title), h('td', null, (s.player || '?') + (s.address ? ' ' + s.address : '')), h('td', null, s.state),
            h('td', null, dec), h('td', { class: 'num' }, s.bitrate_kbps != null ? (s.bitrate_kbps / 1000).toFixed(1) + ' Mb/s' : '—'),
            h('td', null, s.location === 'wan' || s.relayed ? 'remote' : 'local')));
        });
        wrap.appendChild(h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null,
          ['title', 'player', 'state', 'decision', 'bitrate', 'path'].map(function (x) { return h('th', null, x); }))), tb)));
      } else if (p.token_set) {
        wrap.appendChild(h('div', { class: 'small muted' }, 'Nothing playing.'));
      }
    }).catch(function (e) { LL.clear(wrap); wrap.appendChild(h('div', { class: 'muted' }, e.message || 'Plex not available')); });
  };

  D.episodeList = function () { var self = this; return Object.keys(this.episodes).map(function (k) { return self.episodes[k]; }).sort(function (a, b) { return a.t0 - b.t0; }); };
  D.renderEpisodes = function () {
    var self = this, tb = $('episodes-body'); LL.clear(tb);
    var cls = $('ep-class').value, conf = Number($('ep-conf').value || 0);
    var list = this.episodeList().reverse().filter(function (e) { return (!cls || e['class'] === cls) && ((e.confidence || 0) >= conf); });
    var clsSel = $('ep-class');
    if (clsSel.options.length <= 1) { CLASS_LIST.forEach(function (c) { clsSel.appendChild(h('option', { value: c }, fmt.cls(c))); }); }
    list.slice(0, 100).forEach(function (e) {
      var tr = h('tr', { class: (e.t1 == null ? 'open ' : '') + (e.id === self.selected ? 'sel' : ''), onclick: function () { self.selectEpisode(e.id); } },
        h('td', null, fmt.clock(e.t0)), h('td', { class: 'num' }, e.t1 == null ? 'open' : fmt.durShort(e.dur_s)),
        h('td', { class: 'cls' }, fmt.cls(e['class'])), h('td', null, h('span', { class: 'conf ' + confClass(e.confidence) }, fmt.conf(e.confidence))));
      tb.appendChild(tr);
    });
    if (!list.length) tb.appendChild(h('tr', null, h('td', { colspan: 4, class: 'muted' }, 'no episodes' + (cls || conf ? ' match the filter' : ' yet'))));
    $('ep-count').textContent = String(this.episodeList().length);
  };

  D.selectEpisode = function (id) {
    var self = this, ep = this.episodes[id];
    if (!ep) return;
    this.selected = id;
    this.renderEpisodes();
    var t1 = ep.t1 == null ? Date.now() / 1000 : ep.t1;
    this.zoomTo(ep.t0 - 60, t1 + 60, id);
    LL.api.get('/api/episodes/' + encodeURIComponent(id)).then(function (full) {
      self.episodes[id] = Object.assign({}, self.episodes[id], full);
      self.showEvidence(full);
    }).catch(function () { self.showEvidence(ep); });
  };
  D.showEvidence = function (ep) {
    var self = this, wrap = $('evidence'); LL.clear(wrap);
    var similar = this.episodeList().filter(function (e) { return e.id !== ep.id && e['class'] === ep['class']; }).length;
    var closeBtn = h('button', { type: 'button', class: 'small close-x', onclick: function () { self.closeEvidence(); } }, '✕');
    wrap.appendChild(evidenceCard(ep, this.marks, similar, closeBtn));
    wrap.classList.remove('hidden');
  };
  D.closeEvidence = function () { $('evidence').classList.add('hidden'); this.selected = null; this.renderEpisodes(); if (this.stack) { this.stack.setEpisodes(this.episodeList(), null); this.stack.group.overlays.raw = null; this.stack.group.redraw(); } };
  D.zoomTo = function (a, b, id) {
    this.stack.group.setX(a, b, true);
    this.stack.setEpisodes(this.episodeList(), id);
    this.onZoom(a, b, true);
  };
  D.onZoom = function (min, max, fromEpisode) {
    var span = max - min, res = LL.resFor(span);
    if (!this.S || res !== this.S.res || min < this.S.from - 1 || max > this.S.to + 1) this.loadSeries(min, max, res);
    if ((fromEpisode || this.rawOn) && span <= 600) this.loadRaw(min, max); else if (!this.rawOn) { this.stack.group.overlays.raw = null; this.stack.group.redraw(); }
  };
  D.loadRaw = function (a, b) {
    var self = this;
    if (b - a > 600) { LL.toast('Raw samples are limited to 10 min windows', 'bad', 3000); return; }
    LL.api.get('/api/samples?from=' + a + '&to=' + b).then(function (r) {
      self.stack.group.overlays.raw = { rows: r.rows || [], colors: self.stack.colors };
      self.stack.group.redraw();
      if (r.truncated) LL.toast('Raw overlay truncated to 50 000 rows', 'bad', 3000);
    }).catch(function () { /* ignore */ });
  };
  D.loadSeriesForRange = function () {
    var now = Date.now() / 1000, g = this.stack.group;
    var from = g.range ? now - g.range : ((this.state && this.state.session && this.state.session.started) || now - 3600);
    this.loadSeries(from, now, LL.resFor(now - from));
  };
  D.loadSeries = function (from, to, res) {
    var self = this;
    if (this.loading) { this._pending = [from, to, res]; return; }
    this.loading = true;
    LL.api.get('/api/series?from=' + from + '&to=' + to + '&res=' + res).then(function (S) {
      self.S = S; self.stack.feed(S); self.lastData = Date.now() / 1000;
    }).catch(function (e) { if (e.status === 400) LL.toast(e.message, 'bad', 3000); })
      .then(function () { self.loading = false; if (self._pending) { var p = self._pending; self._pending = null; self.loadSeries(p[0], p[1], p[2]); } });
  };
  D.refreshTail = function () {
    var self = this;
    if (!this.S || !this.stack.group.follow || this.loading) return;
    var now = Date.now() / 1000, g = this.stack.group, res = this.S.res;
    var lastT = this.S.t.length ? this.S.t[this.S.t.length - 1] : now - 60;
    var from = Math.max(lastT - 30, now - 7200);
    LL.api.get('/api/series?from=' + from + '&to=' + now + '&res=' + res).then(function (chunk) {
      var keepFrom = g.range ? now - g.range - 60 : null;
      self.S = LL.mergeSeries(self.S, chunk, keepFrom);
      self.stack.feed(self.S); self.lastData = now;
    }).catch(function () { /* status handled by SSE */ });
  };

  D.onEvent = function (name, data) {
    var self = this;
    this.lastData = Date.now() / 1000;
    switch (name) {
      case 'tick':
        if (!this.state) return;
        this.state.state = data.state; this.state.pill = data.pill; this.state.headline = data.headline || this.state.headline;
        if (!this.stopped) this.paintPill(data.state, data.pill);
        if (data.health != null) { this.state.health = Object.assign({}, this.state.health, { now: data.health }); }
        if (data.headline) { var hl = $('headline'); LL.clear(hl); hl.appendChild(doc.createTextNode('Is it my network? ')); hl.appendChild(h('b', null, data.headline.text || '')); if (data.headline.action) hl.appendChild(h('span', { class: 'action' }, data.headline.action)); }
        if (data.health != null) { var dial = $('dial'); dial.style.setProperty('--pct', String(data.health)); $('dial-v').textContent = String(Math.round(data.health)); dial.className = 'dial ' + (data.health >= 80 ? '' : (data.health >= 50 ? 'warn' : 'bad')); }
        (this.state.targets || []).forEach(function (t) {
          var row = data.targets && data.targets[String(t.id)];
          if (!row) return;
          t.last = { rtt: row.rtt, t: data.t };
          t.w5m = Object.assign({}, t.w5m || {}, { p95: row.p95_5m, loss_pct: row.loss_5m });
          if (t.spark) { t.spark.push(row.rtt); if (t.spark.length > 60) t.spark.shift(); }
        });
        this.state.xbox = Object.assign({}, this.state.xbox, { state: data.xbox });
        this.renderCards(this.state.targets || [], this.state);
        break;
      case 'episode_open': case 'episode_update': case 'episode_close':
        this.episodes[data.id] = Object.assign({}, this.episodes[data.id] || {}, data);
        this.renderEpisodes(); this.stack.setEpisodes(this.episodeList(), this.selected);
        if (name === 'episode_open') LL.toast('Episode opened: ' + fmt.cls(data['class']) + ' at ' + fmt.clock(data.t0), 'bad', 5000);
        if (this.selected === data.id && name === 'episode_close') this.showEvidence(this.episodes[data.id]);
        this.renderCards(this.state.targets || [], this.state);
        break;
      case 'mark':
        if (!this.marks.some(function (m) { return m.id === data.id; })) this.marks.push(data); else this.marks = this.marks.map(function (m) { return m.id === data.id ? data : m; });
        this.stack.setMarks(this.marks);
        break;
      case 'activity':
        if (this.state) this.state.activity = data;
        $('activity-sel').value = data.activity || data.current || 'idle';
        break;
      case 'collector':
        if (this.state) { this.state.collectors = this.state.collectors || {}; this.state.collectors[data.name] = data; this.renderCollectors(this.state.collectors); }
        break;
      case 'loadtest':
        if (this.state) { this.state.loadtest = Object.assign({}, this.state.loadtest, { running: data.phase != null && data.phase !== 'done', phase: data.phase }); this.renderLoadtest(this.state.loadtest); }
        if (data.phase === 'done' || data.phase == null) LL.api.get('/api/loadtest').then(function (lt) { self.renderLoadtest(lt); if (lt.last && lt.last.grade) LL.toast('Load test grade ' + lt.last.grade + ' — added up ' + fmt.num(lt.last.added_ms && lt.last.added_ms.up, 0) + ' ms', 'ok', 8000); else if (lt.last && ltFailed(lt.last)) LL.toast('Load test: no grade — ' + ltFailed(lt.last), 'bad', 9000); }).catch(function () { /* ignore */ });
        break;
      case 'verdict':
        if (this.state) this.state.verdict = data;
        this.renderVerdict(data || {});
        break;
      case 'docsis':
        this.loadDocsis();
        break;
      case 'stopping':
        this.markStopped();
        break;
      default:
        break;
    }
  };
  D.markStopped = function () {
    this.stopped = true;
    this.paintPill('STOPPED', 'Stopped — open report');
    var b = $('banner'); b.textContent = 'Lag Lens stopped. Open the report: /report.html'; b.classList.remove('hidden');
    $('btn-lag').disabled = true; $('btn-stop').disabled = true;
  };

  D.lagPressed = function () {
    var self = this;
    if (this.stopped) return;
    var cur = (this.state && this.state.activity && this.state.activity.current) || 'idle';
    var acts = (this.state && this.state.activities) || LL.activities;
    LL.markSheet({ activities: acts, current: cur, source: 'dashboard', onSave: function (payload) {
      LL.submitMark(payload, self.online).then(function (r) {
        if (!r) return;
        var msg = h('div', null, h('b', null, 'Saved ' + r.id + '. '), r.assessment || '', h('div', { class: 'small muted' }, r.episode ? 'Linked to episode ' + r.episode + (r.episode_class ? ' (' + fmt.cls(r.episode_class) + ')' : '') : 'No nearby event'));
        LL.toast(msg, r.episode ? 'bad' : 'ok', 9000);
        self.refreshMarks();
      }).catch(function (e) { LL.toast('Mark failed: ' + e.message, 'bad'); });
    } });
  };
  D.setActivity = function (a) {
    LL.api.post('/api/activity', { activity: a, source: 'dashboard' }).then(function () { LL.toast('Now: ' + LL.actLabel(a), 'ok', 2000); }).catch(function (e) { LL.toast(e.message, 'bad'); });
  };
  D.loadtest = function () {
    var self = this, lt = this.state && this.state.loadtest;
    if (lt && lt.running) {
      LL.api.post('/api/loadtest/stop').then(function () { LL.toast('Load test stopped', 'ok'); }).catch(function (e) { LL.toast(e.message, 'bad'); });
      return;
    }
    LL.api.post('/api/loadtest/start', {}).then(function (r) { LL.toast('Load test started — phases ' + (r.phases || []).join(' → ') + ', ~' + (r.eta_s || 95) + ' s', 'ok'); })
      .catch(function (e) {
        if (e.code === 'episode_open' && root.confirm('An episode is open right now. Start the load test anyway?')) {
          LL.api.post('/api/loadtest/start', { force: true }).then(function () { LL.toast('Load test started', 'ok'); }).catch(function (e2) { LL.toast(e2.message, 'bad'); });
        } else LL.toast(e.message, 'bad');
      });
  };
  D.stop = function () {
    if (!root.confirm('Stop Lag Lens? The final report is written and the process exits.')) return;
    LL.api.post('/api/stop').then(function (r) { LL.toast('Stopping… report at ' + r.report, 'ok', 8000); }).catch(function (e) { LL.toast(e.message, 'bad'); });
  };

  // =====================================================================================
  // STATIC REPORT
  // =====================================================================================
  function section(id, title) { return h('section', { id: id }, h('h2', null, title)); }
  function statsTable(stats, targets) {
    var byId = {}; (targets || []).forEach(function (t) { byId[t.id] = t; });
    var cols = ['sent', 'loss_pct', 'late_pct', 'min', 'p50', 'p95', 'p99', 'max', 'jitter', 'longest_outage_s', 'episodes', 'big_loss_ratio'];
    var heads = ['target', 'sent', 'loss%', 'late%', 'min', 'p50', 'p95', 'p99', 'max', 'jitter', 'outage s', 'episodes', 'big/small'];
    var tb = h('tbody');
    var ids = Object.keys((stats && stats.targets) || {}).sort(function (a, b) { var ta = byId[a] || { key: a }, tb2 = byId[b] || { key: b }; return ICMP_ORDER.indexOf(ta.key) - ICMP_ORDER.indexOf(tb2.key); });
    ids.forEach(function (id) {
      var s = stats.targets[id], t = byId[id] || { label: 'target ' + id };
      var tr = h('tr', null, h('td', null, targetLabel(t)));
      cols.forEach(function (c) { var v = s[c]; tr.appendChild(h('td', { class: 'num' + ((c === 'loss_pct' && v > 1) ? ' bad' : '') }, v == null ? '—' : (c.indexOf('pct') >= 0 ? fmt.pct(v) : (typeof v === 'number' ? fmt.num(v, c === 'sent' || c === 'episodes' ? 0 : undefined) : String(v))))); });
      tb.appendChild(tr);
    });
    return h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, heads.map(function (x) { return h('th', { class: x === 'target' ? '' : 'num' }, x); }))), tb));
  }
  function sliceStats(rows, targets) {
    var by = {};
    rows.forEach(function (r) {
      var b = by[r[1]] || (by[r[1]] = { sent: 0, lost: 0, late: 0, rtts: [] });
      if (r[3] & 2) { b.late++; return; }
      b.sent++;
      if (r[3] & 1) b.lost++; else if (!(r[3] & 4)) b.rtts.push(r[4] / 1000);
    });
    var byId = {}; (targets || []).forEach(function (t) { byId[t.id] = t; });
    return Object.keys(by).map(function (id) {
      var b = by[id], srt = b.rtts.slice().sort(function (x, y) { return x - y; });
      var p95 = srt.length ? srt[Math.min(srt.length - 1, Math.floor(0.95 * (srt.length - 1)))] : null;
      return (byId[id] ? targetLabel(byId[id]) : id) + ': ' + (b.sent ? fmt.pct(100 * b.lost / b.sent) : '—') + ' loss, p95 ' + fmt.ms(p95, 1) + (b.late ? ', ' + b.late + ' late' : '');
    });
  }
  function healthTimeline(data) {
    var S = data.series; if (!S || !S.t || !S.t.length) return null;
    var targets = data.targets || [], ref = targets.filter(function (t) { return ['inet4_cf', 'inet4_g', 'inet6_cf', 'inet6_g', 'isp_hop4'].indexOf(t.key) >= 0; });
    if (!ref.length) return null;
    var bucket = 300, out = { t: [], h: [] }, cur = null, acc = null;
    function flush() {
      if (!acc) return;
      var loss = acc.n ? 100 * acc.lost / acc.n : 0, p50 = acc.p50.length ? acc.p50.reduce(function (a, b) { return a + b; }, 0) / acc.p50.length : 0;
      var p95 = acc.p95.length ? acc.p95.slice().sort(function (a, b) { return a - b; })[Math.floor(0.95 * (acc.p95.length - 1))] : 0;
      var jit = acc.jit.length ? acc.jit.reduce(function (a, b) { return a + b; }, 0) / acc.jit.length : 0;
      out.t.push(cur); out.h.push(LL.healthScore(loss, p95, p50, jit, acc.epMin, 0));
    }
    var eps = data.episodes || [];
    S.t.forEach(function (t, i) {
      var b = Math.floor(t / bucket) * bucket;
      if (b !== cur) { flush(); cur = b; acc = { n: 0, lost: 0, p50: [], p95: [], jit: [], epMin: 0 }; eps.forEach(function (e) { var a = Math.max(e.t0, b), z = Math.min(e.t1 || b + bucket, b + bucket); if (z > a) acc.epMin += (z - a) / 60; }); }
      ref.forEach(function (tg) {
        var s = S.targets[String(tg.id)]; if (!s) return;
        if (s.n[i] != null) { acc.n += s.n[i]; acc.lost += s.lost[i] || 0; }
        if (s.p50[i] != null) acc.p50.push(s.p50[i]); if (s.p95[i] != null) acc.p95.push(s.p95[i]); if (s.jit[i] != null) acc.jit.push(s.jit[i]);
      });
    });
    flush();
    var el = h('div', { class: 'chart' }, h('div', { class: 'title' }, h('span', null, 'Health score per 5 min (reference targets; approximate, recomputed from 5 s rollups)')));
    var plot = h('div'); el.appendChild(plot);
    var g = new LL.ChartGroup({ follow: false });
    var c = g.add(plot, { height: 120, series: [{ label: 'health', stroke: LL.cssVar('--ok'), width: 2, fill: LL.shade(LL.cssVar('--ok'), 0.15), spanGaps: true }], yRange: function () { return [0, 100]; }, opts: { cursor: { sync: { key: 'health' } } } });
    c.setData([out.t, out.h]);
    if (out.t.length > 1) g.setX(out.t[0], out.t[out.t.length - 1] + bucket, false);
    return el;
  }
  function hourHeatmap(rows) {
    var grid = h('div', { class: 'heat24' });
    var maxLoss = 0.01; (rows || []).forEach(function (r) { if (r && r.loss_pct != null) maxLoss = Math.max(maxLoss, r.loss_pct); });
    for (var hr = 0; hr < 24; hr++) {
      var r = (rows || []).filter(function (x) { return x && x.hour === hr; })[0];
      var cell = h('div', { class: 'h' + (!r || r.loss_pct == null ? ' empty' : ''), title: 'hour ' + hr + (r ? ': loss ' + fmt.pct(r.loss_pct) + ', p95 ' + fmt.ms(r.p95) + ', ' + (r.episodes || 0) + ' episodes' : ': no data') }, String(hr));
      if (r && r.loss_pct != null) cell.style.setProperty('--v', String(Math.min(1, r.loss_pct / maxLoss)));
      grid.appendChild(cell);
    }
    return grid;
  }

  function renderReport(data) {
    var rootEl = $('report') || doc.body;
    LL.clear(rootEl);
    var st = data.state || {}, sess = data.session || {}, targets = data.targets || [], marks = data.marks || [], episodes = (data.episodes || []).slice().sort(function (a, b) { return a.t0 - b.t0; });
    var colors = {}; targets.forEach(function (t) { colors[t.id] = LL.roleColor(t); });
    var title = 'Lag Lens report — ' + (sess.id || st.session && st.session.id || '') + (sess.label ? ' — ' + sess.label : '');
    doc.title = title;
    var started = sess.started || (st.session && st.session.started), stopped = sess.stopped;
    rootEl.appendChild(h('header', null, h('h1', null, title), h('div', { class: 'muted' },
      'Session ' + fmt.date(started) + (stopped ? ' → ' + fmt.date(stopped) : ' (running)') + ' · ' + fmt.dur((stopped || data.generated_at || Date.now() / 1000) - started) + ' · generated ' + fmt.date(data.generated_at) + ' · Lag Lens ' + (data.version || '')),
      h('nav', { class: 'toc' }, ['verdict', 'comcast', 'stats', 'episodes', 'marks', 'timelines', 'activity', 'hours', 'path', 'docsis', 'loadtests', 'facts', 'methodology'].map(function (id, i) { return h('a', { href: '#sec-' + id }, (i + 1) + '. ' + id); }))));

    // 1. Verdict
    var v = data.verdict || st.verdict || {}, sec1 = section('sec-verdict', '1. Verdict');
    sec1.appendChild(h('div', { class: 'headline', style: { padding: '0 0 8px 0' } }, 'Is it my network? ', h('b', null, (st.headline && st.headline.text) || 'Can’t tell'), st.headline && st.headline.action ? h('span', { class: 'action' }, st.headline.action) : null));
    sec1.appendChild(h('p', { class: 'verdict-box' }, v.text || 'No verdict (session too short or no data).'));
    sec1.appendChild(h('div', null, 'Confidence: ', h('b', null, v.confidence || '—')));
    if (v.top && v.top.length) sec1.appendChild(h('ul', null, v.top.map(function (t) { return h('li', null, fmt.cls(t['class']) + ' — ' + Math.round((t.share || 0) * 100) + '% of trouble time, ' + (t.episodes || 0) + ' episodes, ' + fmt.dur(t.seconds || 0)); })));
    if (v.next && v.next.length) sec1.appendChild(h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'What to try next'), h('th', null, 'confirmed if'), h('th', null, 'refuted if'))), h('tbody', null, v.next.map(function (n) { return h('tr', null, h('td', null, n.try || ''), h('td', null, n.confirm_if || ''), h('td', null, n.refute_if || '')); })))));
    rootEl.appendChild(sec1);

    // 2. Tell Comcast + privacy checklist
    var sec2 = section('sec-comcast', '2. Tell Comcast');
    var ctext = data.comcast_text || v.comcast || '';
    var pre = h('pre', { id: 'comcast-text' }, ctext || '(no Comcast-relevant episodes in this session)');
    sec2.appendChild(h('div', { class: 'copybox' }, pre, h('button', { type: 'button', class: 'small', onclick: function () { LL.copy(ctext); } }, 'Copy')));
    var hostF = data.state && data.state.host || {};
    sec2.appendChild(h('div', null, h('h3', null, 'Privacy checklist'), h('ul', { class: 'checklist' },
      h('li', null, 'Contains: LAN IPs (' + (hostF.lan_ip ? hostF.lan_ip.replace(/\.\d+$/, '.x') : '10.0.0.x') + '), Comcast hop IPs, your WAN IP, a truncated IPv6 prefix, the probe host name and link speed.'),
      h('li', null, 'Does not contain: the XB7 password, MAC addresses, device names, your config secrets.'),
      h('li', null, 'The export ZIP "comcast" pack holds only this report, comcast_evidence.txt, episodes.csv and docsis_channels.csv.'))));
    rootEl.appendChild(sec2);

    // 3. Health + stats
    var sec3 = section('sec-stats', '3. Health score and session stats');
    var hl = (st.health || {}); sec3.appendChild(h('div', null, 'Health: session ', h('b', null, hl.session != null ? String(hl.session) : '—'), ' · at the end ', h('b', null, hl.now != null ? String(hl.now) : '—')));
    var ht = healthTimeline(data); if (ht) sec3.appendChild(ht);
    sec3.appendChild(h('h3', null, 'Whole session')); sec3.appendChild(statsTable(data.stats || { targets: {} }, targets));
    if (data.stats_1h) { sec3.appendChild(h('h3', null, 'Last hour')); sec3.appendChild(statsTable(data.stats_1h, targets)); }
    rootEl.appendChild(sec3);

    // 4. Episodes
    var sec4 = section('sec-episodes', '4. Episodes (' + episodes.length + ')');
    if (!episodes.length) sec4.appendChild(h('p', { class: 'muted' }, 'No episodes detected.'));
    var byId = {}; targets.forEach(function (t) { byId[t.id] = t; });
    function lossAt(ep, keys) {
      var ev = (ep.evidence || []).filter(function (e) { return keys.some(function (k) { return e.indexOf(k) >= 0; }) && /%\s*loss/.test(e); })[0];
      return ev ? (ev.match(/([\d.]+)%\s*loss/) || [])[1] + '%' : '—';
    }
    episodes.slice().reverse().forEach(function (ep) {
      var summary = h('summary', null, fmt.clock(ep.t0) + ' · ' + fmt.durShort(ep.dur_s) + ' · ', h('b', null, fmt.cls(ep['class'])), ep.subclass ? ' / ' + fmt.cls(ep.subclass) : '', ' ', h('span', { class: 'conf ' + confClass(ep.confidence) }, fmt.conf(ep.confidence)),
        ' · gw ' + lossAt(ep, ['gateway', 'Gateway']) + ' / hop ' + lossAt(ep, ['Comcast hop', 'hop']) + ' / inet ' + lossAt(ep, ['1.1.1.1', '8.8.8.8', 'internet']) + ' · ' + (ep.direction || 'n/a') + ' · Xbox ' + (ep.xbox_state || '?') + ' · ' + LL.actLabel(ep.activity) + ((ep.host_tags || []).length ? ' · host: ' + ep.host_tags.join(',') : ''));
      var det = h('details', null, summary);
      var body = h('div');
      det.appendChild(body);
      var built = false;
      det.addEventListener('toggle', function () {
        if (built || !det.open) return; built = true;
        body.appendChild(evidenceCard(ep, marks, episodes.filter(function (e) { return e.id !== ep.id && e['class'] === ep['class']; }).length));
        var slice = data.raw_slices && data.raw_slices[ep.id];
        if (slice && slice.rows && slice.rows.length) rawChart(body, slice.rows, targets, colors, ep.t0, ep.t1 || ep.t0);
        else body.appendChild(h('div', { class: 'muted small' }, 'no raw slice stored for this episode (aggregate only)'));
      });
      sec4.appendChild(det);
    });
    rootEl.appendChild(sec4);

    // 5. Marks vs evidence
    var sec5 = section('sec-marks', '5. Marks vs evidence');
    var linked = marks.filter(function (m) { return m.episode; }).length;
    sec5.appendChild(h('p', null, marks.length ? (linked + ' of ' + marks.length + ' presses line up with a detected episode.') : 'No "Lag happened" presses in this session.'));
    if (marks.length) {
      var tb5 = h('tbody');
      marks.forEach(function (m) {
        var slice = data.raw_slices && data.raw_slices[m.id];
        var ctxStats = slice && slice.rows ? sliceStats(slice.rows.filter(function (r) { return Math.abs(r[0] / 1000 - m.t_est) <= 60; }), targets) : [];
        tb5.appendChild(h('tr', null, h('td', null, m.id), h('td', null, fmt.clock(m.t_est) + (m.offset_s ? ' (pressed ' + fmt.clock(m.t_pressed) + ', −' + m.offset_s + ' s)' : '')), h('td', null, LL.actLabel(m.activity) + (m.note ? ' — "' + m.note + '"' : '')),
          h('td', null, m.episode ? ('episode ' + m.episode) : 'no visible fault'), h('td', { class: 'small' }, m.assessment || ''), h('td', { class: 'small' }, ctxStats.length ? ctxStats.join('; ') : '—')));
      });
      sec5.appendChild(h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'mark'), h('th', null, 'time'), h('th', null, 'activity'), h('th', null, 'linked'), h('th', null, 'assessment'), h('th', null, '±60 s context'))), tb5)));
    }
    rootEl.appendChild(sec5);

    // 6. Timelines
    var sec6 = section('sec-timelines', '6. Timelines (drag to zoom, double-click to reset)');
    var tools6 = h('div'), charts6 = h('div', { class: 'charts' });
    sec6.appendChild(tools6); sec6.appendChild(charts6);
    rootEl.appendChild(sec6);
    if (data.series && data.series.t && data.series.t.length) {
      var evWrap = h('div');
      var stack = buildStack(charts6, targets, { range: null, follow: false, sessionStart: started, linkUp: hostF.link_up_mbps,
        onEpisode: function (ep) { stack.group.setX(ep.t0 - 60, (ep.t1 || ep.t0) + 60, true); LL.clear(evWrap); evWrap.appendChild(evidenceCard(ep, marks, null)); } });
      var btns = chartTools(tools6, stack, {});
      btns.querySelectorAll('.seg')[1].classList.add('hidden'); // no live follow in a static report
      sec6.insertBefore(evWrap, charts6);
      stack.feed(data.series);
      stack.setEpisodes(episodes, null); stack.setMarks(marks);
      stack.group.sessionStart = started;
      stack.group.setX(data.series.t[0], data.series.t[data.series.t.length - 1] + (data.series.res || 5), false);
      stack.group.follow = false;
    } else charts6.appendChild(h('p', { class: 'muted' }, 'No series data.'));

    // 7. Activity comparison
    var sec7 = section('sec-activity', '7. Activity comparison');
    var acts = data.activity_stats || {};
    var actKeys = Object.keys(acts);
    if (!actKeys.length) sec7.appendChild(h('p', { class: 'muted' }, 'No activity tags (use the "Now:" selector).'));
    else {
      var grid = h('div', { class: 'activity-grid' });
      actKeys.forEach(function (a) {
        var s = acts[a] || {}, tg = s.targets || s, ref = tg[String((targets.filter(function (t) { return t.key === 'inet4_cf'; })[0] || {}).id)] || {};
        var epCount = episodes.filter(function (e) { return e.activity === a; }).length;
        grid.appendChild(h('div', { class: 'act' }, h('b', null, LL.actLabel(a)), h('div', null, 'loss ' + fmt.pct(ref.loss_pct) + ' · p95 ' + fmt.ms(ref.p95)), h('div', { class: 'small muted' }, epCount + ' episodes')));
      });
      sec7.appendChild(grid);
    }
    rootEl.appendChild(sec7);

    // 8. Hour-of-day
    var sec8 = section('sec-hours', '8. Time of day (this session)');
    sec8.appendChild(hourHeatmap(data.hour_heatmap || []));
    sec8.appendChild(h('div', { class: 'hint' }, 'Shade = loss% of the reference targets in that hour; hover for p95 and episode count. Cross-session comparison needs ≥ 3 sessions.'));
    rootEl.appendChild(sec8);

    // 9. Path
    var sec9 = section('sec-path', '9. Path');
    var path = data.path || st.path || {};
    [['IPv4', path.v4], ['IPv6', path.v6]].forEach(function (fam) {
      if (!fam[1] || !fam[1].length) return;
      sec9.appendChild(h('h3', null, fam[0]));
      sec9.appendChild(h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'ttl'), h('th', null, 'ip'), h('th', null, 'rdns'), h('th', null, 'role'), h('th', null, 'mode'))),
        h('tbody', null, fam[1].map(function (hp) { return h('tr', null, h('td', null, String(hp.ttl)), h('td', { class: 'mono' }, hp.ip || '*'), h('td', null, hp.rdns || ''), h('td', null, hp.role || ''), h('td', null, hp.mode || (hp.rate_hz ? 'direct' : 'listed'))); })))));
    });
    if (!(path.v4 && path.v4.length) && !(path.v6 && path.v6.length)) sec9.appendChild(h('p', { class: 'muted' }, 'Path not discovered.'));
    sec9.appendChild(h('div', null, 'Route changes: ' + (path.changes || 0) + (path.method ? ' · method ' + path.method : '') + ((path.history || []).length ? ' · ' + path.history.length + ' discoveries recorded' : '')));
    rootEl.appendChild(sec9);

    // 10. DOCSIS + IGD
    var sec10 = section('sec-docsis', '10. DOCSIS (XB7) and IGD summary');
    var dx = data.docsis;
    if (dx && dx.polls && dx.polls.length) {
      var polls = dx.polls, last = polls[polls.length - 1];
      var snrs = [], usp = [], unc0 = 0, uncN = 0;
      (polls[0].ds || []).forEach(function (c) { unc0 += c.uncorr || 0; });
      (last.ds || []).forEach(function (c) { if (c.snr_db != null) snrs.push(c.snr_db); uncN += c.uncorr || 0; });
      (last.us || []).forEach(function (c) { if (c.pwr_dbmv != null) usp.push(c.pwr_dbmv); });
      var logs = []; polls.forEach(function (p) { (p.log_new || []).forEach(function (l) { logs.push(l); }); });
      var t3 = logs.filter(function (l) { return l['class'] === 't3'; }).length, t4 = logs.filter(function (l) { return l['class'] === 't4'; }).length;
      sec10.appendChild(kv([['Polls', String(polls.length)], ['Uptime at end', last.uptime_s != null ? fmt.dur(last.uptime_s) : null], ['Firmware', last.fw],
        ['DS SNR min / US power max', (snrs.length ? fmt.num(Math.min.apply(null, snrs), 1) + ' dB' : '—') + ' / ' + (usp.length ? fmt.num(Math.max.apply(null, usp), 1) + ' dBmV' : '—')],
        ['Uncorrectables growth', String(uncN - unc0)], ['T3 / T4 timeouts', t3 + ' / ' + t4], ['Flags', (last.flags || []).join(', ') || 'none'], ['Log clock offset', last.log_clock_offset_s != null ? last.log_clock_offset_s + ' s' : null]]));
      if (last.ds && last.ds.length) sec10.appendChild(h('details', null, h('summary', null, 'Downstream channels (' + last.ds.length + ')'), h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['ch', 'freq MHz', 'SNR dB', 'power dBmV', 'mod', 'corr', 'uncorr'].map(function (x) { return h('th', null, x); }))),
        h('tbody', null, last.ds.map(function (c) { return h('tr', null, h('td', null, String(c.ch)), h('td', { class: 'num' }, c.freq_hz ? fmt.num(c.freq_hz / 1e6, 0) : '—'), h('td', { class: 'num' }, fmt.num(c.snr_db, 1)), h('td', { class: 'num' }, fmt.num(c.pwr_dbmv, 1)), h('td', null, c.mod || ''), h('td', { class: 'num' }, String(c.corr == null ? '—' : c.corr)), h('td', { class: 'num' }, String(c.uncorr == null ? '—' : c.uncorr))); }))))));
      if (last.us && last.us.length) sec10.appendChild(h('details', null, h('summary', null, 'Upstream channels (' + last.us.length + ')'), h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['ch', 'freq MHz', 'power dBmV', 'type', 'lock'].map(function (x) { return h('th', null, x); }))),
        h('tbody', null, last.us.map(function (c) { return h('tr', null, h('td', null, String(c.ch)), h('td', { class: 'num' }, c.freq_hz ? fmt.num(c.freq_hz / 1e6, 1) : '—'), h('td', { class: 'num' }, fmt.num(c.pwr_dbmv, 1)), h('td', null, c.type || ''), h('td', null, c.lock == null ? '' : (c.lock ? 'yes' : 'no'))); }))))));
      if (logs.length) sec10.appendChild(h('details', null, h('summary', null, 'Modem log (' + logs.length + ' lines)'), h('div', { class: 'log-lines' }, logs.map(function (l) { return (l.ts || '') + ' [' + (l['class'] || '') + '] ' + (l.text || ''); }).join('\n'))));
    } else sec10.appendChild(h('p', { class: 'muted' }, 'DOCSIS: not collected' + (st.collectors && st.collectors.docsis && st.collectors.docsis.reason ? ' (' + st.collectors.docsis.reason + ')' : '') + '.'));
    var igd = data.igd;
    sec10.appendChild(h('h3', null, 'IGD (UPnP)'));
    if (igd && igd.status) sec10.appendChild(kv([['Status', igd.status + (igd.trusted === false ? ' (untrusted counters)' : '')], ['WAN uptime', igd.uptime_s != null ? fmt.dur(igd.uptime_s) : null], ['External IP', igd.ext_ip], ['Mappings', (igd.mappings || []).map(function (m) { return m.proto + ' ' + m.ext + '→' + m.int + (m.desc ? ' (' + m.desc + ')' : ''); }).join('; ') || 'none']]));
    else sec10.appendChild(h('p', { class: 'muted' }, 'IGD: not collected.'));
    rootEl.appendChild(sec10);

    // 11. Load tests
    var sec11 = section('sec-loadtests', '11. Load tests');
    var lts = data.loadtests || [];
    if (!lts.length) sec11.appendChild(h('p', { class: 'muted' }, 'No load test run.'));
    else sec11.appendChild(h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['start', 'grade', 'down Mb/s', 'up Mb/s', 'idle p50/p95', 'down p50/p95', 'up p50/p95', 'added ms down/up'].map(function (x) { return h('th', null, x); }))),
      h('tbody', null, lts.map(function (l) { var p = l.phases || {}; function pp(k) { return p[k] ? fmt.num(p[k].p50, 0) + ' / ' + fmt.num(p[k].p95, 0) : '—'; }
        return h('tr', null, h('td', null, fmt.clock(l.t0)), h('td', ltFailed(l) ? { title: ltFailed(l) } : null, l.grade || (ltFailed(l) ? 'failed' : '—')), h('td', { class: 'num' }, p.down ? fmt.num(p.down.mbps, 0) : '—'), h('td', { class: 'num' }, p.up ? fmt.num(p.up.mbps, 1) : '—'), h('td', null, pp('idle')), h('td', null, pp('down')), h('td', null, pp('up')), h('td', null, l.added_ms ? fmt.num(l.added_ms.down, 0) + ' / ' + fmt.num(l.added_ms.up, 0) : '—')); })))));
    rootEl.appendChild(sec11);

    // 12. Doctor / collectors / host / config
    var sec12 = section('sec-facts', '12. Doctor, collectors, host facts, config');
    var checks = data.doctor || st.doctor || [];
    if (checks.length) sec12.appendChild(h('div', { class: 'table-wrap doctor' }, h('table', null, h('tbody', null, checks.map(function (c) { return h('tr', null, h('td', { class: c.status }, c.status), h('td', null, c.check), h('td', { class: 'small' }, (c.detail || '') + (c.fallback ? ' → ' + c.fallback : ''))); })))));
    var cols = data.collectors || st.collectors || {}, colWrap = h('div');
    Object.keys(cols).sort().forEach(function (n) { var c = cols[n] || {}; colWrap.appendChild(h('span', { class: 'chip ' + (c.status || '') }, n, c.reason ? h('span', { class: 'why' }, ' ' + c.reason) : null)); });
    sec12.appendChild(h('h3', null, 'Collectors')); sec12.appendChild(colWrap);
    sec12.appendChild(h('h3', null, 'Host'));
    sec12.appendChild(kv([['OS', (sess.os || hostF.os || '') + (hostF.hostname ? ' · ' + hostF.hostname : '')], ['Interface', (hostF.iface || sess.iface || '—') + (hostF.wifi ? ' (Wi-Fi)' : '') + (hostF.speed ? ' · ' + hostF.speed + ' Mb/s ' + (hostF.duplex || '') : '')],
      ['LAN / gateway', (hostF.lan_ip || sess.lan || '—') + ' via ' + (hostF.gateway || sess.gateway || '—')], ['IPv6', hostF.v6 ? 'yes' + (sess.v6_prefix ? ' · ' + sess.v6_prefix : '') : 'no'], ['VPN route', hostF.vpn_route ? 'yes (!)' : 'no'],
      ['Upstream limit', hostF.link_up_mbps ? hostF.link_up_mbps + ' Mb/s' : null], ['Version', data.version || ''], ['Resumed', String(sess.resumed_count || 0)]]));
    sec12.appendChild(h('details', null, h('summary', null, 'Config (redacted)'), h('pre', null, JSON.stringify(data.config || {}, null, 1))));
    rootEl.appendChild(sec12);

    // 13. Methodology
    var sec13 = section('sec-methodology', '13. Methodology and limitations');
    var meth = data.methodology || [];
    if (meth.length) sec13.appendChild(h('ul', null, meth.map(function (m) { return h('li', null, m); })));
    else sec13.appendChild(h('ul', null, [
      'Episodes open on ≥ 2 severity symptoms on a non-hop target and close after 10 s quiet; blips under 1.5 s are not counted.',
      'The loss locus is the shallowest ladder target (gateway → Comcast hop → mid-path → internet) lost in ≥ 70% of the 250 ms slots where a deeper target was lost.',
      'ICMP to the gateway is answered by its CPU: gateway latency alone is weak evidence.',
      'Loss at an intermediate hop alone is not evidence; it only counts when deeper targets suffer in the same slots.',
      'Host-side faults (stalls, Wi-Fi drops, interface errors, VPN routes, clock jumps) exonerate Comcast for overlapping episodes.'
    ].map(function (m) { return h('li', null, m); })));
    rootEl.appendChild(sec13);
  }

  // =====================================================================================
  // entry
  // =====================================================================================
  function start() {
    var blob = doc.getElementById('laglens-data');
    if (blob) {
      var data = null;
      try { data = JSON.parse(blob.textContent || '{}'); } catch (e) { data = null; }
      if (!data) { (doc.getElementById('report') || doc.body).textContent = 'Report data is unreadable.'; return; }
      try { renderReport(data); } catch (e) { var r = doc.getElementById('report') || doc.body; r.appendChild(h('pre', null, 'Report render failed: ' + (e && e.stack || e))); }
      return;
    }
    if (doc.getElementById('btn-lag')) {
      var dash = new Dashboard();
      root.LagLensDashboard = dash;
      dash.boot();
    }
  }
  root.LagLensApp = { renderReport: renderReport, buildStack: buildStack, evidenceCard: evidenceCard, Dashboard: Dashboard, start: start };
  if (doc.readyState === 'loading' && doc.addEventListener) doc.addEventListener('DOMContentLoaded', start); else if (doc.readyState) start();
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
