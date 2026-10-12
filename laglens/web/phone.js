/* Lag Lens — phone page (SPEC §8.4).
 *
 * A giant fixed "Lag happened" button: tap → vibrate + flash → a 10 s sheet (When? / What? /
 * note; auto-saves with defaults) → POST /api/mark → the instant assessment and the
 * linked-episode line. Below: status pill, headline, four big numbers (gateway, Comcast hop,
 * internet v4, internet v6: 5 min loss / p95), one latency chart, the last 5 episodes, the
 * activity toggle, the LAN pager (vibrate + Web Audio beep on episode_open/close, enabled
 * after the first tap) and a keep-awake muted looping video. Presses made while the backend
 * is unreachable are queued in localStorage (common.js LL.queue) and replayed with
 * replay:true when it is back.
 *
 * Safe to evaluate in node with a stub document (top-level code only registers listeners).
 */
(function (root) {
  'use strict';
  var doc = (typeof document !== 'undefined') ? document : null;
  var LL = root.LL;
  if (!doc || !LL) return;
  var h = LL.h, $ = LL.$, fmt = LL.fmt;

  var BIG = [['gw4', 'Gateway'], ['isp_hop4', 'Comcast hop'], ['inet4_cf', 'Internet v4'], ['inet6_cf', 'Internet v6']];
  var BIG_FALLBACK = { inet4_cf: 'inet4_g', inet6_cf: 'inet6_g', isp_hop4: 'mid_hop4' };
  var SERIES_SPAN_S = 600;

  function Phone() {
    this.state = null;
    this.online = true;
    this.lastData = null;
    this.episodes = {};
    this.interacted = false;      // first tap unlocks audio + the keep-awake video
    this.audio = null;
    this.chart = null;
    this.group = null;
    this.S = null;
    this.chartTargets = [];
    this.sheet = null;
    this.stopped = false;
    this.pagerOn = true;
    this.awakeOn = true;
  }
  var P = Phone.prototype;

  // ------------------------------------------------------------------ boot
  P.boot = function () {
    var self = this;
    var btn = $('phone-btn');
    btn.addEventListener('click', function () { self.pressed(); });
    btn.addEventListener('touchstart', function () { self.firstInteraction(); }, { passive: true });
    doc.addEventListener('keydown', function (ev) {
      if ((ev.key === 'l' || ev.key === 'L') && !ev.metaKey && !ev.ctrlKey && !ev.altKey) {
        var tag = (ev.target && ev.target.tagName) || '';
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        ev.preventDefault(); self.pressed();
      }
    });
    var pager = $('pager-toggle'), awake = $('awake-toggle');
    try { this.pagerOn = root.localStorage.getItem('laglens.pager') !== '0'; this.awakeOn = root.localStorage.getItem('laglens.awake') !== '0'; } catch (e) { /* ignore */ }
    if (pager) { pager.checked = this.pagerOn; pager.addEventListener('change', function () { self.pagerOn = pager.checked; try { root.localStorage.setItem('laglens.pager', pager.checked ? '1' : '0'); } catch (e) { /* ignore */ } if (pager.checked) self.firstInteraction(); }); }
    if (awake) { awake.checked = this.awakeOn; awake.addEventListener('change', function () { self.awakeOn = awake.checked; try { root.localStorage.setItem('laglens.awake', awake.checked ? '1' : '0'); } catch (e) { /* ignore */ } if (awake.checked) self.keepAwake(); else self.releaseAwake(); }); }
    doc.addEventListener('visibilitychange', function () { if (!doc.hidden && self.interacted && self.awakeOn) self.keepAwake(); });

    this.renderActivities(LL.activities, 'idle');
    this.buildChart([]);
    this.loadState(true);
    this.sse = LL.sse.connect({
      onEvent: function (name, data) { self.onEvent(name, data); },
      onStatus: function (s) { self.setOnline(s === 'live' || s === 'polling'); if (s === 'live') self.loadState(false); },
      onPoll: function (st) { self.applyState(st); }
    });
    setInterval(function () { self.tickClock(); }, 1000);
    setInterval(function () { if (self.online && !self.stopped) self.loadSeries(); }, 5000);
    setInterval(function () { if (self.online && !self.stopped) self.loadState(false); }, 30000);
  };

  P.loadState = function (first) {
    var self = this;
    LL.api.get('/api/state').then(function (st) {
      self.applyState(st);
      self.setOnline(true);
      if (first) { self.loadEpisodes(); }
      self.loadSeries();
    }).catch(function () { self.setOnline(false); });
  };
  P.loadEpisodes = function () {
    var self = this;
    LL.api.get('/api/episodes?limit=20').then(function (r) { (r.episodes || []).forEach(function (e) { self.episodes[e.id] = e; }); self.renderEpisodes(); }).catch(function () { /* ignore */ });
  };

  // ------------------------------------------------------------------ online / offline
  P.setOnline = function (on) {
    var was = this.online;
    this.online = !!on;
    var banner = $('banner'), btn = $('phone-btn'), sub = $('phone-btn-sub');
    if (!on) {
      this.paintPill('UNREACHABLE', 'UNREACHABLE');
      banner.textContent = 'Lag Lens is not reachable — last data ' + (this.lastData ? fmt.clock(this.lastData) : 'never') + '. Presses are saved on this phone and sent when it is back' + (LL.queue.size() ? ' (' + LL.queue.size() + ' queued)' : '') + '.';
      banner.classList.remove('hidden');
      if (sub) sub.textContent = 'will send when reconnected';
      btn.classList.add('offline');
    } else {
      banner.classList.add('hidden');
      if (sub) sub.textContent = 'tap when the game stutters';
      btn.classList.remove('offline');
      if (this.state) this.paintPill(this.state.state, this.state.pill);
      if (!was) this.flushQueue();
    }
  };
  P.flushQueue = function () {
    var self = this;
    if (!LL.queue.size()) return;
    LL.queue.flush().then(function (n) { if (n) { LL.toast('Sent ' + n + ' queued press' + (n > 1 ? 'es' : ''), 'ok'); self.loadEpisodes(); } });
  };

  // ------------------------------------------------------------------ painting
  P.paintPill = function (state, text) {
    var p = $('pill');
    p.className = 'pill ' + (state || 'STARTING');
    p.textContent = text || state || '';
  };
  P.tickClock = function () {
    if (!this.state || !this.state.session || !this.online || this.stopped) return;
    var started = this.state.session.started;
    if (started) $('elapsed').textContent = fmt.dur(Date.now() / 1000 - started);
    if (this.group && this.group.follow) this.group.followNow();
  };
  P.applyState = function (st) {
    this.state = st;
    this.lastData = st.now || Date.now() / 1000;
    if (!this.stopped) this.paintPill(st.state, st.pill);
    this.renderHeadline(st.headline);
    this.renderBig(st.targets || []);
    this.renderActivities(st.activities || LL.activities, st.activity && st.activity.current);
    (st.episodes_recent || []).forEach(function (e) { this.episodes[e.id] = e; }, this);
    this.renderEpisodes();
    var sig = this.chartKeys(st.targets || []).map(function (t) { return t.id; }).join(',');
    if (sig !== this._chartSig) { this._chartSig = sig; this.buildChart(this.chartKeys(st.targets || [])); }
    if (st.state === 'STOPPED') this.markStopped();
  };
  P.renderHeadline = function (hl) {
    var el = $('headline'); if (!el || !hl) return;
    LL.clear(el);
    el.appendChild(doc.createTextNode('Is it my network? '));
    el.appendChild(h('b', null, hl.text || 'Can’t tell yet'));
    if (hl.action) el.appendChild(h('span', { class: 'action' }, hl.action));
  };
  P.pick = function (targets, key) {
    var byKey = {}; targets.forEach(function (t) { byKey[t.key] = t; });
    return byKey[key] || (BIG_FALLBACK[key] ? byKey[BIG_FALLBACK[key]] : null) || null;
  };
  P.renderBig = function (targets) {
    var self = this, wrap = $('bignums'); if (!wrap) return;
    LL.clear(wrap);
    BIG.forEach(function (b) {
      var t = self.pick(targets, b[0]), w = (t && t.w5m) || {};
      var loss = w.loss_pct, p95 = w.p95;
      var el = h('div', { class: 'bn' + ((loss || 0) > 1 ? ' bad' : '') + (!t || !t.enabled ? ' off' : '') },
        h('div', { class: 'lbl', title: b[1] + (t && t.addr ? ' · ' + t.addr : '') }, b[1]),  // no address on the phone (no hover)
        h('div', { class: 'v' }, t ? fmt.pct(loss) : '—', h('small', null, ' loss')),
        h('div', { class: 'small muted' }, t ? ('p95 ' + fmt.ms(p95, p95 != null && p95 >= 100 ? 0 : 1) + ' · now ' + fmt.ms(t.last && t.last.rtt, 1)) : 'not probed'));
      if (t) el.style.setProperty('--swatch', LL.roleColor(t));
      wrap.appendChild(el);
    });
  };
  P.renderActivities = function (acts, current) {
    var self = this, row = $('activity-row'); if (!row) return;
    acts = acts && acts.length ? acts : LL.activities;
    current = current || 'idle';
    LL.clear(row);
    acts.forEach(function (a) {
      row.appendChild(h('button', { type: 'button', class: a === current ? 'on' : '', style: { flex: '1 1 28%' }, onclick: function () { self.setActivity(a); } }, LL.actLabel(a)));
    });
  };
  P.setActivity = function (a) {
    var self = this;
    this.firstInteraction();
    LL.api.post('/api/activity', { activity: a, source: 'phone' }).then(function () {
      if (self.state) self.state.activity = { current: a };
      self.renderActivities((self.state && self.state.activities) || LL.activities, a);
      LL.toast('Now: ' + LL.actLabel(a), 'ok', 1500);
    }).catch(function (e) { LL.toast(e.message || 'failed', 'bad'); });
  };
  P.episodeList = function () { var self = this; return Object.keys(this.episodes).map(function (k) { return self.episodes[k]; }).sort(function (a, b) { return b.t0 - a.t0; }); };
  P.renderEpisodes = function () {
    var tb = $('episodes-body'); if (!tb) return;
    LL.clear(tb);
    var list = this.episodeList().slice(0, 5);
    if (!list.length) { tb.appendChild(h('tr', null, h('td', { class: 'muted' }, 'no episodes yet'))); return; }
    list.forEach(function (e) {
      tb.appendChild(h('tr', { class: e.t1 == null ? 'open' : '' },
        h('td', null, fmt.clock(e.t0)), h('td', { class: 'num' }, e.t1 == null ? 'open' : fmt.durShort(e.dur_s)),
        h('td', { class: 'cls' }, fmt.cls(e['class'])), h('td', null, fmt.conf(e.confidence))));
    });
  };
  P.markStopped = function () {
    this.stopped = true;
    this.paintPill('STOPPED', 'Stopped — open report');
    var b = $('banner'); b.textContent = 'Lag Lens stopped. Open the report from the links below.'; b.classList.remove('hidden');
    $('phone-btn').disabled = true;
  };

  // ------------------------------------------------------------------ chart
  P.chartKeys = function (targets) {
    var self = this, out = [];
    BIG.forEach(function (b) { var t = self.pick(targets, b[0]); if (t && out.indexOf(t) < 0) out.push(t); });
    return out;
  };
  P.buildChart = function (targets) {
    var self = this, el = $('chart'); if (!el) return;
    if (this.group) { this.group.destroy(); LL._groups = LL._groups.filter(function (g) { return g !== self.group; }); }
    LL.clear(el);
    this.chartTargets = targets;
    this.group = new LL.ChartGroup({ range: SERIES_SPAN_S, follow: true });
    LL._groups.push(this.group);
    var legend = $('chart-legend'); if (legend) { LL.clear(legend); targets.forEach(function (t) { var s = h('span', null, t.label || t.key); s.style.setProperty('--sw', LL.roleColor(t)); legend.appendChild(s); }); }
    this.chart = this.group.add(el, {
      height: 170, yLabel: 'ms', raw: false, markIcons: true,
      series: targets.map(function (t) { return { label: t.label || t.key, stroke: LL.roleColor(t), width: t.role === 'gateway' ? 2 : 1.5 }; }),
      opts: { cursor: { sync: { key: 'phone' }, drag: { x: false, y: false }, points: { size: 6 } } }
    });
    this.chart.pick = targets.map(function (t) { return function (S) { return S.targets && S.targets[String(t.id)] ? S.targets[String(t.id)].p50 : null; }; });
    this.group.followNow();
    if (this.S) this.feed(this.S);
  };
  P.feed = function (S) {
    if (!this.chart || !this.chart.pick || !S || !S.t) return;
    this.chart.setData(LL.seriesData(S, this.chart.pick));
    this.group.overlays.episodes = this.episodeList();
    this.group.redraw();
  };
  P.loadSeries = function () {
    var self = this;
    if (!this.chartTargets.length || this._loadingSeries) return;
    var now = Date.now() / 1000, ids = this.chartTargets.map(function (t) { return t.id; }).join(',');
    var from = this.S && this.S.t && this.S.t.length ? Math.max(this.S.t[this.S.t.length - 1] - 30, now - SERIES_SPAN_S) : now - SERIES_SPAN_S;
    this._loadingSeries = true;
    LL.api.get('/api/series?from=' + from + '&to=' + now + '&res=1&targets=' + ids).then(function (chunk) {
      self.S = self.S ? LL.mergeSeries(self.S, chunk, now - SERIES_SPAN_S - 30) : chunk;
      self.feed(self.S);
      self.lastData = now;
    }).catch(function () { /* status comes from the SSE client */ }).then(function () { self._loadingSeries = false; });
  };

  // ------------------------------------------------------------------ the button
  P.vibrate = function (pattern) {
    try { if (root.navigator && root.navigator.vibrate) root.navigator.vibrate(pattern); } catch (e) { /* ignore */ }
  };
  P.firstInteraction = function () {
    if (this.interacted) return;
    this.interacted = true;
    this.initAudio();
    if (this.awakeOn) this.keepAwake();
    var hint = $('pager-hint'); if (hint) hint.textContent = 'Pager armed: this phone vibrates and beeps when an episode opens or closes.';
  };
  P.pressed = function () {
    var self = this;
    if (this.stopped) return;
    this.firstInteraction();
    this.vibrate([60]);
    var btn = $('phone-btn');
    btn.classList.add('flash'); setTimeout(function () { btn.classList.remove('flash'); }, 180);
    if (this.sheet) { this.sheet.save(); return; }   // second tap while the sheet is open = save now
    var cur = (this.state && this.state.activity && this.state.activity.current) || 'idle';
    var acts = (this.state && this.state.activities) || LL.activities;
    this.sheet = LL.markSheet({ activities: acts, current: cur, source: 'phone', sheet: true, timeoutMs: 10000, onSave: function (payload) {
      self.sheet = null;
      self.submit(payload);
    } });
  };
  P.submit = function (payload) {
    var self = this, box = $('assess');
    LL.submitMark(payload, this.online).then(function (r) {
      if (!r) { self.showAssess(h('div', null, h('b', null, 'Saved on this phone. '), 'Lag Lens is not reachable right now; the press (' + fmt.clock(payload.t_pressed) + ') is queued and will be sent when it is back.'), 'bad'); return; }
      self.showAssess(h('div', null, h('div', null, h('b', null, 'Saved ' + r.id + ' at ' + fmt.clock(r.t_est) + '. '), r.assessment || ''),
        h('div', { class: 'link' }, r.episode ? ('Saved — linked to episode at ' + fmt.clock(self.episodes[r.episode] ? self.episodes[r.episode].t0 : r.t_est) + (r.episode_class ? ' (' + fmt.cls(r.episode_class) + ')' : '')) : 'Saved — no nearby event')), r.episode ? 'bad' : 'ok');
      self.vibrate(r.episode ? [40, 40, 40] : [40]);
    }).catch(function (e) {
      self.showAssess(h('div', null, 'Mark failed: ' + (e.message || e)), 'bad');
    });
    if (box) box.classList.remove('hidden');
  };
  P.showAssess = function (node, kind) {
    var box = $('assess'); if (!box) return;
    LL.clear(box);
    box.className = 'panel assess ' + (kind || '');
    box.appendChild(node);
    box.classList.remove('hidden');
    if (this._assessTimer) clearTimeout(this._assessTimer);
    this._assessTimer = setTimeout(function () { box.classList.add('hidden'); }, 45000);
  };

  // ------------------------------------------------------------------ pager (vibrate + beep)
  P.initAudio = function () {
    if (this.audio) return;
    var AC = root.AudioContext || root.webkitAudioContext;
    if (!AC) return;
    try { this.audio = new AC(); if (this.audio.state === 'suspended' && this.audio.resume) this.audio.resume(); } catch (e) { this.audio = null; }
  };
  P.beep = function (freq, ms, times) {
    var ac = this.audio; if (!ac) return;
    times = times || 1;
    try {
      if (ac.state === 'suspended' && ac.resume) ac.resume();
      for (var i = 0; i < times; i++) {
        var o = ac.createOscillator(), g = ac.createGain();
        var t0 = ac.currentTime + i * (ms / 1000 + 0.08);
        o.type = 'sine'; o.frequency.value = freq;
        g.gain.setValueAtTime(0.0001, t0); g.gain.exponentialRampToValueAtTime(0.4, t0 + 0.01); g.gain.exponentialRampToValueAtTime(0.0001, t0 + ms / 1000);
        o.connect(g); g.connect(ac.destination);
        o.start(t0); o.stop(t0 + ms / 1000 + 0.02);
      }
    } catch (e) { /* ignore */ }
  };
  P.page = function (kind) {
    if (!this.pagerOn || !this.interacted) return;
    if (kind === 'open') { this.vibrate([200, 100, 200, 100, 400]); this.beep(880, 160, 3); }
    else { this.vibrate([120]); this.beep(523, 220, 1); }
  };

  // ------------------------------------------------------------------ keep awake
  P.keepAwake = function () {
    var self = this, v = $('keep-awake');
    if (root.navigator && root.navigator.wakeLock && root.navigator.wakeLock.request) {
      root.navigator.wakeLock.request('screen').then(function (lock) { self.wakeLock = lock; }).catch(function () { /* http: not available, fall through to the video */ });
    }
    if (!v) return;
    try {
      if (!v.srcObject && doc.createElement) {
        // No video asset is shipped: a 1-frame canvas stream is a playing muted video as far as the OS is concerned.
        var c = doc.createElement('canvas'); c.width = 2; c.height = 2;
        var ctx = c.getContext && c.getContext('2d');
        if (ctx) { ctx.fillStyle = '#000'; ctx.fillRect(0, 0, 2, 2); }
        if (c.captureStream) { v.srcObject = c.captureStream(1); setInterval(function () { if (ctx) { ctx.fillStyle = ctx.fillStyle === '#000000' ? '#010101' : '#000000'; ctx.fillRect(0, 0, 2, 2); } }, 1000); }
      }
      v.muted = true; v.loop = true; v.setAttribute('playsinline', '');
      var p = v.play(); if (p && p.catch) p.catch(function () { /* autoplay blocked until the next tap */ });
    } catch (e) { /* ignore */ }
  };
  P.releaseAwake = function () {
    var v = $('keep-awake');
    try { if (v) v.pause(); } catch (e) { /* ignore */ }
    try { if (this.wakeLock && this.wakeLock.release) { this.wakeLock.release(); this.wakeLock = null; } } catch (e) { /* ignore */ }
  };

  // ------------------------------------------------------------------ SSE
  P.onEvent = function (name, data) {
    this.lastData = Date.now() / 1000;
    switch (name) {
      case 'tick':
        if (!this.state) return;
        this.state.state = data.state; this.state.pill = data.pill;
        if (!this.stopped) this.paintPill(data.state, data.pill);
        if (data.headline) { this.state.headline = data.headline; this.renderHeadline(data.headline); }
        (this.state.targets || []).forEach(function (t) {
          var row = data.targets && data.targets[String(t.id)];
          if (!row) return;
          t.last = { rtt: row.rtt, t: data.t };
          t.w5m = Object.assign({}, t.w5m || {}, { p95: row.p95_5m, loss_pct: row.loss_5m });
        });
        this.renderBig(this.state.targets || []);
        break;
      case 'episode_open': case 'episode_update': case 'episode_close':
        this.episodes[data.id] = Object.assign({}, this.episodes[data.id] || {}, data);
        this.renderEpisodes();
        if (this.group) { this.group.overlays.episodes = this.episodeList(); this.group.redraw(); }
        if (name === 'episode_open') { this.page('open'); LL.toast('Episode: ' + fmt.cls(data['class']) + ' at ' + fmt.clock(data.t0), 'bad', 5000); }
        if (name === 'episode_close') this.page('close');
        break;
      case 'mark':
        if (this.group) { this.group.overlays.marks = (this.group.overlays.marks || []).filter(function (m) { return m.id !== data.id; }).concat([data]); this.group.redraw(); }
        break;
      case 'activity':
        if (this.state) this.state.activity = { current: data.activity || data.current };
        this.renderActivities((this.state && this.state.activities) || LL.activities, data.activity || data.current);
        break;
      case 'stopping':
        this.markStopped();
        break;
      default:
        break;
    }
  };

  function start() {
    if (!doc.getElementById('phone-btn')) return;
    var phone = new Phone();
    root.LagLensPhone = phone;
    phone.boot();
  }
  root.LagLensPhoneApp = { Phone: Phone, start: start };
  if (doc.readyState === 'loading' && doc.addEventListener) doc.addEventListener('DOMContentLoaded', start); else if (doc.readyState) start();
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
