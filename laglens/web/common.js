/* Lag Lens — shared browser helpers: API client, SSE client with polling fallback,
 * formatting, DOM helpers, offline press queue, the "Lag happened" sheet and uPlot
 * chart helpers (synced cursors, drag-zoom, range buttons, live follow, overlays).
 *
 * Vanilla JS (ES2017), no dependencies besides the vendored uPlot. Safe to load in
 * node with a stub `document`/`window` (top-level evaluation never touches the DOM).
 */
(function (root) {
  'use strict';

  var doc = (typeof document !== 'undefined') ? document : null;
  var LL = {};

  // ---------------------------------------------------------------- basics
  function meta(name) {
    if (!doc || !doc.querySelector) return '';
    var m = doc.querySelector('meta[name="' + name + '"]');
    return m ? (m.getAttribute('content') || '') : '';
  }
  LL.token = meta('laglens-token');
  LL.version = meta('laglens-version');
  LL.isStatic = !!(doc && doc.getElementById && doc.getElementById('laglens-data'));
  LL.DEFAULT_ACTIVITIES = ['idle', 'bf6', 'rocket_league', 'hbo_max', 'other'];
  // The configured activity slugs come from <meta name="laglens-activities"> (server-injected).
  LL.activities = (function () {
    var m = meta('laglens-activities');
    if (!m || m.indexOf('{{') === 0) return LL.DEFAULT_ACTIVITIES.slice();
    var out = m.split(',').map(function (s) { return s.trim(); }).filter(function (s) { return /^[a-z0-9_\-]{1,40}$/.test(s); });
    return out.length ? out : LL.DEFAULT_ACTIVITIES.slice();
  })();

  LL.esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };

  // h(tag, attrs, ...children) — tiny DOM builder
  LL.h = function (tag, attrs) {
    var el = doc.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === 'class') el.className = v;
        else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
        else if (k === 'html') el.innerHTML = v;
        else if (k === 'text') el.textContent = v;
        else if (k.indexOf('on') === 0 && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (k === 'dataset') Object.keys(v).forEach(function (d) { el.dataset[d] = v[d]; });
        else el.setAttribute(k, v === true ? '' : v);
      });
    }
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  };
  function append(el, child) {
    if (child == null || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(el, c); }); return; }
    if (typeof child === 'string' || typeof child === 'number') el.appendChild(doc.createTextNode(String(child)));
    else el.appendChild(child);
  }
  LL.$ = function (id) { return doc ? doc.getElementById(id) : null; };
  LL.clear = function (el) { if (el) while (el.firstChild) el.removeChild(el.firstChild); return el; };
  LL.cssVar = function (name) {
    if (!doc || !root.getComputedStyle) return '';
    return (root.getComputedStyle(doc.documentElement).getPropertyValue(name) || '').trim();
  };

  // ---------------------------------------------------------------- format
  var fmt = LL.fmt = {};
  fmt.num = function (v, d) {
    if (v == null || isNaN(v)) return '—';
    d = (d == null) ? (Math.abs(v) >= 100 ? 0 : (Math.abs(v) >= 10 ? 1 : 2)) : d;
    return Number(v).toFixed(d);
  };
  fmt.ms = function (v, d) { return v == null || isNaN(v) ? '—' : fmt.num(v, d) + ' ms'; };
  fmt.pct = function (v, d) { return v == null || isNaN(v) ? '—' : Number(v).toFixed(d == null ? 1 : d) + '%'; };
  fmt.mbps = function (v) { return v == null || isNaN(v) ? '—' : fmt.num(v, 1) + ' Mb/s'; };
  fmt.pad = function (n) { return (n < 10 ? '0' : '') + n; };
  fmt.clock = function (t, withSec) {
    if (t == null || isNaN(t)) return '—';
    var d = new Date(t * 1000);
    var s = fmt.pad(d.getHours()) + ':' + fmt.pad(d.getMinutes());
    return withSec === false ? s : s + ':' + fmt.pad(d.getSeconds());
  };
  fmt.date = function (t) {
    if (t == null || isNaN(t)) return '—';
    var d = new Date(t * 1000);
    return d.getFullYear() + '-' + fmt.pad(d.getMonth() + 1) + '-' + fmt.pad(d.getDate()) + ' ' + fmt.clock(t);
  };
  fmt.dur = function (s) {
    if (s == null || isNaN(s)) return '—';
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + ' s';
    var m = Math.floor(s / 60), h = Math.floor(m / 60);
    if (h) return h + ' h ' + fmt.pad(m % 60) + ' m';
    return m + ' m ' + fmt.pad(s % 60) + ' s';
  };
  fmt.durShort = function (s) {
    if (s == null || isNaN(s)) return '—';
    if (s < 60) return fmt.num(s, 1) + ' s';
    return fmt.dur(s);
  };
  fmt.ago = function (t, now) {
    now = now || Date.now() / 1000;
    return fmt.dur(now - t) + ' ago';
  };
  fmt.conf = function (c) {
    if (c == null) return '—';
    if (typeof c === 'string') return c;
    return Math.round(c * 100) + '%';
  };
  fmt.cls = function (c) { return String(c || 'unknown').replace(/_/g, ' '); };

  LL.ACTIVITY_LABELS = { idle: 'Idle', bf6: 'BF6', rocket_league: 'Rocket League', hbo_max: 'HBO Max', other: 'Other' };
  LL.ACTIVITY_ICONS = { idle: '·', bf6: '🎮', rocket_league: '🚗', hbo_max: '📺', other: '•' };
  LL.actLabel = function (a) { return LL.ACTIVITY_LABELS[a] || String(a || 'idle'); };

  // ---------------------------------------------------------------- colours
  LL.roleColor = function (t) {
    if (!t) return LL.cssVar('--fg-3') || '#888';
    var key = t.key || '', role = t.role || '', kind = t.kind || '';
    var v = function (n) { return LL.cssVar(n) || '#888'; };
    if (role === 'gateway') return key.indexOf('6') >= 0 ? v('--c-inet6') : v('--c-gw');
    if (role === 'xbox') return v('--c-xbox');
    if (role === 'isp_hop') return v('--c-isp');
    if (role === 'mid_hop') return v('--c-mid');
    if (kind === 'ntp') return v('--c-udp');
    if (kind === 'dns') return v('--c-dns');
    if (kind === 'tcp') return v('--c-tcp');
    if (kind === 'cdn') return v('--c-cdn');
    if (t.family === 6) return v('--c-inet6');
    return v('--c-inet4');
  };
  LL.shade = function (hex, alpha) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || '');
    if (!m) return hex;
    return 'rgba(' + parseInt(m[1], 16) + ',' + parseInt(m[2], 16) + ',' + parseInt(m[3], 16) + ',' + alpha + ')';
  };

  // ---------------------------------------------------------------- API
  var api = LL.api = {};
  api.lastOk = 0;
  function headers(extra) {
    var h = { 'Accept': 'application/json' };
    if (LL.token) h['X-LagLens-Token'] = LL.token;
    Object.keys(extra || {}).forEach(function (k) { h[k] = extra[k]; });
    return h;
  }
  function handle(r) {
    return r.text().then(function (txt) {
      var body = null;
      try { body = txt ? JSON.parse(txt) : null; } catch (e) { body = { error: txt.slice(0, 200), code: 'bad_body' }; }
      if (!r.ok) {
        var err = new Error((body && body.error) || ('HTTP ' + r.status));
        err.status = r.status; err.code = body && body.code; err.body = body;
        throw err;
      }
      api.lastOk = Date.now() / 1000;
      return body;
    });
  }
  api.get = function (path) {
    return fetch(path, { headers: headers(), cache: 'no-store' }).then(handle);
  };
  api.post = function (path, body) {
    return fetch(path, { method: 'POST', headers: headers({ 'Content-Type': 'application/json' }), body: JSON.stringify(body || {}) }).then(handle);
  };
  api.text = function (path) {
    return fetch(path, { headers: { 'Accept': 'text/plain' }, cache: 'no-store' }).then(function (r) { return r.text(); });
  };

  // ---------------------------------------------------------------- SSE client
  // LL.sse.connect({onEvent(name, data), onStatus('live'|'reconnecting'|'polling'|'down'), onPoll(state), since})
  LL.SSE_NAMES = ['tick', 'rollup5', 'event', 'episode_open', 'episode_update', 'episode_close', 'mark', 'activity',
    'collector', 'loadtest', 'verdict', 'docsis', 'stopping'];
  LL.sse = {
    BACKOFF: [2000, 5000, 10000],
    POLL_MS: 2000,
    connect: function (opts) {
      opts = opts || {};
      var es = null, failures = 0, timer = null, pollTimer = null, closed = false, status = 'connecting', lastT = opts.since || null;
      var ctl = { status: function () { return status; }, close: function () { closed = true; stop(); }, lastEventAt: 0 };
      function setStatus(s) { if (s !== status) { status = s; if (opts.onStatus) opts.onStatus(s); } }
      function stop() {
        if (es) { try { es.close(); } catch (e) { /* ignore */ } es = null; }
        if (timer) { clearTimeout(timer); timer = null; }
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      }
      function startPolling() {
        if (pollTimer || closed) return;
        setStatus('polling');
        var tick = function () {
          api.get('/api/state').then(function (st) {
            ctl.lastEventAt = Date.now() / 1000;
            if (status !== 'live') setStatus('polling');
            if (opts.onPoll) opts.onPoll(st);
          }).catch(function () { setStatus('down'); });
        };
        tick();
        pollTimer = setInterval(tick, LL.sse.POLL_MS);
      }
      function schedule() {
        if (closed) return;
        var wait = LL.sse.BACKOFF[Math.min(failures, LL.sse.BACKOFF.length - 1)];
        if (failures >= 2) startPolling(); else setStatus('reconnecting');
        timer = setTimeout(open, wait);
      }
      function open() {
        if (closed || typeof EventSource === 'undefined') { if (!closed) startPolling(); return; }
        var url = '/events' + (lastT ? ('?since=' + encodeURIComponent(lastT)) : '');
        try { es = new EventSource(url); } catch (e) { failures++; schedule(); return; }
        var opened = false;
        es.onopen = function () {
          opened = true; failures = 0;
          if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
          setStatus('live');
        };
        es.onerror = function () {
          if (es) { try { es.close(); } catch (e) { /* ignore */ } es = null; }
          failures++;
          if (!opened) failures = Math.max(failures, 1);
          schedule();
        };
        LL.SSE_NAMES.forEach(function (name) {
          es.addEventListener(name, function (ev) {
            var data = null;
            try { data = JSON.parse(ev.data); } catch (e) { data = ev.data; }
            ctl.lastEventAt = Date.now() / 1000;
            if (data && typeof data === 'object' && data.t) lastT = data.t;
            if (opts.onEvent) opts.onEvent(name, data);
            if (name === 'stopping' && es) { try { es.close(); } catch (e) { /* ignore */ } es = null; setStatus('down'); }
          });
        });
      }
      open();
      return ctl;
    }
  };

  // ---------------------------------------------------------------- offline queue
  var QKEY = 'laglens.queue';
  var queue = LL.queue = {
    read: function () {
      try { return JSON.parse(root.localStorage.getItem(QKEY) || '[]') || []; } catch (e) { return []; }
    },
    write: function (items) {
      try { root.localStorage.setItem(QKEY, JSON.stringify(items)); } catch (e) { /* ignore */ }
    },
    push: function (item) {
      var items = queue.read();
      item.t_pressed = item.t_pressed || Date.now() / 1000;
      item.replay = true;
      items.push(item);
      queue.write(items);
      return items.length;
    },
    size: function () { return queue.read().length; },
    flush: function (post) {
      post = post || function (item) { return api.post('/api/mark', item); };
      var items = queue.read();
      if (!items.length) return Promise.resolve(0);
      var sent = 0;
      var next = function () {
        if (!items.length) { queue.write([]); return sent; }
        var item = items[0];
        return post(item).then(function () {
          sent++; items.shift(); queue.write(items); return next();
        });
      };
      return next().catch(function () { queue.write(items); return sent; });
    }
  };

  // ---------------------------------------------------------------- toast
  var toastEl = null, toastTimer = null;
  LL.toast = function (msg, kind, ms) {
    if (!doc) return;
    if (!toastEl) { toastEl = LL.h('div', { class: 'toast' }); doc.body.appendChild(toastEl); }
    toastEl.className = 'toast ' + (kind || '');
    if (typeof msg === 'string') toastEl.textContent = msg; else { LL.clear(toastEl); toastEl.appendChild(msg); }
    toastEl.classList.remove('hidden');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.add('hidden'); }, ms || 6000);
  };
  LL.copy = function (text) {
    if (root.navigator && root.navigator.clipboard && root.navigator.clipboard.writeText) {
      return root.navigator.clipboard.writeText(text).then(function () { LL.toast('Copied', 'ok', 2000); }, function () { fallbackCopy(text); });
    }
    fallbackCopy(text);
    return Promise.resolve();
  };
  function fallbackCopy(text) {
    var ta = LL.h('textarea', { style: { position: 'fixed', left: '-1000px' } });
    ta.value = text; doc.body.appendChild(ta); ta.select();
    try { doc.execCommand('copy'); LL.toast('Copied', 'ok', 2000); } catch (e) { LL.toast('Copy failed — select the text manually', 'bad'); }
    doc.body.removeChild(ta);
  }

  // ---------------------------------------------------------------- "Lag happened" sheet
  // LL.markSheet({activities, current, timeoutMs, onSave(payload)}) → shows a modal with When/What/note,
  // auto-saves with defaults when the countdown runs out.
  LL.markSheet = function (opts) {
    opts = opts || {};
    var activities = opts.activities || ['idle', 'bf6', 'rocket_league', 'hbo_max', 'other'];
    var sel = { offset_s: 0, activity: opts.current || 'idle', note: '' };
    var timeoutMs = opts.timeoutMs == null ? 10000 : opts.timeoutMs;
    var pressedAt = Date.now() / 1000;
    var whens = [[0, 'Just now'], [30, '30 s'], [60, '1 min'], [120, '2 min'], [300, '5 min ago']];
    var whenRow = LL.h('div', { class: 'row' }), whatRow = LL.h('div', { class: 'row' });
    function paint(row, items, cur, key) {
      LL.clear(row);
      items.forEach(function (it) {
        row.appendChild(LL.h('button', { type: 'button', class: it[0] === cur ? 'on' : '', onclick: function () { sel[key] = it[0]; repaint(); } }, it[1]));
      });
    }
    function repaint() {
      paint(whenRow, whens, sel.offset_s, 'offset_s');
      paint(whatRow, activities.map(function (a) { return [a, LL.actLabel(a)]; }), sel.activity, 'activity');
    }
    repaint();
    var note = LL.h('textarea', { placeholder: 'Optional note (what happened?)', rows: 2 });
    var countdown = LL.h('div', { class: 'countdown' });
    var box = LL.h('div', { class: 'box' },
      LL.h('h2', null, 'Lag happened — when?'),
      whenRow, LL.h('h3', null, 'What were you doing?'), whatRow,
      LL.h('h3', null, 'Note'), note, countdown,
      LL.h('div', { class: 'row' },
        LL.h('button', { type: 'button', class: 'primary save', onclick: function () { finish(false); } }, 'Save'),
        LL.h('button', { type: 'button', onclick: function () { close(); } }, 'Cancel')));
    var modal = LL.h('div', { class: (opts.sheet ? 'sheet' : 'modal') }, box);
    doc.body.appendChild(modal);
    var done = false, left = Math.ceil(timeoutMs / 1000), tick = null;
    function close() { done = true; if (tick) clearInterval(tick); if (modal.parentNode) modal.parentNode.removeChild(modal); }
    function finish(auto) {
      if (done) return;
      sel.note = note.value || '';
      var payload = { offset_s: sel.offset_s, activity: sel.activity, note: sel.note, source: opts.source || 'dashboard', t_pressed: pressedAt };
      close();
      if (opts.onSave) opts.onSave(payload, auto);
    }
    if (timeoutMs > 0) {
      countdown.textContent = 'Auto-saves in ' + left + ' s';
      tick = setInterval(function () {
        left--;
        countdown.textContent = 'Auto-saves in ' + left + ' s';
        if (left <= 0) finish(true);
      }, 1000);
    }
    return { close: close, save: function () { finish(false); } };
  };

  // Submit a mark (or queue it when the backend is unreachable). Returns a promise of the response or null.
  LL.submitMark = function (payload, online) {
    if (online === false) {
      var n = queue.push(payload);
      LL.toast('Lag Lens is not reachable — press saved locally (' + n + ' queued), will send when reconnected', 'bad');
      return Promise.resolve(null);
    }
    return api.post('/api/mark', payload).catch(function (err) {
      if (!err.status) { queue.push(payload); LL.toast('Not reachable — press queued (' + queue.size() + ')', 'bad'); return null; }
      throw err;
    });
  };

  // ---------------------------------------------------------------- sparkline
  LL.sparkline = function (canvas, values, color) {
    if (!canvas || !canvas.getContext) return;
    var dpr = root.devicePixelRatio || 1;
    var w = canvas.clientWidth || 160, h = canvas.clientHeight || 34;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    var ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    var vals = (values || []).filter(function (v) { return v != null; });
    if (vals.length < 2) return;
    var max = Math.max.apply(null, vals), min = Math.min.apply(null, vals);
    if (max === min) { max = min + 1; }
    var n = values.length;
    ctx.strokeStyle = color || '#888'; ctx.lineWidth = 1.5; ctx.beginPath();
    var started = false;
    for (var i = 0; i < n; i++) {
      var v = values[i];
      if (v == null) { started = false; continue; }
      var x = (i / Math.max(1, n - 1)) * (w - 2) + 1, y = h - 2 - ((v - min) / (max - min)) * (h - 4);
      if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
    }
    ctx.stroke();
  };

  // ---------------------------------------------------------------- uPlot helpers
  // A ChartGroup owns several uPlot charts that share the x range (synced cursors through
  // uPlot.sync('laglens'), drag-zoom and double-click reset propagated to all), the overlay
  // data (marks, episodes, shading) and range/follow state.
  LL.SYNC_KEY = 'laglens';
  LL.RANGES = [[600, '10m'], [3600, '1h'], [21600, '6h'], [null, 'all']];

  function ChartGroup(opts) {
    opts = opts || {};
    this.charts = [];
    this.range = opts.range || 600;
    this.follow = opts.follow !== false;
    this.logY = false;
    this.overlays = { marks: [], episodes: [], sleep: [], stall: [], load: [], raw: null, late: [] };
    this.onZoom = opts.onZoom || null;      // (min, max, byUser) after a zoom/reset
    this.onFollow = opts.onFollow || null;
    this._propagating = false;
    this.xmin = null; this.xmax = null;
    this.ribbon = null;
    this.sessionStart = opts.sessionStart || null;
  }
  LL.ChartGroup = ChartGroup;

  ChartGroup.prototype.add = function (el, cfg) {
    var chart = new Chart(this, el, cfg);
    this.charts.push(chart);
    return chart;
  };
  ChartGroup.prototype.setX = function (min, max, byUser) {
    if (min == null || max == null || !(max > min)) return;
    this.xmin = min; this.xmax = max;
    if (this._propagating) return;
    this._propagating = true;
    try {
      this.charts.forEach(function (c) { if (c.u) c.u.setScale('x', { min: min, max: max }); });
    } finally { this._propagating = false; }
    if (this.ribbon) this.ribbon.render();
    if (byUser) { this.follow = false; if (this.onFollow) this.onFollow(false); }
    if (this.onZoom) this.onZoom(min, max, !!byUser);
  };
  ChartGroup.prototype.setRange = function (seconds, now) {
    this.range = seconds;
    this.follow = true;
    if (this.onFollow) this.onFollow(true);
    this.followNow(now);
  };
  ChartGroup.prototype.followNow = function (now) {
    now = now || Date.now() / 1000;
    var min = this.range ? now - this.range : (this.sessionStart || (now - 3600));
    this.setX(min, now, false);
  };
  ChartGroup.prototype.setFollow = function (on) { this.follow = !!on; if (this.onFollow) this.onFollow(this.follow); if (on) this.followNow(); };
  ChartGroup.prototype.setLogY = function (on) { this.logY = !!on; this.charts.forEach(function (c) { if (c.cfg.logToggle) c.rebuild(); }); };
  ChartGroup.prototype.redraw = function () { this.charts.forEach(function (c) { if (c.u) c.u.redraw(false); }); if (this.ribbon) this.ribbon.render(); };
  ChartGroup.prototype.destroy = function () { this.charts.forEach(function (c) { c.destroy(); }); this.charts = []; };

  function Chart(group, el, cfg) {
    this.group = group; this.el = el; this.cfg = cfg || {}; this.u = null; this.data = null; this.hidden = {};
    this.build();
  }
  LL.Chart = Chart;

  Chart.prototype.build = function () {
    var self = this, cfg = this.cfg, group = this.group;
    if (typeof uPlot === 'undefined' || !this.el) return;
    var height = cfg.height || 170;
    var series = [{ label: 't' }].concat((cfg.series || []).map(function (s) {
      var d = { label: s.label, stroke: s.stroke, width: s.width || 1.5, scale: s.scale || 'y', show: !self.hidden[s.label],
        dash: s.dash, fill: s.fill, points: s.points || { show: false }, spanGaps: !!s.spanGaps, paths: s.paths };
      if (s.bars) d.paths = uPlot.paths.bars ? uPlot.paths.bars({ size: [0.9, 100] }) : undefined;
      return d;
    }));
    var scales = { x: { time: true } };
    var yLog = cfg.logToggle && group.logY;
    scales.y = yLog ? { distr: 3, log: 10 } : { range: cfg.yRange || function (u, min, max) { return [Math.min(0, min), max == null || max <= 0 ? 1 : max * 1.05]; } };
    if (cfg.scales) Object.keys(cfg.scales).forEach(function (k) { scales[k] = cfg.scales[k]; });
    var axes = [{ stroke: LL.cssVar('--fg-3'), grid: { stroke: LL.shade(LL.cssVar('--line'), 0.6), width: 1 }, ticks: { stroke: LL.cssVar('--line') },
      values: function (u, vals) { return vals.map(function (v) { return fmt.clock(v, (u.scales.x.max - u.scales.x.min) < 1800); }); } }];
    axes.push({ stroke: LL.cssVar('--fg-3'), grid: { stroke: LL.shade(LL.cssVar('--line'), 0.6), width: 1 }, ticks: { stroke: LL.cssVar('--line') }, size: 58,
      label: cfg.yLabel, labelSize: cfg.yLabel ? 16 : 0, values: cfg.yValues || function (u, vals) { return vals.map(function (v) { return fmt.num(v, v >= 10 ? 0 : 1); }); } });
    if (cfg.axes) cfg.axes.forEach(function (a) { axes.push(Object.assign({ stroke: LL.cssVar('--fg-3'), grid: { show: false }, ticks: { stroke: LL.cssVar('--line') } }, a)); });
    var opts = {
      width: Math.max(300, this.el.clientWidth || 600), height: height, series: series, scales: scales, axes: axes,
      legend: { show: false },
      cursor: { sync: { key: LL.SYNC_KEY, setSeries: false }, drag: { x: true, y: false, setScale: true }, points: { size: 6 } },
      hooks: {
        setScale: [function (u, key) {
          if (key !== 'x' || group._propagating) return;
          var sc = u.scales.x;
          if (sc.min == null || sc.max == null) return;
          if (group.xmin != null && Math.abs(sc.min - group.xmin) < 1e-6 && Math.abs(sc.max - group.xmax) < 1e-6) return;
          group.setX(sc.min, sc.max, true);
        }],
        draw: [function (u) { self.drawOverlays(u); }]
      },
      plugins: cfg.plugins || []
    };
    if (cfg.opts) Object.keys(cfg.opts).forEach(function (k) { opts[k] = cfg.opts[k]; });
    var data = this.data || [[]].concat((cfg.series || []).map(function () { return []; }));
    this.u = new uPlot(opts, data, this.el);
    if (group.xmin != null && group.xmax != null) this.u.setScale('x', { min: group.xmin, max: group.xmax });
    if (!Chart._resizeBound && root.addEventListener) {
      Chart._resizeBound = true;
      root.addEventListener('resize', function () { LL._groups.forEach(function (g) { g.charts.forEach(function (c) { c.resize(); }); }); });
    }
  };
  LL._groups = [];
  Chart.prototype.resize = function () {
    if (!this.u || !this.el) return;
    var w = Math.max(300, this.el.clientWidth || 600);
    if (w !== this.u.width) this.u.setSize({ width: w, height: this.u.height });
    if (this.group.ribbon) this.group.ribbon.render();
  };
  Chart.prototype.destroy = function () { if (this.u) { this.u.destroy(); this.u = null; } };
  Chart.prototype.rebuild = function () { var data = this.data; this.destroy(); LL.clear(this.el); this.data = data; this.build(); };
  Chart.prototype.setData = function (data) {
    this.data = data;
    if (!this.u) return;
    this.u.setData(data, false);
    if (this.group.xmin != null) this.u.setScale('x', { min: this.group.xmin, max: this.group.xmax });
    else this.u.redraw(false);
  };
  Chart.prototype.toggle = function (label, show) {
    var self = this;
    this.hidden[label] = !show;
    if (!this.u) return;
    this.u.series.forEach(function (s, i) { if (i && s.label === label) self.u.setSeries(i, { show: !!show }); });
  };

  // Draw marks (dashed lines + activity icon), Xbox-asleep / host-stall / load-test shading,
  // the raw-sample overlay and late markers on the chart canvas.
  Chart.prototype.drawOverlays = function (u) {
    var ov = this.group.overlays, ctx = u.ctx, bb = u.bbox, cfg = this.cfg;
    if (!bb || !ctx) return;
    var x0 = bb.left, x1 = bb.left + bb.width, y0 = bb.top, y1 = bb.top + bb.height;
    var xmin = u.scales.x.min, xmax = u.scales.x.max;
    function xp(t) { return u.valToPos(t, 'x', true); }
    ctx.save();
    ctx.beginPath(); ctx.rect(x0, y0, bb.width, bb.height); ctx.clip();
    var shades = [['sleep', LL.cssVar('--shade-sleep')], ['stall', LL.cssVar('--shade-stall')], ['load', LL.cssVar('--shade-load')]];
    shades.forEach(function (sh) {
      var list = ov[sh[0]] || [];
      if (!list.length) return;
      ctx.fillStyle = sh[1] || 'rgba(128,128,128,0.2)';
      list.forEach(function (span) {
        if (span[1] < xmin || span[0] > xmax) return;
        var a = xp(Math.max(span[0], xmin)), b = xp(Math.min(span[1], xmax));
        ctx.fillRect(a, y0, Math.max(1, b - a), bb.height);
      });
    });
    if (cfg.episodeShade !== false) {
      (ov.episodes || []).forEach(function (ep) {
        var t1 = ep.t1 == null ? xmax : ep.t1;
        if (t1 < xmin || ep.t0 > xmax) return;
        var a = xp(Math.max(ep.t0, xmin)), b = xp(Math.min(t1, xmax));
        ctx.fillStyle = ep.selected ? 'rgba(79,140,255,0.22)' : 'rgba(244,63,94,0.10)';
        ctx.fillRect(a, y0, Math.max(2, b - a), bb.height);
      });
    }
    var dpr = root.devicePixelRatio || 1;
    (ov.marks || []).forEach(function (m) {
      var t = m.t_est != null ? m.t_est : m.t;
      if (t < xmin || t > xmax) return;
      var x = xp(t);
      ctx.strokeStyle = LL.cssVar('--fg') || '#fff'; ctx.lineWidth = 1 * dpr; ctx.setLineDash([4 * dpr, 4 * dpr]);
      ctx.beginPath(); ctx.moveTo(x, y0); ctx.lineTo(x, y1); ctx.stroke(); ctx.setLineDash([]);
      if (cfg.markIcons) {
        ctx.font = (11 * dpr) + 'px ' + (LL.cssVar('--font') || 'sans-serif'); ctx.fillStyle = LL.cssVar('--fg') || '#fff';
        ctx.fillText(LL.ACTIVITY_ICONS[m.activity] || '•', x + 3 * dpr, y0 + 12 * dpr);
      }
    });
    if (cfg.raw && ov.raw && ov.raw.rows && ov.raw.rows.length) {
      var colors = ov.raw.colors || {};
      ov.raw.rows.forEach(function (r) {
        var t = r[0] / 1000;
        if (t < xmin || t > xmax) return;
        var x = xp(t), flags = r[3], v = r[4];
        var col = colors[r[1]] || '#999';
        if (flags & 1) { // lost: red tick at the bottom
          ctx.strokeStyle = LL.cssVar('--bad') || '#f43f5e'; ctx.lineWidth = 1.5 * dpr;
          ctx.beginPath(); ctx.moveTo(x, y1 - 10 * dpr); ctx.lineTo(x, y1); ctx.stroke();
          return;
        }
        if (flags & 4 || v < 0) return;
        var y = u.valToPos(v / 1000, 'y', true);
        if (y < y0 || y > y1) return;
        ctx.beginPath(); ctx.arc(x, y, 2.2 * dpr, 0, Math.PI * 2);
        if (flags & 2) { ctx.strokeStyle = col; ctx.lineWidth = 1 * dpr; ctx.stroke(); } else { ctx.fillStyle = col; ctx.fill(); }
      });
    }
    if (cfg.lateMarkers && ov.late && ov.late.length) {
      ctx.strokeStyle = LL.cssVar('--warn') || '#f5b400'; ctx.lineWidth = 1 * dpr;
      ov.late.forEach(function (p) {
        if (p[0] < xmin || p[0] > xmax) return;
        var x = xp(p[0]), y = u.valToPos(p[1], 'y', true);
        if (y < y0 || y > y1) return;
        ctx.beginPath(); ctx.arc(x, y, 3 * dpr, 0, Math.PI * 2); ctx.stroke();
      });
    }
    ctx.restore();
  };

  // Event ribbon: episode blocks (class-coloured) + mark lines + sleep/stall shading, aligned to the group's x range.
  function Ribbon(group, el, opts) {
    this.group = group; this.el = el; this.opts = opts || {}; group.ribbon = this;
  }
  LL.Ribbon = Ribbon;
  Ribbon.prototype.render = function () {
    var g = this.group, el = this.el, self = this;
    if (!el || g.xmin == null) return;
    LL.clear(el);
    var ref = g.charts.length ? g.charts[0].u : null;
    var dpr = root.devicePixelRatio || 1;
    var left = ref && ref.bbox ? ref.bbox.left / dpr : 58, width = ref && ref.bbox ? ref.bbox.width / dpr : (el.clientWidth - 70);
    el.style.marginLeft = left + 'px';
    el.style.width = Math.max(50, width) + 'px';
    var span = g.xmax - g.xmin;
    function px(t) { return Math.max(0, Math.min(width, ((t - g.xmin) / span) * width)); }
    (g.overlays.sleep || []).forEach(function (s) { addShade(s, 'sleep'); });
    (g.overlays.stall || []).forEach(function (s) { addShade(s, 'stall'); });
    function addShade(s, cls) {
      if (s[1] < g.xmin || s[0] > g.xmax) return;
      var d = LL.h('div', { class: 'shade ' + cls }); d.style.left = px(s[0]) + 'px'; d.style.width = Math.max(1, px(s[1]) - px(s[0])) + 'px'; el.appendChild(d);
    }
    (g.overlays.episodes || []).forEach(function (ep) {
      var t1 = ep.t1 == null ? g.xmax : ep.t1;
      if (t1 < g.xmin || ep.t0 > g.xmax) return;
      var d = LL.h('div', { class: 'blk ' + (ep['class'] || 'unknown') + (ep.selected ? ' sel' : ''), title: fmt.clock(ep.t0) + ' ' + fmt.cls(ep['class']) + ' ' + fmt.durShort(ep.dur_s), onclick: function () { if (self.opts.onEpisode) self.opts.onEpisode(ep); } });
      d.style.left = px(ep.t0) + 'px'; d.style.width = Math.max(3, px(t1) - px(ep.t0)) + 'px';
      if (ep.selected) d.style.outline = '2px solid ' + (LL.cssVar('--accent') || '#4f8cff');
      el.appendChild(d);
    });
    (g.overlays.marks || []).forEach(function (m) {
      var t = m.t_est != null ? m.t_est : m.t;
      if (t < g.xmin || t > g.xmax) return;
      var d = LL.h('div', { class: 'mk', title: 'Mark ' + m.id + ' ' + fmt.clock(t) + (m.note ? ' — ' + m.note : ''), dataset: { icon: LL.ACTIVITY_ICONS[m.activity] || '•' }, onclick: function () { if (self.opts.onMark) self.opts.onMark(m); } });
      d.style.left = px(t) + 'px'; el.appendChild(d);
    });
    if (!el.childNodes.length) el.appendChild(LL.h('span', { class: 'lbl' }, 'no events in view'));
  };

  // Build the x/y arrays for a chart from a /api/series body and a list of column pickers.
  // pickers: [{get: (series) => array}]; returns [t, ...arrays] with null gaps preserved.
  LL.seriesData = function (S, pickers) {
    var t = S && S.t ? S.t : [];
    var out = [t];
    pickers.forEach(function (p) {
      var arr = null;
      try { arr = p(S); } catch (e) { arr = null; }
      if (!arr || arr.length !== t.length) arr = t.map(function () { return null; });
      out.push(arr);
    });
    return out;
  };
  // Spans [t0,t1] where pred(value) holds over an aligned array.
  LL.spans = function (t, arr, pred) {
    var out = [], start = null;
    for (var i = 0; i < t.length; i++) {
      var on = pred(arr ? arr[i] : null);
      if (on && start == null) start = t[i];
      if (!on && start != null) { out.push([start, t[i]]); start = null; }
    }
    if (start != null) out.push([start, t[t.length - 1] + (t.length > 1 ? t[1] - t[0] : 5)]);
    return out;
  };
  // Merge a newer /api/series chunk into an existing one (same res); drops points before keepFrom.
  LL.mergeSeries = function (base, chunk, keepFrom) {
    if (!base || !base.t || !base.t.length) return chunk;
    if (!chunk || !chunk.t || !chunk.t.length || chunk.res !== base.res) return base;
    var idx = {}; base.t.forEach(function (t, i) { idx[t] = i; });
    var out = JSON.parse(JSON.stringify(base));
    function walk(dst, src) {
      Object.keys(src).forEach(function (k) {
        if (k === 't' || k === 'from' || k === 'to' || k === 'res') return;
        var v = src[k];
        if (Array.isArray(v) && v.length === chunk.t.length) {
          if (!Array.isArray(dst[k])) dst[k] = out.t.map(function () { return null; });
          chunk.t.forEach(function (t, i) {
            var j = idx[t];
            if (j == null) { j = out.t.length; out.t.push(t); idx[t] = j; growAll(out, j); }
            dst[k][j] = v[i];
          });
        } else if (v && typeof v === 'object') {
          if (!dst[k] || typeof dst[k] !== 'object') dst[k] = Array.isArray(v) ? [] : {};
          walk(dst[k], v);
        }
      });
    }
    function growAll(obj, len) {
      Object.keys(obj).forEach(function (k) {
        if (k === 't') return;
        var v = obj[k];
        if (Array.isArray(v)) { while (v.length <= len) v.push(null); }
        else if (v && typeof v === 'object') growAll(v, len);
      });
    }
    walk(out, chunk);
    // sort by t (chunks normally append) and trim
    var order = out.t.map(function (t, i) { return [t, i]; }).sort(function (a, b) { return a[0] - b[0]; });
    var keep = order.filter(function (p) { return keepFrom == null || p[0] >= keepFrom; }).map(function (p) { return p[1]; });
    function reorder(obj) {
      Object.keys(obj).forEach(function (k) {
        var v = obj[k];
        if (Array.isArray(v) && v.length === out.t.length && k !== 't') obj[k] = keep.map(function (i) { return v[i]; });
        else if (v && typeof v === 'object' && !Array.isArray(v)) reorder(v);
      });
    }
    var tOld = out.t;
    reorder(out);
    out.t = keep.map(function (i) { return tOld[i]; });
    out.to = chunk.to; out.from = keepFrom != null ? keepFrom : base.from;
    return out;
  };

  // Which resolution a visible span should use (SPEC §8.3): <=2 h 1 s, beyond 5 s.
  LL.resFor = function (spanS) { return spanS <= 7200 ? 1 : 5; };

  // Health score helper (SPEC §7.8) over rollup-style stats of the reference set.
  LL.healthScore = function (lossPct, p95, p50, jitter, episodeMinutes, xboxLoss) {
    var h = 100;
    h -= Math.min(40, 20 * (lossPct || 0));
    h -= Math.min(25, Math.max(0, ((p95 || 0) - (p50 || 0) - 10)) / 4);
    h -= Math.min(15, (jitter || 0) / 2);
    h -= Math.min(20, (episodeMinutes || 0) / 6);
    h -= Math.min(20, 40 * (xboxLoss || 0));
    return Math.max(0, Math.round(h));
  };

  root.LL = LL;
  if (typeof module !== 'undefined' && module.exports) module.exports = LL;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
