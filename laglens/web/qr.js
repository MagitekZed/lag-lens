/* Lag Lens — tiny QR encoder (byte mode, versions 1–10, EC level M with L fallback).
 *
 * Pure JS, no dependencies, works in the browser and in node (module.exports).
 *
 *   LagLensQR.encode(text, {ecl: 'M'|'L'}) -> {version, size, ecl, mask, modules: bool[size][size]}
 *   LagLensQR.render(canvasOrDiv, text, pixelSize) -> the element (canvas drawn, or div filled with cells)
 *   LagLensQR.toMatrix(text)                 -> string[] of '#'/'.' rows (debugging / tests)
 *
 * Implements ISO/IEC 18004: Reed–Solomon over GF(256) (0x11D), block interleaving,
 * the 8 mask patterns with penalty scoring (N1..N4), format info (BCH 15,5) and
 * version info (BCH 18,6) for versions 7–10, and a 4-module quiet zone when rendering.
 */
(function (root) {
  'use strict';

  // --- tables (index = version; [0] unused) ---------------------------------------------
  var ECC_PER_BLOCK = {
    L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
    M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26]
  };
  var NUM_BLOCKS = {
    L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
    M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5]
  };
  var ECL_BITS = { L: 1, M: 0, Q: 3, H: 2 };
  var MAX_VERSION = 10;

  // --- GF(256) ---------------------------------------------------------------------------
  var EXP = new Array(512), LOG = new Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x; LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    for (var j = 255; j < 512; j++) EXP[j] = EXP[j - 255];
  })();
  function gfMul(a, b) { return (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]]; }

  function rsGenerator(degree) {
    var g = [1];
    for (var i = 0; i < degree; i++) {
      var next = new Array(g.length + 1);
      for (var k = 0; k < next.length; k++) next[k] = 0;
      for (var j = 0; j < g.length; j++) {
        next[j] ^= g[j];
        next[j + 1] ^= gfMul(g[j], EXP[i]);
      }
      g = next;
    }
    return g;
  }

  function rsRemainder(data, gen) {
    var res = new Array(gen.length - 1);
    for (var i = 0; i < res.length; i++) res[i] = 0;
    for (var d = 0; d < data.length; d++) {
      var factor = data[d] ^ res[0];
      res.shift(); res.push(0);
      for (var j = 0; j < gen.length - 1; j++) res[j] ^= gfMul(gen[j + 1], factor);
    }
    return res;
  }

  // --- capacity --------------------------------------------------------------------------
  function rawDataModules(ver) {
    var r = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var n = Math.floor(ver / 7) + 2;
      r -= (25 * n - 10) * n - 55;
      if (ver >= 7) r -= 36;
    }
    return r;
  }
  function rawCodewords(ver) { return Math.floor(rawDataModules(ver) / 8); }
  function dataCodewords(ver, ecl) { return rawCodewords(ver) - ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver]; }
  function countBits(ver) { return ver <= 9 ? 8 : 16; }

  function utf8Bytes(str) {
    var out = [];
    var s = unescape(encodeURIComponent(String(str)));
    for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xFF);
    return out;
  }

  function chooseVersion(nbytes, ecl) {
    for (var v = 1; v <= MAX_VERSION; v++) {
      var need = 4 + countBits(v) + 8 * nbytes;
      if (need <= dataCodewords(v, ecl) * 8) return v;
    }
    return 0;
  }

  // --- bit buffer ------------------------------------------------------------------------
  function BitBuf() { this.bits = []; }
  BitBuf.prototype.push = function (val, n) {
    for (var i = n - 1; i >= 0; i--) this.bits.push((val >>> i) & 1);
  };

  function buildCodewords(bytes, ver, ecl) {
    var bb = new BitBuf();
    bb.push(4, 4);                   // byte mode
    bb.push(bytes.length, countBits(ver));
    for (var i = 0; i < bytes.length; i++) bb.push(bytes[i], 8);
    var cap = dataCodewords(ver, ecl) * 8;
    bb.push(0, Math.min(4, cap - bb.bits.length));       // terminator
    while (bb.bits.length % 8 !== 0) bb.bits.push(0);
    var pads = [0xEC, 0x11], p = 0;
    while (bb.bits.length < cap) { bb.push(pads[p], 8); p ^= 1; }
    var data = [];
    for (var b = 0; b < bb.bits.length; b += 8) {
      var v = 0;
      for (var k = 0; k < 8; k++) v = (v << 1) | bb.bits[b + k];
      data.push(v);
    }
    // split into blocks, add ECC, interleave
    var nb = NUM_BLOCKS[ecl][ver], ecc = ECC_PER_BLOCK[ecl][ver], raw = rawCodewords(ver);
    var shortBlocks = nb - raw % nb, shortLen = Math.floor(raw / nb);
    var gen = rsGenerator(ecc), blocks = [], off = 0;
    for (var bi = 0; bi < nb; bi++) {
      var len = shortLen - ecc + (bi < shortBlocks ? 0 : 1);
      var chunk = data.slice(off, off + len); off += len;
      var rem = rsRemainder(chunk, gen);
      if (bi < shortBlocks) chunk.push(-1);     // placeholder keeps column indices aligned
      blocks.push(chunk.concat(rem));
    }
    var out = [];
    for (var col = 0; col < blocks[0].length; col++) {
      for (var row = 0; row < blocks.length; row++) {
        if (col === shortLen - ecc && row < shortBlocks) continue;   // skip the placeholder
        out.push(blocks[row][col]);
      }
    }
    return out;
  }

  // --- matrix ----------------------------------------------------------------------------
  function Matrix(size) {
    this.size = size;
    this.m = []; this.f = [];
    for (var y = 0; y < size; y++) {
      var r = [], fr = [];
      for (var x = 0; x < size; x++) { r.push(false); fr.push(false); }
      this.m.push(r); this.f.push(fr);
    }
  }
  Matrix.prototype.setF = function (x, y, dark) { this.m[y][x] = !!dark; this.f[y][x] = true; };

  function alignmentPositions(ver) {
    if (ver === 1) return [];
    var n = Math.floor(ver / 7) + 2, size = ver * 4 + 17;
    var step = (ver === 32) ? 26 : Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2;
    var res = [6];
    for (var pos = size - 7; res.length < n; pos -= step) res.splice(1, 0, pos);
    return res;
  }

  function drawFinder(mx, cx, cy) {
    for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
      var d = Math.max(Math.abs(dx), Math.abs(dy)), x = cx + dx, y = cy + dy;
      if (x >= 0 && x < mx.size && y >= 0 && y < mx.size) mx.setF(x, y, d !== 2 && d !== 4);
    }
  }
  function drawAlignment(mx, cx, cy) {
    for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++)
      mx.setF(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  function getBit(v, i) { return ((v >>> i) & 1) !== 0; }

  function drawFormat(mx, ecl, mask) {
    var data = (ECL_BITS[ecl] << 3) | mask, rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ 0x5412, s = mx.size;
    for (var a = 0; a <= 5; a++) mx.setF(8, a, getBit(bits, a));
    mx.setF(8, 7, getBit(bits, 6)); mx.setF(8, 8, getBit(bits, 7)); mx.setF(7, 8, getBit(bits, 8));
    for (var b = 9; b < 15; b++) mx.setF(14 - b, 8, getBit(bits, b));
    for (var c = 0; c < 8; c++) mx.setF(s - 1 - c, 8, getBit(bits, c));
    for (var d = 8; d < 15; d++) mx.setF(8, s - 15 + d, getBit(bits, d));
    mx.setF(8, s - 8, true);   // the always-dark module
  }

  function drawVersion(mx, ver) {
    if (ver < 7) return;
    var rem = ver;
    for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
    var bits = (ver << 12) | rem, s = mx.size;
    for (var k = 0; k < 18; k++) {
      var bit = getBit(bits, k), a = s - 11 + k % 3, b = Math.floor(k / 3);
      mx.setF(a, b, bit); mx.setF(b, a, bit);
    }
  }

  function drawFunctionPatterns(mx, ver, ecl) {
    var s = mx.size;
    for (var i = 0; i < s; i++) { mx.setF(6, i, i % 2 === 0); mx.setF(i, 6, i % 2 === 0); }
    drawFinder(mx, 3, 3); drawFinder(mx, s - 4, 3); drawFinder(mx, 3, s - 4);
    var ap = alignmentPositions(ver), n = ap.length;
    for (var a = 0; a < n; a++) for (var b = 0; b < n; b++) {
      if ((a === 0 && b === 0) || (a === 0 && b === n - 1) || (a === n - 1 && b === 0)) continue;
      drawAlignment(mx, ap[a], ap[b]);
    }
    drawFormat(mx, ecl, 0);   // reserves the format areas; redrawn with the real mask later
    drawVersion(mx, ver);
  }

  function placeData(mx, codewords) {
    var s = mx.size, i = 0, total = codewords.length * 8;
    for (var right = s - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < s; vert++) {
        for (var j = 0; j < 2; j++) {
          var x = right - j, upward = ((right + 1) & 2) === 0, y = upward ? s - 1 - vert : vert;
          if (!mx.f[y][x] && i < total) {
            mx.m[y][x] = getBit(codewords[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  function maskBit(mask, x, y) {
    switch (mask) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
      case 5: return (x * y) % 2 + (x * y) % 3 === 0;
      case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
      default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
    }
  }
  function applyMask(mx, mask) {
    for (var y = 0; y < mx.size; y++) for (var x = 0; x < mx.size; x++)
      if (!mx.f[y][x] && maskBit(mask, x, y)) mx.m[y][x] = !mx.m[y][x];
  }

  function finderPenalty(run) {   // run = [light, dark, light, dark, light, dark, light] history
    var n = run[1];
    return (n > 0 && run[2] === n && run[3] === n * 3 && run[4] === n && run[5] === n &&
      (run[0] >= 4 * n || run[6] >= 4 * n)) ? 1 : 0;
  }

  function penalty(mx) {
    var s = mx.size, score = 0, x, y;
    // N1 + N3 per row and column
    for (y = 0; y < s; y++) {
      var runColor = false, runLen = 0, hist = [0, 0, 0, 0, 0, 0, 0];
      for (x = 0; x < s; x++) {
        var c = mx.m[y][x];
        if (c === runColor) { runLen++; if (runLen === 5) score += 3; else if (runLen > 5) score++; }
        else {
          hist.shift(); hist.push(runLen);
          if (!runColor) score += finderPenalty(hist) * 40;
          runColor = c; runLen = 1;
        }
      }
      hist.shift(); hist.push(runLen); if (!runColor) score += finderPenalty(hist) * 40;
      hist.shift(); hist.push(4); if (runColor) score += finderPenalty(hist) * 40;
    }
    for (x = 0; x < s; x++) {
      var runColor2 = false, runLen2 = 0, hist2 = [0, 0, 0, 0, 0, 0, 0];
      for (y = 0; y < s; y++) {
        var c2 = mx.m[y][x];
        if (c2 === runColor2) { runLen2++; if (runLen2 === 5) score += 3; else if (runLen2 > 5) score++; }
        else {
          hist2.shift(); hist2.push(runLen2);
          if (!runColor2) score += finderPenalty(hist2) * 40;
          runColor2 = c2; runLen2 = 1;
        }
      }
      hist2.shift(); hist2.push(runLen2); if (!runColor2) score += finderPenalty(hist2) * 40;
      hist2.shift(); hist2.push(4); if (runColor2) score += finderPenalty(hist2) * 40;
    }
    // N2: 2x2 blocks
    for (y = 0; y < s - 1; y++) for (x = 0; x < s - 1; x++) {
      var v = mx.m[y][x];
      if (v === mx.m[y][x + 1] && v === mx.m[y + 1][x] && v === mx.m[y + 1][x + 1]) score += 3;
    }
    // N4: dark proportion
    var dark = 0;
    for (y = 0; y < s; y++) for (x = 0; x < s; x++) if (mx.m[y][x]) dark++;
    var total = s * s, k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    score += Math.max(0, k) * 10;
    return score;
  }

  // --- API -------------------------------------------------------------------------------
  function encode(text, opts) {
    opts = opts || {};
    var want = (opts.ecl || 'M').toUpperCase(), bytes = utf8Bytes(text);
    var ecl = want, ver = chooseVersion(bytes.length, ecl);
    if (!ver && ecl === 'M') { ecl = 'L'; ver = chooseVersion(bytes.length, ecl); }
    if (!ver) throw new Error('LagLensQR: text too long for version ' + MAX_VERSION + ' (' + bytes.length + ' bytes)');
    var codewords = buildCodewords(bytes, ver, ecl), size = ver * 4 + 17;
    var mx = new Matrix(size);
    drawFunctionPatterns(mx, ver, ecl);
    placeData(mx, codewords);
    var best = -1, bestScore = Infinity, forced = (typeof opts.mask === 'number') ? opts.mask : -1;
    for (var mask = 0; mask < 8; mask++) {
      if (forced >= 0 && mask !== forced) continue;
      applyMask(mx, mask); drawFormat(mx, ecl, mask);
      var sc = penalty(mx);
      if (sc < bestScore) { bestScore = sc; best = mask; }
      applyMask(mx, mask);   // undo (XOR)
    }
    applyMask(mx, best); drawFormat(mx, ecl, best);
    return { version: ver, size: size, ecl: ecl, mask: best, modules: mx.m, functions: mx.f, penalty: bestScore,
      codewords: codewords };
  }

  function toMatrix(text, opts) {
    var q = encode(text, opts), rows = [];
    for (var y = 0; y < q.size; y++) {
      var line = '';
      for (var x = 0; x < q.size; x++) line += q.modules[y][x] ? '#' : '.';
      rows.push(line);
    }
    return rows;
  }

  var QUIET = 4;
  function render(el, text, pixelSize) {
    var q = encode(text), px = pixelSize || 4, total = (q.size + QUIET * 2) * px;
    var isCanvas = el && typeof el.getContext === 'function';
    if (isCanvas) {
      el.width = total; el.height = total;
      el.style.width = total + 'px'; el.style.height = total + 'px';
      var ctx = el.getContext('2d');
      ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, total, total);
      ctx.fillStyle = '#000000';
      for (var y = 0; y < q.size; y++) for (var x = 0; x < q.size; x++)
        if (q.modules[y][x]) ctx.fillRect((x + QUIET) * px, (y + QUIET) * px, px, px);
    } else if (el) {
      el.innerHTML = '';
      el.style.display = 'grid';
      el.style.gridTemplateColumns = 'repeat(' + q.size + ', ' + px + 'px)';
      el.style.padding = (QUIET * px) + 'px';
      el.style.background = '#fff';
      el.style.width = (q.size * px) + 'px';
      for (var yy = 0; yy < q.size; yy++) for (var xx = 0; xx < q.size; xx++) {
        var cell = el.ownerDocument.createElement('span');
        cell.style.width = px + 'px'; cell.style.height = px + 'px';
        cell.style.background = q.modules[yy][xx] ? '#000' : '#fff';
        el.appendChild(cell);
      }
    }
    if (el && el.setAttribute) el.setAttribute('aria-label', 'QR code for ' + text);
    return el;
  }

  var api = { encode: encode, render: render, toMatrix: toMatrix, QUIET_ZONE: QUIET, MAX_VERSION: MAX_VERSION,
    _internal: { rawCodewords: rawCodewords, dataCodewords: dataCodewords, alignmentPositions: alignmentPositions, penalty: penalty } };
  root.LagLensQR = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
