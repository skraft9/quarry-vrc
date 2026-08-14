/* Front end. The product name is NOT hardcoded here - it arrives from GET /api/health
   as `app_name` and is applied to the title, brand and login card at boot. See RENAME.md.
 *
 * Vanilla JS. No framework, no build step, no network dependencies.
 * Built strictly against API.md. Loaded from <head> (not deferred) so the stored
 * theme lands on <html> before first paint; everything else waits for DOMContentLoaded.
 *
 * CSP: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
 *      connect-src 'self'.  => no inline script, no <style>, no style="" attributes.
 *      Bar widths are set through the CSSOM (node.style.width = ...), which CSP does not
 *      police; setAttribute('style', ...) is never used.
 *
 * XSS: every string that reaches innerHTML goes through escapeHTML() first. The ONLY
 *      producer of markup is renderMarkdown() below. Everywhere else uses textContent.
 */
(function () {
  'use strict';

  /* ================================================================== theme
     Runs during <head> parsing. documentElement exists; body does not. */

  var THEME_KEY = 'hp.theme';

  function readTheme() {
    try { return localStorage.getItem(THEME_KEY) || 'auto'; } catch (e) { return 'auto'; }
  }

  function applyTheme(mode) {
    if (mode === 'light' || mode === 'dark') {
      document.documentElement.setAttribute('data-theme', mode);
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }

  applyTheme(readTheme());

  /* ================================================================== utils */

  function $(sel, root) { return (root || document).querySelector(sel); }

  function append(parent, kids) {
    if (kids === null || kids === undefined || kids === false || kids === true) return parent;
    if (Array.isArray(kids)) {
      for (var i = 0; i < kids.length; i++) append(parent, kids[i]);
      return parent;
    }
    if (kids instanceof Node) { parent.appendChild(kids); return parent; }
    parent.appendChild(document.createTextNode(String(kids)));
    return parent;
  }

  /* el('div', {class:'x', text:'hi', onclick:fn}, [children])
     `html` is accepted for ONE purpose: pre-escaped markdown from renderMarkdown(). */
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        var v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'text') n.textContent = String(v);
        else if (k === 'html') n.innerHTML = v;
        else if (k === 'class') n.className = v;
        else if (k === 'dataset') { for (var d in v) n.dataset[d] = v[d]; }
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') n.addEventListener(k.slice(2), v);
        else if (v === true) n.setAttribute(k, '');
        else n.setAttribute(k, String(v));
      }
    }
    append(n, kids);
    return n;
  }

  function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); return n; }

  function frag(kids) { var f = document.createDocumentFragment(); append(f, kids); return f; }

  /* Clickable rows: keep them reachable from the keyboard. */
  function activatable(node, fn) {
    node.tabIndex = 0;
    node.setAttribute('role', 'button');
    node.addEventListener('click', fn);
    node.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(e); }
    });
    return node;
  }

  /* Phone widths. The same breakpoint app.css uses for the whole mobile layout, named once here
     so the two cannot drift. Read live rather than cached: rotating the phone crosses it without
     a reload. Nothing outside this predicate branches on width - the layout is CSS. */
  var NARROW_QUERY = '(max-width: 768px)';

  function isNarrow() {
    return !!(window.matchMedia && window.matchMedia(NARROW_QUERY).matches);
  }

  function fmtBytes(n) {
    if (n === null || n === undefined || n === '') return '';
    var b = Number(n);
    if (!isFinite(b)) return String(n);
    if (b < 1024) return b + ' B';
    var u = ['KB', 'MB', 'GB', 'TB'], i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return (b >= 10 ? b.toFixed(0) : b.toFixed(1)) + ' ' + u[i];
  }

  function pad2(n) { return (n < 10 ? '0' : '') + n; }

  /* mtime arrives as an epoch float (filesystem) or an ISO string (DB columns). */
  /* The server writes NAIVE timestamps in UTC: "2026-07-31T03:37:01", no offset, no Z
     (common.now_iso uses time.localtime on a UTC host). JavaScript parses a date-TIME string
     with no designator as LOCAL time, so a browser behind UTC reads every server timestamp as
     being in the future - which is why "last run" sat at "0s ago" forever instead of counting
     up. Append the Z only when the string carries no zone of its own; values that already come
     from the HackerOne API ("...T02:17:57.338Z") must be left alone. */
  function parseServerTime(v) {
    if (v === null || v === undefined || v === '') return NaN;
    var str = String(v).trim().replace(' ', 'T');
    if (!/[Zz]$|[+-]\d{2}:?\d{2}$/.test(str)) str += 'Z';
    return Date.parse(str);
  }

  function fmtTime(v) {
    if (v === null || v === undefined || v === '') return '';
    if (typeof v === 'number' || /^\d+(\.\d+)?$/.test(String(v))) {
      var d = new Date(Number(v) * 1000);
      if (isNaN(d.getTime())) return String(v);
      return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
        ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
    }
    return String(v).replace('T', ' ');
  }

  function fmtDateOnly(v) { return fmtTime(v).slice(0, 10); }

  /* How long since a timestamp, in one or two characters plus a unit. The Tracker's question is
     "which of these has gone quiet", and a date alone does not answer it without arithmetic -
     scanning 157 rows of `2026-06-14` to find the stale ones is work the column should do.
     Measured against the SERVER clock (serverSkewMs), because a laptop with a wrong clock would
     otherwise report every report as stale or none of them. */
  function ageShort(v) {
    var t = parseServerTime(v);
    if (isNaN(t)) return '';
    var ms = (Date.now() + serverSkewMs) - t;
    if (ms < 0) ms = 0;
    var mins = Math.floor(ms / 60000);
    if (mins < 60) return mins + 'm';
    var hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h';
    var days = Math.floor(hrs / 24);
    if (days < 14) return days + 'd';
    if (days < 60) return Math.floor(days / 7) + 'w';
    if (days < 730) return Math.floor(days / 30) + 'mo';
    return Math.floor(days / 365) + 'y';
  }

  /* Staleness bands, deliberately coarse. A report touched this week is live, one untouched for
     a month is worth a nudge, and anything past a quarter has been forgotten by someone. */
  function ageClass(v) {
    var t = parseServerTime(v);
    if (isNaN(t)) return 'age-none';
    var days = ((Date.now() + serverSkewMs) - t) / 86400000;
    if (days <= 7) return 'age-fresh';
    if (days <= 30) return 'age-warm';
    if (days <= 90) return 'age-cool';
    return 'age-stale';
  }

  /* `last_activity` is `last_activity_at or last_program_activity_at`, coalesced at sync time -
     see HACKERONE_API.md. The list endpoint leaves the first empty on essentially every report,
     so the program-activity timestamp is the one that actually carries the signal. */
  function lastActivityCell(r) {
    var v = r.last_activity;
    var age = ageShort(v);
    if (!age) return el('span', { class: 'muted', text: '—', title: 'HackerOne reported no activity timestamp' });
    return el('span', {
      class: 'agecell ' + ageClass(v),
      text: age,
      title: 'Last touched by HackerOne or the vendor: ' + fmtTime(v) + ' UTC'
    });
  }

  function pick(row, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = row[keys[i]];
      if (v !== null && v !== undefined && v !== '') return v;
    }
    return '';
  }

  function qsFrom(obj) {
    var u = new URLSearchParams();
    for (var k in obj) {
      if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
      var v = obj[k];
      if (v === null || v === undefined || v === '') continue;
      u.set(k, String(v));
    }
    return u.toString();
  }

  /* ================================================================ markdown
     Small, self-contained. Escape first, then format. Never sees raw HTML through. */

  function escapeHTML(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function unescapeHTML(s) {
    return String(s)
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&amp;/g, '&');
  }

  /* Only http(s)/mailto/anchor/relative URLs survive. javascript:, data:, vbscript: are dropped. */
  function safeURL(raw) {
    var u = String(raw || '').trim();
    if (!u) return null;
    if (/^[a-z0-9+.-]*[\x00- ]*:/i.test(u)) {
      if (!/^(https?|mailto|ftp):/i.test(u)) return null;
    }
    if (/[\x00-\x1f]/.test(u)) return null;
    return u;
  }

  function renderInline(src) {
    var codes = [];
    var s = escapeHTML(src);

    /* inline code first, so its contents are inert for every later rule */
    s = s.replace(/(`+)([\s\S]+?)\1/g, function (m, ticks, code) {
      codes.push('<code>' + code.replace(/^ | $/g, '') + '</code>');
      return '\x00' + (codes.length - 1) + '\x00';
    });

    /* [[wikilink]] -> internal search for the slug */
    s = s.replace(/\[\[([^\]\n|]+)(?:\|([^\]\n]+))?\]\]/g, function (m, target, label) {
      var slug = unescapeHTML(target).trim();
      var shown = (label !== undefined && label !== null && label !== '') ? label : target;
      return '<a class="wikilink" href="#/search?' + escapeHTML(qsFrom({ q: slug })) + '">' + shown + '</a>';
    });

    /* [text](url "optional title") */
    s = s.replace(/\[([^\]\n]*)\]\(\s*([^)\s]+)(?:\s+(?:&quot;|&#39;)[^)]*(?:&quot;|&#39;))?\s*\)/g,
      function (m, label, url) {
        var u = safeURL(unescapeHTML(url));
        if (!u) return label;
        var ext = /^(https?|mailto|ftp):/i.test(u);
        return '<a href="' + escapeHTML(u) + '"' +
          (ext ? ' target="_blank" rel="noopener noreferrer"' : '') + '>' + (label || escapeHTML(u)) + '</a>';
      });

    /* bare autolinks (not already inside an href="...") */
    s = s.replace(/(^|[\s(<])(https?:\/\/[^\s<>()"']+)/g, function (m, pre, url) {
      return pre + '<a href="' + escapeHTML(unescapeHTML(url)) + '" target="_blank" rel="noopener noreferrer">' + url + '</a>';
    });

    s = s.replace(/\*\*([^\n]+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[^\w\\])__([^\n_]+?)__(?!\w)/g, '$1<strong>$2</strong>');
    s = s.replace(/(^|[^*\w\\])\*([^*\n]+?)\*(?!\*)/g, '$1<em>$2</em>');
    s = s.replace(/(^|[^\w\\_])_([^_\n]+?)_(?!\w)/g, '$1<em>$2</em>');
    s = s.replace(/~~([^~\n]+?)~~/g, '<del>$1</del>');

    s = s.replace(/\x00(\d+)\x00/g, function (m, i) { return codes[Number(i)]; });
    return s;
  }

  function isBlockStart(line) {
    return /^\s{0,3}(#{1,6}\s|>|`{3,}|~{3,}|([-*+]|\d{1,9}[.)])\s)/.test(line) ||
      /^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$/.test(line);
  }

  function parseItem(line) {
    var m = /^(\s*)(?:([-*+])|(\d{1,9})[.)])\s+(.*)$/.exec(line);
    if (!m) return null;
    return {
      indent: m[1].replace(/\t/g, '    ').length,
      ordered: !!m[3],
      num: m[3] || null,
      text: m[4]
    };
  }

  function renderList(lines, i) {
    var first = parseItem(lines[i]);
    var ordered = first.ordered;
    var tag = ordered ? 'ol' : 'ul';
    var items = [];
    var cur = null;

    while (i < lines.length) {
      var line = lines[i];
      if (/^\s*$/.test(line)) {
        var j = i + 1;
        while (j < lines.length && /^\s*$/.test(lines[j])) j++;
        var nxt = j < lines.length ? parseItem(lines[j]) : null;
        if (nxt && nxt.indent >= first.indent) { i = j; continue; }
        break;
      }
      var it = parseItem(line);
      if (it) {
        if (it.indent >= first.indent + 2) {
          var sub = renderList(lines, i);
          if (!cur) { cur = { text: [], html: [], task: null }; items.push(cur); }
          cur.html.push(sub.html);
          i = sub.i;
          continue;
        }
        if (it.indent < first.indent || it.ordered !== ordered) break;
        cur = { text: [it.text], html: [], task: null };
        var t = /^\[([ xX])\]\s*(.*)$/.exec(it.text);
        if (t) { cur.task = t[1].toLowerCase() === 'x'; cur.text = [t[2]]; }
        items.push(cur);
        i++;
        continue;
      }
      if (cur && /^\s+\S/.test(line) && !isBlockStart(line)) { cur.text.push(line.trim()); i++; continue; }
      break;
    }

    var start = (ordered && first.num && first.num !== '1') ? ' start="' + parseInt(first.num, 10) + '"' : '';
    var body = items.map(function (item) {
      var box = '';
      var cls = '';
      if (item.task !== null) {
        cls = ' class="task"';
        box = '<span class="tag">' + (item.task ? 'x' : '&nbsp;&nbsp;') + '</span> ';
      }
      /* Same CommonMark rule as the paragraph branch: a wrapped list item is gathered into
         item.text one continuation line at a time, and joining those with <br> broke every
         wrapped bullet at its source column. A `## Next` section full of two-line bullets is
         where this showed. Two trailing spaces still force a break. */
      var inner = renderInline(item.text.join('\n'))
        .replace(/ {2,}\n/g, '<br>')
        .replace(/\n/g, ' ');
      return '<li' + cls + '>' + box + inner + item.html.join('') + '</li>';
    }).join('');

    return { html: '<' + tag + start + '>' + body + '</' + tag + '>', i: i };
  }

  function splitTableRow(line) {
    var s = line.trim();
    if (s.charAt(0) === '|') s = s.slice(1);
    if (s.charAt(s.length - 1) === '|' && s.charAt(s.length - 2) !== '\\') s = s.slice(0, -1);
    return s.split('|').map(function (c) { return c.trim(); });
  }

  function isTableSep(line) {
    return line.indexOf('|') >= 0 &&
      /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/.test(line);
  }

  /* `Label: value` with a short label. The label class is deliberately narrow so a sentence
     that merely contains a colon, or a bare URL, cannot pose as a field. */
  var FIELD_LINE_RE = /^\s*(?:\*\*)?([A-Z][A-Za-z0-9 /_.-]{0,24})(?:\*\*)?:[ \t]+(\S.*)$/;

  /* Every hunt note opens with a header block:

       Researcher: yourhandle | Date: 2026-01-01 | Target: SomeProduct 1.2.3 @ https://...
       Source: ~/someproduct @ tag v1.2.3 (abcd1234...)
       Class: broken access control, privilege escalation (manage to read). Not DoS.
       PoC: bin/downsample_target_permission_poc.py (23 assertions, self-verifying, exit 0)

     As a paragraph that renders as a <br>-joined wall with the field names buried mid-line.
     A list makes it scannable and lines the names up.

     Two guards against eating ordinary prose: the whole paragraph must be fields (one bad line
     and it stays a paragraph), and it must be at least two lines, so a lone "Purpose: ..."
     sentence is left alone. ' | ' packs several fields onto one line and is split only when
     every piece on that line is itself a field, which leaves prose like
     "legend: [VERIFIED] ... | [SWEEP] ..." whole. */
  function fieldBlock(lines) {
    if (lines.length < 2) return null;
    var items = [];
    for (var i = 0; i < lines.length; i++) {
      var parts = lines[i].split(/[ \t]+\|[ \t]+/);
      for (var j = 0; j < parts.length; j++) {
        var m = FIELD_LINE_RE.exec(parts[j]);
        if (!m) return null;
        items.push(m);
      }
    }
    return '<ul class="fields">' + items.map(function (m) {
      return '<li><span class="fk">' + renderInline(m[1]) + '</span>' + renderInline(m[2]) + '</li>';
    }).join('') + '</ul>';
  }

  function renderMarkdown(src) {
    var lines = String(src === null || src === undefined ? '' : src).replace(/\r\n?/g, '\n').split('\n');
    var out = [];
    var i = 0;

    while (i < lines.length) {
      var line = lines[i];

      /* fenced code */
      var fence = /^\s{0,3}(`{3,}|~{3,})\s*([\w.+-]*)\s*$/.exec(line);
      if (fence) {
        var mark = fence[1].charAt(0);
        var buf = [];
        i++;
        while (i < lines.length && !new RegExp('^\\s{0,3}' + (mark === '`' ? '`{3,}' : '~{3,}') + '\\s*$').test(lines[i])) {
          buf.push(lines[i]); i++;
        }
        if (i < lines.length) i++;
        out.push('<pre class="code"><code>' + escapeHTML(buf.join('\n')) + '</code></pre>');
        continue;
      }

      if (/^\s*$/.test(line)) { i++; continue; }

      var h = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
      if (h) {
        var lvl = h[1].length;
        out.push('<h' + lvl + '>' + renderInline(h[2]) + '</h' + lvl + '>');
        i++;
        continue;
      }

      if (/^\s{0,3}(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) { out.push('<hr>'); i++; continue; }

      if (/^\s{0,3}>/.test(line)) {
        var qbuf = [];
        while (i < lines.length && (/^\s{0,3}>/.test(lines[i]) || (qbuf.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i])))) {
          qbuf.push(lines[i].replace(/^\s{0,3}>\s?/, ''));
          i++;
        }
        out.push('<blockquote>' + renderMarkdown(qbuf.join('\n')) + '</blockquote>');
        continue;
      }

      if (line.indexOf('|') >= 0 && i + 1 < lines.length && isTableSep(lines[i + 1])) {
        var head = splitTableRow(line);
        i += 2;
        var rows = [];
        while (i < lines.length && lines[i].indexOf('|') >= 0 && !/^\s*$/.test(lines[i])) {
          rows.push(splitTableRow(lines[i]));
          i++;
        }
        var thtml = '<div class="tablewrap"><table><thead><tr>' +
          head.map(function (c) { return '<th>' + renderInline(c) + '</th>'; }).join('') +
          '</tr></thead><tbody>' +
          rows.map(function (r) {
            return '<tr>' + r.map(function (c) { return '<td>' + renderInline(c) + '</td>'; }).join('') + '</tr>';
          }).join('') +
          '</tbody></table></div>';
        out.push(thtml);
        continue;
      }

      if (parseItem(line)) {
        var lst = renderList(lines, i);
        out.push(lst.html);
        i = lst.i;
        continue;
      }

      var pbuf = [];
      while (i < lines.length && !/^\s*$/.test(lines[i]) && !(pbuf.length && isBlockStart(lines[i]))) {
        pbuf.push(lines[i]);
        i++;
        if (i < lines.length && isBlockStart(lines[i])) break;
      }
      var fb = fieldBlock(pbuf);
      if (fb) { out.push(fb); continue; }
      /* CommonMark soft line breaks: a single newline inside a paragraph is a SPACE, not a
         forced break. Emitting <br> for every newline meant a paragraph hard-wrapped in the
         source rendered broken at whatever column it was wrapped at - which is every lead body
         in the corpus, since the files are wrapped for readability in an editor. Fixing the
         renderer fixes ~200 files at once and leaves the research markdown untouched, which
         matters because that markdown is the authority and this is only a view of it.

         A hard break is still available the standard way, two trailing spaces, so anything that
         genuinely needs one keeps it. */
      out.push('<p>' + renderInline(pbuf.join('\n'))
        .replace(/ {2,}\n/g, '<br>')
        .replace(/\n/g, ' ') + '</p>');
    }

    return out.join('\n');
  }

  /* Rendered markdown block. The only innerHTML consumer in the app. */
  var LEADING_H1_RE = /^\s*#\s+[^\n]*\n+/;

  function mdBlock(src, extraClass, stripTitle) {
    var body = String(src === null || src === undefined ? '' : src);
    /* ingest stores the first heading in `header` AND leaves it at the top of `body`, so a lead
       pane rendered the title twice: once as the pane heading and again as an <h1> above the
       header table. Strip it at render time rather than at index time - the markdown file is the
       authority and a title is what makes it a lead. */
    if (stripTitle) body = body.replace(LEADING_H1_RE, '');
    if (!body.trim()) return el('div', { class: 'empty', text: 'No content.' });
    var node = el('div', { class: 'md' + (extraClass ? ' ' + extraClass : ''), html: renderMarkdown(body) });
    addCodeCopyButtons(node);
    return node;
  }

  /* A lead that carries a command exists to have that command RUN, and selecting a fenced block
     by hand is where the copy goes wrong - a trailing backslash continuation copied out of a
     wrapped block once produced `Option '--server.headless' requires an argument`. Every fenced
     block in rendered markdown gets a copy button, rather than commands being special-cased,
     because deciding what "is a command" is a guess and the button is harmless on prose.

     Reads textContent, so it copies what is DISPLAYED - the renderer has already escaped the
     source, and nothing here puts anything back into the DOM as markup. */
  function addCodeCopyButtons(node) {
    var blocks = node.querySelectorAll ? node.querySelectorAll('pre') : [];
    for (var i = 0; i < blocks.length; i++) {
      (function (pre) {
        if (pre.querySelector('.codecopy')) return;
        var btn = el('button', {
          class: 'btn btn-sm codecopy', type: 'button', title: 'Copy this block'
        }, [el('span', { text: 'Copy' })]);
        btn.addEventListener('click', function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          /* Same rule as copyButton: confirm through the toast, never by mutating the label. */
          copyText(pre.textContent || '').then(function () {
            toast('Copied code block', 'ok');
          }).catch(function () { toast('Could not copy code block', 'err'); });
        });
        pre.classList.add('has-copy');
        pre.appendChild(btn);
      })(blocks[i]);
    }
  }

  /* ===================================================================== api */

  var API = '/api';

  function ApiError(status, message, body) {
    var e = new Error(message || ('HTTP ' + status));
    e.name = 'ApiError';
    e.status = status;
    e.body = body || null;
    return e;
  }

  function statusText(status, path) {
    if (status === 0) return 'Cannot reach the server. Is the server running, and is the certificate accepted?';
    if (status === 403) return 'Forbidden (403). Read-scope credentials, or a missing ' + CSRF_HEADER + ' header.';
    if (status === 404) return 'Not found (404): ' + path + ' — this endpoint may not be implemented yet.';
    if (status === 405) return 'Method not allowed (405): ' + path;
    if (status >= 500) return 'Server error (' + status + ') on ' + path;
    return 'Request failed (' + status + ') on ' + path;
  }

  var onUnauthorized = function () {};

  var CSRF_HEADER = 'X-App-CSRF';   /* must match common.CSRF_HEADER */

  function api(path, opts) {
    opts = opts || {};
    var method = opts.method || 'GET';
    var headers = { 'Accept': 'application/json' };
    var body;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    if (method !== 'GET' && method !== 'HEAD') headers[CSRF_HEADER] = '1';

    return fetch(API + path, {
      method: method,
      headers: headers,
      body: body,
      credentials: 'same-origin',
      cache: 'no-store'
    }).catch(function (e) {
      throw ApiError(0, statusText(0, path) + ' (' + e.message + ')');
    }).then(function (res) {
      var ct = res.headers.get('content-type') || '';
      var reader = ct.indexOf('json') >= 0 ? res.json() : res.text();
      return reader.catch(function () { return null; }).then(function (data) {
        if (res.status === 401) {
          if (!opts.noAuthRedirect) onUnauthorized();
          throw ApiError(401, (data && data.error) || 'Not authenticated.');
        }
        if (!res.ok) {
          var msg = (data && typeof data === 'object' && data.error) ? data.error : statusText(res.status, path);
          throw ApiError(res.status, msg, data);
        }
        return data;
      });
    });
  }

  /* Multipart upload with progress: fetch() cannot report upload progress, XHR can. */
  function uploadFile(file, fileTo, kind, onProgress) {
    return new Promise(function (resolve, reject) {
      var fd = new FormData();
      fd.append('file', file, file.name);
      if (fileTo) fd.append('file_to', fileTo);
      if (kind) fd.append('kind', kind);

      var xhr = new XMLHttpRequest();
      xhr.open('POST', API + '/upload', true);
      xhr.withCredentials = true;
      xhr.setRequestHeader(CSRF_HEADER, '1');
      xhr.setRequestHeader('Accept', 'application/json');
      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
      });
      xhr.addEventListener('load', function () {
        var data = null;
        try { data = JSON.parse(xhr.responseText); } catch (e) { /* non-JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) { resolve(data || {}); return; }
        if (xhr.status === 401) { onUnauthorized(); reject(ApiError(401, 'Not authenticated.')); return; }
        reject(ApiError(xhr.status, (data && data.error) || statusText(xhr.status, '/upload')));
      });
      xhr.addEventListener('error', function () { reject(ApiError(0, statusText(0, '/upload'))); });
      xhr.addEventListener('abort', function () { reject(ApiError(0, 'Upload aborted.')); });
      xhr.send(fd);
    });
  }

  /* =================================================================== state */

  var state = {
    user: null,
    targets: [],
    targetsLoaded: false,
    route: { view: 'dashboard', id: null, q: new URLSearchParams() },
    /* Server build, from GET /api/health. One source of truth: server.py VERSION. */
    version: '',
    lastNewToken: null,
    /* Payload categories, cached so the filter is populated before the first response lands. */
    payloadCategories: [],
    /* Same treatment for the Tracker's program picker. */
    programs: [],
    programsLoaded: false
  };

  function loadPrograms(force) {
    if (state.programsLoaded && !force) return Promise.resolve(state.programs);
    return api('/programs?limit=200').then(function (data) {
      state.programs = (data && data.items) || [];
      state.programsLoaded = true;
      return state.programs;
    }).catch(function () {
      state.programs = [];
      state.programsLoaded = true;
      return state.programs;
    });
  }

  function programOptions() {
    var opts = [{ value: ALL_PROGRAMS, label: 'All programs' }];
    state.programs.slice().sort(function (a, b) {
      return String(a.name || a.slug).localeCompare(String(b.name || b.slug));
    }).forEach(function (p) {
      if (p.slug) opts.push({ value: p.slug, label: p.name || p.slug });
    });
    return opts;
  }

  /* The add-program picker. Searches every program the HackerOne credential can see - including the
     private/invited ones that never appear in your reports - and onboards the one you pick. `onAdded`
     re-loads the Programs list so the new row appears with its synced details. Built as an inline
     panel rather than a modal, matching the app's no-overlay style. */
  function buildAddProgramPanel(onAdded) {
    var panel = el('div', { class: 'card add-program' });
    var input = el('input', {
      type: 'search', spellcheck: 'false',
      placeholder: 'Search your HackerOne programs by name or handle (private included)…'
    });
    var results = el('div', { class: 'add-program-results' });
    panel.appendChild(el('div', { class: 'add-program-head' }, [
      el('span', { class: 'field-label', text: 'Add a program from HackerOne' }), input
    ]));
    panel.appendChild(results);

    function addRow(p) {
      var badge = p.state === 'public_mode'
        ? el('span', { class: 'pill pill-open', text: 'public' })
        : el('span', { class: 'pill pill-neutral', text: 'private' });
      var action;
      if (p.tracked) {
        action = el('span', { class: 'pill pill-parked', text: 'tracked' });
      } else {
        action = el('button', { class: 'btn btn-sm', type: 'button', text: 'Add' });
        action.addEventListener('click', function () {
          action.disabled = true; action.textContent = 'Adding…';
          api('/integrations/hackerone/programs', { method: 'POST', body: { handle: p.handle } })
            .then(function () {
              toast('Added ' + (p.name || p.handle), 'ok');
              action.replaceWith(el('span', { class: 'pill pill-confirmed', text: 'added' }));
              if (onAdded) onAdded();
            })
            .catch(function (e) {
              action.disabled = false; action.textContent = 'Add';
              toast('Could not add: ' + ((e && e.message) || e), 'err');
            });
        });
      }
      return el('div', { class: 'add-program-row' }, [
        el('div', { class: 'add-program-name' }, [
          el('span', { class: 'apn-title', text: p.name || p.handle }), badge,
          p.offers_bounties ? el('span', { class: 'pill pill-confirmed', text: 'bounty' }) : null
        ]),
        el('code', { class: 'add-program-handle', text: p.handle }),
        action
      ]);
    }

    var timer = null;
    function search() {
      var q = input.value.trim();
      clear(results); results.appendChild(loading('Searching your HackerOne programs…'));
      api('/integrations/hackerone/programs' + (q ? '?q=' + encodeURIComponent(q) : ''))
        .then(function (d) {
          clear(results);
          var items = (d && d.items) || [];
          if (!items.length) {
            results.appendChild(empty('No programs match', 'Try a different name or handle.'));
            return;
          }
          if (d.total > d.shown) {
            results.appendChild(el('div', { class: 'tiny dim add-program-more',
              text: 'Showing ' + d.shown + ' of ' + d.total + ' - narrow the search to see the rest.' }));
          }
          items.forEach(function (p) { results.appendChild(addRow(p)); });
        })
        .catch(function (e) {
          clear(results);
          /* The one that actually happens: no credential yet. Say so plainly. */
          var msg = (e && e.status === 400) ? 'Connect your HackerOne account in Integrations first.'
                                            : ('Could not load programs: ' + ((e && e.message) || e));
          results.appendChild(el('div', { class: 'alert alert-warn', text: msg }));
        });
    }
    input.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(search, 300); });
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { clearTimeout(timer); search(); } });
    search();   // empty query lists the first page immediately
    return panel;
  }

  function loadTargets(force) {
    if (state.targetsLoaded && !force) return Promise.resolve(state.targets);
    return api('/targets?limit=500').then(function (data) {
      state.targets = (data && data.items) || [];
      state.targetsLoaded = true;
      return state.targets;
    }).catch(function () {
      state.targets = [];
      state.targetsLoaded = true;
      return state.targets;
    });
  }

  function targetLabel(row) {
    if (!row) return '';
    /* `asset_label` is derived server-side from the lead's own `Target` row and normalised to the
       HackerOne asset name - one row for four drivers otherwise. Server-side for both list and
       detail, because parsing it in the browser printed the whole row, lab conditions included. */
    if (row.asset_label) return String(row.asset_label);
    var direct = pick(row, ['target', 'target_slug', 'target_name']);
    if (direct) return String(direct);
    if (row.target_id) {
      for (var i = 0; i < state.targets.length; i++) {
        if (String(state.targets[i].id) === String(row.target_id)) {
          return state.targets[i].slug || state.targets[i].name || ('#' + row.target_id);
        }
      }
      return '#' + row.target_id;
    }
    return '';
  }

  /* ================================================================= toasts */

  function toast(message, kind) {
    var host = $('#toasts');
    if (!host) return;
    var node = el('div', { class: 'toast' + (kind ? ' ' + kind : '') }, [
      el('span', { text: message }),
      el('button', { type: 'button', 'aria-label': 'Dismiss', text: '×', onclick: function () { node.remove(); } })
    ]);
    host.appendChild(node);
    setTimeout(function () { node.remove(); }, kind === 'err' ? 9000 : 5000);
  }

  function toastError(err) {
    toast((err && err.message) || 'Something went wrong.', 'err');
  }

  /* ============================================================ components */

  function loading(msg) {
    return el('div', { class: 'loading' }, [
      el('div', { class: 'spinner', 'aria-hidden': 'true' }),
      el('div', { text: msg || 'Loading…' })
    ]);
  }

  function empty(title, sub) {
    return el('div', { class: 'empty' }, [
      el('strong', { class: 'empty-title', text: title }),
      sub ? el('span', { text: sub }) : null
    ]);
  }

  function errorPanel(err, retry) {
    return el('div', { class: 'alert alert-error' }, [
      el('strong', { class: 'alert-title', text: 'Request failed' + (err && err.status ? ' (' + err.status + ')' : '') }),
      el('span', { text: (err && err.message) || String(err) }),
      retry ? el('div', {}, el('button', { class: 'btn btn-sm', type: 'button', text: 'Retry', onclick: retry })) : null
    ]);
  }

  var KNOWN_PILLS = ['open', 'confirmed', 'ready', 'submitted', 'awarded', 'parked', 'killed',
                     'unknown'];

  function pillClass(value) {
    var s = String(value || '').toLowerCase().trim();
    if (KNOWN_PILLS.indexOf(s) >= 0) return 'pill pill-' + s;
    if (s === 'resolved') return 'pill pill-submitted';
    if (s === 'triaged' || s === 'retesting' || s === 'relevant' || s === 'accepted') return 'pill pill-confirmed';
    if (s === 'new' || s === 'watch' || s === 'pending') return 'pill pill-open';
    if (s === 'duplicate' || s === 'n/a' || s === 'n-a' || s === 'informative' || s === 'spam') return 'pill pill-killed';
    if (s === 'dismissed' || s === 'closed') return 'pill pill-parked';
    if (!s) return 'pill pill-unknown';
    return 'pill pill-neutral';
  }

  function pill(value) {
    var v = String(value === null || value === undefined || value === '' ? 'unknown' : value);
    return el('span', { class: pillClass(v), text: v });
  }

  function tag(value) {
    if (value === null || value === undefined || value === '') return el('span', { class: 'muted', text: '—' });
    return el('span', { class: 'tag', text: String(value) });
  }

  /* HackerOne asset types, humanised. The API's set is OPEN - it gains entries whenever
     HackerOne adds an asset kind - so this is a display lookup and NOT a whitelist:
     assetTypeLabel falls through to the raw value for anything not listed, because a scope
     rendering as its SCREAMING_CASE type is readable, and a scope rendering as blank is a lie
     about what is in scope. */
  var ASSET_TYPE_LABELS = {
    URL: 'URL',
    WILDCARD: 'Wildcard',
    CIDR: 'CIDR',
    IP_ADDRESS: 'IP address',
    SOURCE_CODE: 'Source code',
    DOWNLOADABLE_EXECUTABLES: 'Executable',
    GOOGLE_PLAY_APP_ID: 'Android app',
    APPLE_STORE_APP_ID: 'iOS app',
    WINDOWS_APP_STORE_APP_ID: 'Windows app',
    OTHER_APK: 'Android APK',
    OTHER_IPA: 'iOS IPA',
    TESTFLIGHT: 'TestFlight',
    HARDWARE: 'Hardware',
    AI_MODEL: 'AI model',
    SMART_CONTRACT: 'Smart contract',
    OTHER: 'Other'
  };

  function assetTypeLabel(raw) {
    var key = (raw === null || raw === undefined) ? '' : String(raw).trim();
    if (!key) return '';
    /* hasOwnProperty, not a bare lookup: 'constructor' and 'toString' are values the API could
       in principle send, and an inherited Object.prototype member is not a label. */
    if (Object.prototype.hasOwnProperty.call(ASSET_TYPE_LABELS, key)) return ASSET_TYPE_LABELS[key];
    return key;
  }

  function extLink(url, label) {
    var u = safeURL(url);
    if (!u) return el('span', { text: label || '' });
    return el('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: label || u });
  }

  /* cols: [{key,label,sort,cls,render(row)}]
     opts.cards turns the table into one card per row at phone widths - see the .tablewrap.cards
     rules in app.css. Opt-in rather than automatic: a card is the right shape for a list you read
     (Leads, Tracker, Programs, the audit trail) and the wrong one for a dense reference table
     like the file browser, which keeps the horizontal-scroll fallback. */
  function dataTable(cols, rows, opts) {
    opts = opts || {};
    var thead = el('tr', {}, cols.map(function (c) {
      var inner;
      var sortable = !!(c.sort && opts.onSort);
      if (sortable) {
        var active = opts.sort === c.sort || opts.sort === '-' + c.sort;
        var desc = opts.sort === '-' + c.sort;
        inner = el('button', {
          class: 'sortbtn', type: 'button',
          title: 'Sort by ' + c.label,
          /* An ACTIVE column toggles its current direction. An INACTIVE one takes its default:
             ascending, except a `descFirst` (numeric) column opens on the largest value, because
             "which program paid the most" wants the top of the list, not the bottom - a first
             click that buries the $24k row under a column of dashes reads as broken. */
          onclick: function () {
            var next;
            if (active) next = desc ? c.sort : '-' + c.sort;
            else next = c.descFirst ? '-' + c.sort : c.sort;
            opts.onSort(next);
          }
        }, [c.label, active ? el('span', { class: 'arrow', text: desc ? ' ↓' : ' ↑' }) : null]);
      } else {
        inner = document.createTextNode(c.label);
      }
      /* th-sort marks the headers that carry a sort control. In card mode the header row is
         redrawn as a strip of sort chips, and the plain labels are dropped from it - without a
         class there is no selector for "this th is a button" that older Safari can read. */
      var thCls = (sortable ? 'th-sort ' : '') + (c.cls || '');
      return el('th', { class: thCls.trim() || null }, inner);
    }));

    var tbody = el('tbody', {}, rows.map(function (row) {
      var tr = el('tr', {}, cols.map(function (c) {
        var v = c.render ? c.render(row) : (row[c.key] === null || row[c.key] === undefined ? '' : String(row[c.key]));
        /* data-col is what redact mode targets. Tagging the cell here rather than at each of
           the fourteen column definitions means a table added later is covered for free.
           data-label is the same idea for card mode: the header row is hidden there, so each
           cell has to carry its own column name to print in front of the value.
           An empty value is appended as nothing rather than as an empty text node, so `:empty`
           matches and a card does not print a label with no value after it. */
        return el('td', {
          class: c.cls || null, 'data-col': c.key || null, 'data-label': c.label || null
        }, v === '' ? null : v);
      }));
      if (opts.rowClass) {
        var rc = opts.rowClass(row);
        if (rc) tr.className = rc;
      }
      if (opts.onRow && !(opts.rowDisabled && opts.rowDisabled(row))) {
        tr.classList.add('clickable');
        activatable(tr, function () { opts.onRow(row); });
      }
      if (opts.selectedId !== undefined && opts.selectedId !== null &&
        String(row[opts.idKey || 'id']) === String(opts.selectedId)) tr.classList.add('selected');
      return tr;
    }));

    return el('div', { class: 'tablewrap' + (opts.cards ? ' cards' : '') },
      el('table', { class: 'data' }, [el('thead', {}, thead), tbody]));
  }

  function pagerBar(total, limit, offset, onOffset, onLimit) {
    var shownFrom = total === 0 ? 0 : offset + 1;
    var shownTo = Math.min(offset + limit, total);
    var bar = el('div', { class: 'pager' }, [
      el('span', { text: shownFrom + '–' + shownTo + ' of ' + total }),
      el('span', { class: 'spacer' }),
      el('label', { class: 'tiny dim' }, [
        'Per page ',
        el('select', {
          onchange: function (e) { onLimit(parseInt(e.target.value, 10)); }
        }, [25, 50, 100, 200].map(function (n) {
          return el('option', { value: n, text: String(n), selected: n === limit });
        }))
      ]),
      el('button', {
        class: 'btn btn-sm', type: 'button', text: '‹ Prev',
        disabled: offset <= 0,
        onclick: function () { onOffset(Math.max(0, offset - limit)); }
      }),
      el('button', {
        class: 'btn btn-sm', type: 'button', text: 'Next ›',
        disabled: offset + limit >= total,
        onclick: function () { onOffset(offset + limit); }
      })
    ]);
    return bar;
  }

  function field(label, control, hint) {
    return el('label', { class: 'field' }, [
      el('span', { class: 'field-label', text: label }),
      control,
      hint ? el('span', { class: 'field-hint', text: hint }) : null
    ]);
  }

  function selectEl(options, value, onchange, opts) {
    opts = opts || {};
    var sel = el('select', { onchange: onchange ? function (e) { onchange(e.target.value); } : null });
    options.forEach(function (o) {
      var v = (typeof o === 'object') ? o.value : o;
      var l = (typeof o === 'object') ? o.label : (o === '' ? (opts.blank || 'Any') : o);
      sel.appendChild(el('option', { value: v, text: l, selected: String(v) === String(value === null || value === undefined ? '' : value) }));
    });
    return sel;
  }

  function targetOptions(blankLabel) {
    var opts = [{ value: '', label: blankLabel || 'Any target' }];
    state.targets.forEach(function (t) {
      opts.push({ value: t.slug || String(t.id), label: (t.slug || t.name) + (t.name && t.slug && t.name !== t.slug ? ' — ' + t.name : '') });
    });
    return opts;
  }

  function targetIdOptions() {
    var opts = [{ value: '', label: '— none —' }];
    state.targets.forEach(function (t) {
      opts.push({ value: String(t.id), label: (t.slug || t.name) + (t.version ? ' (' + t.version + ')' : '') });
    });
    return opts;
  }

  /* One clipboard implementation, promised, so a caller that has to FETCH the text first can
     share it with the synchronous buttons. Rejects rather than resolving false, so a failure
     lands in the same .catch as a failed request. */
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    /* clipboard API needs a secure context; self-signed HTTPS qualifies, but --no-tls does not */
    return new Promise(function (resolve, reject) {
      var ta = el('textarea', { class: 'sr-only' });
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
      ok ? resolve() : reject(new Error('clipboard unavailable'));
    });
  }

  /* Every copy in Quarry confirms through the SAME green toast, and the button label never
     changes. Swapping the label to 'Copied' was the old behaviour and it read as a bug: on a wide
     label like 'Copy markdown' the button visibly shrank and then grew back, which looks like it
     vanished rather than like it worked. The toast also survives the button being re-rendered,
     which the label never did.

     The message names WHAT was copied - 'Copied report markdown', not 'Copied' - because these
     buttons sit in a row of four and the confirmation is worthless if it does not say which one
     fired. `noun` is derived from the label so a new copy button gets a correct message for free. */
  function copyNoun(label) {
    var s = String(label || 'Copy').replace(/^Copy\s*/i, '').trim();
    return s ? s.toLowerCase() : 'to clipboard';
  }

  function copyButton(getText, label) {
    var btn = el('button', { class: 'btn btn-sm', type: 'button', text: label || 'Copy' });
    btn.addEventListener('click', function () {
      var noun = copyNoun(label);
      copyText(getText()).then(
        function () { toast('Copied ' + noun, 'ok'); },
        function () { toast('Could not copy ' + noun, 'err'); }
      );
    });
    return btn;
  }

  /* CVSS vectors read as line noise ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H") and wrap
     badly in a meta grid, so detail panes show the decoded words instead. The decoding is done
     once, server-side, by advisories.decode_cvss_vector() and arrives on detail rows as
     `cvss_decoded`; the raw string is kept as the tooltip so nothing is lost. Returns '' when
     absent, which metaGrid drops - an all-None impact prints no row rather than "none". */
  function cvssPart(r, key) {
    var d = r && r.cvss_decoded;
    var v = d && d[key];
    if (v === null || v === undefined || v === '') return '';
    return el('span', { title: r.cvss_vector || '', text: String(v) });
  }

  /* metagrid: [[label, value-node-or-string], ...] */
  function metaGrid(pairs) {
    var kids = [];
    pairs.forEach(function (p) {
      if (!p) return;
      var v = p[1];
      if (v === null || v === undefined || v === '') return;
      kids.push(el('div', {}, [
        el('span', { class: 'k', text: p[0] }),
        el('span', { class: 'v' + (p[2] ? ' ' + p[2] : '') }, v)
      ]));
    });
    if (!kids.length) return null;
    return el('div', { class: 'metagrid' }, kids);
  }

  /* ============================================================ entity config
     Query-string filter names come from API.md (q/target/class/status/limit/offset/sort).
     Request-body field names come from schema.sql. */


  /* Severity band as a coloured pill. Distinct from pill() so advisory levels do not collide
     with lead/report status colours. */
  function sevPill(level) {
    var v = String(level || '').toLowerCase();
    return el('span', { class: 'pill sev-' + (v || 'none'), text: v || 'none' });
  }

  /* An advisory can carry several CVEs; render each as a link to its NVD entry. */
  function cveCell(cve) {
    var list = String(cve || '').split(',').map(function (c) { return c.trim(); })
      .filter(function (c) { return c; });
    if (!list.length) return document.createTextNode('\u2014');
    var wrap = el('span', { class: 'cvelist' });
    list.forEach(function (c, i) {
      if (i) wrap.appendChild(document.createTextNode(' '));
      wrap.appendChild(el('a', {
        class: 'cve', href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c),
        target: '_blank', rel: 'noopener noreferrer', text: c
      }));
    });
    return wrap;
  }

  /* The VulDB feed crams a program's metadata into one `product` string:
     "Vendor: X, Product: Y, Type: Z, Risk: ..., Physical: ..., Local: ..., Remote: ..., ...".
     Only Vendor/Product/Type are worth a column; the rest is noise in a table. Parse by taking
     each label's value up to the next "<Key>:" boundary, so a value containing a comma is not cut
     short. A string with none of these labels (e.g. a CISA advisory) is shown whole under Product. */
  var ADVISORY_META_KEYS = ['Vendor', 'Product', 'Type', 'Risk', 'Physical', 'Local', 'Remote',
                            'Exploit', 'Countermeasures'];
  function parseAdvisoryMeta(product) {
    var out = { vendor: '', product: '', type: '' };
    if (!product) return out;
    var boundary = '(?=,\\s*(?:' + ADVISORY_META_KEYS.join('|') + '):|$)';
    var found = false;
    ADVISORY_META_KEYS.forEach(function (k) {
      var m = String(product).match(new RegExp('(?:^|,\\s*)' + k + ':\\s*(.+?)' + boundary));
      if (!m) return;
      found = true;
      var v = m[1].trim();
      if (k === 'Vendor') out.vendor = v;
      else if (k === 'Product') out.product = v;
      else if (k === 'Type') out.type = v;
    });
    /* No fallback to the raw string: feeds that do not use this labelled format (CISA stores the
       feed name in `product`) carry their vendor/product in the title instead, so leaving the three
       columns blank is honest rather than printing "CISA Advisories" under Product. */
    void found;
    return out;
  }

  /* VulDB titles read "CVE-2026-1234 | the actual title", and the CVE is already its own column,
     so the prefix is printed twice. Strip it, preferring the row's own ref/cve, then fall back to
     stripping any leading "CVE-YYYY-NNN |". */
  function advisoryTitle(r) {
    var t = String((r && r.title) || '').trim();
    var ref = String((r && (r.cve || r.ref)) || '').trim();
    if (ref && t.indexOf(ref) === 0) {
      t = t.slice(ref.length).replace(/^\s*\|\s*/, '');
    } else {
      t = t.replace(/^CVE-\d{4}-\d+\s*\|\s*/i, '');
    }
    return t || '(untitled)';
  }

  /* The feed titles are verbose ("VulDB Recent", "CISA Advisories"); the column wants the source
     itself. */
  function advisorySource(s) {
    s = String(s || '');
    if (/vuldb/i.test(s)) return 'VulDB';
    if (/cisa/i.test(s)) return 'CISA';
    return s;
  }

  /* Weakness class. HackerOne stores it lowercase ('cwe-400'); ExampleVendor advisories store it
     uppercase and sometimes comma-separated. Normalise to CWE-400 and link to MITRE, matching
     cveCell's treatment so the two classification columns read the same. */
  function cweCell(cwe) {
    var list = String(cwe || '').split(',').map(function (c) { return c.trim(); })
      .filter(function (c) { return c; });
    if (!list.length) return document.createTextNode('—');
    var wrap = el('span', { class: 'cvelist' });
    list.forEach(function (c, i) {
      if (i) wrap.appendChild(document.createTextNode(' '));
      var num = /^cwe[-_ ]?(\d{1,5})$/i.exec(c);
      var label = num ? ('CWE-' + num[1]) : c.toUpperCase();
      if (!num) {
        /* A weakness that is not a numbered CWE cannot be linked to MITRE, so it is a plain
           badge rather than a link, but it still reads as a badge next to the ones that are. */
        wrap.appendChild(el('span', { class: 'cwe-badge', text: label }));
        return;
      }
      /* Badge-styled to sit in the row with State / Sev / Impact, but still a link: the whole
         point of the column is one click to the CWE definition on MITRE. */
      wrap.appendChild(el('a', {
        class: 'cwe-badge', href: 'https://cwe.mitre.org/data/definitions/' + num[1] + '.html',
        target: '_blank', rel: 'noopener noreferrer', text: label
      }));
    });
    return wrap;
  }

  /* Privileges-required, read off the decoded CVSS vector the server attaches as
     `cvss_decoded` (advisories.decode_cvss_vector). It answers "who can actually do this" -
     None means unauthenticated - which is the first thing you want to know about a finding and
     is otherwise buried mid-vector. Rows with no vector show a dash; 21 of 111 reports and 119
     of 266 advisories have none, and that gap is real data, not a zero. */
  var PRIV_CLASS = { 'None': 'priv-none', 'Low': 'priv-low', 'High': 'priv-high' };
  /* Compact one-letter badge in the PRIV column (N / L / H); the full word stays in the title. */
  var PRIV_SHORT = { 'None': 'N', 'Low': 'L', 'High': 'H' };

  function privCell(r) {
    var d = r && r.cvss_decoded;
    var v = d && d.privileges;
    if (!v) return el('span', { class: 'muted', text: '—' });
    return el('span', {
      class: 'privpill ' + (PRIV_CLASS[v] || ''),
      title: 'Privileges required: ' + v + (r.cvss_vector ? '\n' + r.cvss_vector : ''),
      text: (PRIV_SHORT[v] || v)
    });
  }

  /* Impact on Confidentiality / Integrity / Availability, read off the same decoded CVSS vector
     as privCell. One coloured letter badge per impacted dimension - C red, I amber, A blue - with
     an up arrow for a High impact and a down arrow for Low. None-scored dimensions are dropped by
     the decoder, so a badge appears only where there IS impact, and a report with all three shows
     three badges. v4 vectors spell the same dimensions VC/VI/VA; both map to the one letter. The
     subsequent-system metrics (SC/SI/SA) are deliberately not shown here - they would double the
     letters - and stay in the detail pane's full impact line. */
  var IMPACT_LETTER = { C: 'C', VC: 'C', I: 'I', VI: 'I', A: 'A', VA: 'A' };
  var IMPACT_CLASS = { C: 'imp-c', I: 'imp-i', A: 'imp-a' };

  function impactCell(r) {
    var d = r && r.cvss_decoded;
    var list = (d && d.impact) || [];
    var badges = [];
    list.forEach(function (im) {
      var letter = IMPACT_LETTER[im.metric];
      if (!letter) return;
      var high = String(im.level) === 'High';
      badges.push(el('span', {
        class: 'impact-badge ' + IMPACT_CLASS[letter],
        title: im.label + ': ' + im.level + (r.cvss_vector ? '\n' + r.cvss_vector : '')
      }, [
        el('span', { class: 'ib-letter', text: letter }),
        el('span', { class: 'ib-arrow', 'aria-hidden': 'true', text: high ? '↑' : '↓' })
      ]));
    });
    if (!badges.length) return el('span', { class: 'muted', text: '—' });
    return el('span', { class: 'impactcell' }, badges);
  }

  /* ------------------------------------------------------------------ money
     Bounties arrive as strings. The HackerOne sync writes "1390.00"; the older hand-maintained
     tracker rows still in the index carry "[amount]", "$0" or "-". Parse defensively, format once. */

  function parseMoney(v) {
    if (v === null || v === undefined || v === '') return null;
    if (typeof v === 'number') return isFinite(v) ? v : null;
    var s = String(v).replace(/[^0-9.-]/g, '');
    if (!s || s === '-' || s === '.' || s === '-.') return null;
    var n = Number(s);
    return isFinite(n) ? n : null;
  }

  /* Thousands separators and exactly two decimals, always. */
  function fmtMoney(v, currency) {
    var n = (typeof v === 'number') ? v : parseMoney(v);
    if (n === null || !isFinite(n)) return '';
    var neg = n < 0;
    var parts = Math.abs(n).toFixed(2).split('.');
    parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    var body = parts.join('.');
    var cur = String(currency || '').toUpperCase();
    if (!cur || cur === 'USD') return (neg ? '-$' : '$') + body;
    return (neg ? '-' : '') + body + ' ' + cur;
  }

  /* ------------------------------------------------------- report state/role
     HackerOne report states (HACKERONE_API.md §7). `state` is authoritative - it comes from the
     API, not from parsing prose. resolved reads as a win, triaged as in flight, new as waiting on
     the program. The closed-without-action states are deliberately grey rather than red: they are
     outcomes, not errors, and colouring 80% of the tracker red makes the table unreadable. */
  /* Each report state gets its OWN class, so the Tracker's State pill can carry HackerOne's
     palette (user correction 2026-08-03). Several of these used to share `st-muted` with a KILLED
     lead, and recolouring a shared class would have dragged the lead pills along with them. Lead
     statuses keep the app's own semantic scale and are deliberately untouched. */
  var REPORT_STATE_CLASS = {
    'resolved': 'st-resolved',
    'triaged': 'st-triaged',
    /* A fix has shipped and is being verified. The last in-flight state, and the closest one to a
       win that is not yet a win, so it reads like triaged rather than like resolved. */
    'retesting': 'st-retesting',
    'new': 'st-new',
    'pending-program-review': 'st-pending-program-review',
    'duplicate': 'st-duplicate',
    'informative': 'st-informative',
    'not-applicable': 'st-not-applicable',
    'n/a': 'st-muted',
    'n-a': 'st-muted',
    'spam': 'st-spam'
  };

  /* Lifecycle order, and therefore the order the dashboard draws the `Reports by state` bars in.
     Those bars are NOT coloured by the classes above - they read `.bf.s-<state>` off HackerOne's
     own palette (--h1-* in app.css), so a state added here needs a bar colour adding there or it
     draws in the generic accent. test_smoke.py fails on that. */
  var REPORT_STATES = [
    'new', 'pending-program-review', 'triaged', 'retesting', 'resolved',
    'duplicate', 'informative', 'not-applicable', 'spam'
  ];

  function stateClass(v) {
    var s = String(v === null || v === undefined ? '' : v).toLowerCase().trim();
    if (!s) return 'st-unknown';
    return REPORT_STATE_CLASS[s] || 'st-other';
  }

  function statePill(v) {
    var s = String(v === null || v === undefined ? '' : v).toLowerCase().trim();
    return el('span', { class: 'pill ' + stateClass(s), text: s || 'unknown' });
  }

  /* ------------------------------------------------------------ lead status
     The lead vocabulary, in LIFECYCLE order (LEAD_STANDARD.md): open, reproduced, sent, paid, and
     the two ways out of the queue. This list must hold exactly the values `ingest.VALID_STATUSES`
     accepts - anything else is parsed to `unknown` on the way into the database, so a chip for a
     value not in that tuple could never match a row. test_smoke.py asserts the two agree rather
     than trusting this comment. */
  /* Kept on ONE line: both test suites extract this declaration with a single-line regex. */
  var LEAD_STATUSES = ['open', 'confirmed', 'ready', 'submitted', 'awarded', 'parked', 'killed'];

  /* `ready` is stored as one word because the marker parser keeps only the first word after
     **Status:**, so a two-word value would silently truncate. The queue is the one place the
     full phrase belongs, since 'ready' alone does not say ready for WHAT. */
  var LEAD_STATUS_LABEL = { 'ready': 'ready to ship' };

  function leadStatusLabel(k) {
    return Object.prototype.hasOwnProperty.call(LEAD_STATUS_LABEL, k) ? LEAD_STATUS_LABEL[k] : k;
  }

  /* Lead statuses onto the SAME st-* classes the Tracker's states use, so a chip means the same
     colour on both tabs: warn = waiting on us, info = in hand, ok = done and gone.

     killed and parked are grey for the reason the Tracker greys duplicate/informative: they are
     OUTCOMES, not errors, they are 46 of the 55 rows here, and a majority chip in red would read
     as something being broken. */
  var LEAD_STATUS_CLASS = {
    'open': 'st-new',
    'confirmed': 'st-triaged',
    /* Its own colour, and the only one in the vocabulary that means WAITING ON SETH. Sharing
       `confirmed`'s blue would bury the single state that needs him to act. */
    'ready': 'st-ready',
    'submitted': 'st-resolved',
    /* The one terminal GOOD outcome, and the only status past `submitted`, so it gets a colour of
       its own rather than sharing that green. See app.css for why gold and not a second green. */
    'awarded': 'st-awarded',
    'killed': 'st-muted',
    'parked': 'st-muted',
    'unknown': 'st-unknown'
  };

  /* The HackerOne id off a lead's `Submitted` header row, e.g.
     `| **Submitted** | 2026-08-02 as #0000000 (high, cwe-284, scope 438731) |`.
     Header first because that is where the convention puts it; body second so an older lead
     that recorded the id in prose still resolves. */
  var LEAD_H1_RE = /#(\d{6,9})\b/;

  function leadH1Id(r) {
    if (!r) return '';
    var m = LEAD_H1_RE.exec(String(r.header || '')) || LEAD_H1_RE.exec(String(r.body || ''));
    return m ? m[1] : '';
  }

  function leadStatusClass(v) {
    var s = String(v === null || v === undefined ? '' : v).toLowerCase().trim();
    if (!s) return 'st-unknown';
    return Object.prototype.hasOwnProperty.call(LEAD_STATUS_CLASS, s)
      ? LEAD_STATUS_CLASS[s] : 'st-other';
  }

  /* my_role is derived, not reported: HACKERONE_API.md §6. A collaborator row is someone else's
     report that we were invited onto, so it must not read like one of ours at a glance. */
  function rolePill(v) {
    var s = String(v === null || v === undefined ? '' : v).toLowerCase().trim();
    if (!s) return el('span', { class: 'muted', text: '—' });
    var mine = s !== 'collaborator';
    return el('span', {
      class: 'pill role-' + (mine ? 'reporter' : 'collaborator'),
      text: s,
      title: mine ? 'We submitted this report.'
                  : 'Someone else submitted this report; we were invited onto it.'
    });
  }

  /* "medium 6.5" - the rating word from the list endpoint, the score from the detail pass. */
  function sevCell(r) {
    var word = String(r.severity === null || r.severity === undefined ? '' : r.severity).toLowerCase().trim();
    var score = String(r.cvss === null || r.cvss === undefined ? '' : r.cvss).trim();
    if (!word && !score) return el('span', { class: 'muted', text: '—' });
    return el('span', { class: 'sevcell' }, [
      word ? sevPill(word) : null,
      score ? el('span', { class: 'cvss', text: score }) : null
    ]);
  }

  /* ------------------------------------------------- anticipated (unconfirmed) awards
     `bounty` / `my_bounty` come from HackerOne and are facts. `expected_bounty` does NOT:
     the researcher typed it in after spotting a published ExampleVendor advisory they believe
     matches their report, so they expect to be paid. It is a belief, and the UI must never
     let it be mistaken for money that has actually landed.

     Rules applied everywhere below:
       - anticipated amounts are NEVER added to a confirmed total;
       - they always carry the dashed "expected" treatment plus the word "expected";
       - the tooltip spells out that HackerOne has not confirmed the payment. */
  var EXPECTED_CAVEAT =
    'Anticipated, not confirmed. The researcher recorded this after seeing a published ' +
    'advisory they believe matches this report. HackerOne has not confirmed a payment.';

  /* The HackerOne conversation on a report: triage bot, vendor engineers, our replies.
     Sourced from the API's `activities` feed and stored as JSON on the row, so this is the
     real exchange rather than anything reconstructed from a local file. */
  function threadPanel(r) {
    if (!r || !r.thread) return null;
    var items;
    try { items = JSON.parse(r.thread); } catch (e) { return null; }
    if (!items || !items.length) return null;

    var rows = items.map(function (m) {
      var kind = String(m.kind || '').replace(/-/g, ' ');
      var head = [
        el('span', { class: 'th-actor', text: String(m.actor || 'unknown') }),
        kind && kind !== 'comment'
          ? el('span', { class: 'th-kind', text: kind }) : null,
        m.internal ? el('span', { class: 'th-internal', text: 'internal' }) : null,
        el('span', { class: 'th-at', text: fmtTime(m.at) })
      ].filter(Boolean);
      return el('div', { class: 'th-msg' + (m.internal ? ' is-internal' : '') }, [
        el('div', { class: 'th-head' }, head),
        /* `html` is safe here for the one reason it is safe anywhere in this app: the string
           comes from renderMarkdown(), which escapes at the boundary. See tests/test_render.js. */
        m.message
          ? el('div', { class: 'th-body md', html: renderMarkdown(String(m.message)) })
          : null
      ]);
    });

    /* `id` is what the Comments button scrolls to. The horizontal rule matters more than it
       looks: the report body ends in Remediation, and without a divider the first comment reads
       as another Remediation bullet. */
    var panel = el('div', { class: 'thread-panel', id: 'thread-panel' }, [
      el('hr', { class: 'thread-rule' }),
      el('h3', { class: 'th-title' },
        [el('span', { text: 'Comments' }),
         el('span', { class: 'th-count', text: String(items.length) })]),
      el('div', { class: 'th-list' }, rows)
    ]);
    return panel;
  }

  /* A recorded 0 means "nothing anticipated", not "an anticipated award of nothing". */
  function hasExpected(r) {
    var n = r ? parseMoney(r.expected_bounty) : null;
    return n !== null && n > 0;
  }

  function expectedTitle(r) {
    var bits = [EXPECTED_CAVEAT];
    if (r && r.expected_cve) bits.push('Expected CVE: ' + String(r.expected_cve));
    if (r && r.expected_note) bits.push(String(r.expected_note));
    return bits.join('\n');
  }

  /* The one renderer for an anticipated amount. Returns null when there is nothing to show,
     so callers can fall through to their normal em-dash. */
  function expectedMoney(amount, currency, title) {
    var n = parseMoney(amount);
    if (n === null || n <= 0) return null;
    /* The dashed outline IS the "this is anticipated, not confirmed" signal now - the same dashed
       badge the summary tally carries - so the literal word is dropped. It read as "[amount]EXPECTED"
       jammed against the amount in the narrow Bounty cell, and the border plus the warn hue, the
       italics and the title tooltip already carry the meaning without it. */
    return el('span', { class: 'money money-expected', title: title || EXPECTED_CAVEAT }, [
      el('span', { class: 'exp-amt', text: fmtMoney(n, currency) })
    ]);
  }

  /* A payout split means my_bounty < bounty: part of the award went to a co-reporter. Show what
     actually landed for us, and keep the report total in the tooltip. */
  function bountyCell(r) {
    var total = parseMoney(r.bounty);
    var mine = parseMoney(r.my_bounty);
    if (total === null && mine === null) {
      /* No confirmed award. If the researcher is anticipating one, show that instead of a
         dash - in the unconfirmed treatment, never as a plain figure. */
      return expectedMoney(r.expected_bounty, r.currency, expectedTitle(r)) ||
        el('span', { class: 'muted', text: '—' });
    }
    if (total !== null && mine !== null && Math.abs(total - mine) > 0.004) {
      return el('span', {
        class: 'money money-split',
        title: 'Payout split: ' + fmtMoney(mine, r.currency) + ' of ' +
               fmtMoney(total, r.currency) + ' awarded on this report'
      }, [
        el('strong', { text: fmtMoney(mine, r.currency) }),
        el('span', { class: 'money-of', text: ' / ' + fmtMoney(total, r.currency) })
      ]);
    }
    return el('span', { class: 'money', text: fmtMoney(total === null ? mine : total, r.currency) });
  }

  /* payout_split is a JSON string written by h1.normalize_report: [{username,user_id,amount}]. */
  function payoutSplitNode(raw, currency) {
    var t = String(raw === null || raw === undefined ? '' : raw).trim();
    if (!t || t === 'null' || t === '[]' || t === '{}') return null;
    var parsed = null;
    try { parsed = JSON.parse(t); } catch (e) { parsed = null; }
    if (Array.isArray(parsed) && parsed.length) {
      var list = el('ul', { class: 'splitlist' });
      parsed.forEach(function (e) {
        if (!e || typeof e !== 'object') { list.appendChild(el('li', { text: String(e) })); return; }
        var who = e.username || e.user || '(unknown)';
        var amt = fmtMoney(e.amount, currency);
        list.appendChild(el('li', {}, [
          el('span', { class: 'splitwho', text: who + (e.user_id ? ' (id=' + e.user_id + ')' : '') }),
          amt ? el('span', { class: 'splitamt', text: amt }) : null
        ]));
      });
      return list;
    }
    return el('pre', { class: 'jsonblock', text: parsed ? JSON.stringify(parsed, null, 2) : t });
  }

  /* collaborators is a comma-joined "username (id=N)" string. The id is stored so a rename
     upstream stays traceable, but it is stripped for display for the same reason the reporter's
     is: nobody reads a report pane to learn a numeric user id. */
  function collaboratorsNode(raw) {
    var list = String(raw === null || raw === undefined ? '' : raw)
      .split(',').map(function (c) { return c.trim().replace(/\s*\(id=\d+\)\s*$/, ''); })
      .filter(function (c) { return c; });
    if (!list.length) return null;
    var wrap = el('span', { class: 'collabs' });
    list.forEach(function (c) { wrap.appendChild(el('span', { class: 'tag', text: c })); });
    return wrap;
  }

  /* Copy of a params object with a patch applied and paging reset. */
  function withParams(params, patch) {
    var out = {};
    for (var k in params) { if (Object.prototype.hasOwnProperty.call(params, k)) out[k] = params[k]; }
    for (var p in patch) { if (Object.prototype.hasOwnProperty.call(patch, p)) out[p] = patch[p]; }
    out.offset = 0;
    return out;
  }

  function sumStat(value, label, sub, opts) {
    opts = opts || {};
    return el('div', { class: 'sumstat' + (opts.cls ? ' ' + opts.cls : ''), title: opts.title || null }, [
      el('span', { class: 'n', text: value }),
      el('span', { class: 'k', text: label }),
      sub ? el('span', { class: 's', text: sub }) : null
    ]);
  }

  /* Computed from the rows actually on screen, not from an endpoint - the Tracker fetches its
     whole filtered set in one request, so these totals cover every row the filters match, not
     just the current page. */
  /* ------------------------------------------------- exclusion ("NOT") filters
     The Tracker's State filter is inclusive: pick one, see only that. The inverse is what the
     view actually needs day to day - 78 of 111 reports are duplicate/informative/
     not-applicable, so the default view is mostly closed noise.

     Carried in the URL as `exclude=duplicate,informative` so a filtered view is linkable and
     survives a refresh, exactly like status/role/anticipated.

     PRECEDENCE: an explicit State selection WINS and exclusions are ignored while it is set -
     "only duplicates, except duplicates" has no useful answer, and silently returning zero
     rows would look like a bug. The chips are disabled and labelled when that happens, and the
     exclusion list stays in the URL so clearing the State restores it. */
  var NOISE_STATES = ['duplicate', 'informative', 'not-applicable'];

  function stateKey(r) {
    return String((r && r.state) || '').toLowerCase().trim() || 'unknown';
  }

  function leadStatusKey(r) {
    return String((r && r.status) || '').toLowerCase().trim() || 'unknown';
  }

  /* Which column the chips work on, per entity. The bar itself is generic: it counts keys,
     orders them by `order` (anything unlisted falls to the end, by tally), and offers `preset`
     as the one-press combination that view wants most often. */
  var EXCLUDE_DIMENSIONS = {
    reports: {
      key: stateKey,
      order: REPORT_STATES,
      noun: 'report',
      /* 78 of 111 reports are closed noise. */
      preset: { keys: NOISE_STATES, hide: 'Hide noise', show: 'Showing noise' }
    },
    leads: {
      key: leadStatusKey,
      /* Same list, same order, as the include chips above the bar. Two hand-kept orderings of
         one vocabulary would eventually disagree and the two rows would stop lining up. */
      order: LEAD_STATUSES,
      noun: 'lead',
      /* Mid-hunt the question is almost always "what is still live?", and killed/parked notes
         are kept forever precisely so they are never re-hunted - which makes them the bulk. */
      preset: { keys: ['killed', 'parked'], hide: 'Hide settled', show: 'Showing settled' }
    }
  };

  function excludeDim(cfg) {
    return EXCLUDE_DIMENSIONS[cfg && cfg.entity] || EXCLUDE_DIMENSIONS.reports;
  }

  function parseExclude(raw) {
    var out = [];
    String(raw || '').split(',').forEach(function (s) {
      var t = s.trim().toLowerCase();
      if (t && out.indexOf(t) < 0) out.push(t);
    });
    return out;
  }

  /* ------------------------------------------------- program scope (Tracker)
     The database holds reports from every program on the HackerOne account, but the Tracker is
     the working list for ONE hunt and defaults to the primary program. The server owns that
     default - it reads the credential, which the browser is never allowed to see - so an empty
     value here means "whatever the server says is primary", not "no filter".

     Only the exact string 'all' widens the scope. A typo, a stale bookmark or a hand-edited URL
     therefore cannot quietly pull 35 other programs' reports into the primary hunt's queue; it
     falls back to the narrow default instead. */
  var ALL_PROGRAMS = 'all';

  function parseProgramScope(raw) {
    var s = String(raw == null ? '' : raw).trim().toLowerCase();
    if (s === ALL_PROGRAMS) return ALL_PROGRAMS;
    /* HackerOne handles are [a-z0-9] with _ - . inside, e.g. acme_bbp, example-public, some_co. */
    return /^[a-z0-9][a-z0-9_.-]*$/.test(s) ? s : '';
  }

  /* Exclusions are inert while an inclusive State is set - see PRECEDENCE above. */
  function activeExclusions(params) {
    if (params && params.status) return [];
    return parseExclude(params && params.exclude);
  }

  function applyExclusions(items, params, cfg) {
    var ex = activeExclusions(params);
    if (!ex.length) return items;
    var keyOf = excludeDim(cfg).key;
    return items.filter(function (r) { return ex.indexOf(keyOf(r)) < 0; });
  }

  /* ------------------------------------------------- inclusion filter (Leads)
     The INCLUDE half of the Leads chip pair, and the mirror of the Tracker's State chips. It
     carries `status` in the URL exactly like the Tracker's does, which is also what makes the
     PRECEDENCE rule above apply to Leads unchanged: `activeExclusions` already goes inert the
     moment `status` is set, whichever control set it.

     Applied HERE rather than in the query, unlike the Tracker's, for one reason: the chips carry
     counts, and counts sourced from a status-filtered response would collapse to a single
     non-zero chip the moment one was pressed, so you could never see that there are 46 killed
     leads while looking at the 2 confirmed ones, nor click straight across to them. The list is
     fetched whole already (fetchAll, 55 rows against a 500 cap), so this costs nothing.

     A row with no status at all keys as 'unknown', matching the exclusion chips, so the two
     halves of the bar agree on which bucket a blank row is in. */
  function applyLeadStatus(items, params) {
    var want = String((params && params.status) || '').toLowerCase().trim();
    if (!want) return items;
    return items.filter(function (r) { return leadStatusKey(r) === want; });
  }

  function reportsSummary(items, params) {
    var totalBounty = 0, myShare = 0, paid = 0, splits = 0, collabs = 0;
    /* Kept in its own accumulator on purpose: anticipated money must never touch totalBounty
       or myShare, which are the HackerOne-confirmed figures. */
    var expectedTotal = 0, expectedCount = 0;
    var currency = '';
    var byState = {};

    items.forEach(function (r) {
      var b = parseMoney(r.bounty);
      var m = parseMoney(r.my_bounty);
      var x = parseMoney(r.expected_bounty);
      if (!currency && r.currency) currency = String(r.currency);
      if (x !== null && x > 0) { expectedTotal += x; expectedCount++; }
      if (b !== null) { totalBounty += b; paid++; }
      /* my_bounty is only written when the award was split; otherwise the whole bounty is ours. */
      myShare += (m !== null ? m : (b !== null ? b : 0));
      if (b !== null && m !== null && Math.abs(b - m) > 0.004) splits++;
      if (String(r.my_role || '').toLowerCase() === 'collaborator') collabs++;
      var s = String(r.state || '').toLowerCase().trim() || 'unknown';
      byState[s] = (byState[s] || 0) + 1;
    });

    var stats = el('div', { class: 'sumstats' }, [
      sumStat(String(items.length), items.length === 1 ? 'report' : 'reports',
        collabs ? collabs + ' as collaborator' : 'all as reporter'),
      sumStat(fmtMoney(totalBounty, currency) || '$0.00', 'total bounty',
        paid + ' of ' + items.length + ' carry an award'),
      sumStat(fmtMoney(myShare, currency) || '$0.00', 'my share',
        splits ? splits + ' payout split' + (splits === 1 ? '' : 's') : 'no payout splits')
    ]);

    /* Anticipated money sits after a rule, in the dashed unconfirmed treatment, and is never
       folded into the two figures above. */
    if (expectedCount) {
      stats.appendChild(sumStat(
        fmtMoney(expectedTotal, currency),
        'anticipated · unconfirmed',
        expectedCount + ' report' + (expectedCount === 1 ? '' : 's') + ' awaiting confirmation',
        { cls: 'sumstat-expected', title: EXPECTED_CAVEAT }));
    }

    var keys = Object.keys(byState).sort(function (a, b) {
      var ia = REPORT_STATES.indexOf(a), ib = REPORT_STATES.indexOf(b);
      if (ia < 0) ia = 99;
      if (ib < 0) ib = 99;
      if (ia !== ib) return ia - ib;
      return byState[b] - byState[a];
    });

    var chips = el('div', { class: 'sumstates' }, keys.map(function (k) {
      var kids = [
        el('span', { class: 'sc-k', text: leadStatusLabel(k) }),
        el('span', { class: 'sc-n', text: String(byState[k]) })
      ];
      if (k === 'unknown') {
        return el('span', { class: 'statechip ' + stateClass(''), title: 'No state recorded' }, kids);
      }
      return el('a', {
        class: 'statechip ' + stateClass(k),
        href: '#/reports?' + qsFrom(withParams(params, { status: k })),
        title: byState[k] + ' ' + k
      }, kids);
    }));

    return el('section', { class: 'summary card' }, [stats, chips]);
  }

  /* A note carrying no `**Status:**` marker indexes as 'unknown', and the server keeps those out
     of the Leads list entirely (server.LEAD_IS_REAL): they are sweep logs, primers and findings
     tables, not queue items. So the unknown chip is structurally 0 here rather than incidentally
     empty, and it says so instead of offering a click that lands on "nothing matches". */
  var LEAD_UNKNOWN_NOTE =
    'Notes with no Status: marker index as unknown and are deliberately kept out of the Leads ' +
    'queue - they are research apparatus, not leads. They are still in Notes, Files and Search.';

  /* The Leads summary strip. Its chips are the INCLUDE filter, and the deliberate twin of the
     Tracker's state chips: same .statechip treatment, same st-* colours, same `status` query
     param, same withParams() link building.

     Two differences, both forced by the data rather than chosen. Every status gets a chip, in
     lifecycle order, including the ones at zero - four of the seven are empty right now and a
     bar that showed only what happened to be present would leave you unable to see that. And
     `all` is the whole fetched set, not the rows on screen, so the counts stay true while one
     status is selected; that is what makes a chip a toggle you can click across, and it is why
     the selected chip is drawn `on` and clicking it clears back to every status. */
  function leadsSummary(items, params, all) {
    var rows = all || items;
    var sel = String((params && params.status) || '').toLowerCase().trim();

    var counts = {};
    var extra = [];
    LEAD_STATUSES.forEach(function (k) { counts[k] = 0; });
    rows.forEach(function (r) {
      var k = leadStatusKey(r);
      if (counts[k] === undefined) { counts[k] = 0; extra.push(k); }
      counts[k]++;
    });
    /* A status the vocabulary does not know cannot reach the database - ingest maps it to
       'unknown' - but the list is built defensively anyway, biggest first, so a future value
       shows up here rather than being silently dropped from a bar that claims to be complete. */
    extra.sort(function (a, b) { return counts[b] - counts[a]; });

    var live = counts.open + counts.confirmed + counts.ready;
    var stats = el('div', { class: 'sumstats' }, [
      sumStat(String(items.length), items.length === 1 ? 'lead' : 'leads',
        items.length === rows.length ? 'every status' : 'of ' + rows.length + ' indexed'),
      sumStat(String(live), 'live', 'open, confirmed or ready'),
      sumStat(String(counts.submitted), 'submitted', 'sent to HackerOne'),
      /* The figure the whole queue is worked towards, so it earns a stat rather than only a chip.
         It reads 0 until the first bounty lands, which is itself the honest answer. */
      sumStat(String(counts.awarded), 'awarded', 'paid a bounty')
    ]);

    var chips = el('div', { class: 'sumstates' }, LEAD_STATUSES.concat(extra).map(function (k) {
      var n = counts[k] || 0;
      var on = sel === k;
      var kids = [
        el('span', { class: 'sc-k', text: leadStatusLabel(k) }),
        el('span', { class: 'sc-n', text: String(n) })
      ];
      if (!n && !on) {
        return el('span', {
          class: 'statechip ' + leadStatusClass(k) + ' is-zero',
          title: k === 'unknown' ? LEAD_UNKNOWN_NOTE
            : 'No ' + leadStatusLabel(k) + ' leads match the other filters'
        }, kids);
      }
      return el('a', {
        class: 'statechip ' + leadStatusClass(k) + (on ? ' on' : ''),
        href: '#/leads?' + qsFrom(withParams(params, { status: on ? '' : k })),
        'aria-pressed': on ? 'true' : 'false',
        title: on
          ? 'Showing only ' + k + ' leads - click to show every status again'
          : 'Show only the ' + n + ' ' + k + ' lead' + (n === 1 ? '' : 's')
      }, kids);
    }));

    return el('section', { class: 'summary card' }, [stats, chips]);
  }

  /* ==================================================== advisory <-> report matches
     GET /api/advisories/matches -> {items:[{advisory_id, report_id, h1_id, score,
     confidence, signals, confirmed}]}. The whole set is fetched ONCE per Advisories render
     and indexed by advisory_id here; the Mine column then reads the index, so a 500-row page
     costs one request, not 500.

     The endpoint may not exist yet. Every failure path - 404, 500, offline, garbage payload -
     resolves to an empty index, so the column degrades to em-dashes with no toast and no
     error panel. A missing match is not an error. */

  var advMatchIndex = {};       /* advisory_id (string) -> best match */
  var advMatchPromise = null;

  var MATCH_CONFIDENCES = ['confirmed', 'likely', 'possible'];

  function matchConfidence(m) {
    var c = String((m && m.confidence) || '').toLowerCase().trim();
    if (MATCH_CONFIDENCES.indexOf(c) >= 0) return c;
    if (m && m.confirmed) return 'confirmed';
    return 'possible';
  }

  function matchScore(m) {
    var n = (m && m.score !== null && m.score !== undefined) ? Number(m.score) : NaN;
    return isFinite(n) ? n : null;
  }

  /* confirmed beats likely beats possible; score breaks the tie. Used to pick one row when the
     matcher offers several candidates for the same advisory. */
  /* Does this match represent CREDIT to us?

     A duplicate means someone filed it first. Informative and not-applicable earned nothing.
     temporal_conflict means the report was submitted AFTER the advisory published, so the CVE
     is genuinely related but the finding is not ours. */
  function matchIsCredit(m) {
    var st = String((m && m.report_state) || '').toLowerCase();
    if (st === 'duplicate' || st === 'informative' || st === 'not-applicable') return false;
    if (matchSignals(m).indexOf('temporal_conflict') >= 0) return false;
    return true;
  }

  function matchRank(m) {
    var i = MATCH_CONFIDENCES.indexOf(matchConfidence(m));
    var s = matchScore(m);
    /* Credit dominates confidence. If an advisory has both a duplicate match and a real one,
       the real one has to win the slot, or blanking the duplicate would hide the good match. */
    return (matchIsCredit(m) ? 100000 : 0) +
      (3 - (i < 0 ? 2 : i)) * 1000 + (s === null ? 0 : Math.max(0, Math.min(999, s)));
  }

  /* signals may arrive as an array, a JSON-encoded array, or a comma-joined string. */
  function matchSignals(m) {
    var raw = m ? m.signals : null;
    if (raw === null || raw === undefined || raw === '') return [];
    var list = raw;
    if (!Array.isArray(list)) {
      var s = String(raw).trim();
      if (s.charAt(0) === '[') {
        try { list = JSON.parse(s); } catch (e) { list = null; }
      }
      if (!Array.isArray(list)) list = s.split(',');
    }
    var out = [];
    list.forEach(function (v) {
      if (v === null || v === undefined || v === '') return;
      if (typeof v === 'object') {
        var name = v.name || v.signal || v.kind || v.key || '';
        var val = (v.value !== undefined && v.value !== null) ? v.value : v.detail;
        out.push(String(name || JSON.stringify(v)) + (val ? ': ' + String(val) : ''));
      } else {
        var t = String(v).trim();
        if (t) out.push(t);
      }
    });
    return out;
  }

  function ensureAdvisoryMatches(refresh) {
    if (advMatchPromise && !refresh) return advMatchPromise;
    advMatchPromise = api('/advisories/matches')
      .then(function (data) {
        var idx = {};
        var items = (data && data.items) || [];
        if (!Array.isArray(items)) items = [];
        items.forEach(function (m) {
          if (!m || typeof m !== 'object') return;
          if (m.advisory_id === null || m.advisory_id === undefined || m.advisory_id === '') return;
          /* 'possible' NEVER reaches the Mine column. ExampleVendor advisory titles are generic
             ("ExampleProduct 8.19.19, 9.3.8, 9.4.4 Security Update (ESA-2026-68)") with no
             description of the flaw, so text_similarity against them is close to meaningless,
             and product_match plus timing_plausible are true of essentially every report in
             this program. That bucket is the matcher's own review queue, not a claim - showing
             an H1 number for one asserted a link that does not exist. It is still visible on
             the advisory detail page, clearly labelled. */
          if (matchConfidence(m) === 'possible') return;
          var k = String(m.advisory_id);
          if (!idx[k] || matchRank(m) > matchRank(idx[k])) idx[k] = m;
        });
        advMatchIndex = idx;
        return idx;
      })
      .catch(function () {
        /* Not deployed, or unreachable. Silent by design - see the note above. */
        advMatchIndex = {};
        return advMatchIndex;
      });
    return advMatchPromise;
  }

  var MATCH_BLURB = {
    confirmed: 'Confirmed link between this advisory and the report.',
    likely: 'Likely match, inferred by Quarry’s matcher. Not confirmed by ExampleVendor or HackerOne.',
    possible: 'Possible match, inferred by Quarry’s matcher. Not confirmed by ExampleVendor or HackerOne.'
  };

  /* The HackerOne report number. The API calls it report_h1_id (the row joins an advisory to a
     report, so the bare name would be ambiguous); h1_id is accepted as a fallback. */
  function matchH1(m) {
    var v = m ? (m.report_h1_id || m.h1_id) : null;
    return (v === null || v === undefined || v === '') ? '' : String(v);
  }

  /* Why the matcher thinks this is a match, in prose. `reasons` is generated per signal by
     matcher.score_pair; the same tolerance as matchSignals applies to its wire shape. */
  function matchReasons(m) {
    var raw = m ? m.reasons : null;
    if (raw === null || raw === undefined || raw === '') return [];
    var list = raw;
    if (!Array.isArray(list)) {
      var s = String(raw).trim();
      if (s.charAt(0) === '[') {
        try { list = JSON.parse(s); } catch (e) { list = null; }
      }
      if (!Array.isArray(list)) list = [s];
    }
    var out = [];
    list.forEach(function (v) {
      if (v === null || v === undefined) return;
      var t = (typeof v === 'object') ? JSON.stringify(v) : String(v).trim();
      if (t) out.push(t);
    });
    return out;
  }

  function matchTitle(m) {
    var conf = matchConfidence(m);
    var bits = [MATCH_BLURB[conf] || MATCH_BLURB.possible];
    var h1 = matchH1(m);
    if (h1) bits.push('HackerOne report #' + h1);
    var score = matchScore(m);
    if (score !== null) bits.push('Score: ' + score);
    var sig = matchSignals(m);
    if (sig.length) bits.push('Signals: ' + sig.join(', '));
    matchReasons(m).forEach(function (r) { bits.push('• ' + r); });
    return bits.join('\n');
  }

  function matchLabel(m) {
    var h1 = matchH1(m);
    return h1 ? ('#' + h1) : matchConfidence(m);
  }

  /* The Mine cell. Reads the pre-built index; never issues a request of its own. */
  function mineCell(r) {
    var m = advMatchIndex[String(r.id)];
    if (!m) return el('span', { class: 'muted', text: '—' });
    var conf = matchConfidence(m);
    var st = String(m.report_state || '').toLowerCase();
    /* A DUPLICATE prints nothing. The column is called Credit, and someone else filed it
       first, so there is no credit to report - putting a struck-through report number here
       only invited the reader to re-litigate it on every scroll. It is still on the advisory
       detail page with the full explanation. */
    if (st === 'duplicate') return el('span', { class: 'muted', text: '—' });
    var noCredit = !matchIsCredit(m);
    var kids = [
      el('span', { class: 'mb-dot', 'aria-hidden': 'true' }),
      el('span', { class: 'mb-t', text: matchLabel(m) })
    ];
    var attrs = {
      class: 'matchbadge mb-' + conf + (noCredit ? ' mb-nocredit' : ''),
      title: (noCredit ? 'NOT credit to you: ' +
        (st === 'duplicate' ? 'the report is a duplicate, someone filed it first.'
          : st === 'informative' || st === 'not-applicable' ? 'the report was closed as ' + st + '.'
            : 'the report was submitted after this advisory published.') + '\n\n' : '') +
        matchTitle(m)
    };
    if (m.report_id === null || m.report_id === undefined || m.report_id === '') {
      return el('span', attrs, kids);
    }
    attrs.href = '#/reports/' + encodeURIComponent(m.report_id);
    /* The whole row is clickable and opens the advisory; the badge must win. */
    attrs.onclick = function (e) { e.stopPropagation(); };
    return el('a', attrs, kids);
  }

  /* Detail-pane section. Resolves its own index so a deep link straight to
     #/advisories/<id> works without the list view having rendered first. */
  function matchedReportPanel(advisoryId) {
    var host = el('div', {});
    ensureAdvisoryMatches(false).then(function (idx) {
      var m = idx[String(advisoryId)];
      clear(host);
      if (!m) return;   /* no match, or no endpoint: render nothing at all */

      var conf = matchConfidence(m);
      var score = matchScore(m);
      var sig = matchSignals(m);

      var h1 = matchH1(m);
      var link;
      if (m.report_id === null || m.report_id === undefined || m.report_id === '') {
        link = el('span', { class: 'muted', text: h1 ? 'HackerOne #' + h1 : '(unlinked)' });
      } else {
        link = el('a', {
          href: '#/reports/' + encodeURIComponent(m.report_id),
          text: h1 ? 'HackerOne #' + h1 : 'report #' + m.report_id
        });
      }

      var sigNode = null;
      if (sig.length) {
        sigNode = el('span', { class: 'siglist' });
        sig.forEach(function (s) { sigNode.appendChild(el('span', { class: 'tag', text: s })); });
      }

      /* The reasoning, spelled out. A confidence bucket on its own is an assertion; this is the
         evidence behind it, so the reader can disagree with the matcher. */
      var reasons = matchReasons(m);
      var whyNode = null;
      if (reasons.length) {
        whyNode = el('ul', { class: 'mp-why' });
        reasons.forEach(function (t) { whyNode.appendChild(el('li', { text: t })); });
      }

      var panel = el('div', { class: 'matchpanel mp-' + conf }, [
        el('div', { class: 'mp-head' }, [
          el('span', { class: 'mp-title', text: 'Matched report' }),
          el('span', { class: 'matchbadge mb-' + conf, title: matchTitle(m) }, [
            el('span', { class: 'mb-dot', 'aria-hidden': 'true' }),
            el('span', { class: 'mb-t', text: conf })
          ])
        ]),
        metaGrid([
          /* Confidence, score and the H1 number are all shown elsewhere on this panel - the
             badge in the head, and the link itself. Repeating them as grid rows was noise. */
          ['Report', link],
          ['Title', m.report_title || ''],
          /* The report's own state is the thing that decides whether a match means CREDIT.
             A match to a DUPLICATE means somebody else reported it first, which is the
             opposite of good news, and it used to be invisible here. */
          ['State', m.report_state ? statePill(m.report_state) : ''],
          ['Submitted', fmtDateOnly(m.report_submitted_on)]
        ]),
        creditNote(conf, m.report_state),
        whyBlock(conf, reasons, sigNode, score)
      ]);
      host.appendChild(panel);
    });
    return host;
  }

  /* Spells out what a match to a report in THIS state actually means for credit. A "confirmed"
     match to a duplicate is still not your CVE - someone else filed it first - and that is the
     single most misleading thing this panel could imply. */
  function creditNote(conf, state) {
    var st = String(state || '').toLowerCase();
    if (st === 'duplicate') {
      return el('p', { class: 'mp-note mp-warn' },
        'This report is a DUPLICATE. Even if the advisory is the same issue, it was reported ' +
        'by someone else first, so this is not credit to you.');
    }
    if (st === 'informative' || st === 'not-applicable') {
      return el('p', { class: 'mp-note mp-warn' },
        'This report was closed as ' + st + '. A matching advisory does not reverse that.');
    }
    return null;
  }

  /* One prose block instead of a Signals row, a Why list and a separate caveat paragraph. The
     reader wants a sentence explaining the inference, not three fields to reassemble. */
  function whyBlock(conf, reasons, sigNode, score) {
    var body = el('div', { class: 'mp-why-body' });

    if (reasons && reasons.length) {
      body.appendChild(el('p', { class: 'mp-why-text', text: reasons.join(' ') }));
    } else {
      body.appendChild(el('p', { class: 'mp-why-text muted',
        text: 'No reasoning was recorded for this match.' }));
    }

    body.appendChild(el('p', { class: 'mp-why-caveat' },
      conf === 'confirmed'
        ? 'Recorded as confirmed by hand. The signals below are still Quarry’s own inference.'
        : 'Inferred by Quarry’s matcher. Neither ExampleVendor nor HackerOne has confirmed that this ' +
          'advisory corresponds to this report, so treat a "' + conf + '" match as a lead, ' +
          'not a fact.'));

    var foot = el('div', { class: 'mp-why-foot' });
    if (sigNode) foot.appendChild(sigNode);
    if (score !== null && score !== undefined && score !== '') {
      foot.appendChild(el('span', { class: 'mp-score', text: 'score ' + score }));
    }
    if (foot.childNodes.length) body.appendChild(foot);

    return el('div', { class: 'mp-why-block' }, [
      el('div', { class: 'mp-why-h', text: 'Why this matched' }),
      body
    ]);
  }

  var ENTITIES = {
    leads: {
      entity: 'leads',
      workable: true,
      label: 'Leads',
      sub: 'Live hunt leads. Status is written back to the markdown note on disk.',
      singular: 'lead',
      canCreate: true,
      filters: { q: true, target: true, cls: true, status: true, exclude: true },
      statusLabel: 'Status',
      statusOptions: [''].concat(LEAD_STATUSES),
      defaultSort: '-mtime',
      /* Same reason the Tracker fetches everything: the exclusion chips count keys across the
         whole filtered set, so building them from one page would under-count and a chip could
         vanish just because its rows fell off the page. 64 notes against a 500 cap. */
      fetchAll: true,
      /* Status is filtered in the browser here, so it is left out of the query - see
         applyLeadStatus for why the include chips need an unfiltered response to count. */
      clientStatus: true,
      clientFilter: function (items, params) {
        var out = applyLeadStatus(items, params);
        /* Last, so "Hiding N of M" counts against the status selection too - though the
           exclusions are inert whenever one is set. */
        return applyExclusions(out, params, ENTITIES.leads);
      },
      summary: leadsSummary,
      summaryWhenEmpty: true,
      columns: [
        {
          key: 'title', label: 'Title', sort: 'title', cls: 'cell-title cell-max',
          /* The tile says three leads moved; this says WHICH three. Computed from the watermark
             in force before the section was opened, so it survives exactly one visit and is gone
             on the next - which is what "on first view" means. */
          render: function (r) {
            var fresh = freshTag(rowFreshness(r, 'leads', 'lead_updates'));
            var name = el('span', { class: 'trunc', text: r.title || '(untitled)',
                                    title: r.title || '' });
            return fresh ? el('span', { class: 'titlewrap' }, [fresh, name]) : name;
          }
        },
        /* The lead code (F27, G8), and the join between a lead and its eventual report: report
           files are named <h1_id>_<REF>-<slug>.md, so this is what connects a row here to a
           submission. It sits immediately right of the title because that is the pair being
           read. Plenty of notes carry no ref - 7 of 55 - and those render as an EMPTY cell: a
           dash would claim the column had been consulted and found nothing to say, when the
           truth is the lead was never given a code. `nowrap` shrinks it to fit its three
           characters rather than letting the table spread it. */
        { key: 'ref', label: 'Ref', sort: 'ref', cls: 'cell-mono nowrap' },
        { key: 'class', label: 'Class', sort: 'class', cls: 'nowrap', render: function (r) { return tag(r['class']); } },
        { key: 'status', label: 'Status', sort: 'status', cls: 'nowrap', render: function (r) { return pill(r.status); } },
        { key: 'severity', label: 'Sev', sort: 'severity', cls: 'nowrap',
          /* A lead that was never rated shows a dash, not an empty cell. 73 of them have no
             rating because none was ever assigned - blank read as a bug, which it was not. */
          render: function (r) { return r.severity || '\u2014'; } },
        /* Program sits immediately left of Target because the two read as a pair: ExampleVendor ->
           ExampleApp, ExampleVendor -> example-connector-python. It is the program NAME rather than
           the handle, since the handle is an API detail nobody reads a table by. */
        { key: 'program_name', label: 'Program', sort: 'program_name', cls: 'nowrap',
          render: function (r) { return r.program_name || '—'; } },
        { key: 'target', label: 'Target', cls: 'nowrap', render: function (r) { return targetLabel(r) || '—'; } },
        { key: 'mtime', label: 'Modified', sort: 'mtime', cls: 'nowrap tiny dim', render: function (r) { return fmtTime(r.mtime); } }
      ],
      meta: function (r) {
        return [
          ['Ref', r.ref, 'mono'],
          ['Class', r['class']],
          ['Status', pill(r.status)],
          ['Severity', r.severity],
          ['Program', r.program_name],
          ['Target', targetLabel(r)],
          ['Modified', fmtTime(r.mtime)],
          ['Indexed', fmtTime(r.indexed_at)],
          /* Whose lead it is, read from the header's Researcher row (server: lead_researcher).
             Multi-user attribution: a lead synced in from another researcher lands with their
             handle here. Absent on the operator's own leads, which name no researcher, so it
             renders as nothing rather than a dash. */
          ['User', r.lead_user]
          /* No File row: it is a long absolute path that wraps across the grid, and the two
             header buttons ("Copy path", "Open in Files") already cover every use of it. */
        ];
      },
      fields: [
        { key: 'title', label: 'Title', type: 'text', required: true },
        { key: 'ref', label: 'Ref (L2, G8…)', type: 'text' },
        { key: 'class', label: 'Class', type: 'text', list: 'hp-classes' },
        /* The whole pickable vocabulary, off the one list, so the editor cannot offer a narrower
           set than the filter does - it once silently lacked a status, which made that status
           unsettable from the form whose entire job is setting status. */
        { key: 'status', label: 'Status', type: 'select', options: LEAD_STATUSES },
        { key: 'severity', label: 'Severity', type: 'text' },
        { key: 'target_id', label: 'Target', type: 'target' },
        { key: 'body', label: 'Body (markdown)', type: 'markdown' }
      ]
    },

    /* The Tracker is sourced from the HackerOne API (see HACKERONE_API.md), not from a
       hand-maintained markdown table. `state` is authoritative; bounty/CVSS/collaborator data
       only exists because the sync does a per-report detail pass.

       fetchAll: the whole filtered set comes back in one request so the summary strip and the
       my_role filter operate on every matching row rather than the visible page. There are ~116
       reports; the server caps a page at 500, which is checked for below. */
    reports: {
      entity: 'reports',
      /* NOT workable. HackerOne owns a report's state, so a local status picker and worklog
         would only let you record something the next sync overwrites. Leads and advisories
         keep theirs: those are still markdown-backed and genuinely yours to move. */
      workable: false,
      label: 'Tracker',
      sub: 'Reports submitted to HackerOne, scoped to the primary program. State, bounty and ' +
        'comments come from the API.',
      plural: 'reports',
      singular: 'report',
      canCreate: true,
      filters: { q: true, target: true, cls: true, status: true, role: true, anticipated: true,
                 program: true, exclude: true },
      /* No filter strip above the table. The state chips in the summary and the exclusion chips
         under it already ARE the filters, and a row of selects duplicating them only pushed the
         table it filters down the page. q/target/class still work from the URL and the Search
         tab. */
      filterBar: false,
      programLabel: 'All programs',
      programTitle: 'Off: only the primary program, the one this HackerOne credential is ' +
        'configured for. On: every program with reports on the account. The default is ' +
        'deliberately narrow - the Tracker is the queue for the hunt being worked.',
      statusLabel: 'State',
      statusOptions: [''].concat(REPORT_STATES),
      roleLabel: 'Role',
      roleOptions: ['', 'reporter', 'collaborator'],
      anticipatedLabel: 'Anticipated only',
      anticipatedTitle: 'Show only reports carrying an anticipated (unconfirmed) award. ' +
        EXPECTED_CAVEAT,
      defaultSort: '-submitted_on',
      fetchAll: true,
      /* Both of these are client-side: the server filters on q/target/class/status only
         (API.md), and my_role is derived. fetchAll means they still cover the whole set. */
      clientFilter: function (items, params) {
        var out = items;
        if (params.role) {
          out = out.filter(function (r) {
            return String(r.my_role || '').toLowerCase() === params.role;
          });
        }
        if (params.anticipated === '1') out = out.filter(hasExpected);
        /* Last, so "Hiding N of M" counts against everything else the user asked for. */
        out = applyExclusions(out, params);
        return out;
      },
      summary: reportsSummary,
      columns: [
        {
          key: 'h1_id', label: 'H1', sort: 'h1_id', cls: 'cell-mono nowrap',
          render: function (r) {
            if (!r.h1_id) return el('span', { class: 'muted', text: '—' });
            if (r.url) return extLink(r.url, '#' + r.h1_id);
            return el('span', { text: '#' + r.h1_id });
          }
        },
        /* Program and target sit between the report number and the title, which is where the
           eye goes after the id: together they answer "whose is this, and what is it against"
           before the title has to be read. Either can be empty - a report that came straight
           from the API has no local file and so no target - and an empty one renders as a dash
           rather than as a guess. */
        {
          key: 'program', label: 'Program', sort: 'program', cls: 'nowrap tiny',
          render: function (r) {
            if (!r.program) return el('span', { class: 'muted', text: '—' });
            return el('span', { class: 'trunc', text: r.program, title: r.program });
          }
        },
        {
          /* Not sortable: `target` is a joined alias, and the server can only ORDER BY a
             real column on the row.

             FALLS BACK TO THE HACKERONE ASSET. A local target is derived from the workspace
             path, so a report that only ever existed in the API has none - 69 of them, and
             every single one of those is a report with no local markdown file. 67 of the 69
             carry an `asset` from HackerOne instead ("ExampleProduct", "ExampleApp", "ExampleVendor
             Synthetics Monitoring"), which answers the same question and comes from the source
             of truth. It is marked so the two are not silently conflated: a local target is one
             of our workspaces, an asset is what the program calls it. */
          key: 'target', label: 'Target', cls: 'nowrap tiny',
          render: function (r) {
            var t = targetLabel(r);
            if (t) return el('span', { class: 'trunc', text: t, title: t });
            if (r.asset) {
              /* Lowercased and styled identically to a workspace target. Local targets are
                 lowercase slugs and H1 assets are title-cased prose ("ExampleVendor Synthetics
                 Monitoring"), so rendering them verbatim made one column look like two. The
                 distinction still exists, it just lives in the tooltip rather than in italics
                 the eye has to parse on every row. */
              /* asset_label is the server's short form. A SOURCE_CODE scope registers a whole
                 repository URL - `https://github.com/example-org/example-repo` in a column two words
                 wide - so the cell shows the repo name and the full identifier lives in the
                 tooltip, which is where the authoritative value belongs. */
              var short = r.asset_label || String(r.asset);
              return el('span', { class: 'trunc', text: short.toLowerCase(),
                                  title: r.asset + ' (HackerOne asset; no local workspace)' });
            }
            return el('span', { class: 'muted', text: '—' });
          }
        },
        {
          key: 'title', label: 'Title', sort: 'title', cls: 'cell-title cell-max',
          /* Same treatment as the Leads list. Here 'updated' means HackerOne moved the report -
             a triage, an award, a severity - rather than an edit of ours. */
          render: function (r) {
            var fresh = freshTag(rowFreshness(r, 'reports', 'report_updates'));
            var name = el('span', { class: 'trunc', text: r.title || '(untitled)',
                                    title: r.title || '' });
            return fresh ? el('span', { class: 'titlewrap' }, [fresh, name]) : name;
          }
        },
        { key: 'state', label: 'State', sort: 'state', cls: 'nowrap', render: function (r) { return statePill(r.state); } },
        { key: 'severity', label: 'Sev', sort: 'severity', cls: 'nowrap', render: function (r) { return sevCell(r); } },
        /* Next to Sev: the two together are the classification of the finding. 25 of 111 rows
           have no CWE, which is real missing data - rendered as a dash, never guessed. */
        { key: 'cwe', label: 'CWE', sort: 'cwe', cls: 'nowrap', render: function (r) { return cweCell(r.cwe); } },
        /* Not sortable: it is derived from the CVSS vector at render time, and the server can
           only ORDER BY real columns. */
        { key: 'priv', label: 'Priv', cls: 'nowrap', render: function (r) { return privCell(r); } },
        /* Not sortable, same reason as Priv: derived from the CVSS vector at render time. */
        { key: 'impact', label: 'Impact', cls: 'nowrap', render: function (r) { return impactCell(r); } },
        { key: 'bounty', label: 'Bounty', cls: 'nowrap cell-money', render: function (r) { return bountyCell(r); } },
        { key: 'my_role', label: 'Role', sort: 'my_role', cls: 'nowrap', render: function (r) { return rolePill(r.my_role); } },
        /* Between Role and Submitted: the pair reads as "whose report, when did anyone last touch
           it, when did it start". Sorted on the real column so `-last_activity` surfaces the
           freshest and `last_activity` the forgotten. */
        {
          key: 'last_activity', label: 'Last update', sort: 'last_activity', cls: 'nowrap tiny',
          render: lastActivityCell
        },
        {
          key: 'submitted_on', label: 'Submitted', sort: 'submitted_on', cls: 'nowrap tiny dim',
          render: function (r) { return fmtDateOnly(r.submitted_on) || '—'; }
        }
      ],
      rowClass: function (r) {
        return String(r.my_role || '').toLowerCase() === 'collaborator' ? 'is-collab' : '';
      },
      meta: function (r) {
        var split = payoutSplitNode(r.payout_split, r.currency);
        var collabs = collaboratorsNode(r.collaborators);
        /* Username only. The numeric HackerOne user id is not something anyone reads a report
           pane to find out, and it made every row noisier than the name it decorated. */
        var reporter = r.reporter_username || '';
        return [
          ['HackerOne', r.h1_id ? (r.url ? extLink(r.url, '#' + r.h1_id) : '#' + r.h1_id) : ''],
          ['State', r.state ? statePill(r.state) : ''],
          ['Severity', (r.severity || r.cvss) ? sevCell(r) : ''],
          ['Impact', cvssPart(r, 'impact_text')],
          ['Privileges', cvssPart(r, 'privileges')],
          ['CWE', r.cwe ? cweCell(r.cwe) : ''],
          ['CVE', r.cve ? cveCell(r.cve) : ''],
          ['Bounty', fmtMoney(r.bounty, r.currency)],
          ['My share', fmtMoney(r.my_bounty, r.currency)],
          ['Payout split', split],
          /* Deliberately below the confirmed money and visibly different: this is the
             researcher's own expectation, not a HackerOne figure. */
          ['Expected bounty (unconfirmed)',
            expectedMoney(r.expected_bounty, r.currency, expectedTitle(r))],
          ['Expected CVE', r.expected_cve ? cveCell(r.expected_cve) : ''],
          ['Expected note', r.expected_note],
          ['Role', r.my_role ? rolePill(r.my_role) : ''],
          ['Reporter', reporter],
          ['Collaborators', collabs],
          ['Program', r.program],
          ['Asset', r.asset_label || r.asset, 'mono'],
          /* Only ever present while a report is retesting. Which side owns the retest is the one
             thing about that state that changes what we do, so it is stated rather than inferred. */
          r.retest_owner ? ['Retest', r.retest_owner === 'us'
            ? 'OURS - verify the fix and reply'
            : 'HackerOne Triage retests this, no action required'] : null,
          ['Weakness', r.weakness],
          ['Last update', r.last_activity
            ? fmtTime(r.last_activity) + ' UTC (' + ageShort(r.last_activity) + ' ago)' : ''],
          ['Submitted', fmtDateOnly(r.submitted_on)],
          ['Closed', fmtDateOnly(r.resolved_on)],
          ['Last activity', fmtTime(r.last_activity)],
          ['Synced', fmtTime(r.synced_at)],
          ['Source', r.source],
          ['Class', r['class']],
          ['Target', targetLabel(r)]
          /* Ref / Tracker only / H1 body / File deliberately absent. They are legacy
             file-tracker plumbing, and HackerOne is the authority for reports now. */
        ];
      },
      extra: function (r) {
        var out = [];
        /* An unmissable caveat next to the number, for the one case where the pane shows an
           amount nobody has actually been paid. */
        if (hasExpected(r)) {
          out.push(el('div', { class: 'expected-panel' }, [
            el('div', { class: 'ep-head' }, [
              el('span', { class: 'ep-title', text: 'Anticipated award' }),
              el('span', { class: 'exp-tag', text: 'unconfirmed' })
            ]),
            el('div', { class: 'ep-amt' }, [
              expectedMoney(r.expected_bounty, r.currency, expectedTitle(r)),
              r.expected_cve ? el('span', { class: 'ep-cve', text: String(r.expected_cve) }) : null
            ]),
            el('p', { class: 'ep-note', text: EXPECTED_CAVEAT }),
            r.expected_note ? el('p', { class: 'ep-note ep-own', text: String(r.expected_note) }) : null
          ]));
        }
        /* The raw legacy tracker markdown row is NOT rendered. It was a horizontally
           scrolling pipe-delimited line duplicating fields already shown above, sourced
           from the file tracker that HackerOne has replaced. */
        return out.length ? frag(out) : null;
      },
      /* Comments go below the report body - see drawView. */
      after: function (r) {
        return threadPanel(r);
      },
      fields: [
        { key: 'title', label: 'Title', type: 'text', required: true },
        { key: 'h1_id', label: 'H1 id', type: 'text' },
        { key: 'ref', label: 'Ref', type: 'text' },
        { key: 'state', label: 'State', type: 'text' },
        { key: 'severity', label: 'Severity', type: 'text' },
        { key: 'bounty', label: 'Bounty', type: 'text' },
        { key: 'submitted_on', label: 'Submitted on', type: 'text' },
        { key: 'resolved_on', label: 'Resolved on', type: 'text' },
        { key: 'url', label: 'URL', type: 'text' },
        { key: 'class', label: 'Class', type: 'text', list: 'hp-classes' },
        { key: 'target_id', label: 'Target', type: 'target' },
        { key: 'body', label: 'Body (markdown)', type: 'markdown' }
      ]
    },

    advisories: {
      entity: 'advisories',
      /* NOT workable. An advisory is a published vendor artefact - it has no status you can
         move and no worklog you would keep against it. The picker and the note box were
         inherited from the leads config and only added clutter above the match panel, which
         is the part of this page anyone actually reads. */
      workable: false,
      label: 'Advisories',
      sub: 'Published vendor security advisories, cross-referenced against your reports.',
      singular: 'advisory',
      canCreate: true,
      filters: { q: true, target: true, status: true },
      statusLabel: 'Status',
      statusOptions: ['', 'watch', 'relevant', 'dismissed'],
      defaultSort: '-published',
      columns: [
        { key: 'ref', label: 'Ref', cls: 'cell-mono nowrap' },
        {
          key: 'title', label: 'Title', sort: 'title', cls: 'cell-title cell-max',
          /* The stored title keeps its CVE prefix so search still matches it; the column strips it,
             since Ref and CVE already carry the id. */
          render: function (r) { var t = advisoryTitle(r); return el('span', { class: 'trunc', text: t, title: t }); }
        },
        /* The single Product column used to print the whole VulDB metadata blob. Split into the
           three fields worth a column - Vendor, Product, Type - and drop the rest (Risk, Physical,
           Local, Remote, Exploit, Countermeasures), which belonged in the detail pane at most. */
        { key: 'vendor', label: 'Vendor', sort: 'product', cls: 'nowrap',
          render: function (r) { return parseAdvisoryMeta(r.product).vendor || '—'; } },
        { key: 'product', label: 'Product', sort: 'product', cls: 'nowrap',
          render: function (r) { return parseAdvisoryMeta(r.product).product || '—'; } },
        { key: 'ptype', label: 'Type', cls: 'nowrap',
          render: function (r) { return parseAdvisoryMeta(r.product).type || '—'; } },
        { key: 'cve', label: 'CVE', sort: 'cve', cls: 'cell-mono nowrap',
          render: function (r) { return cveCell(r.cve); } },
        /* ExampleVendor states the weakness class twice - as "Problem Type: CWE-863" and inline in
           the opening sentence - and advisories.parse_cwe() prefers the labelled line. Older
           advisories name none, hence the dash. */
        { key: 'cwe', label: 'CWE', sort: 'cwe', cls: 'nowrap',
          render: function (r) { return cweCell(r.cwe); } },
        { key: 'cvss', label: 'CVSS', sort: 'cvss', cls: 'nowrap cell-mono',
          render: function (r) { return r.cvss || '—'; } },
        { key: 'priv', label: 'Priv', cls: 'nowrap', render: function (r) { return privCell(r); } },
        { key: 'severity', label: 'Level', sort: 'severity', cls: 'nowrap',
          render: function (r) { return r.severity ? sevPill(r.severity) : '—'; } },
        { key: 'status', label: 'Status', sort: 'status', cls: 'nowrap', render: function (r) { return pill(r.status); } },
        { key: 'mine', label: 'Credit', cls: 'nowrap', render: function (r) { return mineCell(r); } },
        { key: 'published', label: 'Published', sort: 'published', cls: 'nowrap tiny dim', render: function (r) { return fmtDateOnly(r.published); } },
        { key: 'target', label: 'Target', cls: 'nowrap', render: function (r) { return targetLabel(r) || '—'; } },
        /* Far right: which feed this came from (VulDB, CISA, ...), so a mixed list is legible. */
        { key: 'source', label: 'Source', sort: 'source', cls: 'nowrap',
          render: function (r) { return r.source ? el('span', { class: 'pill pill-neutral', text: advisorySource(r.source) }) : el('span', { class: 'muted', text: '—' }); } }
      ],
      /* One fetch per render; the table is drawn only once this settles, so every Mine cell
         reads a warm index. It never rejects, so a missing endpoint cannot block the list. */
      preload: function () { return ensureAdvisoryMatches(true); },
      extra: function (r) { return matchedReportPanel(r.id); },
      meta: function (r) {
        return [
          ['Ref', r.ref, 'mono'],
          ['Vendor', parseAdvisoryMeta(r.product).vendor],
          ['Product', parseAdvisoryMeta(r.product).product],
          ['Type', parseAdvisoryMeta(r.product).type],
          ['CVE', r.cve ? cveCell(r.cve) : ''],
          ['CVSS', r.cvss],
          ['Level', r.severity ? sevPill(r.severity) : ''],
          ['Impact', cvssPart(r, 'impact_text')],
          ['Privileges', cvssPart(r, 'privileges')],
          ['CWE', r.cwe ? cweCell(r.cwe) : ''],
          ['Source', r.source],
          ['Status', r.status ? pill(r.status) : ''],
          ['Published', fmtTime(r.published)],
          ['Link', r.url ? extLink(r.url, r.url) : ''],
          ['Target', targetLabel(r)],
          ['Lead', r.lead_id ? el('a', { href: '#/leads/' + encodeURIComponent(r.lead_id), text: 'lead #' + r.lead_id }) : ''],
          ['File', r.file_path, 'mono'],
          ['Indexed', fmtTime(r.indexed_at)]
        ];
      },
      fields: [
        { key: 'title', label: 'Title', type: 'text', required: true },
        { key: 'ref', label: 'Ref (CVE…)', type: 'text' },
        { key: 'source', label: 'Source', type: 'text' },
        { key: 'url', label: 'URL', type: 'text' },
        { key: 'published', label: 'Published', type: 'text', hint: 'YYYY-MM-DD' },
        { key: 'status', label: 'Status', type: 'select', options: ['watch', 'relevant', 'dismissed'] },
        { key: 'target_id', label: 'Target', type: 'target' },
        { key: 'lead_id', label: 'Linked lead id', type: 'text' },
        { key: 'body', label: 'Body (markdown)', type: 'markdown' }
      ]
    },

    programs: {
      entity: 'programs',
      label: 'Programs',
      sub: 'Bounty program scope and rules of engagement.',
      singular: 'program',
      canCreate: false,
      readOnly: true,
      /* Programs are read-only and discovered from the reports you file, which never surfaces a
         private or newly-awarded program until a report exists against it. The add-program picker
         closes that gap: it searches every program the credential can SEE on HackerOne (private
         and invited included) and onboards the one you choose. */
      addPrograms: true,
      filters: { q: true },
      defaultSort: 'name',
      /* Conceal mode (the crossed-circle toggle) blurs the identity of every program that is NOT
         public - private, soft-launched or never-synced - so the tab screenshots without leaking
         which private programs you are in. Public rows carry no class and stay readable. */
      rowClass: function (r) { return r.state === 'public_mode' ? null : 'prog-conceal'; },
      columns: [
        { key: 'slug', label: 'Slug', sort: 'slug', cls: 'cell-mono nowrap' },
        /* Content-width, not `cell-title`: a program name is short, and cell-title's 20rem
           min-width plus its slack-absorbing behaviour left a wide near-empty column that pushed
           every data column to the right. `nowrap` packs it left; `cell-name` keeps the weight. */
        { key: 'name', label: 'Name', sort: 'name', cls: 'nowrap cell-name' },
        {
          /* Whether a program PAYS is the first thing worth knowing about it, and 'unknown' is
             an honest third state: NULL means this program has never been through
             `h1.py --sync-programs`, which is not the same as "does not pay". */
          key: 'offers_bounties', label: 'Bounties', sort: 'offers_bounties', cls: 'nowrap',
          render: function (r) {
            if (r.offers_bounties === null || r.offers_bounties === undefined) return el('span', { class: 'muted', text: '—' });
            return Number(r.offers_bounties)
              ? el('span', { class: 'pill pill-confirmed', text: 'bounty' })
              : el('span', { class: 'pill pill-parked', text: 'VDP' });
          }
        },
        {
          key: 'submission_state', label: 'Intake', sort: 'submission_state', cls: 'nowrap',
          render: function (r) { return r.submission_state ? pill(r.submission_state) : el('span', { class: 'muted', text: '—' }); }
        },
        {
          /* HackerOne's own visibility flag, from the accessible-programs list: `public_mode` is a
             public program, anything else (`soft_launched`, ...) is a private/invite program. NULL
             means never synced, shown clear (dash) rather than guessed at. */
          key: 'state', label: 'Visibility', sort: 'state', cls: 'nowrap',
          render: function (r) {
            if (!r.state) return el('span', { class: 'muted', text: '—' });
            return r.state === 'public_mode'
              ? el('span', { class: 'pill pill-open', text: 'public' })
              : el('span', { class: 'pill pill-neutral', text: 'private' });
          }
        },
        {
          /* Awards, Avg and Earned read left to right as n / mean / sum: the count of awarded
             reports, the average award, and the total, where count x average = total. A VDP report
             resolved for no money still counts as an award (it carries bounty '0'), which is why a
             VDP row can show an award count with a $0.00 average and a dash under Earned. */
          key: 'award_count', label: 'Awards', sort: 'award_count', cls: 'nowrap', descFirst: true,
          render: function (r) {
            var n = Number(r.award_count);
            return n > 0 ? el('span', { class: 'money', text: String(n) })
                         : el('span', { class: 'muted', text: '—' });
          }
        },
        {
          key: 'avg_bounty', label: 'Avg', sort: 'avg_bounty', cls: 'nowrap', descFirst: true,
          render: function (r) {
            /* Null only when there are no awards to average, which is a dash. An average of $0.00
               is a real answer (a program whose awards were all VDP), so it is shown, not hidden. */
            if (r.avg_bounty === null || r.avg_bounty === undefined) return el('span', { class: 'muted', text: '—' });
            return el('span', { class: 'money', text: fmtMoney(r.avg_bounty, r.currency || 'USD') });
          }
        },
        {
          key: 'bounty_earned', label: 'Earned', sort: 'bounty_earned', cls: 'nowrap', descFirst: true,
          render: function (r) {
            var n = parseMoney(r.bounty_earned);
            return n ? el('span', { class: 'money', text: fmtMoney(n, r.currency || 'USD') })
                     : el('span', { class: 'muted', text: '—' });
          }
        },
        /* The flexible column now: it absorbs the row's slack (cell-max) so everything to its left
           packs tight, and it truncates with the full path on hover instead of overflowing into
           Updated the way an un-nowrapped `tiny` cell did. */
        { key: 'workspace', label: 'Workspace', cls: 'cell-mono dim cell-max',
          render: function (r) {
            return r.workspace ? el('span', { class: 'trunc', text: r.workspace, title: r.workspace })
                               : el('span', { class: 'muted', text: '—' });
          } },
        { key: 'updated_at', label: 'Updated', cls: 'nowrap tiny dim', render: function (r) { return fmtTime(r.updated_at); } }
      ],
      meta: function (r) {
        return [
          ['Slug', r.slug, 'mono'],
          ['Platform', r.platform],
          ['Link', r.url ? extLink(r.url, r.url) : ''],
          ['Workspace', r.workspace, 'mono'],
          ['Intake', r.submission_state || ''],
          ['Visibility', r.state ? (r.state === 'public_mode' ? 'public' : 'private') : ''],
          ['Bounties', r.offers_bounties === null || r.offers_bounties === undefined
            ? '' : (Number(r.offers_bounties) ? 'yes' : 'no')],
          ['Awards', Number(r.award_count) > 0 ? String(Number(r.award_count)) : ''],
          ['Average award', (r.avg_bounty === null || r.avg_bounty === undefined)
            ? '' : fmtMoney(r.avg_bounty, r.currency || 'USD')],
          ['Earned', parseMoney(r.bounty_earned) ? fmtMoney(parseMoney(r.bounty_earned), r.currency || 'USD') : ''],
          ['Guidelines synced', fmtTime(r.synced_at)],
          ['Updated', fmtTime(r.updated_at)]
        ];
      },
      bodyRender: function (r) {
        /* Hand-entered first, always. scope_md and roe_md come from the program's workdir
           program/ folder, are the authority where they exist, and are what has been read and
           acted on. policy_md is HackerOne's own copy, kept in its own column and shown below
           rather than merged, so neither can quietly stand in for the other. */
        var out = [];
        if (r.scope_md) {
          out.push(el('h3', { class: 'card-title', text: 'Scope / guidelines' }));
          out.push(mdBlock(r.scope_md));
        }
        if (r.roe_md) {
          out.push(el('h3', { class: 'card-title', text: 'Rules of engagement' }));
          out.push(mdBlock(r.roe_md));
        }
        if (r.policy_md) {
          out.push(el('h3', { class: 'card-title', text: 'Program policy (HackerOne)' }));
          out.push(mdBlock(r.policy_md));
        }
        if (!out.length) {
          out.push(empty('No scope or ROE indexed',
            'Run `python3 h1.py --sync-programs`, or add program/GUIDELINES.md to the workspace and re-index.'));
        }
        return frag(out);
      }
    }
  };

  /* ============================================================ detail pane */

  function buildForm(fields, values) {
    var wrap = el('div', {});
    var grid = el('div', { class: 'form-grid' });
    var inputs = {};
    var mdArea = null;
    var mdKey = null;

    fields.forEach(function (f) {
      var v = values && values[f.key] !== undefined && values[f.key] !== null ? values[f.key] : '';
      if (f.type === 'markdown') {
        mdKey = f.key;
        mdArea = el('textarea', { spellcheck: 'false', 'aria-label': f.label });
        mdArea.value = String(v);
        return;
      }
      var ctrl;
      if (f.type === 'select') {
        ctrl = selectEl(f.options, v);
      } else if (f.type === 'target') {
        ctrl = selectEl(targetIdOptions(), v === '' ? '' : String(v));
      } else {
        ctrl = el('input', { type: 'text', value: String(v), list: f.list || null, spellcheck: 'false' });
      }
      inputs[f.key] = ctrl;
      grid.appendChild(field(f.label, ctrl, f.hint));
    });

    wrap.appendChild(grid);
    if (mdArea) wrap.appendChild(field('Body (markdown)', mdArea));

    return {
      node: wrap,
      focusFirst: function () {
        var first = grid.querySelector('input, select');
        if (first) first.focus();
        else if (mdArea) mdArea.focus();
      },
      read: function () {
        var out = {};
        for (var k in inputs) {
          var val = inputs[k].value;
          out[k] = val === '' ? null : val;
        }
        if (mdKey) out[mdKey] = mdArea ? mdArea.value : '';
        return out;
      }
    };
  }

  /* Shared by Leads / Reports / Advisories / Programs / Notes. */
  function detailPane(cfg, id, onSaved) {
    var wrap = el('section', { class: 'pane card' });
    var row = null;
    var editing = false;

    function load() {
      clear(wrap);
      append(wrap, loading('Loading ' + cfg.singular + ' #' + id + '…'));
      api('/' + cfg.entity + '/' + encodeURIComponent(id)).then(function (data) {
        row = data || {};
        draw();
      }).catch(function (err) {
        clear(wrap);
        append(wrap, el('div', { class: 'pane-body' }, errorPanel(err, load)));
      });
    }

    function head(actions) {
      return el('div', { class: 'pane-head' }, [
        el('h2', { text: row.title || row.name || ('#' + id) }),
        el('div', { class: 'pane-actions' }, actions)
      ]);
    }

    function draw() {
      clear(wrap);
      var actions = [];
      /* Leftmost, ahead of Edit. The title is what gets typed into a HackerOne search, a triage
         reply or a message to a collaborator far more often than the body gets pasted, so it is
         the first thing reached for rather than something to hunt for at the end of the row.
         Copies the bare title without the ref prefix, since that is what reads as a name. */
      /* ORDER IS FIXED and identical on every entity: Comments, Copy markdown, Copy name,
         Copy report ID, Copy URL, then the file-backed extras, then Edit and Close. Seth reads these rows
         on a phone as well as a desktop, and a button that moves between tabs has to be hunted
         for every time. The copies run left to right from the shortest, most-pasted value to the
         longest, and the two that CHANGE something sit at the end where a mis-tap is least
         likely. */
      /* Jumps to the conversation, which on a long report is several screens down and is the
         part that actually changes. Only offered when there IS a thread; a button that scrolls
         nowhere is worse than an absent one. */
      if (row.thread) {
        actions.push(el('button', {
          class: 'btn btn-sm', type: 'button', text: 'Comments',
          title: 'Jump to the comment thread',
          onclick: function () {
            var target = document.getElementById('thread-panel');
            if (target && target.scrollIntoView) {
              target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          }
        }));
      }
      var bodyKey = 'body';
      (cfg.fields || []).forEach(function (f) { if (f.type === 'markdown') bodyKey = f.key; });
      if (row[bodyKey] === undefined && row.scope_md !== undefined) bodyKey = 'scope_md';
      if (row[bodyKey]) {
        actions.push(copyButton(function () { return String(row[bodyKey] || ''); }, 'Copy markdown'));
      }
      if (row.title) {
        actions.push(copyButton(function () { return String(row.title || ''); }, 'Copy name'));
      }
      /* A row on the Tracker always carries its HackerOne id, and that id is what goes into a
         comment, a dedup check or a message about the report - far more often than the URL. */
      if (row.h1_id) {
        actions.push(copyButton(function () { return String(row.h1_id); }, 'Copy report ID'));
      }
      if (row.url) {
        actions.push(copyButton(function () { return String(row.url); }, 'Copy URL'));
      }
      /* Quick copy: the markdown body is what gets pasted into a HackerOne report or handed to
         a collaborator, so it is the single most useful thing to lift out of this pane.
         Derive the key from cfg.fields rather than assuming 'body' - programs use 'scope_md'. */
      if (row.file_path) {
        actions.push(copyButton(function () { return String(row.file_path); }, 'Copy path'));
        actions.push(el('a', {
          class: 'btn btn-sm', text: 'Open in Files',
          href: '#/files?' + qsFrom({ path: row.file_path.replace(/\/[^/]*$/, ''), file: row.file_path })
        }));
      }
      if (!cfg.readOnly) {
        actions.push(el('button', {
          class: 'btn btn-sm', type: 'button', text: editing ? 'Cancel' : 'Edit',
          onclick: function () { editing = !editing; draw(); }
        }));
      }
      actions.push(el('a', { class: 'btn btn-sm btn-quiet', text: 'Close', href: '#/' + cfg.entity + hashQuery() }));
      append(wrap, head(actions));

      var body = el('div', { class: 'pane-body' });
      append(wrap, body);

      if (editing) {
        drawEditor(body);
        return;
      }

      /* Working panel: the things you do to a lead DURING a hunt, without opening the editor.
         Status changes and worklog appends both write the markdown file and re-index, so the
         file on disk stays the source of truth. */
      if (cfg.workable) {
        var wp = workPanel(cfg, row, load);
        /* Only if it has rows. A killed or open lead has no report to copy and, since the status
           picker was removed, nothing else either - appending it anyway drew an empty box. */
        if (wp && wp.childNodes.length) body.appendChild(wp);
      }

      var mg = cfg.meta ? metaGrid(cfg.meta(row)) : null;
      if (mg) body.appendChild(mg);
      /* row.header (the note's raw first line, e.g. "# L3 - collectd codec ... CONFIRMED.
         2026-07-31.") is deliberately NOT rendered. The pane heading above is derived from it,
         so showing it too just repeats the title back with its markdown still on. */
      if (cfg.extra) {
        var x = cfg.extra(row);
        if (x) body.appendChild(x);
      }
      if (cfg.bodyRender) body.appendChild(cfg.bodyRender(row));
      else body.appendChild(mdBlock(row.body, null, true));

      /* Rendered AFTER the report text, not before it. The report is what you came to read;
         the conversation is what happened to it afterwards, so it belongs underneath. */
      if (cfg.after) {
        var a = cfg.after(row);
        if (a) body.appendChild(a);
      }
    }

    function drawEditor(body) {
      var form = buildForm(cfg.fields, row);
      var errHost = el('div', {});
      var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Save' });

      saveBtn.addEventListener('click', function () {
        var payload = form.read();
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving…';
        clear(errHost);
        api('/' + cfg.entity + '/' + encodeURIComponent(id), { method: 'PUT', body: payload })
          .then(function (updated) {
            row = (updated && typeof updated === 'object' && (updated.id || updated.title)) ? updated : row;
            editing = false;
            toast('Saved ' + cfg.singular + ' #' + id + (row.file_path ? ' → ' + row.file_path : ''), 'ok');
            draw();
            if (onSaved) onSaved(row);
          })
          .catch(function (err) {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Save';
            append(errHost, errorPanel(err));
          });
      });

      append(body, [
        el('div', { class: 'alert alert-info tiny' },
          'Saving writes the markdown file first, then re-indexes that path.'),
        errHost,
        form.node,
        el('div', { class: 'form-actions' }, [
          saveBtn,
          el('button', {
            class: 'btn', type: 'button', text: 'Cancel',
            onclick: function () { editing = false; draw(); }
          })
        ])
      ]);
      form.focusFirst();
    }

    load();
    return wrap;
  }

  function createPane(cfg, presets) {
    var wrap = el('section', { class: 'pane card' });
    var form = buildForm(cfg.fields, presets || {});
    var errHost = el('div', {});
    var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Create ' + cfg.singular });

    saveBtn.addEventListener('click', function () {
      var payload = form.read();
      if (!payload.title) {
        clear(errHost);
        append(errHost, el('div', { class: 'alert alert-warn', text: 'A title is required.' }));
        return;
      }
      saveBtn.disabled = true;
      saveBtn.textContent = 'Creating…';
      clear(errHost);
      api('/' + cfg.entity, { method: 'POST', body: payload })
        .then(function (created) {
          toast('Created ' + cfg.singular + (created && created.file_path ? ' → ' + created.file_path : ''), 'ok');
          if (created && created.id !== undefined && created.id !== null) {
            location.hash = '#/' + cfg.entity + '/' + encodeURIComponent(created.id);
          } else {
            location.hash = '#/' + cfg.entity;
          }
        })
        .catch(function (err) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Create ' + cfg.singular;
          append(errHost, errorPanel(err));
        });
    });

    append(wrap, [
      el('div', { class: 'pane-head' }, [
        el('h2', { text: 'New ' + cfg.singular }),
        el('div', { class: 'pane-actions' },
          el('a', { class: 'btn btn-sm btn-quiet', text: 'Cancel', href: '#/' + cfg.entity }))
      ]),
      el('div', { class: 'pane-body' }, [
        el('div', { class: 'alert alert-info tiny' },
          'Paste markdown straight into the body. The server writes the file first, then indexes it.'),
        errHost,
        form.node,
        el('div', { class: 'form-actions' }, saveBtn)
      ])
    ]);

    form.focusFirst();
    return wrap;
  }

  /* ============================================================ list views */

  function classDatalist(items) {
    var seen = {};
    items.forEach(function (r) { if (r['class']) seen[r['class']] = 1; });
    var dl = el('datalist', { id: 'hp-classes' });
    Object.keys(seen).sort().forEach(function (c) { dl.appendChild(el('option', { value: c })); });
    return dl;
  }

  function entityListView(root, cfg, ctx) {
    var q = ctx.q;
    var params = {
      q: q.get('q') || '',
      target: q.get('target') || '',
      'class': q.get('class') || '',
      status: q.get('status') || '',
      /* `role` is filtered client-side: the server has no my_role filter (API.md documents
         q/target/class/status only), and my_role is a derived column. */
      role: q.get('role') || '',
      /* '1' = only rows carrying an anticipated (unconfirmed) award. Client-side, same reason. */
      anticipated: q.get('anticipated') === '1' ? '1' : '',
      /* '' = let the server apply the primary program, 'all' = every program, otherwise one
         handle. Server-side: the default lives with the credential it is derived from, so a
         direct API call is scoped the same way the tab is. */
      program: parseProgramScope(q.get('program')),
      /* '1' = only rows where money actually reached me (my_bounty > 0). Unlike the two above
         this IS server-side: it is a predicate on the reports entity, so the row count and the
         dashboard card that links here cannot drift apart. */
      paid: q.get('paid') === '1' ? '1' : '',
      /* Comma-separated states to HIDE, e.g. 'duplicate,informative'. Normalised on read so a
         hand-edited URL with spaces or repeats still behaves. Client-side, same reason. */
      exclude: parseExclude(q.get('exclude')).join(','),
      sort: q.get('sort') || cfg.defaultSort || '',
      limit: parseInt(q.get('limit') || '50', 10) || 50,
      offset: parseInt(q.get('offset') || '0', 10) || 0
    };

    function go(patch, keepId) {
      var next = {};
      for (var k in params) next[k] = params[k];
      for (var p in patch) next[p] = patch[p];
      if (patch.offset === undefined && (patch.q !== undefined || patch.target !== undefined ||
        patch['class'] !== undefined || patch.status !== undefined || patch.role !== undefined ||
        patch.anticipated !== undefined || patch.exclude !== undefined ||
        patch.program !== undefined || patch.paid !== undefined || patch.limit !== undefined)) {
        next.offset = 0;
      }
      var id = keepId === false ? null : ctx.id;
      location.hash = '#/' + cfg.entity + (id ? '/' + encodeURIComponent(id) : '') +
        (qsFrom(next) ? '?' + qsFrom(next) : '');
    }

    /* Declared as a function so it is hoisted above the head that calls it. Returns the button's
       label, or null when there is nothing to collapse: a view with `filterBar: false` has no card
       at all, and one with no filters has an empty one. */
    function mobileToggleLabel() {
      if (!cfg.filters) return null;
      /* A `filterBar: false` view still HAS filters - the Tracker's state chips and exclusion
         chips are its filters, they just live inside the list card instead of in a strip above
         it. Those need collapsing on a phone for the same reason the strip does, so the button
         exists for them too and targets the list card. */
      if (cfg.filterBar === false) return (cfg.summary || cfg.filters.exclude) ? 'Filters' : null;
      var f = cfg.filters;
      var beyondSearch = f.target || f.cls || f.status || f.role || f.program || f.anticipated;
      if (beyondSearch) return 'Filters';
      return f.q ? 'Search' : null;
    }

    /* Does the URL already narrow the list? If so the card opens on load, so a filtered list is
       never shown with nothing on screen saying why. This is the reason the card cannot simply
       start closed and stay closed until tapped. */
    function anyFilterApplied() {
      return !!(params.q || params.target || params['class'] || params.status || params.role ||
        params.program || params.anticipated === '1');
    }

    var isNew = ctx.id === 'new';
    var head = el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: cfg.label })
        /* Per-tab description subtitles were removed: the title stands on its own and the cards
           below say what each page is. `cfg.sub` is still accepted by the view config but no
           longer rendered, so nothing downstream breaks. */
      ]),
      el('div', { class: 'page-actions' }, [
        /* MOBILE FILTER TOGGLE. Hidden on desktop by CSS, where the card is already visible and a
           second control would be clutter. On a phone the card is four controls deep and is
           reached rarely, so the whole thing collapses behind one button next to the other page
           actions. Built for every entity so Advisories, Programs, Leads and Reports all behave
           the same way.

           The LABEL names what the button actually reveals. On Leads that is Target, Class and
           Status as well as search, and calling it "Search" would hide three controls behind a
           word that does not describe them. */
        mobileToggleLabel()
          ? el('button', {
              class: 'btn btn-sm mobile-search-toggle', type: 'button', text: mobileToggleLabel(),
              title: 'Show the ' + mobileToggleLabel().toLowerCase()
            })
          : null,
        /* SORT. In card mode the column headers collapse to a single sort row, which was sitting
           above the rows taking a chunk of a phone screen for a control used occasionally. It
           becomes a button, like Search and Filters, and reveals the same row. */
        cfg.columns
          ? el('button', {
              class: 'btn btn-sm mobile-sort-toggle', type: 'button', text: 'Sort',
              title: 'Show the sort controls'
            })
          : null,
        cfg.addPrograms ? el('button', { class: 'btn btn-primary', type: 'button', text: '+ Add program',
          title: 'Search your HackerOne programs and add one to track' }) : null,
        cfg.canCreate ? el('a', { class: 'btn btn-primary', href: '#/' + cfg.entity + '/new', text: 'New ' + cfg.singular }) : null
      ])
    ]);
    root.appendChild(head);

    /* The add-program picker sits collapsed under the header until the button reveals it, so the
       Programs list is what you see first. Built once; toggled open. */
    if (cfg.addPrograms) {
      var addPanel = buildAddProgramPanel(function () { loadPrograms(true).then(function () { load(); }); });
      addPanel.hidden = true;
      root.appendChild(addPanel);
      var addBtn = head.querySelector('.page-actions .btn-primary');
      if (addBtn) addBtn.addEventListener('click', function () {
        addPanel.hidden = !addPanel.hidden;
        if (!addPanel.hidden) { var i = addPanel.querySelector('input'); if (i) i.focus(); }
      });
    }

    /* Wired after the filter card exists, further down, because the toggle targets it. */
    var mobileSearchBtn = head.querySelector('.mobile-search-toggle');
    var mobileSortBtn = head.querySelector('.mobile-sort-toggle');

    /* MODE CHIPS. Yes/no cuts over the whole list - the sort of thing a select buries. Built
       in one place and rendered by whichever container is active: the filter strip when a view
       has one, the chip bar under the list when it does not. One definition, so a mode can never
       end up with two switches that disagree.

       Anticipated: it has to be obvious enough that unconfirmed awards are findable without
       already knowing they exist. Programs: it widens the WHOLE list, which is not something to
       bury in a select full of handles. */
    function modeChips() {
      var out = [];
      if (cfg.filters.anticipated) {
        var antiOn = params.anticipated === '1';
        out.push(el('button', {
          class: 'btn chip-expected' + (antiOn ? ' on' : ''),
          type: 'button',
          'aria-pressed': antiOn ? 'true' : 'false',
          title: cfg.anticipatedTitle || '',
          text: cfg.anticipatedLabel || 'Anticipated only',
          onclick: function () { go({ anticipated: antiOn ? '' : '1' }); }
        }));
      }
      if (cfg.filters.program) {
        /* A picker rather than an all-or-primary toggle. The list defaults to every program now,
           so the useful action is "narrow to one", which a two-state button cannot express once
           there are more than two programs. An empty ?program= means the default, which is all. */
        var cur = params.program || ALL_PROGRAMS;
        out.push(el('label', { class: 'field field-program' }, [
          el('span', { class: 'flab', text: 'Program' }),
          selectEl(programOptions(), cur, function (v) {
            go({ program: v === ALL_PROGRAMS ? '' : v });
          })
        ]));
      }
      return out;
    }

    /* filters
       A view can suppress this whole strip with `filterBar: false`. The Tracker does: a row of
       selects sitting above the list was a second, uglier copy of controls the list already
       carries as chips, and it pushed the table it filters below the fold. Its chips move into
       the list card instead - see modeChips() and drawChipBar().

       It is BUILT either way and only the append is conditional. Wrapping eighty lines in an
       `if` to save a handful of detached DOM nodes would have re-indented the whole block for
       nothing. */
    var filters = el('div', { class: 'filters card' });
    if (cfg.filters.q) {
      var qInput = el('input', { type: 'search', value: params.q, placeholder: 'title / body…', spellcheck: 'false' });
      qInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') go({ q: qInput.value }); });
      var qField = el('label', { class: 'field grow field-q' }, [
        el('span', { class: 'field-label', text: 'Search' }), qInput
      ]);
      filters.appendChild(qField);
    }
    if (cfg.filters.target) {
      filters.appendChild(field('Target', selectEl(targetOptions(), params.target, function (v) { go({ target: v }); })));
    }
    if (cfg.filters.cls) {
      var clsInput = el('input', { type: 'text', value: params['class'], placeholder: 'BAC, DoS…', list: 'hp-classes', spellcheck: 'false' });
      clsInput.addEventListener('change', function () { go({ 'class': clsInput.value }); });
      clsInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') go({ 'class': clsInput.value }); });
      filters.appendChild(el('label', { class: 'field' }, [
        el('span', { class: 'field-label', text: 'Class' }), clsInput
      ]));
    }
    if (cfg.filters.status) {
      filters.appendChild(field(cfg.statusLabel || 'Status',
        selectEl(cfg.statusOptions.map(function (s) { return { value: s, label: s === '' ? 'Any' : s }; }),
          params.status, function (v) { go({ status: v }); })));
    }
    if (cfg.filters.role) {
      filters.appendChild(field(cfg.roleLabel || 'Role',
        selectEl((cfg.roleOptions || []).map(function (s) { return { value: s, label: s === '' ? 'Any' : s }; }),
          params.role, function (v) { go({ role: v }); })));
    }
    modeChips().forEach(function (chip) {
      filters.appendChild(el('div', { class: 'field' }, [
        el('span', { class: 'field-label', text: ' ' }), chip
      ]));
    });
    filters.appendChild(el('div', { class: 'field' }, [
      el('span', { class: 'field-label', text: ' ' }),
      el('button', { class: 'btn', type: 'button', text: 'Apply', onclick: function () {
        var patch = {};
        if (cfg.filters.q) patch.q = filters.querySelector('input[type=search]').value;
        if (cfg.filters.cls) patch['class'] = clsInput.value;
        go(patch);
      } })
    ]));
    filters.appendChild(el('div', { class: 'field' }, [
      el('span', { class: 'field-label', text: ' ' }),
      el('a', { class: 'btn btn-quiet', text: 'Reset', href: '#/' + cfg.entity })
    ]));
    /* The card starts hidden on mobile via CSS and the toggle reveals it, rather than the button
       owning the state: a filter already applied must stay visible on load, or the user cannot see
       what is narrowing the list they are looking at. Desktop ignores `q-open` entirely - the card
       is always shown there, so this class only ever means something below 768px. */
    if (anyFilterApplied()) filters.classList.add('q-open');
    if (cfg.filterBar !== false) root.appendChild(filters);

    /* Filter chips, INSIDE the list card and under the include chips the summary strip draws,
       filled in by load() once the rows are known: the exclusion list is built from the states
       PRESENT IN THE DATA, so a new HackerOne state appears here without a code change. Building
       it from the UNFILTERED rows also means a chip never vanishes as a consequence of being
       switched on. */
    var chipBar = (cfg.filters.exclude || cfg.filterBar === false)
      ? el('div', { class: 'excludebar' }) : null;

    function drawChipBar(allRows, shownCount) {
      if (!chipBar) return;
      clear(chipBar);
      if (cfg.filters.exclude) drawExcludeRow(allRows, shownCount);
      /* Only when there is no filter strip above; otherwise these chips already live there and
         drawing them twice would give one setting two switches. */
      if (cfg.filterBar === false) {
        var mode = modeChips();
        /* Reset lives here too. Without the filter strip there is nowhere else to clear a
           filter set from a bookmark, a dashboard drill-through or the state chips above. */
        if (filtersActive()) {
          mode.push(el('a', { class: 'btn btn-quiet btn-sm', text: 'Reset all filters',
                              href: '#/' + cfg.entity }));
        }
        if (mode.length) {
          chipBar.appendChild(el('div', { class: 'exrow' },
            [el('span', { class: 'exlabel', text: 'Show' })].concat(mode)));
        }
      }
    }

    /* Anything narrowing the list AWAY from the view's own defaults. sort/limit/offset are
       presentation, not a filter, so they do not light up Reset. */
    function filtersActive() {
      return !!(params.q || params.target || params['class'] || params.status || params.role ||
                params.anticipated || params.paid || params.exclude || params.program);
    }

    function drawExcludeRow(allRows, shownCount) {
      var excludeBar = chipBar;
      var ex = parseExclude(params.exclude);
      var inert = !!params.status;          /* inclusive State wins - see PRECEDENCE */
      var dim = excludeDim(cfg);

      var counts = {};
      var order = [];
      allRows.forEach(function (r) {
        var k = dim.key(r);
        if (counts[k] === undefined) { counts[k] = 0; order.push(k); }
        counts[k]++;
      });
      order.sort(function (a, b) {
        var ia = dim.order.indexOf(a), ib = dim.order.indexOf(b);
        if (ia < 0) ia = 99;
        if (ib < 0) ib = 99;
        if (ia !== ib) return ia - ib;
        return counts[b] - counts[a];
      });

      var row = el('div', { class: 'exrow' });
      row.appendChild(el('span', { class: 'exlabel', text: 'Exclude' }));

      order.forEach(function (k) {
        var on = ex.indexOf(k) >= 0;
        row.appendChild(el('button', {
          class: 'exchip' + (on ? ' on' : '') + (inert ? ' inert' : ''),
          type: 'button',
          disabled: inert || null,
          'aria-pressed': on ? 'true' : 'false',
          title: inert
            ? 'Ignored while the ' + (cfg.statusLabel || 'State') + ' filter is set to "' +
              params.status + '".'
            : (on ? 'Currently hiding ' : 'Currently showing ') + counts[k] + ' ' +
              prettyKey(k).toLowerCase() + ' ' + dim.noun +
              (counts[k] === 1 ? '' : 's') + ' — click to ' +
              (on ? 'show' : 'hide') + ' them',
          onclick: function () {
            var next = ex.slice();
            var i = next.indexOf(k);
            if (i >= 0) next.splice(i, 1); else next.push(k);
            go({ exclude: next.join(',') });
          }
        }, [
          el('span', { class: 'ex-sign', 'aria-hidden': 'true', text: on ? '−' : '+' }),
          el('span', { class: 'ex-k', text: prettyKey(k) }),
          el('span', { class: 'ex-n', text: String(counts[k]) })
        ]));
      });

      /* The combination they will want most often, in one press. */
      var present = dim.preset.keys.filter(function (k) { return counts[k]; });
      var noiseOn = present.length > 0 && present.every(function (k) { return ex.indexOf(k) >= 0; });
      if (present.length) {
        row.appendChild(el('button', {
          class: 'exchip exchip-preset' + (noiseOn ? ' on' : '') + (inert ? ' inert' : ''),
          type: 'button',
          disabled: inert || null,
          'aria-pressed': noiseOn ? 'true' : 'false',
          title: (noiseOn ? 'Stop hiding ' : 'Hide ') + present.join(', ') + ' in one press',
          text: noiseOn ? dim.preset.show : dim.preset.hide,
          onclick: function () {
            var next = ex.slice();
            present.forEach(function (k) {
              var i = next.indexOf(k);
              if (noiseOn) { if (i >= 0) next.splice(i, 1); }
              else if (i < 0) next.push(k);
            });
            go({ exclude: next.join(',') });
          }
        }));
      }
      excludeBar.appendChild(row);

      /* Never let the row count look small for an unexplained reason. */
      if (inert && ex.length) {
        excludeBar.appendChild(el('div', { class: 'exnote' },
          el('span', { text: 'Exclusions (' + ex.join(', ') + ') are ignored while ' +
            (cfg.statusLabel || 'State') + ' is "' + params.status + '". Clear it to apply ' +
            'them again.' })));
      } else if (ex.length) {
        excludeBar.appendChild(el('div', { class: 'exnote exnote-on' }, [
          el('span', { text: 'Hiding ' + (allRows.length - shownCount) + ' of ' +
            allRows.length + ' (' + ex.join(', ') + ')' }),
          el('button', {
            class: 'btn btn-quiet btn-sm', type: 'button', text: 'Clear',
            onclick: function () { go({ exclude: '' }); }
          })
        ]));
      }
    }


    var split = el('div', { class: 'split' + (ctx.id ? '' : ' no-detail') });
    var listCard = el('section', { class: 'pane card' });
    /* FILTERS LIVE IN TWO PLACES and one button has to reach both. Leads keeps a filter strip
       above the list AND include chips inside the list card; the Tracker has no strip at all and
       only the chips. Toggling just one of them is how the Leads chips ended up hidden with no
       way to bring them back. So `q-open` goes on both, always, and each stylesheet rule picks
       up whichever it owns.

       Same rule as before for the initial state: if the URL already narrows the list, both open
       on load, so a filtered list is never shown on a phone with nothing saying why it is short. */
    if (anyFilterApplied()) listCard.classList.add('q-open');
    if (mobileSearchBtn) {
      mobileSearchBtn.addEventListener('click', function () {
        var open = !filters.classList.contains('q-open');
        filters.classList.toggle('q-open', open);
        listCard.classList.toggle('q-open', open);
        mobileSearchBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        /* Focus the search box when there is one, since typing is the likeliest next action.
           Views whose controls are only chips get no focus call rather than a wrong one. */
        if (open && qInput) { qInput.focus(); qInput.select(); }
      });
      mobileSearchBtn.setAttribute('aria-expanded', anyFilterApplied() ? 'true' : 'false');
    }
    if (mobileSortBtn) {
      mobileSortBtn.addEventListener('click', function () {
        var open = listCard.classList.toggle('sort-open');
        mobileSortBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
      mobileSortBtn.setAttribute('aria-expanded', 'false');
    }
    split.appendChild(listCard);
    root.appendChild(split);

    if (isNew) {
      split.appendChild(createPane(cfg, { status: cfg.entity === 'leads' ? 'open' : undefined, target_id: '' }));
    } else if (ctx.id) {
      split.appendChild(detailPane(cfg, ctx.id, function () { load(); }));
    }

    function load() {
      clear(listCard);
      append(listCard, loading('Loading ' + cfg.label.toLowerCase() + '…'));

      /* fetchAll views pull the whole filtered set in one request and page it in the browser, so
         a client-side filter and a summary computed from the rows both cover every match. */
      var serverMax = 500;
      var query = {
        q: params.q, target: params.target, 'class': params['class'],
        /* clientStatus views filter on status themselves and must see every status in the
           response to count the include chips honestly. */
        status: cfg.clientStatus ? '' : params.status,
        paid: params.paid, program: params.program,
        sort: params.sort,
        limit: cfg.fetchAll ? serverMax : params.limit,
        offset: cfg.fetchAll ? 0 : params.offset
      };
      /* cfg.preload runs alongside the list request and must never reject: it is for auxiliary
         data (the advisory match index) that the columns read synchronously while rendering.
         Waiting for it here is what keeps the Mine column to one request per render. */
      Promise.all([
        api('/' + cfg.entity + (qsFrom(query) ? '?' + qsFrom(query) : '')),
        cfg.preload ? cfg.preload(params) : null
      ])
        .then(function (res) {
          var data = res[0];
          var items = (data && data.items) || [];
          var total = (data && typeof data.total === 'number') ? data.total : items.length;
          var truncated = cfg.fetchAll && total > items.length;

          /* `considered` is everything that passes every OTHER filter - the honest
             denominator for "Hiding N of M". The exclusion pass is run twice rather than
             threaded through clientFilter's single return value; over a few hundred rows that
             is free, and it keeps one definition of each filter. */
          var considered = items;
          /* Everything the server returned, before any client-side filter. The include chips
             count from this so their totals do not collapse when one of them is pressed. */
          var fetched = items;
          if (cfg.fetchAll && cfg.clientFilter) {
            if (cfg.filters.exclude) {
              considered = cfg.clientFilter(items, withParams(params, { exclude: '' }));
            }
            items = cfg.clientFilter(items, params);
          }
          if (cfg.fetchAll) total = items.length;

          var page = cfg.fetchAll
            ? items.slice(params.offset, params.offset + params.limit)
            : items;

          clear(listCard);
          /* The applied program scope comes back from the server because only the server knows
             what the default resolves to. Naming it here is what stops a narrowed list from
             looking like a complete one. */
          var scope = data && data.program_scope;
          var note = [];
          if (scope && scope !== ALL_PROGRAMS) note.push('program: ' + scope);
          else if (scope === ALL_PROGRAMS) note.push('all programs');
          if (params.sort) note.push('sorted: ' + params.sort);
          listCard.appendChild(el('div', { class: 'pane-head' }, [
            el('h2', { text: total + ' ' + (total === 1 ? cfg.singular : (cfg.plural || cfg.label.toLowerCase())) }),
            el('div', { class: 'pane-actions tiny dim' }, note.join('  ·  '))
          ]));

          if (truncated) {
            listCard.appendChild(el('div', { class: 'alert alert-warn tiny' },
              'Only the first ' + serverMax + ' rows were fetched, so the totals below cover those ' +
              'rows and not the whole set. Narrow the filters.'));
          }

          /* `summaryWhenEmpty` views keep the strip up even when the filters match nothing,
             because on Leads the chips in it ARE the filter: dropping them on an empty result
             would leave no way back to a non-empty one except Reset. */
          if (cfg.summary && (items.length || (cfg.summaryWhenEmpty && fetched.length))) {
            listCard.appendChild(cfg.summary(items, params, fetched));
          }
          /* Directly beneath the include chips the summary draws, so the two halves of one
             decision - what to show, what to hide - read as one strip instead of one being a
             separate card floating above the table. */
          if (chipBar) {
            listCard.appendChild(chipBar);
            drawChipBar(considered, items.length);
          }

          if (!page.length) {
            listCard.appendChild(empty('Nothing matches these filters',
              'Clear the filters, or run a re-index from Tools if files were added on disk.'));
          } else {
            listCard.appendChild(classDatalist(page));
            listCard.appendChild(dataTable(cfg.columns, page, {
              cards: true,
              sort: params.sort,
              onSort: function (s) { go({ sort: s }); },
              rowClass: cfg.rowClass || null,
              onRow: function (r) {
                location.hash = '#/' + cfg.entity + '/' + encodeURIComponent(r.id) +
                  (qsFrom(params) ? '?' + qsFrom(params) : '');
              },
              selectedId: ctx.id
            }));
            listCard.appendChild(pagerBar(total, params.limit, params.offset,
              function (off) { go({ offset: off }); },
              function (lim) { go({ limit: lim }); }));
          }
        })
        .catch(function (err) {
          clear(listCard);
          append(listCard, el('div', { class: 'pane-body' }, errorPanel(err, load)));
        });
    }

    load();
  }

  /* ============================================================== dashboard */

  function barRow(label, value, max, opts) {
    opts = opts || {};
    var pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
    var fill = el('div', { class: 'bf' + (opts.fillClass ? ' ' + opts.fillClass : '') });
    fill.style.width = pct + '%';   /* CSSOM: allowed under style-src 'self' */
    var labelNode = opts.href
      ? el('a', { class: 'bl', href: opts.href, text: label, title: label })
      : el('span', { class: 'bl', text: label, title: label });
    return el('div', { class: 'barrow' + (opts.rowClass ? ' ' + opts.rowClass : '') }, [
      labelNode,
      el('div', { class: 'bt' }, fill),
      el('span', { class: 'bn', text: String(value) })
    ]);
  }

  /* Display label for a breakdown key: capitalise the first letter and turn separators into
     spaces ("not-applicable" -> "Not applicable"). The RAW key is still what gets used for the
     link target and the colour class, so filtering by state keeps working. */
  function prettyKey(k) {
    var s = String(k == null ? '' : k).trim();
    if (!s) return '(none)';
    s = s.replace(/[-_]+/g, ' ');
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  /* Row order for a breakdown card. Pure, so it can be tested without a DOM.

     Default is highest tally first, which is what a reader wants from a tally: the biggest
     number is the headline. Ties break alphabetically rather than by whatever order the keys
     happened to arrive in, so reloading does not reshuffle rows that share a count.

     `opts.order` pins a fixed key sequence instead and is for cards where position carries
     meaning (a lifecycle, say) rather than magnitude. Keys missing from that list sort last. */
  function breakdownKeys(obj, opts) {
    opts = opts || {};
    var keys = Object.keys(obj || {});
    /* Buckets that are the absence of a value rather than a value. Dropped here, in the shared
       key builder, so the tally bars and any future consumer agree on what the card contains. */
    if (opts.omit && opts.omit.length) {
      keys = keys.filter(function (k) { return opts.omit.indexOf(k) < 0; });
    }
    if (opts.order) {
      keys.sort(function (a, b) {
        var ia = opts.order.indexOf(a), ib = opts.order.indexOf(b);
        if (ia < 0) ia = 999;
        if (ib < 0) ib = 999;
        if (ia !== ib) return ia - ib;
        return (obj[b] || 0) - (obj[a] || 0);
      });
    } else {
      keys.sort(function (a, b) {
        var d = (obj[b] || 0) - (obj[a] || 0);
        return d !== 0 ? d : String(a).localeCompare(String(b));
      });
    }
    return opts.limit ? keys.slice(0, opts.limit) : keys;
  }

  function breakdownCard(title, obj, opts) {
    opts = opts || {};
    var keys = breakdownKeys(obj, opts);

    var max = 0;
    keys.forEach(function (k) { max = Math.max(max, obj[k] || 0); });

    var card = el('section', { class: 'card' }, el('div', { class: 'card-title', text: title }));
    if (!keys.length) {
      card.appendChild(empty('No data yet'));
      return card;
    }
    card.appendChild(el('div', { class: 'bars' }, keys.map(function (k) {
      return barRow(opts.prettyLabels === false ? (k || '(none)') : prettyKey(k),
                    obj[k] || 0, max, {
        fillClass: opts.statusColors ? 's-' + String(k).toLowerCase() : null,
        rowClass: (opts.statusColors && k === 'open') ? 'is-open' : null,
        href: opts.hrefFor ? opts.hrefFor(k) : null
      });
    })));
    return card;
  }

  /* ------------------------------------------------------ program hacktivity

     "Is ExampleVendor's triage team moving right now." Everything about this card is bent toward that
     one question: the action comes first because that is what changed, the age comes last and is
     RELATIVE because "14m ago" answers the question and "2026-08-01T03:08" makes you do the
     subtraction, and the whole thing is five rows because a longer list stops being a glance. */

  var HACKTIVITY_REFRESH_MS = 5 * 60 * 1000;

  /* Freshness verdict for the tile. Pure, so the degraded path is unit-testable - that path is
     the one that will actually break in production, and it is the one nothing else exercises.

     Rules, in order of what the reader needs to know first:
       never configured -> say so, it is not a failure
       never fetched    -> say so, the cron entry is probably missing
       failing          -> the error wins, but the rows below it are still real
       stale            -> honest age, no alarm
       fresh            -> the timestamp, quietly */
  function hacktivityFreshness(d) {
    d = d || {};
    if (!d.configured) {
      return { level: 'warn', text: 'No HackerOne credential stored', hint: 'Add one in Integrations.' };
    }
    if (!d.as_of) {
      return { level: 'warn', text: 'Never fetched',
               hint: 'scripts/sync-hacktivity.sh has not run yet.' };
    }
    /* The zone is not decoration. as_of is the SERVER's clock, this box runs UTC, and the
       person reading it does not - so a bare "04:23" reads as an hour that never happened
       to them. The server sends its own zone rather than the browser guessing. */
    var when = 'as of ' + String(d.as_of).slice(11, 16) +
               (d.as_of_tz ? ' ' + d.as_of_tz : '');
    var st = String(d.status || '');
    if (st === 'auth_failed' || st === 'error') {
      return { level: 'bad', text: when + ', not refreshing',
               hint: d.error || 'The last refresh failed.' };
    }
    if (d.stale) {
      return { level: 'warn', text: when + ', stale',
               hint: 'No successful refresh for over ' +
                     Math.round((d.stale_after || 900) / 60) + ' minutes.' };
    }
    return { level: 'ok', text: when, hint: '' };
  }

  /* One line of the feed. `mine` rows are the ones whose outcome matters to us, so they carry a
     title (the API only sends one for reports we can see) and a marker; everyone else's entry is
     an id and a handle, which is all the program discloses and all the activity question needs. */
  function hacktivityRow(r, seen) {
    var label = el('span', { class: 'ha-act', text: r.action_label || 'Activity' });
    if (/bounty/i.test(r.action_label || '')) label.className += ' ha-act-money';
    /* Our own rows carry the handle like anyone else's, so show it rather than swapping in
       'you'. The highlight already says which ones are ours; a pronoun in a column of
       handles just reads as a different kind of thing. */
    var who = r.reporter || 'unknown';
    var line = el('span', { class: 'ha-what' }, [
      extLink(r.url, '#' + r.h1_id),
      el('span', { class: 'ha-who', text: who })
    ]);
    if (r.title) {
      line.appendChild(el('span', { class: 'ha-title trunc', text: r.title, title: r.title }));
    }
    if (r.awarded_total) {
      line.appendChild(el('span', { class: 'ha-amt', text: '$' + r.awarded_total,
                                    title: 'Total awarded on that report by the program.' }));
    }
    /* Anything newer than the last thing we showed. The feed is a wall of near-identical rows,
       so a new entry blends into the ones above it - which defeats the point of a tile you
       glance at to see whether the program is moving. An empty watermark means a first visit and
       highlights nothing, rather than opening on a wall of green. */
    var fresh = !!(seen && r.activity_at && r.activity_at > seen);
    return el('div', {
      class: 'ha-row' + (r.is_mine ? ' is-mine' : '') + (fresh ? ' is-fresh' : ''),
      title: fresh ? 'New since you last looked' : ''
    }, [
      label, line,
      el('span', { class: 'ha-when', text: ago(r.activity_at), title: r.activity_at || '' })
    ]);
  }

  /* One constant for both the load and the Refresh round trip. They were separate numbers,
     and Refresh's was 5, so pressing it shrank a full card to five rows.
     The card asks for everything storage keeps and lets its own height decide how many are
     visible; .ha-rows scrolls for the rest. KEEP_ROWS in hacktivity.py is the real ceiling,
     and recent() clamps anything larger. */
  var HACKTIVITY_ROWS = 50;
  /* "New since you last looked", not "new for an hour". The watermark stores the newest
     `activity_at` we have actually SHOWN, and rows above it are highlighted until they have been
     seen once. Comparing stored activity timestamps against each other rather than against a
     clock reading is deliberate: `activity_at` is UTC with a Z suffix while the other watermarks
     in this file are naive server-local, and mixing the two formats compares as garbage. */
  var HACKTIVITY_SEEN_KEY = 'quarry.seen.hacktivity.activity';

  function hacktivitySeen() {
    try { return localStorage.getItem(HACKTIVITY_SEEN_KEY) || ''; }
    catch (e) { return ''; }
  }

  function markHacktivitySeen(newest) {
    if (!newest) return;
    try { localStorage.setItem(HACKTIVITY_SEEN_KEY, newest); }
    catch (e) { /* private mode: rows just stay highlighted, which is harmless */ }
  }

  /* No scrollbar in the card: the feed shows what fits and stops. A scroll region inside a
     dashboard tile is a second thing to drive, and the card exists to be GLANCED at.
     CSS alone would clip the last row through the middle, which reads as broken rather than as
     "there is more". So the rows are laid out, then whole rows that fall past the bottom edge
     are hidden. Re-run on resize because the card's height comes from the column beside it. */
  function fitHacktivityRows(rowsEl) {
    /* false means "I am detached, stop calling me" - see onResize. */
    if (!rowsEl || !rowsEl.isConnected) return false;
    var kids = Array.prototype.slice.call(rowsEl.children);
    kids.forEach(function (k) { k.style.display = ''; });
    var box = rowsEl.getBoundingClientRect();
    if (!box.height) return;
    var shown = 0;
    kids.forEach(function (k) {
      /* Always keep the first row. A card too short for even one is a layout problem to see,
         not one to hide by rendering an empty list. */
      if (shown && k.getBoundingClientRect().bottom > box.bottom + 0.5) k.style.display = 'none';
      else shown++;
    });
  }

  /* Resize subscribers, pruned as their elements leave the document. The hacktivity card
     repaints on every dashboard load and on every Refresh, so a plain addEventListener per
     paint would accumulate stale closures for the life of the tab. */
  var resizeSubs = [];
  var resizeBound = false;
  function onResize(fn) {
    resizeSubs.push(fn);
    if (resizeBound) return;
    resizeBound = true;
    var t = null;
    window.addEventListener('resize', function () {
      if (t) clearTimeout(t);
      t = setTimeout(function () {
        resizeSubs = resizeSubs.filter(function (f) { return f() !== false; });
      }, 120);
    });
  }

  /* Same shape as onResize, and for the same reason: one global listener with a self-pruning
     subscriber list, because a card that re-renders on every dashboard paint would otherwise
     stack a fresh listener each time and never drop the old ones. A subscriber returning false
     has finished and is removed. */
  var wakeSubs = [];
  var wakeBound = false;

  function onWake(fn) {
    wakeSubs.push(fn);
    if (wakeBound) return;
    wakeBound = true;
    function fire() {
      if (document.hidden) return;
      wakeSubs = wakeSubs.filter(function (f) { return f() !== false; });
    }
    document.addEventListener('visibilitychange', fire);
    window.addEventListener('focus', fire);
  }

  function hacktivityCard() {
    var card = el('section', { class: 'card hacktivity' });
    var head = el('div', { class: 'card-head' });
    var host = el('div', {});
    card.appendChild(head);
    card.appendChild(host);
    append(host, loading('Loading hacktivity…'));

    function paint(d) {
      d = d || {};
      var items = d.items || [];
      var fresh = hacktivityFreshness(d);

      clear(head);
      head.appendChild(el('div', { class: 'ha-head' }, [
        /* No card-sub. The two-line caveat about which actions an undisclosed report exposes
           was read once and then cost a line of card height on every load after that; it lives
           in the module docstring in hacktivity.py, which is where someone reading the feed's
           behaviour will look for it. */
        el('div', { class: 'card-title', text: 'Program hacktivity' }),
        el('div', { class: 'ha-head-r' }, [
          /* Pick which program's feed to watch. Options are the user's own programs, A-Z. There is
             no magic 'credential' entry: the server defaults an unset pick to the alphabetically
             first program (see effective_hacktivity_program), so `d.program` is always a real
             program the reader recognises. Changing it persists the choice and polls immediately. */
          selectEl(
            (state.programs || []).filter(function (p) { return p.slug; })
              .map(function (p) { return { value: p.slug, label: p.name || p.slug }; })
              .sort(function (a, b) { return a.label.localeCompare(b.label); }),
            d.program || '',
            function (v) { refreshNow(v); }),
          el('span', { class: 'hpill h-' + fresh.level, text: fresh.text,
                       title: fresh.hint || '' }),
          el('button', { class: 'btn btn-sm', type: 'button', text: 'Refresh',
                         title: 'One request to HackerOne now, instead of waiting for cron.',
                         onclick: function () { refreshNow(); } })
        ])
      ]));

      clear(host);
      if (fresh.hint) host.appendChild(el('div', { class: 'ha-note', text: fresh.hint }));
      if (!items.length) {
        host.appendChild(empty('Nothing stored yet',
          'Add the sync-hacktivity.sh cron entry, or use Refresh.'));
      } else {
        /* STALE ROWS ARE STILL SHOWN. Blanking the list on a failed refresh throws away the last
           thing we did know for the sake of tidiness; the pill above already says how old it is. */
        var seen = hacktivitySeen();
        var rowsEl = el('div', { class: 'ha-rows' }, items.map(function (r) {
          return hacktivityRow(r, seen);
        }));
        host.appendChild(rowsEl);
        /* After layout, not during: the row heights and the card's own height are only real
           once the browser has laid the grid out. */
        requestAnimationFrame(function () { fitHacktivityRows(rowsEl); });
        /* Advance the watermark to the newest row on screen, so this paint keeps its highlight
           and the NEXT one comes up normal. Only when the tab is actually visible: a poll that
           repaints behind another tab has not been looked at, and clearing on it would mean
           coming back to a feed that had already quietly marked itself read.
           `max`, not items[0], because the feed's order is not guaranteed to be the ordering
           this comparison uses. */
        if (!document.hidden) {
          markHacktivitySeen(items.reduce(function (m, r) {
            return (r.activity_at && r.activity_at > m) ? r.activity_at : m;
          }, seen));
        }
        onResize(function () { fitHacktivityRows(rowsEl); });
      }

      /* The other half of the question. The feed above is about the PROGRAM; this line is about
         us, and it is here rather than as a filter because both readings matter at once: a busy
         team plus nothing on your reports for three weeks is itself the answer. */
      var mine = d.mine_latest;
      var foot = el('div', { class: 'ha-foot' });
      if (mine) {
        foot.appendChild(el('span', {}, [
          el('span', { class: 'ha-foot-k', text: 'Yours: ' }),
          el('span', { text: (mine.action_label || 'activity') + ' on ' }),
          extLink(mine.url, '#' + mine.h1_id),
          el('span', { text: ' ' + ago(mine.activity_at) })
        ]));
      } else if (d.stored) {
        foot.appendChild(el('span', { class: 'dim',
          text: 'None of the last ' + d.stored + ' entries are on your reports.' }));
      }
      if (d.hacktivity_url) {
        foot.appendChild(extLink(d.hacktivity_url, 'Open on HackerOne'));
      }
      if (foot.firstChild) host.appendChild(foot);
    }

    /* `force` skips the failure backoff: the button exists for the case where you know the feed
       should have moved and do not want to sit out a 15-minute window to find out. The response
       carries the refreshed view, so one request repaints the card whether it succeeded or not. */
    function refreshNow(program) {
      var body = { force: true, limit: HACKTIVITY_ROWS };
      /* Only sent when the picker changes it, so the plain Refresh button never rewrites the
         stored choice. An empty string is a real value here: it means "back to the credential
         program", so it is included while `undefined` is not. */
      if (program !== undefined) body.program = program;
      return api('/hacktivity/refresh', { method: 'POST', body: body })
        .then(function (d) {
          paint(d);
          var r = (d && d.refresh) || {};
          if (r.status && r.status !== 'ok') toast('Hacktivity: ' + (r.error || r.status), 'err');
        })
        .catch(toastError);
    }

    function load() {
      return api('/hacktivity?limit=' + HACKTIVITY_ROWS).then(paint).catch(function (err) {
        /* A dead endpoint must not take the dashboard with it. Show the failure inside the card
           and leave every other tile alone. */
        clear(head);
        head.appendChild(el('div', { class: 'card-title', text: 'Program hacktivity' }));
        clear(host);
        append(host, errorPanel(err, load));
      });
    }

    var lastLoad = 0;
    function reload() {
      lastLoad = Date.now();
      return load();
    }
    /* Load the program list first so the picker has its options on the very first paint. */
    loadPrograms().then(reload);

    /* The browser polls Quarry; cron polls HackerOne. Opening ten tabs costs Quarry ten cheap
       reads and HackerOne nothing. Self-cancelling on detach because views are torn down by
       clearing the DOM and there is no unmount hook to hang a clearInterval on. */
    var timer = setInterval(function () {
      if (!card.isConnected) { clearInterval(timer); return; }
      reload();
    }, HACKTIVITY_REFRESH_MS);

    /* A TIMER ALONE DOES NOT KEEP THIS FRESH. Browsers throttle setInterval hard in a background
       tab - minutes, not milliseconds - so a dashboard left open behind another tab comes back
       showing an "as of" from whenever the throttling started, while cron has been writing a new
       one every 5 minutes the whole time. The tile then reads as broken when the pipeline behind
       it is healthy, which is exactly how this was reported.

       So refresh on the way back in, not only on a schedule. The staleness test is real elapsed
       time, which is the one thing throttling cannot distort, and it is also what stops repeated
       alt-tabbing from turning into a request per focus event. */
    onWake(function () {
      if (!card.isConnected) return false;          // detached: drop the subscription
      if (Date.now() - lastLoad >= HACKTIVITY_REFRESH_MS) reload();
    });

    return card;
  }

  function activityCard() {
    var card = el('section', { class: 'card' }, el('div', { class: 'card-title', text: 'Recent activity' }));
    var host = el('div', {});
    card.appendChild(host);
    append(host, loading('Loading audit trail…'));

    api('/audit?limit=15').then(function (data) {
      var items = (data && data.items) || [];
      clear(host);
      if (!items.length) { host.appendChild(empty('No audit entries yet')); return; }
      host.appendChild(dataTable([
        { key: 'ts', label: 'When', cls: 'nowrap tiny dim', render: function (r) { return fmtTime(r.ts); } },
        { key: 'action', label: 'Action', cls: 'nowrap', render: function (r) { return tag(r.action); } },
        {
          key: 'entity', label: 'Entity', cls: 'nowrap',
          render: function (r) {
            if (!r.entity) return el('span', { class: 'muted', text: '—' });
            var label = r.entity + (r.entity_id ? ' #' + r.entity_id : '');
            var known = ENTITIES[r.entity] || ENTITIES[r.entity + 's'];
            if (known && r.entity_id) {
              return el('a', { href: '#/' + known.entity + '/' + encodeURIComponent(r.entity_id), text: label });
            }
            return el('span', { text: label });
          }
        },
        { key: 'actor', label: 'Actor', cls: 'nowrap tiny dim' },
        {
          key: 'detail', label: 'Detail', cls: 'tiny dim cell-max',
          render: function (r) { return el('span', { class: 'trunc', text: r.detail || '', title: r.detail || '' }); }
        }
      ], items, {}));
    }).catch(function (err) {
      clear(host);
      append(host, el('div', { class: 'pane-body' }, errorPanel(err)));
    });

    return card;
  }



  /* ------------------------------------------------------------ work panel */
  /* WORK_STATUSES and the status picker it drove were removed once the pipeline started setting
     status itself: a validator writes the marker into the markdown when it reaches a verdict, and
     the orchestrator writes `submitted` on filing. A button that races those writes is a way to
     get the file and the index disagreeing, and it had stopped being used by hand.
     POST /api/leads/<id>/status is deliberately KEPT - it is a documented endpoint, it is what
     rewrites the marker safely, and the smoke suite asserts its validation. */

  /* What the Title row should say, given GET /api/leads/<id>/report.

     Pure, and separate from the drawing, because the interesting cases are the empty ones: no
     draft yet (say nothing at all), and a draft with no `# ` heading (say so, and offer no button
     - there is no title to copy). A mismatch is the only state that gets a control. */
  function titleSyncState(rep) {
    if (!rep || !rep.found) return { state: 'none', note: '', heading: '' };
    if (rep.title_synced === true) {
      return { state: 'synced', note: 'matches the report', heading: '' };
    }
    if (rep.title_synced !== false) {
      return { state: 'unknown', note: 'the draft report has no title line', heading: '' };
    }
    var heading = (rep.ref ? rep.ref + ' - ' : '') + (rep.report_title || '');
    return {
      state: 'mismatch', heading: heading,
      note: 'differs from the report: ' + (rep.report_title || '')
    };
  }

  function workPanel(cfg, row, reload) {
    var wrap = el('section', { class: 'workpanel' });

    /* --- copy the draft report ---------------------------------------- */
    /* Only for leads, and only once one is worth copying. A lead that is still `open` has no
       draft to speak of, so the row would be a dead control on most of the list. `confirmed` is
       the state where a draft exists and is waiting to be read, `ready` is the state where one is
       finished and waiting on approval, `submitted` keeps it because the filed text is exactly what
       you want to hand a triager mid-thread, and `awarded` keeps it for the same reason - a paid
       report is still the report the next one gets written against. */
    var REPORT_STATUSES = ['confirmed', 'ready', 'parked', 'submitted', 'awarded'];
    /* `parked` is in that list as of 2026-08-05. A parked lead routinely HAS a finished draft -
       SL13 was parked with its report written and shape-checked, waiting on a ship decision - and
       losing the button at exactly that moment is losing it when it is most wanted. Parking is a
       decision about whether to send, not about whether the draft exists.
       Status alone is not enough: a lead can reach `confirmed` or `parked` before its draft is
       written, and the row would then offer a button that fetches nothing. The row is built now
       and removed if the lookup says there is no draft, which keeps the common case a single
       render. */
    if (cfg.entity === 'leads' && REPORT_STATUSES.indexOf(row.status) >= 0) {
      var repRow = el('div', { class: 'work-row' }, [
        el('span', { class: 'work-label', text: 'Report' })
      ]);
      var repHost = el('div', { class: 'tabrow' });
      var copyBtn = el('button', {
        class: 'btn btn-sm', type: 'button', text: 'Copy report',
        title: 'Copy the draft report markdown to the clipboard'
      });
      var repNote = el('span', { class: 'muted small' });
      repHost.appendChild(copyBtn);

      /* Straight to the filed report. The id lives in the lead's `Submitted` header row, which
         is the authority for it - leads carry no h1_id column, and matching on `ref` would be
         wrong the moment two workspaces reuse a code, which they already do (G7 twice). Only
         shown from `submitted` on, because before that there is nothing to open - and an
         `awarded` lead is the one you most want to reach, since the payment is on that thread. */
      var h1id = leadH1Id(row);
      if ((row.status === 'submitted' || row.status === 'awarded') && h1id) {
        repHost.appendChild(el('a', {
          class: 'btn btn-sm', href: 'https://hackerone.com/reports/' + h1id,
          target: '_blank', rel: 'noopener noreferrer',
          text: 'View #' + h1id,
          title: 'Open report ' + h1id + ' on HackerOne'
        }));
      }
      repHost.appendChild(repNote);
      repRow.appendChild(repHost);
      wrap.appendChild(repRow);

      /* --- lead title vs report title ---------------------------------- */
      /* The report title is the sentence that goes to HackerOne, so it is the authority. A lead
         reading differently from its own draft has been mistaken for a different finding, which
         is the whole reason this row exists. Asked for on render rather than on click: the point
         is to SEE the disagreement while looking at the lead, not to discover it after copying. */
      var titleRow = el('div', { class: 'work-row' }, [
        el('span', { class: 'work-label', text: 'Title' })
      ]);
      var titleHost = el('div', { class: 'tabrow' });
      titleRow.appendChild(titleHost);

      function drawTitleSync(rep) {
        clear(titleHost);
        var st = titleSyncState(rep);
        if (st.state === 'none') return;
        if (st.state !== 'mismatch') {
          titleHost.appendChild(el('span', { class: 'muted small', text: st.note }));
          return;
        }
        var syncBtn = el('button', {
          class: 'btn btn-sm', type: 'button', text: 'Sync title',
          title: 'Rewrite the lead heading to "' + st.heading + '"'
        });
        syncBtn.addEventListener('click', function () {
          syncBtn.disabled = true;
          syncBtn.textContent = 'Syncing…';
          api('/leads/' + encodeURIComponent(row.id) + '/sync-title', { method: 'POST', body: {} })
            .then(function (r) {
              toast(r && r.changed ? 'Lead title now matches the report' : 'Already in sync', 'ok');
              reload();
            })
            .catch(function (err) {
              syncBtn.disabled = false;
              syncBtn.textContent = 'Sync title';
              toastError(err);
            });
        });
        titleHost.appendChild(syncBtn);
        titleHost.appendChild(el('span', { class: 'muted small', text: st.note }));
      }

      api('/leads/' + encodeURIComponent(row.id) + '/report')
        .then(function (r) {
          /* The comment above promised this removal and never implemented it, so every lead in a
             report status carried the row whether or not a draft existed. It matters more now
             that `parked` is included, because parking is a common resting state. On a failed
             lookup the row STAYS - a network error is not evidence that the draft is missing,
             and the button reports its own failure on click. */
          if (!r || !r.found) {
            if (repRow.parentNode) repRow.parentNode.removeChild(repRow);
            return;
          }
          if (!r.title_synced) wrap.appendChild(titleRow);
          drawTitleSync(r);
        })
        .catch(function () { /* the Copy button reports its own failures; stay quiet here */ });

      copyBtn.addEventListener('click', function () {
        copyBtn.disabled = true;
        copyBtn.textContent = 'Loading…';
        api('/leads/' + encodeURIComponent(row.id) + '/report')
          .then(function (r) {
            if (!r || !r.found) {
              repNote.textContent = 'no draft found in reports/';
              copyBtn.textContent = 'Copy report';
              copyBtn.disabled = false;
              return;
            }
            return copyText(r.text).then(function () {
              /* The toast is the confirmation; the label goes straight back to its resting text.
                 This one already toasted AND swapped the label, which double-reported it. */
              toast('Copied ' + r.name + ' (' + fmtBytes(r.bytes) + ')', 'ok');
              repNote.textContent = r.name;
              copyBtn.textContent = 'Copy report';
              copyBtn.disabled = false;
            });
          })
          .catch(function (err) {
            copyBtn.textContent = 'Copy report';
            copyBtn.disabled = false;
            toastError(err);
          });
      });
    }

    /* The worklog appender used to sit here: a heading field, a textarea and an "Append to note"
       button that wrote a timestamped section into the lead's markdown. Removed on request.
       The status picker is the whole panel now.

       POST /api/<entity>/<id>/append is deliberately left in place. The markdown under
       the workspace volume is the system of record and is edited directly far more often than it
       ever was through this box; removing the endpoint would take a working write path away from
       the CLI and from anything scripted against it, which is not what was asked for. */

    return wrap;
  }

  /* ------------------------------------------------------------ NEW badges
     A per-browser watermark, not a per-account one: "new" means "appeared since THIS browser
     last opened that section". Stored in localStorage, so it cannot desync from what you have
     actually looked at on this machine. The server just counts rows newer than the watermark
     (GET /api/unseen), which keeps the whole feature stateless server-side. */

  var SEEN_KEY_PREFIX = 'quarry.seen.';
  var UNSEEN_REFRESH_MS = 60 * 1000;

  /* WHY the money badge lingers where the others do not: an award is good news and Seth wants to
     be reminded of it for the rest of the day, so it deliberately does NOT clear on first sight.
     It retires on whichever comes first:
       - he clicks through the Bounty card, which is an explicit "yes, I saw it", or
       - the same award set has been painted on this many separate dashboard LOADS.
     Loads, not repaints: the dashboard refreshes badges every 60s and counting those would retire
     it three minutes after it appeared. Three loads is roughly "a few times today". */
  var MONEY_LINGER_LOADS = 3;
  var MONEY_VIEWS_KEY = 'quarry.money.views';

  /* Counts loads of the CURRENT award set. A different set (new money) resets the count, so an
     award that lands on the third viewing of the previous one still gets its full run. */
  function bumpMoneyViews(sig) {
    var n = 1;
    try {
      var prev = JSON.parse(localStorage.getItem(MONEY_VIEWS_KEY) || 'null');
      if (prev && prev.sig === sig) n = (prev.n || 0) + 1;
      localStorage.setItem(MONEY_VIEWS_KEY, JSON.stringify({ sig: sig, n: n }));
    } catch (e) { /* private mode - the badge just keeps lingering, the harmless direction */ }
    return n;
  }

  function seenAt(entity) {
    try { return localStorage.getItem(SEEN_KEY_PREFIX + entity) || ''; } catch (e) { return ''; }
  }

  /* The watermark MUST be written on the server's clock and in the server's format, because
     /api/unseen compares it as a STRING against indexed_at, which the server writes.

     Using the browser clock was wrong twice over. `new Date().toISOString()` emits a Z-suffixed
     millisecond string that does not compare cleanly against a naive second string, and the
     browser runs on a different machine whose clock can sit behind the server's. When it does,
     opening a section writes a watermark in the server's past, so rows indexed during the gap
     badge again after you have already looked at them.

     serverSkewMs is refreshed from any response carrying `now`. Parsing the server's own string
     and re-emitting in the same frame keeps this correct whatever timezone the server is in:
     the value is treated as a wall-clock label, never converted. */
  var serverSkewMs = 0;

  function noteServerNow(iso) {
    if (!iso) return;
    var t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
    if (!isNaN(t)) serverSkewMs = t - Date.now();
  }

  function serverNowIso() {
    var d = new Date(Date.now() + serverSkewMs);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate()) + 'T'
         + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ':' + p(d.getUTCSeconds());
  }

  function markSeen(entity, when) {
    if (when) noteServerNow(when);
    try {
      /* Keep the value being replaced. Clicking a tile advances the watermark and THEN
         navigates, so by the time the list renders, "what changed since last time" has already
         been erased. The row tags are computed against this instead. */
      var prev = localStorage.getItem(SEEN_KEY_PREFIX + entity);
      if (prev) localStorage.setItem(SEEN_KEY_PREFIX + entity + '.prev', prev);
      localStorage.setItem(SEEN_KEY_PREFIX + entity, when || serverNowIso());
    } catch (e) { /* private mode - badges just keep showing, which is harmless */ }
  }

  /* Force `.prev` forward. markSeen deliberately leaves it one step behind so a row tag survives
     the visit that revealed it; Refresh is the explicit "clear these now" and has to collapse the
     two, or the tags would come back on the very next render. */
  function markSeenPrev(entity, when) {
    try { localStorage.setItem(SEEN_KEY_PREFIX + entity + '.prev', when || serverNowIso()); }
    catch (e) { /* private mode - tags just linger, which is harmless */ }
  }

  function seenAtPrev(entity) {
    try { return localStorage.getItem(SEEN_KEY_PREFIX + entity + '.prev') || ''; }
    catch (e) { return ''; }
  }

  /* Was this row new, or merely edited, as of the last time the section was opened? Returns
     'new', 'updated' or ''. Both watermarks are read fresh per render rather than captured once,
     so navigating away and back does not strand a stale answer on the page. */
  function rowFreshness(r, entity, updEntity) {
    var seenNew = seenAtPrev(entity);
    var seenUpd = seenAtPrev(updEntity || entity);
    var first = r.first_seen_at || r.indexed_at || '';
    var idx = r.indexed_at || '';
    if (seenNew && first && first > seenNew) return 'new';
    if (seenUpd && idx && idx > seenUpd && first && first <= seenUpd) return 'updated';
    return '';
  }

  function freshTag(kind) {
    if (!kind) return null;
    return el('span', { class: 'rowtag rowtag-' + kind, text: kind,
                        title: kind === 'new' ? 'First seen since you last opened this section'
                                              : 'Edited since you last opened this section' });
  }

  /* First ever visit: set the watermark to now rather than showing every historical row as new. */
  function ensureSeenInitialised(entities, now) {
    noteServerNow(now);
    entities.forEach(function (e) { if (!seenAt(e)) markSeen(e, now || serverNowIso()); });
  }

  function newBadge(count) {
    if (!count) return null;
    return el('span', {
      class: 'newbadge', title: count + ' added since you last opened this section'
    }, [
      el('span', { class: 'newbadge-label', text: 'New' }),
      el('span', { class: 'newbadge-count', text: '+' + count })
    ]);
  }

  /* ------------------------------------------------------------ UPDATED badge
     The other half of "what moved". `newbadge` means a report ARRIVED; this means a report you
     already had CHANGED on HackerOne - triaged, awarded, severity set. Both can sit on the
     Reports tile at once and they are deliberately different colours, because "you filed
     something new" and "the program acted on your filing" are not the same news. */

  /* Phrased as the state the report is now IN, not as the transition. The badge tooltip is read
     in a glance and "now triaged" answers the question; "new -> triaged" makes you parse it. */
  function eventLabel(e) {
    e = e || {};
    var v = e.new_value || '';
    switch (e.event_type) {
      case 'state_change':      return v ? 'now ' + v : 'state changed';
      case 'bounty_awarded':    return v ? 'bounty awarded, ' + v : 'bounty awarded';
      case 'bounty_increased':  return v ? 'bounty raised to ' + v : 'bounty raised';
      case 'severity_change':   return v ? 'severity ' + v : 'severity set';
      case 'cve_assigned':      return v ? 'CVE ' + v : 'CVE assigned';
      case 'collaborator_added': return v ? 'collaborator ' + v : 'collaborator added';
      /* A SILENT touch: the program did something that changed no field we track - a comment, a
         reassignment, a triager reading it. This is most of what happens to a live report, and
         until these events existed the dashboard stayed dark through all of it. */
      case 'program_activity':  return 'program activity';
      case 'activity':          return 'activity';
      /* An event type this build does not know about still renders as something readable
         rather than vanishing: h1_watch can grow EVENT_TYPES without a UI change. */
      default: return String(e.event_type || 'updated').replace(/_/g, ' ');
    }
  }

  function updatedBadge(count, latest, opts) {
    if (!count) return null;
    opts = opts || {};
    var lines = (latest || []).map(function (e) {
      return '#' + (e.h1_id || '?') + '  ' + eventLabel(e);
    });
    /* The count is by report and the list is by event, so the list can legitimately be longer
       than the count. Say which is which instead of letting the two numbers look like a bug. */
    /* Leads change because YOU edited them; reports change because the program did. Same badge,
       and the tooltip has to say which, or "Updated +3" on two different tiles means two
       different things with no way to tell. */
    var noun = opts.noun || 'report';
    var verb = opts.verb || 'changed on HackerOne';
    var head = count === 1
      ? ('1 ' + noun + ' ' + verb)
      : (count + ' ' + noun + 's ' + verb);
    var badge = el('span', {
      class: 'updbadge' + (opts.href ? ' updbadge-link' : ''),
      title: (lines.length ? head + '\n' + lines.join('\n') : head)
             + (opts.href ? '\n\nClick to open sorted by what moved most recently.' : '')
    }, [
      el('span', { class: 'updbadge-label', text: 'Updated' }),
      el('span', { class: 'updbadge-count', text: '+' + count })
    ]);
    /* The badge sits INSIDE the tile's own anchor, so its click has to be taken before the tile
       sees it. The tile means "show me the reports", newest filed first, which is the right
       default nearly always. The badge means "show me what MOVED", and sorting by filing date
       buries that - a report filed six weeks ago that the program touched an hour ago is the
       whole reason the badge is lit. Nested anchors are invalid, hence a handler rather than an
       <a>: the href lives in opts and is applied here. */
    if (opts.href) {
      activatable(badge, function (ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        location.hash = opts.href;
      });
    }
    return badge;
  }

  /* ------------------------------------------------------- BOUNTY AWARD badge
     Money that landed, on the Bounty card's own tiles. Three of the four tiles get one and they
     are three different figures on purpose: the full award, MY share of it (which is smaller on
     a split payout, and seeing the two side by side is the point), and the count of reports newly
     paid. The Reports tile is a submission count and no award moves it, so it stays bare.

     Server side is /api/unseen -> _bounty_awards(), on its own `bounty_awards` watermark. Its own,
     because clearing the Updated badge by opening Reports must not silently retire an award he
     never read - the two answer different questions about the same events. */

  /* Pure, so the render suite can exercise the arithmetic and the wording without a DOM.
     Returns null when nothing landed, else a part per badged tile (any of which may be null).

     STACKING: several awards show as ONE summed amount with the per-report breakdown in the
     tooltip, rather than '+[amount] +$450' laid out side by side. Two amounts already overflow a
     tile that is a quarter of the card wide, and the sum is the figure that reconciles against
     the tile it sits next to - the tooltip still says which reports made it up. */
  function awardBadgeParts(m, cur) {
    m = m || {};
    var total = Number(m.bounty_delta_total || 0);
    var mine = Number(m.bounty_delta_mine || 0);
    var n = Number(m.bounty_awards || 0);
    var list = m.bounty_awards_latest || [];
    if (!(total > 0) && !(mine > 0) && !(n > 0)) return null;

    var lines = list.map(function (e) {
      var d = Number(e.delta || 0), share = Number(e.mine || 0);
      /* Only spell the share out when it differs. Repeating the same number twice on every line
         makes the split payouts, which are the interesting ones, harder to spot. */
      return '#' + (e.h1_id || '?') + '  +' + fmtMoney(d, cur)
           + (share && share !== d ? ' (your share +' + fmtMoney(share, cur) + ')' : '')
           + (e.title ? '  ' + String(e.title).slice(0, 70) : '');
    });
    var head = (list.length === 1 ? 'A bounty landed' : list.length + ' bounties landed')
             + ' since you last looked:';
    var body = lines.length ? head + '\n' + lines.join('\n') : head;
    return {
      total: total > 0
        ? { text: '+' + fmtMoney(total, cur), title: body } : null,
      mine: mine > 0
        ? { text: '+' + fmtMoney(mine, cur),
            title: (mine === total
                      ? 'All of it is yours - no payout split.'
                      : 'Your share of ' + fmtMoney(total, cur) + ' awarded, after the split.')
                   + '\n' + body } : null,
      awards: n > 0
        ? { text: '+' + n,
            title: (n === 1 ? '1 report' : n + ' reports') + ' newly carrying an award.\n' + body }
        : null
    };
  }

  function awardBadge(part) {
    if (!part) return null;
    return el('span', { class: 'awardbadge', title: part.title }, [
      el('span', { class: 'awardbadge-amount', text: part.text })
    ]);
  }

  /* Fade out, then remove. Called when the user opens the section the badge refers to. */
  function fadeBadges(scope) {
    var nodes = (scope || document)
      .querySelectorAll('.newbadge:not(.fading), .updbadge:not(.fading),'
                      + ' .awardbadge:not(.fading)');
    Array.prototype.forEach.call(nodes, function (n) {
      n.classList.add('fading');
      setTimeout(function () { if (n.parentNode) n.parentNode.removeChild(n); }, 500);
    });
  }

  /* Ask the server how many rows are newer than each watermark. */
  function fetchUnseen(entities) {
    var q = {};
    var any = false;
    entities.forEach(function (e) {
      var w = seenAt(e);
      if (w) { q['since_' + e] = w; any = true; }
    });
    if (!any) return Promise.resolve({});
    return api('/unseen?' + qsFrom(q)).catch(function () { return {}; });
  }

  function dashboardView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      /* No page-sub. The cards below say what this page is; a sentence restating it only
         pushes the first real figure further down. */
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Dashboard' })
      ]),
      el('div', { class: 'page-actions' }, [
        el('a', { class: 'btn', href: '#/search', text: 'Search' }),
        el('a', { class: 'btn', href: '#/status', text: 'Status' })
      ])
    ]));

    /* Named so the phone layout can reorder its children. On a phone the Bounty card is read
       far less often than the counts, and it was pushing Leads, Reports and Advisories below the
       fold. See the .dash-host rules in the max-width:768px block; the desktop order is the
       source order and is untouched. */
    var host = el('div', { class: 'dash-host' });
    root.appendChild(host);
    append(host, loading('Loading stats…'));

    function load() {
      clear(host);
      append(host, loading('Loading stats…'));
      api('/stats').then(function (s) {
        clear(host);
        s = s || {};
        var counts = s.counts || {};
        var byStatus = s.leads_by_status || {};
        var byTarget = s.leads_by_target || {};
        var byClass = s.reports_by_class || {};
        var byState = s.reports_by_state || {};
        var byRepTarget = s.reports_by_target || {};

        /* 1. the money, straight from the HackerOne sync. It leads: the confirmed total is
           the one number on this page that is not a restatement of the workspace on disk.
           (The open-leads hero used to sit above it. Dropped - the count it showed is the
           Leads tile below, and the two buttons are one click from the Leads tab.)
           Deliberately computed server-side (GET /api/stats -> bounty) using the same query the
           Tracker uses, so the dashboard and the Tracker can never disagree. Earlier they did:
           the Tracker was summing legacy markdown rows alongside the API rows and double-counting
           52 duplicated report ids. */
        var money = s.bounty || null;
        var moneyCard = null;         // set below when there is a Bounty card to badge
        var moneyHosts = {};
        var moneyCur = (money && money.currency) || 'USD';
        if (money && money.reports) {
          var cur = moneyCur;
          /* `badge` names which delta from /api/unseen lands on this tile. Reports has none: it
             counts submissions, and no award moves that figure. */
          var awardTiles = [
            { k: 'Total bounty', v: fmtMoney(money.total, cur), badge: 'total',
              sub: money.awards + ' of ' + money.reports + ' reports carry an award' },
            { k: 'My share', v: fmtMoney(money.my_share, cur), badge: 'mine',
              sub: money.splits ? (money.splits + ' payout split' + (money.splits === 1 ? '' : 's'))
                                : 'no payout splits' },
            { k: 'Awards', v: String(money.awards), badge: 'awards',
              sub: 'bounties awarded by the program' },
            /* The value reads "34 / 150" rather than the bare total, because on a card about
               earnings the live question is how much is still outstanding. The open count leads
               and is coloured; the total stays as the denominator that gives it scale.
               `open` is optional - an older server that does not send it degrades to the plain
               total rather than rendering "undefined / 150". */
            { k: 'Reports',
              v: money.open === undefined || money.open === null
                ? String(money.reports)
                : [el('span', { class: 'mt-open', text: String(money.open) }),
                   el('span', { class: 'mt-of', text: ' / ' + money.reports })],
              sub: money.open === undefined || money.open === null
                ? (money.as_collaborator
                    ? (money.as_collaborator + ' as collaborator') : 'all as reporter')
                : ('open, ' + Math.max(0, (money.reports || 0) - money.open) + ' closed'
                   + (money.as_collaborator
                      ? ' | ' + money.as_collaborator + ' as collaborator' : '')) }
          ];
          var card = el('section', { class: 'card moneycard' }, [
            el('div', { class: 'card-head' }, [
              el('div', { class: 'card-title', text: 'Bounty' }),
            ]),
            /* EVERY dashboard drill-through into the Tracker carries program=all. The dashboard
               counts every program (server.py entity_scope); the Tracker shows one by default.
               Without this the list you land on is smaller than the number you clicked. */
            el('div', { class: 'moneytiles' }, awardTiles.map(function (t) {
              /* `v` is a plain string on every tile but Reports, which composes two spans so the
                 open count can carry its own colour. Accept either rather than making three
                 tiles build nodes they do not need. */
              var value = Array.isArray(t.v)
                ? el('span', { class: 'mt-v' }, t.v)
                : el('span', { class: 'mt-v', text: t.v || '—' });
              /* Same shape as the count tiles: the badge gets its own host so the timed repaint
                 can clear it, rather than appending a second badge every minute. */
              var kRow = el('span', { class: 'mt-k' }, [el('span', { text: t.k })]);
              if (t.badge) {
                moneyHosts[t.badge] = el('span', { class: 'tile-badges' });
                kRow.appendChild(moneyHosts[t.badge]);
              }
              /* program=all so the list matches the number that was just clicked: the tile counts
                 every program, while the Tracker itself defaults to the primary one. */
              return el('a', { class: 'moneytile',
                               href: '#/reports?' + qsFrom({ program: ALL_PROGRAMS }) }, [
                value,
                kRow,
                el('span', { class: 'mt-s', text: t.sub })
              ]);
            }))
          ]);
          moneyCard = card;

          /* Anticipated awards. These keys are being added to /api/stats separately, so treat
             them as optional: absent, unparseable or zero => render nothing extra rather than
             a "$0" or "NaN" tile. The block is fenced off below the confirmed tiles and never
             shares a total with them. */
          var expTotal = parseMoney(money.expected_total);
          var expCount = parseMoney(money.expected_awards);
          if (expTotal !== null && expTotal > 0) {
            var n = (expCount !== null && expCount > 0) ? Math.round(expCount) : null;
            var combined = parseMoney(money.total);
            card.appendChild(el('div', { class: 'money-sep' }, [
              el('span', { class: 'ms-t', text: 'Not confirmed by HackerOne' }),
              el('span', { class: 'ms-s',
                text: 'Recorded by the researcher, pending payment. Kept out of every figure above.' })
            ]));
            card.appendChild(el('div', { class: 'moneytiles moneytiles-expected' }, [
              el('a', {
                class: 'moneytile moneytile-expected',
                href: '#/reports?' + qsFrom({ anticipated: '1', program: ALL_PROGRAMS }),
                title: EXPECTED_CAVEAT
              }, [
                el('span', { class: 'mt-v' }, [
                  el('span', { text: fmtMoney(expTotal, cur) }),
                  el('span', { class: 'exp-tag', text: 'expected' })
                ]),
                el('span', { class: 'mt-k', text: 'Anticipated' }),
                el('span', { class: 'mt-s',
                  text: n === null
                    ? 'awaiting HackerOne confirmation'
                    : 'across ' + n + ' report' + (n === 1 ? '' : 's') + ', awaiting confirmation' })
              ])
            ]));
            if (combined !== null) {
              /* The only place the two are added up, and it says so in full. */
              card.appendChild(el('p', { class: 'money-potential', text:
                'Potential total (confirmed + anticipated): ' + fmtMoney(combined + expTotal, cur) +
                ' = ' + fmtMoney(combined, cur) + ' confirmed + ' + fmtMoney(expTotal, cur) +
                ' anticipated.' }));
            }
          }

          host.appendChild(card);
        }

        /* 2. counts */
        var tiles = [
          { k: 'Leads', n: counts.leads, href: '#/leads', watch: 'leads' },
          { k: 'Reports', n: counts.reports, href: '#/reports', watch: 'reports' },
          { k: 'Advisories', n: counts.advisories, href: '#/advisories', watch: 'advisories' },
          { k: 'Programs', n: counts.programs, href: '#/programs' },
          /* counts.scopes, not counts.targets: the tab lists the 970 HackerOne assets, while
             `targets` is the 3 local workspace directories. A tile that disagrees with the page
             it opens is worse than no tile. */
          { k: 'Targets', n: counts.scopes, href: '#/targets' },
          /* Fixes DUE a retest, not resolved reports - the tile is a to-do, and a count of every
             fix we ever earned would sit there unchanged forever. It opens the bucket it counts.
             A zero is the honest reading on a console that has never synced, and the tab says so
             when you get there. */
          { k: 'Retests due', n: (s.regression || {}).due, href: '#/regression?bucket=due' },
          /* Replaced the Uploads tile: an upload count says nothing about the state of a hunt,
             where the size of the payload arsenal is a live figure worth seeing. A zero here
             means the arsenal has never been synced (scripts/sync-payloads.sh), which is
             exactly when you want to notice. Uploads are still counted on the Status page. */
          { k: 'Payloads', n: counts.payloads, href: '#/payloads' }
        ];
        /* Badges hang in their own span rather than being appended straight to the label row,
           because the tiles are repainted on a timer now: without a host to clear, every refresh
           would stack another badge onto the one already there. */
        var badgeHosts = {};
        var tilesEl = el('div', { class: 'tiles' }, tiles.map(function (t) {
          var kRow = el('span', { class: 'k' }, [el('span', { text: t.k })]);
          if (t.watch) {
            badgeHosts[t.watch] = el('span', { class: 'tile-badges' });
            kRow.appendChild(badgeHosts[t.watch]);
          }
          return el('a', { class: 'card tile', href: t.href }, [
            el('span', { class: 'n', text: String(t.n === undefined || t.n === null ? '—' : t.n) }),
            kRow
          ]);
        }));

        host.appendChild(tilesEl);

        /* Badge the tiles the user asked to be alerted on. Counts come from the server, the
           watermark from this browser. Clicking through marks the section read.

           `report_updates` is watched alongside the three tile entities but has no tile of its
           own: it rides on Reports, because a report changing state is news ABOUT the reports
           you can already see there. It keeps a separate watermark all the same, so opening
           Reports to look at a new submission does not silently bury a triage you never read. */
        var WATCHED = ['advisories', 'reports', 'leads', 'report_updates', 'lead_updates',
                       'bounty_awards'];
        var TILED = ['advisories', 'reports', 'leads'];
        var MONEY_TILED = ['total', 'mine', 'awards'];
        ensureSeenInitialised(WATCHED, s.now);

        /* The award badge is PINNED for the life of this dashboard view once it has been painted,
           so the 60s repaint that follows the watermark being advanced (see the linger rule) does
           not yank it off the card while he is looking at it. A later poll that carries money
           always wins, so an award landing mid-session replaces the pinned one rather than
           hiding behind it. */
        var moneyPinned = null;
        var moneyCounted = false;

        function moneyFor(u) {
          if ((u.bounty_delta_total || 0) > 0 || (u.bounty_delta_mine || 0) > 0
              || (u.bounty_awards || 0) > 0) moneyPinned = u;
          return moneyPinned;
        }

        function paintBadges(u) {
          noteServerNow(u.now);
          TILED.forEach(function (e) { clear(badgeHosts[e]); });
          TILED.forEach(function (e) {
            var badge = newBadge(u[e] || 0);
            if (badge) badgeHosts[e].appendChild(badge);
          });
          var upd = updatedBadge(u.report_updates || 0, u.report_updates_latest,
                                 { href: '/reports?sort=-last_activity' });
          if (upd) badgeHosts.reports.appendChild(upd);
          /* Leads get the same treatment. Editing a lead to record a kill used to bump
             `indexed_at` and light the NEW badge, so a night of housekeeping read as a night of
             discoveries. New now means first seen; Updated means it was already here. */
          var lupd = updatedBadge(u.lead_updates || 0, null,
                                  { noun: 'lead', verb: 'edited since you last looked' });
          if (lupd) badgeHosts.leads.appendChild(lupd);

          MONEY_TILED.forEach(function (k) { if (moneyHosts[k]) clear(moneyHosts[k]); });
          var m = moneyFor(u);
          var parts = m ? awardBadgeParts(m, moneyCur) : null;
          if (!parts) return;
          MONEY_TILED.forEach(function (k) {
            var badge = moneyHosts[k] && awardBadge(parts[k]);
            if (badge) moneyHosts[k].appendChild(badge);
          });
          /* Counted once per LOAD, on the first paint that actually shows money. Retiring the
             watermark here rather than on paint means the badge is still on screen for this
             visit; the next load is the quiet one. */
          if (!moneyCounted) {
            moneyCounted = true;
            var sig = (m.bounty_awards_at || '') + '|' + (m.bounty_delta_total || 0);
            if (bumpMoneyViews(sig) >= MONEY_LINGER_LOADS) markSeen('bounty_awards', u.now);
          }
        }

        /* Bound once, not per paint: these listeners outlive any single refresh, and rebinding
           them on every poll would mark the section seen once per elapsed minute. `u` is read
           through the closure variable so a click always uses the newest server clock. */
        var unseen = {};
        TILED.forEach(function (e) {
          var tile = badgeHosts[e].parentNode.parentNode;
          if (!tile) return;
          tile.addEventListener('click', function () {
            markSeen(e, unseen.now);
            /* Opening Reports is what acknowledges a triage, so its two watermarks move
               together. Only here: the other tiles have nothing to acknowledge but themselves. */
            if (e === 'reports') markSeen('report_updates', unseen.now);
            if (e === 'leads') markSeen('lead_updates', unseen.now);
            fadeBadges(tile);
          });
        });

        /* Clicking anywhere on the Bounty card is the explicit acknowledgement, and it retires
           the badge early whatever the load counter says. The view counter is dropped with it so
           the NEXT award starts its linger from zero. */
        if (moneyCard) {
          moneyCard.addEventListener('click', function () {
            markSeen('bounty_awards', unseen.now);
            moneyPinned = null;
            try { localStorage.removeItem(MONEY_VIEWS_KEY); } catch (e) { /* private mode */ }
            fadeBadges(moneyCard);
          });
        }

        function refreshBadges() {
          return fetchUnseen(WATCHED).then(function (u) {
            unseen = u || {};
            paintBadges(unseen);
          });
        }
        refreshBadges();

        /* A triage that lands at 19:22 should not wait for a page reload to show up. The h1
           poll writes events every 15 minutes (cron), and this is a local SQL read with no
           HackerOne request behind it, so a minute is cheap. Self-cancelling on detach, same
           reason as the hacktivity timer: views are torn down by clearing the DOM. */
        var badgeTimer = setInterval(function () {
          if (!tilesEl.isConnected) { clearInterval(badgeTimer); return; }
          refreshBadges();
        }, UNSEEN_REFRESH_MS);

        /* Background tabs throttle this timer the same way they throttle the hacktivity one, so
           coming back to a long-open dashboard would otherwise show badges from whenever the
           throttling began. Refreshing on the way back in is also when it matters most: that is
           the moment the numbers are actually being read. */
        onWake(function () {
          if (!tilesEl.isConnected) return false;
          refreshBadges();
        });

        /* 3. breakdowns down the left half, hacktivity holding the right.
           One row, two columns. The breakdowns stack in their column and the column simply gets
           taller as cards are added, which is why a fifth card does not strand one card alone on
           a row the way a quadrant did. Hacktivity sits at the top of its column at its natural
           height rather than stretching to match. */
        host.appendChild(el('div', { class: 'dash-split' }, [
          el('div', { class: 'dash-col' }, [
            /* Reports first, leads under them. A report is a result and a lead is work in
               progress, and the column is read top down. */
            breakdownCard('Reports by state', byState, {
              statusColors: true,
              hrefFor: function (k) {
                return '#/reports?' + qsFrom({ status: k, program: ALL_PROGRAMS });
              }
            }),
            /* PAID reports only, here and on the target card below. A submission is an attempt;
               an award is a result, so this answers "what kind of bug actually earns" rather
               than "what did I file". The drill-down carries paid=1 so the list returns exactly
               the rows counted here - without it the card would say 19 and the page would show
               72. Classes for API-only reports are derived from the CWE, see common.CWE_CLASS. */
            breakdownCard('Paid reports by class', byClass, {
              limit: 12,
              hrefFor: function (k) {
                return '#/reports?' + qsFrom({ 'class': k, paid: '1', program: ALL_PROGRAMS });
              }
            }),
            /* Thinner than the class card on purpose: a report the API owns has no local file
               and so no target. 'unknown' is the no-target bucket rather than a target, so it is
               dropped here and on the leads card - it cannot be clicked through to anything and
               it outranks real targets on tally. */
            breakdownCard('Paid reports by target', byRepTarget, {
              limit: 12, omit: ['unknown'],
              /* The key is a target slug where the report has one and a PROGRAM handle where it
                 does not - API-only rows have no local file and so no target (see /api/stats).
                 Drill through on whichever it is, or the click would filter on a target that
                 does not exist and open an empty list. */
              hrefFor: function (k) {
                var isTarget = (state.targets || []).some(function (t) { return t.slug === k; });
                return '#/reports?' + qsFrom(isTarget
                  ? { target: k, paid: '1', program: ALL_PROGRAMS }
                  : { program: k, paid: '1' });
              }
            }),
            /* Ranked by tally, biggest first. It used to pin a fixed status order, which put
               whatever was most numerous wherever that list happened to place it - killed led on
               count and rendered third - and dumped any status missing from the list at the
               bottom regardless of size. */
            breakdownCard('Leads by status', byStatus, {
              statusColors: true,
              hrefFor: function (k) { return '#/leads?' + qsFrom({ status: k }); }
            }),
            breakdownCard('Leads by target', byTarget, {
              limit: 12, omit: ['unknown'],
              hrefFor: function (k) { return '#/leads?' + qsFrom({ target: k }); }
            })
          ]),
          /* Wrapped, not bare. See .dash-side: the wrapper is what the grid stretches to the
             left column's height, and the card fills it absolutely so its own row count can
             never push the row taller than the column beside it. */
          el('div', { class: 'dash-side' }, [hacktivityCard()])
        ]));

        /* Recent activity now lives in the Audit Log tab, which has room for the job-health,
           advisory-feed and H1 panels alongside it. */
      }).catch(function (err) {
        clear(host);
        append(host, errorPanel(err, load));
      });
    }

    load();
  }


  /* ================================================================== files */

  function filesView(root, ctx) {
    var path = ctx.q.get('path') || '';
    var file = ctx.q.get('file') || '';

    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Files' })
      ]),
    ]));

    var split = el('div', { class: 'split' + (file ? '' : ' no-detail') });
    var treeCard = el('section', { class: 'pane card' });
    split.appendChild(treeCard);
    root.appendChild(split);

    function goto(p, f) {
      location.hash = '#/files' + (qsFrom({ path: p, file: f }) ? '?' + qsFrom({ path: p, file: f }) : '');
    }

    function breadcrumbs(current, parent) {
      var box = el('div', { class: 'crumbs' });
      box.appendChild(el('button', { type: 'button', text: 'roots', onclick: function () { goto('', ''); } }));
      if (!current) return box;
      var parts = String(current).split('/').filter(function (x) { return x !== ''; });
      var acc = String(current).charAt(0) === '/' ? '' : '.';
      parts.forEach(function (p, idx) {
        acc = acc + '/' + p;
        var here = acc;
        box.appendChild(el('span', { class: 'sep', text: '/' }));
        if (idx === parts.length - 1) box.appendChild(el('span', { class: 'cur', text: p }));
        else box.appendChild(el('button', { type: 'button', text: p, onclick: function () { goto(here, ''); } }));
      });
      if (parent !== undefined && parent !== null && parent !== '' && parent !== current) {
        box.appendChild(el('span', { class: 'sep', text: ' ' }));
        box.appendChild(el('button', { type: 'button', text: '↑ up', onclick: function () { goto(parent, ''); } }));
      }
      return box;
    }

    function loadTree() {
      clear(treeCard);
      append(treeCard, loading('Listing ' + (path || 'browse roots') + '…'));
      api('/fs/tree' + (path ? '?' + qsFrom({ path: path }) : '?path='))
        .then(function (data) {
          data = data || {};
          var entries = data.entries || [];
          clear(treeCard);
          treeCard.appendChild(breadcrumbs(data.path !== undefined ? data.path : path, data.parent));

          if (!entries.length) {
            treeCard.appendChild(empty('Empty directory'));
            return;
          }

          entries = entries.slice().sort(function (a, b) {
            if (!!a.is_dir !== !!b.is_dir) return a.is_dir ? -1 : 1;
            return String(a.name || '').localeCompare(String(b.name || ''));
          });

          treeCard.appendChild(dataTable([
            {
              key: 'name', label: 'Name', cls: 'cell-title cell-max',
              render: function (e) {
                return frag([
                  el('span', { class: 'ftype', text: e.is_dir ? '▸' : '·' }),
                  el('span', { text: e.name || e.path || '' }),
                  e.denied ? ' ' : null,
                  e.denied ? el('span', { class: 'lock', text: 'denied' }) : null
                ]);
              }
            },
            {
              key: 'size', label: 'Size', cls: 'nowrap tiny dim',
              render: function (e) { return e.is_dir ? '' : fmtBytes(e.size); }
            },
            { key: 'mtime', label: 'Modified', cls: 'nowrap tiny dim', render: function (e) { return fmtTime(e.mtime); } },
            {
              key: 'dl', label: '', cls: 'nowrap',
              render: function (e) {
                if (e.is_dir || e.denied) return '';
                return el('a', {
                  class: 'btn btn-sm', text: 'Download',
                  href: API + '/fs/download?' + qsFrom({ path: e.path }),
                  onclick: function (ev) { ev.stopPropagation(); }
                });
              }
            }
          ], entries, {
            idKey: 'path',
            selectedId: file,
            rowClass: function (e) { return e.denied ? 'denied' : ''; },
            rowDisabled: function (e) { return !!e.denied; },
            onRow: function (e) {
              if (e.denied) return;
              if (e.is_dir) goto(e.path, '');
              else goto(data.path !== undefined && data.path !== null ? data.path : path, e.path);
            }
          }));

          var deniedCount = entries.filter(function (e) { return e.denied; }).length;
          if (deniedCount) {
            treeCard.appendChild(el('div', { class: 'pager' },
              el('span', { text: deniedCount + ' entr' + (deniedCount === 1 ? 'y is' : 'ies are') + ' blocked by config.browse_deny_globs and cannot be opened.' })));
          }
        })
        .catch(function (err) {
          clear(treeCard);
          append(treeCard, el('div', { class: 'pane-body' }, errorPanel(err, loadTree)));
        });
    }

    loadTree();

    if (!file) return;

    var fileCard = el('section', { class: 'pane card' });
    split.appendChild(fileCard);
    var editing = false;
    var fileData = null;

    function loadFile() {
      clear(fileCard);
      append(fileCard, loading('Reading ' + file + '…'));
      api('/fs/read?' + qsFrom({ path: file }))
        .then(function (data) { fileData = data || {}; drawFile(); })
        .catch(function (err) {
          clear(fileCard);
          append(fileCard, [
            el('div', { class: 'pane-head' }, el('h2', { text: file.split('/').pop() })),
            el('div', { class: 'pane-body' }, errorPanel(err, loadFile))
          ]);
        });
    }

    function drawFile() {
      clear(fileCard);
      var isMd = /\.(md|markdown|mdown)$/i.test(file);
      var canEdit = !fileData.binary && !fileData.truncated;

      fileCard.appendChild(el('div', { class: 'pane-head' }, [
        el('h2', { text: file.split('/').pop() || file }),
        el('div', { class: 'pane-actions' }, [
          canEdit ? el('button', {
            class: 'btn btn-sm', type: 'button', text: editing ? 'Cancel' : 'Edit',
            onclick: function () { editing = !editing; drawFile(); }
          }) : null,
          (!fileData.binary && fileData.text)
            ? copyButton(function () { return String(fileData.text || ''); }, 'Copy contents') : null,
          copyButton(function () { return String(file); }, 'Copy path'),
          el('a', { class: 'btn btn-sm', text: 'Download', href: API + '/fs/download?' + qsFrom({ path: file }) }),
          el('a', { class: 'btn btn-sm btn-quiet', text: 'Close', href: '#/files?' + qsFrom({ path: path }) })
        ])
      ]));

      var body = el('div', { class: 'pane-body' });
      fileCard.appendChild(body);

      var mg = metaGrid([
        ['Path', fileData.path || file, 'mono'],
        ['Size', fmtBytes(fileData.size)],
        ['Modified', fmtTime(fileData.mtime)]
      ]);
      if (mg) body.appendChild(mg);

      if (fileData.binary) {
        body.appendChild(el('div', { class: 'alert alert-warn' },
          'Binary file. Use the download link — it is not rendered here.'));
        return;
      }
      if (fileData.truncated) {
        body.appendChild(el('div', { class: 'alert alert-warn' },
          'Truncated for display (over config.browse_max_bytes). Editing is disabled so a save cannot destroy the tail.'));
      }

      if (!editing) {
        if (isMd) body.appendChild(mdBlock(fileData.text));
        else body.appendChild(el('pre', { class: 'filetext', text: String(fileData.text || '') }));
        return;
      }

      var ta = el('textarea', { spellcheck: 'false', 'aria-label': 'File contents' });
      ta.value = String(fileData.text || '');
      var errHost = el('div', {});
      var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Save file' });
      saveBtn.addEventListener('click', function () {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving…';
        clear(errHost);
        api('/fs/write', { method: 'PUT', body: { path: file, text: ta.value } })
          .then(function () {
            toast('Wrote ' + file, 'ok');
            editing = false;
            loadFile();
          })
          .catch(function (err) {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Save file';
            append(errHost, errorPanel(err));
          });
      });

      append(body, [
        errHost,
        ta,
        el('div', { class: 'form-actions' }, [
          saveBtn,
          el('button', { class: 'btn', type: 'button', text: 'Cancel', onclick: function () { editing = false; drawFile(); } })
        ])
      ]);
      ta.focus();
    }

    loadFile();
  }

  /* ================================================================= search */

  var KIND_ROUTE = { lead: 'leads', report: 'reports', advisory: 'advisories', program: 'programs' };

  function searchView(root, ctx) {
    var q = ctx.q.get('q') || '';
    var kind = ctx.q.get('kind') || '';
    var limit = parseInt(ctx.q.get('limit') || '50', 10) || 50;

    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Search' })
      ])
    ]));

    var input = el('input', { type: 'search', value: q, placeholder: 'FTS5 query…', spellcheck: 'false' });
    function run(patch) {
      var next = { q: input.value, kind: kind, limit: limit };
      for (var k in patch) next[k] = patch[k];
      location.hash = '#/search' + (qsFrom(next) ? '?' + qsFrom(next) : '');
    }
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') run({}); });

    root.appendChild(el('div', { class: 'filters card' }, [
      el('label', { class: 'field grow' }, [el('span', { class: 'field-label', text: 'Query' }), input]),
      field('Kind', selectEl([
        { value: '', label: 'Everything' },
        { value: 'lead', label: 'Leads' },
        { value: 'report', label: 'Reports' },
        { value: 'advisory', label: 'Advisories' },
        { value: 'program', label: 'Programs' }
      ], kind, function (v) { run({ kind: v }); })),
      field('Limit', selectEl([25, 50, 100, 200], limit, function (v) { run({ limit: v }); })),
      el('div', { class: 'field' }, [
        el('span', { class: 'field-label', text: ' ' }),
        el('button', { class: 'btn btn-primary', type: 'button', text: 'Search', onclick: function () { run({}); } })
      ])
    ]));

    var host = el('div', {});
    root.appendChild(host);

    if (!q) {
      host.appendChild(empty('Type a query', 'Wikilinks in any note jump straight here.'));
      input.focus();
      return;
    }

    append(host, loading('Searching…'));

    function load() {
      clear(host);
      append(host, loading('Searching…'));
      api('/search?' + qsFrom({ q: q, kind: kind, limit: limit }))
        .then(function (data) {
          var items = (data && data.items) || [];
          clear(host);
          if (!items.length) {
            host.appendChild(empty('No matches for "' + q + '"', 'FTS5 syntax applies: try a prefix* or a "quoted phrase".'));
            return;
          }

          var groups = {};
          var order = [];
          items.forEach(function (it) {
            var k = it.kind || 'other';
            if (!groups[k]) { groups[k] = []; order.push(k); }
            groups[k].push(it);
          });

          host.appendChild(el('p', { class: 'page-sub', text: items.length + ' result' + (items.length === 1 ? '' : 's') + ' across ' + order.length + ' kind' + (order.length === 1 ? '' : 's') }));

          order.forEach(function (k) {
            var card = el('section', { class: 'card' }, [
              el('div', { class: 'card-title', text: (KIND_ROUTE[k] || k) + ' · ' + groups[k].length })
            ]);
            var list = el('div', { class: 'results' });
            groups[k].forEach(function (it) {
              var route = KIND_ROUTE[it.kind];
              var node = el('button', { class: 'result', type: 'button' }, [
                el('div', { class: 'rt', text: it.title || it.ref || ('#' + it.id) }),
                el('div', { class: 'rm' }, [
                  it.ref ? el('span', { class: 'tag', text: it.ref }) : null,
                  it.target ? el('span', { text: it.target }) : null,
                  it.score !== undefined && it.score !== null ? el('span', { text: 'score ' + it.score }) : null,
                  el('span', { text: (it.kind || '') + (it.id ? ' #' + it.id : '') })
                ]),
                /* snippet is rendered as plain text on purpose: it can contain arbitrary file content */
                it.snippet ? el('div', { class: 'rs', text: String(it.snippet) }) : null
              ]);
              node.addEventListener('click', function () {
                if (route && it.id !== undefined && it.id !== null) {
                  location.hash = '#/' + route + '/' + encodeURIComponent(it.id);
                } else {
                  toast('No detail view for kind "' + it.kind + '".', 'err');
                }
              });
              list.appendChild(node);
            });
            card.appendChild(list);
            host.appendChild(card);
          });
        })
        .catch(function (err) {
          clear(host);
          append(host, errorPanel(err, load));
        });
    }

    load();
  }

  /* =============================================================== payloads */

  /* The arsenal is third-party reference material, so it has its own endpoint and its own
     table and never appears in Search: a cheatsheet must not rank against a hunt note.
     See payloads.py. */
  function payloadsView(root, ctx) {
    var q = ctx.q.get('q') || '';
    var category = ctx.q.get('category') || '';
    var limit = parseInt(ctx.q.get('limit') || '50', 10) || 50;

    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Payloads' })
      ])
    ]));

    var input = el('input', { type: 'search', value: q, placeholder: 'jinja2 ssti, jwt none, xxe billion…', spellcheck: 'false' });
    function run(patch) {
      var next = { q: input.value, category: category, limit: limit };
      for (var k in patch) next[k] = patch[k];
      location.hash = '#/payloads' + (qsFrom(next) ? '?' + qsFrom(next) : '');
    }
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') run({}); });

    function categoryOptions() {
      var opts = [{ value: '', label: 'Every category' }];
      state.payloadCategories.forEach(function (c) {
        opts.push({ value: c.category, label: c.category + ' (' + c.n + ')' });
      });
      /* A category chosen before the list arrived must still show as selected. */
      if (category && !state.payloadCategories.some(function (c) { return c.category === category; })) {
        opts.push({ value: category, label: category });
      }
      return opts;
    }
    var catSel = selectEl(categoryOptions(), category, function (v) { run({ category: v }); });

    root.appendChild(el('div', { class: 'filters card' }, [
      el('label', { class: 'field grow' }, [el('span', { class: 'field-label', text: 'Query' }), input]),
      field('Category', catSel),
      field('Limit', selectEl([25, 50, 100, 200], limit, function (v) { run({ limit: v }); })),
      el('div', { class: 'field' }, [
        el('span', { class: 'field-label', text: ' ' }),
        el('button', { class: 'btn btn-primary', type: 'button', text: 'Search', onclick: function () { run({}); } })
      ])
    ]));

    var host = el('div', {});
    root.appendChild(host);

    function load() {
      clear(host);
      append(host, loading('Searching payloads…'));
      api('/payloads?' + qsFrom({ q: q, category: category, limit: limit }))
        .then(function (data) {
          var items = (data && data.items) || [];
          var stats = (data && data.stats) || {};
          state.payloadCategories = (data && data.categories) || [];
          /* Repopulate in place rather than re-rendering: the query box may already have focus. */
          clear(catSel);
          categoryOptions().forEach(function (o) {
            catSel.appendChild(el('option', { value: o.value, text: o.label, selected: o.value === category }));
          });

          clear(host);
          if (!stats.payloads) {
            host.appendChild(empty('No payloads indexed',
              'index.db ships empty. Run ./scripts/sync-payloads.sh to clone the arsenal and build the table.'));
            return;
          }
          if (!items.length) {
            host.appendChild(empty('No payloads match "' + q + '"',
              'FTS5 syntax applies: try a prefix* or a "quoted phrase".'));
            return;
          }

          host.appendChild(el('p', { class: 'page-sub', text: items.length + ' of ' + stats.payloads + ' payloads' + (data.interpreted_as ? ' (read as ' + data.interpreted_as + ')' : '') }));

          items.forEach(function (it) {
            var dir = String(it.file_path || '').replace(/\/[^/]*$/, '');
            host.appendChild(el('section', { class: 'card' }, [
              el('div', { class: 'card-title', text: it.category + (it.technique ? ' · ' + it.technique : '') }),
              el('div', { class: 'payload-meta' }, [
                it.section ? el('span', { class: 'tag', text: it.section }) : null,
                it.lang ? el('span', { text: it.lang }) : null,
                el('a', { href: '#/files?' + qsFrom({ path: dir, file: it.file_path }), text: 'source:' + it.line })
              ]),
              /* Payload text is rendered as plain text, never markdown: it is attack input. */
              el('pre', { class: 'payload', text: String(it.payload || '') }),
              el('div', { class: 'form-actions' }, [copyButton(function () { return it.payload; }, 'Copy payload')])
            ]));
          });
        })
        .catch(function (err) {
          clear(host);
          append(host, errorPanel(err, load));
        });
    }

    load();
  }

  /* ================================================================= tokens */

  function tokensView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'API tokens' })
      ])
    ]));

    var tokenHost = el('div', {});
    root.appendChild(tokenHost);

    if (state.lastNewToken) {
      var t = state.lastNewToken;
      tokenHost.appendChild(el('div', { class: 'tokenbox' }, [
        el('strong', { class: 'alert-title', text: 'Copy this token now — it will never be shown again.' }),
        el('div', { class: 'tiny', text: 'Token #' + t.id + ' (' + t.name + ', scope ' + t.scope + '). The server stores only its hash; there is no way to recover it later.' }),
        el('code', { class: 'tv', text: t.token }),
        el('div', { class: 'form-actions' }, [
          copyButton(function () { return t.token; }, 'Copy token'),
          el('button', {
            class: 'btn', type: 'button', text: 'I have saved it — hide',
            onclick: function () { state.lastNewToken = null; render(); }
          })
        ])
      ]));
    }

    /* create */
    var nameInput = el('input', { type: 'text', placeholder: 'ingest box, laptop cli…', spellcheck: 'false' });
    var scopeSel = selectEl([{ value: 'read', label: 'read' }, { value: 'write', label: 'write' }], 'read');
    var createErr = el('div', {});
    var createBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Create token' });

    createBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      if (!name) {
        clear(createErr);
        append(createErr, el('div', { class: 'alert alert-warn', text: 'Give the token a name so you can tell them apart later.' }));
        return;
      }
      createBtn.disabled = true;
      createBtn.textContent = 'Creating…';
      clear(createErr);
      api('/tokens', { method: 'POST', body: { name: name, scope: scopeSel.value } })
        .then(function (data) {
          state.lastNewToken = {
            id: (data && data.id) !== undefined ? data.id : '?',
            token: (data && data.token) || '',
            name: name,
            scope: scopeSel.value
          };
          render();
        })
        .catch(function (err) {
          createBtn.disabled = false;
          createBtn.textContent = 'Create token';
          append(createErr, errorPanel(err));
        });
    });

    root.appendChild(el('section', { class: 'card' }, [
      el('div', { class: 'card-title', text: 'New token' }),
      el('div', { class: 'pane-body' }, [
        createErr,
        el('div', { class: 'form-grid' }, [
          field('Name', nameInput),
          field('Scope', scopeSel, 'read tokens are rejected on every mutating verb')
        ]),
        el('div', { class: 'form-actions' }, createBtn)
      ])
    ]));

    var listCard = el('section', { class: 'card' }, el('div', { class: 'card-title', text: 'Existing tokens' }));
    root.appendChild(listCard);
    var listHost = el('div', {});
    listCard.appendChild(listHost);

    function load() {
      clear(listHost);
      append(listHost, loading('Loading tokens…'));
      api('/tokens').then(function (data) {
        var items = (data && data.items) || [];
        clear(listHost);
        if (!items.length) { listHost.appendChild(empty('No API tokens yet')); return; }
        listHost.appendChild(dataTable([
          { key: 'id', label: 'ID', cls: 'cell-mono nowrap' },
          { key: 'name', label: 'Name', cls: 'cell-title' },
          { key: 'prefix', label: 'Prefix', cls: 'cell-mono nowrap', render: function (r) { return (r.prefix || '') + '…'; } },
          { key: 'scope', label: 'Scope', cls: 'nowrap', render: function (r) { return tag(r.scope); } },
          { key: 'created_at', label: 'Created', cls: 'nowrap tiny dim', render: function (r) { return fmtTime(r.created_at); } },
          { key: 'last_used', label: 'Last used', cls: 'nowrap tiny dim', render: function (r) { return r.last_used ? fmtTime(r.last_used) : 'never'; } },
          {
            key: 'revoked', label: 'Status', cls: 'nowrap',
            render: function (r) { return r.revoked ? pill('killed') : pill('confirmed'); }
          },
          {
            key: 'act', label: '', cls: 'nowrap',
            render: function (r) {
              if (r.revoked) return el('span', { class: 'muted', text: 'revoked' });
              var b = el('button', { class: 'btn btn-sm btn-danger', type: 'button', text: 'Revoke' });
              b.addEventListener('click', function () {
                if (!window.confirm('Revoke token "' + (r.name || r.id) + '"? Clients using it will start getting 401s.')) return;
                b.disabled = true;
                api('/tokens/' + encodeURIComponent(r.id) + '/revoke', { method: 'POST' })
                  .then(function () { toast('Token revoked.', 'ok'); load(); })
                  .catch(function (err) { b.disabled = false; toastError(err); });
              });
              return b;
            }
          }
        ], items, {}));
      }).catch(function (err) {
        clear(listHost);
        append(listHost, el('div', { class: 'pane-body' }, errorPanel(err, load)));
      });
    }

    load();

    root.appendChild(el('div', { class: 'alert alert-info tiny' },
      'Bearer requests are CSRF-exempt (no ambient credential). Browser sessions must always send ' + CSRF_HEADER + ': 1.'));
  }

  /* ================================================================== tools */

  function describeRow(r) {
    if (r === null || r === undefined) return '';
    if (typeof r === 'string') return r;
    if (typeof r !== 'object') return String(r);
    if (r.tracker_row) return String(r.tracker_row);
    var bits = [];
    ['h1_id', 'ref', 'title', 'state', 'severity', 'bounty', 'submitted_on', 'resolved_on'].forEach(function (k) {
      if (r[k] !== undefined && r[k] !== null && r[k] !== '') bits.push(k + '=' + r[k]);
    });
    if (bits.length) return bits.join('  ');
    try { return JSON.stringify(r); } catch (e) { return String(r); }
  }

  function reindexCard() {
    var card = el('section', { class: 'card' }, el('div', { class: 'card-title', text: 'Re-index' }));
    var out = el('div', {});
    var btn = el('button', { class: 'btn', type: 'button', text: 'Re-index workspaces' });
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = 'Scanning…';
      clear(out);
      append(out, loading('Walking the workspaces…'));
      api('/reindex', { method: 'POST' })
        .then(function (r) {
          btn.disabled = false;
          btn.textContent = 'Re-index workspaces';
          clear(out);
          append(out, el('div', { class: 'alert alert-ok' },
            'Scanned ' + ((r && r.scanned) || 0) + ' files, ' + ((r && r.changed) || 0) + ' changed, in ' + ((r && r.elapsed_ms) || 0) + ' ms.'));
          state.targetsLoaded = false;
          loadTargets(true);
        })
        .catch(function (err) {
          btn.disabled = false;
          btn.textContent = 'Re-index workspaces';
          clear(out);
          append(out, errorPanel(err));
        });
    });
    card.appendChild(el('div', { class: 'pane-body' }, [
      el('p', { class: 'page-sub', text: 'Re-walks the hunt workspaces and refreshes the index. Leads and notes are read from disk; reports are not touched.' }),
      el('div', { class: 'form-actions' }, btn),
      out
    ]));
    return card;
  }

  /* ================================================================ status */

  /* Age of an ISO timestamp, phrased for a health panel: "4m ago", "never". */
  function ago(iso) {
    if (!iso) return 'never';
    var t = parseServerTime(iso);
    if (isNaN(t)) return String(iso);
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 90) return Math.round(s) + 's ago';
    if (s < 5400) return Math.round(s / 60) + 'm ago';
    /* Rolls to days at 24h, not 48h. Holding hours for a second day meant the hacktivity tile
       read "31h ago" where every other age column in the app already said "1d", and then jumped
       straight from 47h to 2d without ever showing 1d at all.
       FLOOR, not round: at 36h the elapsed day is one, and rounding to 2d claims a day that has
       not happened. Same rule ageShort() uses, so the two never disagree on one row. */
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function agoSeconds(iso) {
    if (!iso) return Infinity;
    var t = parseServerTime(iso);
    return isNaN(t) ? Infinity : Math.max(0, (Date.now() - t) / 1000);
  }

  /* A health verdict with its reason attached. The reason matters more than the colour: an
     empty cron log looks broken and is not, and that has to be sayable. */
  function healthPill(level, text) {
    return el('span', { class: 'hpill h-' + level, text: text });
  }

  function statusRow(label, value, note) {
    return el('div', { class: 'srow' }, [
      el('span', { class: 'srow-k', text: label }),
      el('span', { class: 'srow-v' }, typeof value === 'string' ? document.createTextNode(value) : value),
      note ? el('span', { class: 'srow-note', text: note }) : null
    ]);
  }

  function statusCard(title, verdict, rows, actions) {
    return el('section', { class: 'card statuscard' }, [
      el('div', { class: 'statuscard-head' }, [
        el('h2', { class: 'card-title', text: title }),
        verdict || null
      ]),
      el('div', { class: 'srows' }, rows.filter(Boolean)),
      actions && actions.length ? el('div', { class: 'statuscard-actions' }, actions) : null
    ]);
  }

  /* ------------------------------------------------------------ polling schedule
     One editable row per cron job, in minutes. The value is written to config.json and installed
     into the crontab in one request; see POST /api/schedule. */
  function scheduleCard(sched, reload) {
    var jobs = sched.jobs || [];
    var inputs = {};

    /* in_sync is null when the crontab could not be read at all, which is a different state from
       "read it, and it disagrees". Only the second one is a warning the user can act on. */
    var verdict = sched.error ? healthPill('bad', 'cron unreadable')
      : (sched.in_sync === false ? healthPill('warn', 'crontab differs')
        : healthPill('ok', 'installed'));

    /* The control reads as a sentence - "every [15] minutes" - rather than a bare number box
       tagged with a unit and trailed by the raw cron field. The cron string was the literal
       output of what this card configures, which made it noise sitting in the widest column of
       every row; anyone who wants it can read the crontab. */
    var rows = jobs.map(function (j) {
      var input = el('input', {
        class: 'sched-input', type: 'number', min: String(sched.min || 1),
        max: String(sched.max || 1440), step: '1', value: String(j.minutes),
        title: 'cron: ' + j.cron
      });
      inputs[j.key] = input;
      var row = el('div', { class: 'sched-row' }, [
        el('div', { class: 'sched-label' }, [
          el('span', { class: 'sched-name', text: j.label }),
          el('span', { class: 'sched-desc', text: j.desc || '' })
        ]),
        el('div', { class: 'sched-ctl' }, [
          el('span', { class: 'sched-every', text: 'every' }),
          input,
          el('span', { class: 'sched-unit', text: 'minutes' })
        ])
      ]);
      /* Only when it applies. A value that went in cleanly carries no explanation at all. */
      if (j.snapped_from) {
        row.appendChild(el('div', { class: 'sched-snap',
          text: 'Asked for ' + j.snapped_from + ' minutes. Cron cannot divide the hour by that, '
              + 'so it is running every ' + j.minutes + '.' }));
      }
      return row;
    });

    (sched.fixed || []).forEach(function (f) {
      rows.push(el('div', { class: 'sched-row sched-row-fixed' }, [
        el('div', { class: 'sched-label' }, [
          el('span', { class: 'sched-name', text: f.label }),
          el('span', { class: 'sched-desc', text: f.desc || '' })
        ]),
        el('div', { class: 'sched-ctl' }, [
          el('span', { class: 'sched-fixedwhen', text: f.when || f.cron })
        ])
      ]));
    });

    var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Save and install' });
    saveBtn.addEventListener('click', function () {
      var payload = {};
      jobs.forEach(function (j) {
        var v = parseInt(inputs[j.key].value, 10);
        if (!isNaN(v)) payload[j.key] = v;
      });
      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving…';
      api('/schedule', { method: 'POST', body: { intervals: payload } })
        .then(function (r) {
          /* Saved and installed are reported separately because they can genuinely differ: the
             setting is stored first, so a failed crontab write leaves a real state to describe
             rather than an ambiguous one. */
          if (r && r.installed) toast('Schedule installed', 'ok');
          else toast('Saved, but the crontab was not written: ' +
                     ((r && r.error) || 'unknown error'), 'err');
          reload();
        })
        .catch(function (e) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save and install';
          toast(String((e && e.message) || e), 'err');
        });
    });

    var body = el('div', { class: 'sched-rows' }, rows);
    var card = statusCard('Polling schedule', verdict, [], [saveBtn]);
    /* statusCard builds head/rows/actions; the editor goes between the rows and the actions. */
    var actions = card.querySelector('.statuscard-actions');
    if (actions) card.insertBefore(body, actions);
    else card.appendChild(body);
    card.appendChild(el('p', { class: 'status-note' },
      'Intervals snap to a value that divides the hour evenly, so "every N minutes" stays true ' +
      'across the hour boundary. Jobs are staggered by a fixed offset each so they do not all ' +
      'fire on the same tick. Everything outside the managed block in your crontab is left alone.'));
    if (sched.error) {
      card.appendChild(el('p', { class: 'status-note', text: 'crontab: ' + sched.error }));
    }
    return card;
  }

  /* ---------------------------------------------------------------- settings

     Everything that CHANGES behaviour. Status is the read-only twin: what the app currently
     believes, with no control on it that can alter anything. The two were one page until
     2026-08-03, which made "check whether the poller is healthy" and "change how often it runs"
     the same page, and the health half is looked at ten times as often. */
  function settingsView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Settings' })
      ])
    ]));

    var host = el('div', {});
    root.appendChild(host);

    function load() {
      clear(host);
      append(host, loading('Loading…'));
      Promise.all([
        api('/settings'),
        api('/schedule').catch(function () { return null; })
      ]).then(function (res) {
        var cfg = res[0] || {};
        var sched = res[1];
        clear(host);
        /* Cadence first: it is changed far more often than the session timeout, which is set
           once and then left alone. */
        if (sched) {
          host.appendChild(scheduleCard(sched, load));
        } else {
          host.appendChild(statusCard('Schedule', healthPill('bad', 'unavailable'),
            [statusRow('Reason', 'The schedule module did not answer. Cadence cannot be changed '
                               + 'from here until it does.')], []));
        }
        host.appendChild(sessionCard(cfg, load));
      }).catch(function (err) {
        clear(host);
        append(host, errorPanel(err, load));
      });
    }
    load();
  }

  /* The session timeout. Off by default: one operator, bound to loopback, and being logged out
     mid-hunt cost more than the timer ever bought. The trade is stated on the card rather than
     buried, because the box holds unreported findings.

     The whole card REDRAWS on toggle. It first shipped computing its rows once and mutating only
     the button label and the input's disabled flag, so the state rows and the verdict pill kept
     saying "never" after you turned expiry on - which read as a control that does nothing. Any
     card whose text is derived from a value the user can change has to redraw, not patch. */
  function sessionCard(cfg, reload) {
    var card = el('section', { class: 'card statuscard' });
    var on = !!cfg.session_expiry_enabled;
    var hours = cfg.session_hours > 0 ? cfg.session_hours : 12;

    function draw() {
      clear(card);

      var hoursInput = el('input', {
        class: 'sched-input', type: 'number', min: '1', max: '8760', step: '1',
        value: String(hours)
      });
      hoursInput.disabled = !on;
      hoursInput.addEventListener('input', function () {
        var v = parseInt(hoursInput.value, 10);
        if (!isNaN(v)) hours = v;
      });

      var toggle = el('button', {
        class: 'btn btn-sm toggle-btn' + (on ? ' on' : ''), type: 'button',
        'aria-pressed': on ? 'true' : 'false',
        title: on ? 'Turn the timeout off - the login lasts until you log out'
                  : 'Turn the timeout on - the login expires after a set number of hours',
        text: on ? 'Expiry on' : 'Expiry off'
      });
      toggle.addEventListener('click', function () { on = !on; draw(); });

      var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Save' });
      saveBtn.addEventListener('click', function () {
        /* 0 IS the off value, not a missing one - the server reads it as "never expires". */
        var send = 0;
        if (on) {
          send = parseInt(hoursInput.value, 10);
          if (isNaN(send) || send < 1) { toast('Hours must be 1 or more', 'err'); return; }
        }
        saveBtn.disabled = true;
        api('/settings', { method: 'POST', body: { session_hours: send } })
          .then(function (r) {
            toast(send > 0 ? 'Sessions now expire after ' + send + ' hours'
                           : 'Session expiry disabled', 'ok');
            if (r && r.applies_to) toast('Applies to ' + r.applies_to, 'info');
            reload();
          })
          .catch(function (e) {
            saveBtn.disabled = false;
            toast(String((e && e.message) || e), 'err');
          });
      });

      /* Unsaved state is visible rather than implied: the pill reports what is STORED, and the
         row reports what the form currently says, so a toggled-but-unsaved card cannot be
         mistaken for a saved one. */
      var stored = !!cfg.session_expiry_enabled;
      var dirty = (on !== stored) || (on && hours !== cfg.session_hours);

      var rows = [
        statusRow('Expiry', on ? 'after ' + hours + ' hours' : 'never',
                  on ? '' : 'the login lasts until you log out'),
        statusRow('Hours', el('span', { class: 'sched-ctl' }, [hoursInput]),
                  on ? '' : 'ignored while expiry is off'),
        statusRow('Applies to', 'sessions created from the next login onward',
                  'changing this does not end or extend a session already open')
      ];
      if (dirty) {
        rows.push(statusRow('Unsaved', 'stored value is '
                            + (stored ? cfg.session_hours + ' hours' : 'never')));
      }
      if (!on && cfg.session_note) rows.push(statusRow('Note', cfg.session_note));

      append(card, [
        el('div', { class: 'statuscard-head' }, [
          el('h2', { class: 'card-title', text: 'Session' }),
          stored ? healthPill('ok', cfg.session_hours + ' hours')
                 : healthPill('warn', 'no timeout')
        ]),
        el('div', { class: 'srows' }, rows.filter(Boolean)),
        el('div', { class: 'statuscard-actions' }, [toggle, saveBtn])
      ]);
    }

    draw();
    return card;
  }

  function statusView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Status' })
      ])
    ]));

    var host = el('div', {});
    root.appendChild(host);

    function load() {
      clear(host);
      append(host, loading('Checking…'));
      /* The schedule is a second endpoint but not a second spinner: a status page that renders
         in two stages reads as broken. A failure there degrades to an absent card rather than
         taking the whole page down, same reasoning as the hacktivity tile. */
      /* The schedule is still READ here, because every job card quotes its own cadence, but it
         is no longer DRAWN here - the controls that change it live on Settings. A failure
         degrades to cards without a cadence line rather than taking the page down. */
      Promise.all([
        api('/status'),
        api('/schedule').catch(function () { return null; })
      ]).then(function (res) {
        var d = res[0];
        var sched = res[1];
        clear(host);
        d = d || {};
        var integ = d.integration || {};
        var poll = d.poller || null;
        var adv = d.advisories || {};
        var idx = d.index || {};
        var money = d.bounty || {};
        /* Every job's cadence now comes from one place, so the hardcoded "every 15 minutes" and
           "every 30 minutes" strings that used to sit in the cards below cannot drift from what
           cron is actually running. */
        var cadence = {};
        ((sched && sched.jobs) || []).forEach(function (j) { cadence[j.key] = j; });
        function schedRow(key, fallback) {
          var j = cadence[key];
          return statusRow('Schedule', j ? j.describe : fallback, j ? 'cron ' + j.cron : '');
        }


        /* --- build ------------------------------------------------------- */
        host.appendChild(statusCard('Build', healthPill('ok', 'v' + (d.version || '?')), [
          statusRow('Version', 'v' + (d.version || '?')),
          statusRow('Server time', d.now || '-')
        ], []));

        /* --- index ------------------------------------------------------- */
        var idxVerdict = (idx.shadow_rows || 0) > 0
          ? healthPill('bad', idx.shadow_rows + ' shadow rows')
          : healthPill('ok', 'clean');
        host.appendChild(statusCard('Index', idxVerdict, [
          statusRow('Reports', String(idx.reports || 0), 'from the HackerOne API'),
          statusRow('With body', String(idx.reports_with_body || 0) + ' / ' + (idx.reports || 0)),
          statusRow('With comments', String(idx.reports_with_thread || 0) + ' / ' + (idx.reports || 0)),
          statusRow('Leads', String(idx.leads || 0), 'excludes unstatused notes'),
          statusRow('Legacy shadow rows', String(idx.shadow_rows || 0),
                    (idx.shadow_rows || 0) === 0 ? 'purged' : 'run a reindex'),
          statusRow('Last indexed', ago(idx.last_indexed), idx.last_indexed || '')
        ], []));

        /* --- credential ------------------------------------------------- */
        var credVerdict = integ.configured
          ? healthPill('ok', 'configured')
          : healthPill('bad', 'not configured');
        host.appendChild(statusCard('HackerOne credential', credVerdict, [
          statusRow('Username', integ.username || '-'),
          statusRow('Token', integ.masked_token || '-'),
          statusRow('Fingerprint', integ.fingerprint || '-'),
          statusRow('Last full sync', ago(integ.last_sync), integ.last_sync || '')
        ], [
          el('a', { class: 'btn', href: '#/integrations', text: 'Manage credential' })
        ]));

        /* --- poller ------------------------------------------------------ */
        if (poll) {
          var stale = agoSeconds(poll.last_success) > 3600;   /* cron is every 15 min */
          var verdict = poll.in_backoff ? healthPill('bad', 'backing off')
            : (poll.consecutive_failures > 0 ? healthPill('warn', poll.consecutive_failures + ' failed in a row')
              : (stale ? healthPill('warn', 'stale') : healthPill('ok', 'healthy')));

          var pollBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Poll now' });
          pollBtn.addEventListener('click', function () {
            pollBtn.disabled = true;
            pollBtn.textContent = 'Polling…';
            api('/h1/poll', { method: 'POST', body: { force: true } })
              .then(function (r) {
                toast('Poll finished: ' + (r.events || 0) + ' event' +
                      ((r.events || 0) === 1 ? '' : 's') + ', ' +
                      (r.requests || 0) + ' request' + ((r.requests || 0) === 1 ? '' : 's'), 'ok');
                load();
              })
              .catch(function (e) {
                pollBtn.disabled = false;
                pollBtn.textContent = 'Poll now';
                toast(String((e && e.message) || e), 'err');
              });
          });

          host.appendChild(statusCard('Incremental poll', verdict, [
            schedRow('h1', 'every 15 minutes'),
            statusRow('Last run', ago(poll.last_run), poll.last_run || ''),
            statusRow('Last success', ago(poll.last_success), poll.last_success || ''),
            statusRow('Result', poll.last_status || '-',
                      poll.last_duration_ms ? poll.last_duration_ms + ' ms' : ''),
            poll.last_error ? statusRow('Last error', poll.last_error) : null,
            statusRow('Runs', String(poll.runs || 0),
                      (poll.failures || 0) + ' failed'),
            statusRow('Requests used', String(poll.cumulative_requests || 0),
                      poll.runs ? (Math.round((poll.cumulative_requests || 0) / poll.runs * 10) / 10) + ' per run' : ''),
            statusRow('Watched reports', String(poll.watched_reports || 0)),
            statusRow('Changes seen', String(poll.events_total || 0),
                      (poll.events_unseen || 0) + ' unread')
          ], [
            pollBtn,
            el('a', { class: 'btn', href: '#/audit', text: 'View changes' })
          ]));

          /* An empty cron log reads as a broken job and is not one. Say so where it is seen. */
          if (!poll.last_error && (poll.failures || 0) === 0) {
            host.appendChild(el('p', { class: 'status-note' },
              'The cron job runs with --quiet and prints nothing on success, so an empty ' +
              'h1-cron.log is the healthy case. Activity is recorded here and in the Audit log, ' +
              'not in that file.'));
          }
        } else {
          host.appendChild(statusCard('Incremental poll',
            healthPill('bad', 'unavailable'),
            [statusRow('Module', 'h1_watch could not be imported')], []));
        }

        /* --- advisory feed ----------------------------------------------- */
        var fetchAge = agoSeconds(adv.last_fetched);
        var advVerdict = fetchAge > 86400 ? healthPill('warn', 'stale')
          : healthPill('ok', 'healthy');
        host.appendChild(statusCard('Advisory feed', advVerdict, [
          schedRow('advisories', 'every 15 minutes'),
          statusRow('Last fetch', ago(adv.last_fetched), adv.last_fetched || ''),
          statusRow('Advisories', String(adv.count || 0)),
          statusRow('Newest published', adv.latest_published ? ago(adv.latest_published) : '-',
                    adv.latest_published || ''),
          statusRow('Report matches', String(adv.matches || 0))
        ], [
          el('a', { class: 'btn', href: '#/advisories', text: 'Advisories' })
        ]));

        /* --- money ------------------------------------------------------- */
        host.appendChild(statusCard('Earnings', healthPill('ok', 'from HackerOne'), [
          statusRow('Awards', String(money.awards || 0)),
          statusRow('Total', fmtMoney(String(money.total || 0), money.currency)),
          statusRow('My share', fmtMoney(String(money.my_share || 0), money.currency)),
          statusRow('Splits', String(money.splits || 0)),
          statusRow('As collaborator', String(money.as_collaborator || 0))
        ], []));

        /* Reindex still needs a home; it is maintenance, and this is the maintenance page.
           The Upload card that used to sit here is gone: dropping files into a workspace is
           done from a shell, and a form for it on the health page was never used. Its
           uploadCard() builder went with it: nothing else mounted it. POST /api/uploads is
           untouched and still works for anything that posts to it. */
        host.appendChild(el('div', { class: 'cards3' }, reindexCard()));
      }).catch(function (err) {
        clear(host);
        append(host, errorPanel(err, load));
      });
    }

    load();
  }

  /* ============================================================== programs */

  function programsView(root, ctx) {
    entityListView(root, ENTITIES.programs, ctx);
  }

  /* =============================================================== targets */

  /* Two tables, because there are two different things called a target and conflating them is
     what made this page confusing while it lived under Programs.

     SCOPES are HackerOne's answer to "what may I test", many per program, each with an asset
     type and a bounty-eligibility flag. WORKSPACE TARGETS are local the workspace volume directories
     that leads and reports are keyed to by target_id. The first is fetched and rewritten by
     `h1.py --sync-programs`; the second is derived from disk by ingest.py and is what the
     research is filed against. Neither can substitute for the other. */
  function targetsView(root, ctx) {
    var q = (ctx && ctx.q) || new URLSearchParams('');
    var params = {
      program: q.get('program') || '',
      type: q.get('type') || '',
      bounty: q.get('bounty') === '1' ? '1' : ''
    };

    function go(patch) {
      var next = {};
      for (var k in params) next[k] = params[k];
      for (var p in patch) next[p] = patch[p];
      location.hash = '#/targets' + (qsFrom(next) ? '?' + qsFrom(next) : '');
    }

    root.appendChild(el('div', { class: 'page-head' }, el('div', {}, [
      el('h1', { class: 'page-title', text: 'Targets' })
    ])));

    var filters = el('div', { class: 'filters card' });
    var scopeCard = el('section', { class: 'card' },
      el('div', { class: 'card-title', text: 'In-scope assets (HackerOne)' }));
    var scopeHost = el('div', {});
    scopeCard.appendChild(scopeHost);

    var wsCard = el('section', { class: 'card' },
      el('div', { class: 'card-title', text: 'Workspace targets' }));
    var wsHost = el('div', {});
    wsCard.appendChild(wsHost);

    root.appendChild(el('div', {}, [filters, scopeCard, wsCard]));

    append(scopeHost, loading('Loading scopes…'));
    append(wsHost, loading('Loading workspace targets…'));

    fetchAllPages('/scopes').then(function (items) {
      clear(scopeHost);

      var programs = uniqueSorted(items.map(function (r) { return r.program || ''; }));
      var types = uniqueSorted(items.map(function (r) { return r.asset_type || ''; }));
      filters.appendChild(field('Program', selectEl(
        [{ value: '', label: 'All programs' }].concat(programs.map(function (p) {
          return { value: p, label: p };
        })), params.program, function (v) { go({ program: v }); })));
      filters.appendChild(field('Asset type', selectEl(
        [{ value: '', label: 'All types' }].concat(types.map(function (t) {
          return { value: t, label: assetTypeLabel(t) };
        })), params.type, function (v) { go({ type: v }); })));
      filters.appendChild(el('div', { class: 'field' }, el('button', {
        class: 'btn chip-program' + (params.bounty === '1' ? ' on' : ''),
        type: 'button',
        'aria-pressed': params.bounty === '1' ? 'true' : 'false',
        title: 'Hide assets the program says earn no bounty',
        text: 'Bounty-eligible only',
        onclick: function () { go({ bounty: params.bounty === '1' ? '' : '1' }); }
      })));

      var shown = items.filter(function (r) {
        if (params.program && (r.program || '') !== params.program) return false;
        if (params.type && (r.asset_type || '') !== params.type) return false;
        if (params.bounty === '1' && !Number(r.eligible_for_bounty)) return false;
        return true;
      });

      if (!items.length) {
        scopeHost.appendChild(empty('No scopes synced',
          'Run `python3 h1.py --sync-programs` to pull every program\'s in-scope assets.'));
        return;
      }
      if (!shown.length) { scopeHost.appendChild(empty('No assets match these filters')); return; }
      scopeHost.appendChild(dataTable([
        { key: 'program', label: 'Program', cls: 'cell-mono nowrap tiny' },
        { key: 'identifier', label: 'Asset', cls: 'cell-title cell-mono' },
        {
          key: 'asset_type', label: 'Type', cls: 'nowrap',
          render: function (r) { return tag(assetTypeLabel(r.asset_type)); }
        },
        {
          /* Spelled out rather than shown as a tick. An asset that is in scope but pays nothing
             is a different proposition from one that pays, and a blank cell reads as missing
             data rather than as "no bounty". */
          key: 'eligible_for_bounty', label: 'Bounty', cls: 'nowrap',
          render: function (r) {
            return Number(r.eligible_for_bounty)
              ? el('span', { class: 'pill pill-confirmed', text: 'eligible' })
              : el('span', { class: 'pill pill-parked', text: 'no bounty' });
          }
        }
      ], shown, {}));
      var note = shown.length === items.length
        ? items.length + ' assets across ' + programs.length + ' programs'
        : shown.length + ' of ' + items.length + ' assets';
      scopeHost.appendChild(el('div', { class: 'tiny dim pane-body', text: note }));
    }).catch(function (err) {
      clear(scopeHost);
      append(scopeHost, el('div', { class: 'pane-body' }, errorPanel(err)));
    });

    api('/targets?limit=500').then(function (data) {
      var items = (data && data.items) || [];
      clear(wsHost);
      if (!items.length) { wsHost.appendChild(empty('No targets indexed')); return; }
      wsHost.appendChild(dataTable([
        { key: 'slug', label: 'Slug', cls: 'cell-mono nowrap' },
        { key: 'name', label: 'Name', cls: 'cell-title' },
        { key: 'program', label: 'Program', cls: 'cell-mono nowrap tiny' },
        { key: 'version', label: 'Version', cls: 'nowrap' },
        { key: 'workspace', label: 'Workspace', cls: 'cell-mono tiny dim' },
        { key: 'codeql_db', label: 'CodeQL DB', cls: 'cell-mono tiny dim' },
        {
          key: 'leads', label: '', cls: 'nowrap',
          render: function (r) { return el('a', { class: 'btn btn-sm', href: '#/leads?' + qsFrom({ target: r.slug }), text: 'Leads' }); }
        }
      ], items, {}));
    }).catch(function (err) {
      clear(wsHost);
      append(wsHost, el('div', { class: 'pane-body' }, errorPanel(err)));
    });
  }

  /* Every row of a list endpoint, following the server's 500-row page cap. The scope list is
     already ~970 assets across 18 programs and only grows, and a scope list that stops part-way
     asserts that a real in-scope asset is out of scope. */
  function fetchAllPages(path, pageSize) {
    var size = pageSize || 500;
    var out = [];
    function page(offset) {
      return api(path + '?limit=' + size + '&offset=' + offset).then(function (data) {
        var items = (data && data.items) || [];
        out = out.concat(items);
        var total = (data && data.total) || out.length;
        // The length guard is the real terminator: a server that ignores offset would otherwise
        // return the same page forever.
        if (out.length >= total || !items.length) return out;
        return page(offset + items.length);
      });
    }
    return page(0);
  }

  function uniqueSorted(values) {
    var seen = {}, out = [];
    values.forEach(function (v) {
      if (!v || Object.prototype.hasOwnProperty.call(seen, v)) return;
      seen[v] = 1;
      out.push(v);
    });
    return out.sort();
  }

  /* ============================================================== regression
     The queue over shipped fixes: which of our resolved reports is due a retest, and what the
     retest found. The list is DERIVED server-side from the Tracker's resolved rows, so there is
     nothing to sync here and no Refresh that talks to HackerOne - re-rendering the tab is the
     refresh, exactly like Targets.

     Two things drive the ordering and both are shown rather than implied: `moved_since_test`,
     meaning the program touched the report after we tested it, and `days_overdue`. A row that
     moved is the one to open first, so it carries a badge instead of relying on position. */

  /* Verdict -> the pill class it borrows. The same st-* scale the Tracker's states use, so a
     colour means the same thing on both tabs: green is a finished good outcome, red is something
     that needs acting on, grey is an outcome we chose not to pursue. `broken` is the one verdict
     in the vocabulary that is a FINDING rather than a closure, which is why it takes the danger
     colour that nothing else on this tab uses. */
  var REGRESSION_VERDICT_CLASS = {
    'pending': 'st-new',
    'holds': 'st-resolved',
    'broken': 'st-duplicate',
    'skipped': 'st-muted'
  };

  var REGRESSION_BUCKETS = [
    { key: 'due', label: 'Due' },
    { key: 'scheduled', label: 'Scheduled' },
    { key: 'broken', label: 'Fix broken' },
    { key: 'holds', label: 'Fix holds' },
    { key: 'skipped', label: 'Skipped' },
    { key: 'all', label: 'All' }
  ];

  var REGRESSION_VERDICT_HINT = {
    'holds': 'Retested, the fix stands.',
    'broken': 'The fix is incomplete or bypassable. Draft the lead.',
    'skipped': 'Deliberately not retesting this one.',
    'pending': 'Clear the verdict and put it back in the queue.'
  };

  function regressionVerdictPill(v) {
    var s = String(v || 'pending').toLowerCase();
    return el('span', {
      class: 'pill ' + (REGRESSION_VERDICT_CLASS[s] || 'st-unknown'),
      text: s, title: REGRESSION_VERDICT_HINT[s] || ''
    });
  }

  /* "34 days overdue" / "in 6 days". Reads as a sentence in the cell rather than as a signed
     number the reader has to work out the sign of. */
  function regressionDueCell(r) {
    var over = Number(r.days_overdue || 0);
    if (over > 0) {
      return el('span', {
        class: 'reg-over', text: over + 'd overdue',
        title: 'Due ' + (r.due_on || 'unknown')
      });
    }
    return el('span', {
      class: 'tiny dim', text: r.due_on || '-',
      title: r.snoozed ? 'Snoozed. Window would have made it ' + (r.due_derived || '-')
                       : 'Fix closed ' + (r.resolved_on || 'unknown')
    });
  }

  function regressionView(root, ctx) {
    var q = (ctx && ctx.q) || new URLSearchParams('');
    var params = {
      bucket: q.get('bucket') || 'due',
      program: q.get('program') || '',
      q: q.get('q') || ''
    };
    var openId = (ctx && ctx.id) || null;

    function go(patch) {
      var next = {};
      for (var k in params) next[k] = params[k];
      for (var p in patch) next[p] = patch[p];
      var qs = qsFrom(next);
      location.hash = '#/regression' + (openId ? '/' + openId : '') + (qs ? '?' + qs : '');
    }

    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Regression' }),
        el('p', {
          class: 'page-sub',
          text: 'The fixes shipped for your resolved reports, and what a retest found. ' +
                'Derived from the Tracker; makes no HackerOne request.'
        })
      ])
    ]));

    var filters = el('div', { class: 'filters card' });
    root.appendChild(filters);

    var host = el('div', {});
    root.appendChild(host);

    var paneHost = el('div', {});
    root.appendChild(paneHost);

    function load() {
      clear(host);
      append(host, loading('Reading the queue...'));
      api('/regression?' + qsFrom({
        bucket: params.bucket, program: params.program, q: params.q, limit: 500
      })).then(draw).catch(function (err) {
        clear(host);
        clear(filters);
        append(host, el('div', { class: 'pane-body' }, errorPanel(err, load)));
      });
    }

    function drawFilters(data) {
      clear(filters);

      /* Counts on the chips, because "Due 12" is the whole reason to look at this tab and a bare
         label makes you click each one to find out. They count the WHOLE queue, not the filtered
         page, so the numbers do not move as you filter. */
      var chips = el('div', { class: 'field grow' }, [
        el('span', { class: 'field-label', text: 'Show' }),
        el('div', { class: 'reg-chips' }, REGRESSION_BUCKETS.map(function (b) {
          var n = (data.counts || {})[b.key];
          return el('button', {
            class: 'btn chip-program' + (params.bucket === b.key ? ' on' : ''),
            type: 'button',
            'aria-pressed': params.bucket === b.key ? 'true' : 'false',
            onclick: function () { go({ bucket: b.key }); }
          }, [
            el('span', { text: b.label }),
            el('span', { class: 'chipcount', text: n === undefined ? '' : String(n) })
          ]);
        }))
      ]);
      filters.appendChild(chips);

      filters.appendChild(field('Program', selectEl(
        [{ value: '', label: 'All programs' }].concat((data.programs || []).map(function (p) {
          return { value: p, label: p };
        })), params.program, function (v) { go({ program: v }); })));

      var input = el('input', {
        type: 'search', value: params.q, placeholder: 'title, id, asset, note...',
        spellcheck: 'false'
      });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') go({ q: input.value });
      });
      filters.appendChild(el('label', { class: 'field grow' }, [
        el('span', { class: 'field-label', text: 'Search' }), input
      ]));

      filters.appendChild(el('div', { class: 'field' }, [
        el('span', { class: 'field-label', text: ' ' }),
        el('span', {
          class: 'tiny dim',
          text: 'Window ' + data.window_days + ' days',
          title: 'A fix reads as due this many days after the report closed. Change it in Settings.'
        })
      ]));
    }

    function draw(data) {
      drawFilters(data);
      clear(host);
      var items = data.items || [];

      if (!(data.counts || {}).all) {
        host.appendChild(empty('No resolved reports yet',
          'This queue is built from reports HackerOne has marked resolved. Run ' +
          '`python3 h1.py --sync` to pull them.'));
        return;
      }
      if (!items.length) {
        host.appendChild(empty('Nothing in this bucket',
          params.bucket === 'due'
            ? 'Every shipped fix has been looked at, or is still inside the ' +
              data.window_days + '-day window.'
            : 'Try another filter.'));
        return;
      }

      host.appendChild(dataTable([
        {
          key: 'h1_id', label: 'Report', cls: 'cell-mono nowrap tiny',
          render: function (r) { return '#' + r.h1_id; }
        },
        { key: 'program', label: 'Program', cls: 'cell-mono nowrap tiny' },
        {
          key: 'title', label: 'Title', cls: 'cell-title',
          render: function (r) {
            return el('span', {}, [
              el('span', { text: r.title || '' }),
              /* The badge, not the sort position, is what says "this one moved". A reader
                 scanning the list cannot see an ordering rule, only a mark. */
              r.moved_since_test
                ? el('span', {
                    class: 'rowtag rowtag-updated', text: 'moved',
                    title: 'The program touched this report after your retest, so the verdict ' +
                           'below no longer describes it.'
                  })
                : null
            ]);
          }
        },
        { key: 'asset', label: 'Asset', cls: 'cell-mono tiny dim' },
        {
          key: 'resolved_on', label: 'Fixed', cls: 'nowrap tiny',
          render: function (r) {
            return el('span', {
              text: r.resolved_on || '-',
              title: (r.days_since_fix === null || r.days_since_fix === undefined)
                ? '' : r.days_since_fix + ' days ago'
            });
          }
        },
        { key: 'due_on', label: 'Due', cls: 'nowrap', render: regressionDueCell },
        {
          key: 'verdict', label: 'Verdict', cls: 'nowrap',
          render: function (r) { return regressionVerdictPill(r.verdict); }
        },
        {
          key: 'bounty', label: 'Paid', cls: 'nowrap tiny',
          render: function (r) {
            /* What the original earned. Not decoration: it is the best available proxy for how
               much the program cared, and therefore for how carefully the fix was written. */
            return r.bounty ? fmtMoney(r.bounty, r.currency) : el('span', { class: 'muted', text: '-' });
          }
        }
      ], items, {
        cards: true,
        idKey: 'h1_id',
        selectedId: openId,
        rowClass: function (r) { return r.moved_since_test ? 'reg-moved' : ''; },
        onRow: function (r) {
          location.hash = '#/regression/' + encodeURIComponent(r.h1_id) + hashQuery();
        }
      }));

      host.appendChild(el('div', { class: 'tiny dim pane-body', text:
        items.length + ' of ' + data.counts.all + ' resolved reports  |  ' +
        data.counts.untested + ' never retested  |  ' + data.counts.broken + ' fixes broken' }));

      if (openId) drawPane();
    }

    /* ------------------------------------------------------------- detail --- */
    function drawPane() {
      clear(paneHost);
      var wrap = el('section', { class: 'card pane' });
      paneHost.appendChild(wrap);
      append(wrap, loading('Loading the report...'));

      api('/regression/' + encodeURIComponent(openId)).then(function (r) {
        clear(wrap);
        wrap.appendChild(el('div', { class: 'pane-head' }, [
          el('h2', { text: '#' + r.h1_id + '  ' + (r.title || '') }),
          el('div', { class: 'pane-actions' }, [
            copyButton(function () { return String(r.h1_id); }, 'Copy report ID'),
            /* Built here rather than through extLink, which returns a bare anchor: this one sits
               in a row of buttons and has to carry the button classes to match them. safeURL is
               still what decides the href is safe to follow. */
            safeURL(r.url) ? el('a', {
              class: 'btn btn-sm', href: safeURL(r.url),
              target: '_blank', rel: 'noopener noreferrer', text: 'Open on HackerOne'
            }) : null,
            el('a', {
              class: 'btn btn-sm', text: 'Open in Tracker',
              href: '#/reports?' + qsFrom({ q: r.h1_id, program: ALL_PROGRAMS })
            }),
            el('a', {
              class: 'btn btn-sm btn-quiet', text: 'Close',
              href: '#/regression' + hashQuery()
            })
          ].filter(Boolean))
        ]));

        var body = el('div', { class: 'pane-body' });
        wrap.appendChild(body);

        body.appendChild(metaGrid([
          ['Program', r.program || '-'],
          ['Asset', r.asset || '-', 'mono'],
          ['Weakness', r.weakness || r.cwe || '-'],
          ['Severity', r.severity || '-'],
          ['Fixed on', r.resolved_on || '-'],
          ['Due', (r.due_on || '-') + (r.snoozed ? '  (snoozed)' : '')],
          ['Retests', String(r.attempts || 0) +
                      (r.last_tested ? ', last ' + r.last_tested : ', never')],
          ['Bounty', r.bounty ? String(r.bounty) : '-']
        ]));

        if (r.moved_since_test) {
          body.appendChild(el('div', { class: 'alert alert-warn' }, [
            el('strong', { class: 'alert-title', text: 'Moved since your retest. ' }),
            'HackerOne recorded activity on this report after ' + r.last_tested +
            ', so the verdict below describes the report as it stood before that. Re-read the ' +
            'thread before trusting it.'
          ]));
        }

        body.appendChild(regressionActions(r));

        if (r.note) {
          body.appendChild(el('div', { class: 'pane-label', text: 'Retest note' }));
          body.appendChild(el('div', { class: 'md' }, el('p', { text: r.note })));
        }

        if (r.lead_path) {
          body.appendChild(el('div', { class: 'form-actions' }, [
            el('span', { class: 'tiny dim', text: 'Lead drafted: ' }),
            el('a', {
              class: 'btn btn-sm', text: 'Open in Files',
              href: '#/files?' + qsFrom({
                path: r.lead_path.replace(/\/[^/]*$/, ''), file: r.lead_path
              })
            })
          ]));
        }

        /* The original report, then the thread. In that order because the thread only makes sense
           once you have re-read what was claimed - and the thread is where the program said what
           it changed, which is the paragraph the retest is planned from. */
        if (r.body) {
          body.appendChild(el('div', { class: 'pane-label', text: 'The original report' }));
          body.appendChild(mdBlock(String(r.body)));
        }
        var thread = threadPanel({ thread: JSON.stringify(r.thread || []) });
        if (thread) body.appendChild(thread);
      }).catch(function (err) {
        clear(wrap);
        append(wrap, el('div', { class: 'pane-body' }, errorPanel(err, drawPane)));
      });
    }

    /* --------------------------------------------------------- the actions --- */
    function regressionActions(r) {
      var panel = el('div', { class: 'workpanel' });
      var busy = false;

      function post(path, payload, okMsg) {
        if (busy) return;
        busy = true;
        api('/regression/' + encodeURIComponent(r.h1_id) + path, {
          method: 'POST', body: payload
        }).then(function () {
          toast(okMsg, 'ok');
          busy = false;
          /* load() alone: it re-fetches the queue, and draw() re-opens the pane when a row is
             selected. Calling drawPane() here as well would fetch the detail twice per click. */
          load();
        }).catch(function (err) { busy = false; toastError(err); });
      }

      var note = el('textarea', {
        rows: 2, spellcheck: 'true',
        placeholder: 'What the retest actually did - the request you replayed and what came back.',
        value: r.note || ''
      });

      panel.appendChild(el('div', { class: 'pane-label', text: 'Record a retest' }));
      panel.appendChild(el('label', { class: 'field grow' }, [
        el('span', { class: 'field-label', text: 'Note' }), note
      ]));

      var verdicts = el('div', { class: 'form-actions' }, ['holds', 'broken', 'skipped'].map(
        function (v) {
          return el('button', {
            class: 'btn btn-sm' + (v === 'broken' ? ' btn-danger' : '') +
                   (r.verdict === v ? ' active' : ''),
            type: 'button', title: REGRESSION_VERDICT_HINT[v],
            text: v === 'holds' ? 'Fix holds' : (v === 'broken' ? 'Fix broken' : 'Skip'),
            onclick: function () {
              post('/verdict', { verdict: v, note: note.value },
                   'Recorded: ' + v);
            }
          });
        }));
      if (r.verdict !== 'pending') {
        verdicts.appendChild(el('button', {
          class: 'btn btn-sm btn-quiet', type: 'button', text: 'Clear verdict',
          title: REGRESSION_VERDICT_HINT.pending,
          onclick: function () {
            post('/verdict', { verdict: 'pending', note: note.value }, 'Verdict cleared');
          }
        }));
      }
      panel.appendChild(verdicts);

      /* Drafting the lead is offered ONLY on a broken fix, matching the server, and the button
         says why it is disabled rather than being absent - "how do I turn this into a lead" is
         the question this tab exists to answer. */
      var canDraft = r.verdict === 'broken' && !r.lead_path;
      var targetSel = selectEl([{ value: '', label: 'Pick a workspace...' }], '', null);
      api('/targets?limit=500').then(function (d) {
        clear(targetSel);
        targetSel.appendChild(el('option', { value: '', text: 'Pick a workspace...' }));
        ((d && d.items) || []).forEach(function (t) {
          targetSel.appendChild(el('option', { value: t.slug, text: t.slug }));
        });
      }).catch(function () { /* the draft button reports its own failure */ });

      panel.appendChild(el('div', { class: 'pane-label', text: 'Draft the bypass lead' }));
      panel.appendChild(el('div', { class: 'form-actions' }, [
        field('Workspace', targetSel),
        el('button', {
          class: 'btn btn-sm btn-primary', type: 'button', text: 'Draft lead',
          disabled: !canDraft,
          title: r.lead_path ? 'A lead has already been drafted for this fix.'
               : (canDraft ? 'Write a pre-filled lead into the workspace and index it.'
                           : 'Record a "Fix broken" verdict first - a lead states that a fix failed.'),
          onclick: function () {
            if (!targetSel.value) { toast('Pick a workspace first.', 'err'); return; }
            post('/lead', { target: targetSel.value }, 'Lead drafted into ' + targetSel.value);
          }
        })
      ]));

      /* Snooze is deliberately below the verdicts and quieter: it is the action you take when you
         are NOT going to look, and making it as prominent as recording a result would be an
         invitation to keep pushing the queue away. */
      panel.appendChild(el('div', { class: 'form-actions' }, [
        el('span', { class: 'tiny dim', text: 'Not yet: ' }),
        el('button', {
          class: 'btn btn-sm btn-quiet', type: 'button', text: '+7 days',
          onclick: function () { post('/snooze', { days: 7 }, 'Snoozed 7 days'); }
        }),
        el('button', {
          class: 'btn btn-sm btn-quiet', type: 'button', text: '+30 days',
          onclick: function () { post('/snooze', { days: 30 }, 'Snoozed 30 days'); }
        }),
        r.snoozed ? el('button', {
          class: 'btn btn-sm btn-quiet', type: 'button', text: 'Clear snooze',
          onclick: function () { post('/snooze', { clear: true }, 'Snooze cleared'); }
        }) : null
      ].filter(Boolean)));

      return panel;
    }

    load();
  }

  /* ================================================================= router */

  /* ============================================================ certificates */

  var CERT_PLATFORMS = [
    {
      id: 'windows', label: 'Windows (Chrome / Edge)', md: [
        '1. Rename the downloaded file to **`APPSLUG-ca.crt`** if it is not already.',
        '2. Double-click it, then choose **Install Certificate**.',
        '3. Store location: **Local Machine** (needs admin). Per-user also works but only for that user.',
        '4. Choose **Place all certificates in the following store** -> **Browse** ->',
        '   **Trusted Root Certification Authorities**. Do not leave it on "Automatically select".',
        '5. Finish, and accept the security warning.',
        '6. **Fully restart the browser** (close every window, not just the tab).',
        '',
        'Chrome and Edge both read the Windows store, so this covers both. Firefox does not - see its own tab.'
      ].join('\n')
    },
    {
      id: 'firefox', label: 'Firefox (any OS)', md: [
        'Firefox keeps its **own** trust store and ignores the operating system one, so it needs this even',
        'if you already imported the CA at the OS level.',
        '',
        '1. Open `about:preferences#privacy`.',
        '2. Scroll to **Certificates** -> **View Certificates**.',
        '3. **Authorities** tab -> **Import**.',
        '4. Select the downloaded `.crt` / `.pem` file.',
        '5. Tick **Trust this CA to identify websites**, then OK.',
        '6. Reload the page.'
      ].join('\n')
    },
    {
      id: 'macos', label: 'macOS (Safari / Chrome)', md: [
        '1. Double-click the downloaded file to open **Keychain Access**.',
        '2. Add it to the **System** keychain (login also works, System is machine-wide).',
        '3. Find **"APPNAME Local CA"** in the list and double-click it.',
        '4. Expand **Trust**, and set *When using this certificate* to **Always Trust**.',
        '5. Close the window and authenticate to save.',
        '6. Restart the browser.',
        '',
        'Or from a terminal:',
        '',
        '```',
        'sudo security add-trusted-cert -d -r trustRoot \\',
        '  -k /Library/Keychains/System.keychain ~/Downloads/APPSLUG-ca.crt',
        '```'
      ].join('\n')
    },
    {
      id: 'linux', label: 'Linux', md: [
        'Debian / Ubuntu:',
        '',
        '```',
        'sudo cp APPSLUG-ca.crt /usr/local/share/ca-certificates/APPSLUG-ca.crt',
        'sudo update-ca-certificates',
        '```',
        '',
        'Fedora / RHEL:',
        '',
        '```',
        'sudo cp APPSLUG-ca.crt /etc/pki/ca-trust/source/anchors/',
        'sudo update-ca-trust',
        '```',
        '',
        'That covers `curl` and anything using the system store. **Firefox and Chrome on Linux still',
        'need their own import** - see the Firefox tab; Chrome uses the NSS database:',
        '',
        '```',
        'certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "APPNAME Local CA" -i APPSLUG-ca.crt',
        '```'
      ].join('\n')
    }
  ];

  function certRow(label, value, mono) {
    if (!value) return null;
    return el('div', { class: 'certrow' }, [
      el('span', { class: 'certrow-label', text: label }),
      el('span', { class: 'certrow-value' + (mono ? ' mono' : ''), text: String(value) })
    ]);
  }

  function certCard(title, info, extra) {
    if (!info || !info.exists) {
      return el('section', { class: 'card pane' }, [
        el('div', { class: 'pane-head' }, el('h2', { text: title })),
        el('div', { class: 'pane-body' },
          el('div', { class: 'alert alert-warn', text: 'Not present on disk.' }))
      ]);
    }
    var rows = [
      certRow('Subject', info.subject, true),
      certRow('Issuer', info.issuer, true),
      certRow('Valid from', info.not_before),
      certRow('Valid until', info.not_after),
      certRow('SAN', info.san, true),
      certRow('SHA-256', info.sha256, true),
      certRow('Path', info.path, true)
    ].filter(Boolean);

    var actions = [];
    if (info.sha256) {
      actions.push(copyButton(function () { return info.sha256; }, 'Copy fingerprint'));
    }
    if (extra) actions = actions.concat(extra);

    return el('section', { class: 'card pane' }, [
      el('div', { class: 'pane-head' }, [
        el('h2', { text: title }),
        el('div', { class: 'pane-actions' }, actions)
      ]),
      el('div', { class: 'pane-body' }, el('div', { class: 'certgrid' }, rows))
    ]);
  }

  function certificatesView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Certificates' })
      ])
    ]));

    var host = el('div', {});
    root.appendChild(host);
    append(host, loading('Reading TLS material…'));

    api('/certs').then(function (d) {
      clear(host);
      var name = d.app_name || APP_NAME;
      var slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

      /* --- status ------------------------------------------------------- */
      if (d.ca_available) {
        append(host, el('div', { class: 'alert alert-ok' }, [
          el('strong', { class: 'alert-title', text: 'A local CA is in use.' }),
          el('div', {
            text: 'Import the CA certificate once and every certificate this server issues from ' +
                  'now on is trusted automatically, including after a re-issue. You will not have ' +
                  'to repeat this.'
          })
        ]));
      } else {
        append(host, el('div', { class: 'alert alert-warn' }, [
          el('strong', { class: 'alert-title', text: 'No local CA - the certificate is self-signed.' }),
          el('div', {
            text: 'A bare self-signed certificate has to be re-trusted every time it is ' +
                  'regenerated. Run  python3 server.py --gencert  on the server to create a local ' +
                  'CA and re-issue, then reload this page.'
          })
        ]));
      }

      /* --- step 1: download --------------------------------------------- */
      var dlBtn = el('a', {
        class: 'btn btn-primary',
        text: 'Download CA certificate',
        href: API + '/certs/ca',
        download: slug + '-ca.crt'
      });
      append(host, el('section', { class: 'card pane' }, [
        el('div', { class: 'pane-head' }, [
          el('h2', { text: 'Step 1 — download the CA' }),
          el('div', { class: 'pane-actions' }, d.ca_available ? [dlBtn] : [])
        ]),
        el('div', { class: 'pane-body' },
          el('div', {
            html: renderMarkdown(
              d.ca_available
                ? ('Saves as `' + slug + '-ca.crt`. This is a **public certificate** - it contains no ' +
                   'private key, and it is safe to copy to any machine you want to trust this server.\n\n' +
                   'You can also fetch it from a terminal:\n\n```\nscp dev@' + (d.bind_host || '') +
                   ':' + ((d.ca && d.ca.path) || '') + ' .\n```')
                : 'Nothing to download until a local CA exists.'
            )
          }))
      ]));

      /* --- step 2: verify ----------------------------------------------- */
      if (d.ca_available && d.ca && d.ca.sha256) {
        append(host, el('section', { class: 'card pane' }, [
          el('div', { class: 'pane-head' }, [
            el('h2', { text: 'Step 2 — verify the fingerprint' }),
            el('div', { class: 'pane-actions' },
              [copyButton(function () { return d.ca.sha256; }, 'Copy fingerprint')])
          ]),
          el('div', { class: 'pane-body' }, [
            el('div', {
              html: renderMarkdown(
                'Check this **before** trusting it. You are about to tell your machine to trust ' +
                'anything this CA signs, so confirm the file you downloaded is the file this ' +
                'server actually holds.')
            }),
            el('code', { class: 'tv', text: d.ca.sha256 }),
            el('div', {
              html: renderMarkdown(
                '**Windows**\n\n```\ncertutil -hashfile ' + slug + '-ca.crt SHA256\n```\n\n' +
                '**macOS / Linux**\n\n```\nopenssl x509 -in ' + slug +
                '-ca.crt -noout -fingerprint -sha256\n```')
            })
          ])
        ]));
      }

      /* --- step 3: import, per platform --------------------------------- */
      var body = el('div', { class: 'pane-body' });
      var tabs = el('div', { class: 'tabrow' });
      var current = state.certPlatform || 'windows';

      function drawPlatform() {
        clear(tabs);
        CERT_PLATFORMS.forEach(function (p) {
          var b = el('button', {
            class: 'btn btn-sm' + (p.id === current ? ' active' : ''),
            type: 'button', text: p.label
          });
          b.addEventListener('click', function () {
            current = p.id;
            state.certPlatform = p.id;
            drawPlatform();
          });
          tabs.appendChild(b);
        });
        clear(body);
        var chosen = null;
        CERT_PLATFORMS.forEach(function (p) { if (p.id === current) chosen = p; });
        if (chosen) {
          var md = chosen.md.split('APPSLUG').join(slug).split('APPNAME').join(name);
          body.appendChild(el('div', { html: renderMarkdown(md) }));
        }
      }
      drawPlatform();

      append(host, el('section', { class: 'card pane' }, [
        el('div', { class: 'pane-head' }, [
          el('h2', { text: 'Step 3 — import it' }),
          el('div', { class: 'pane-actions' }, [tabs])
        ]),
        body
      ]));

      /* --- details ------------------------------------------------------ */
      append(host, certCard('Server certificate', d.server));
      if (d.ca_available) {
        append(host, certCard('CA certificate', d.ca, [
          el('a', { class: 'btn btn-sm', text: 'Download', href: API + '/certs/ca',
                    download: slug + '-ca.crt' })
        ]));
      }

      /* --- gotchas ------------------------------------------------------ */
      append(host, el('section', { class: 'card pane' }, [
        el('div', { class: 'pane-head' }, el('h2', { text: 'Things that will still warn you' })),
        el('div', { class: 'pane-body' }, el('div', {
          html: renderMarkdown(
            '- **Reach it by the exact address in the SAN.** The certificate covers `' +
            ((d.server && d.server.san) || 'the configured address') + '`. Browsing to a hostname ' +
            'or a different interface will still warn, even with the CA trusted.\n' +
            '- **Firefox needs its own import** even when the OS store already trusts the CA.\n' +
            '- **Restart the browser fully** after importing. A reload is not always enough.\n' +
            '- **If you change `bind_host`**, re-run `python3 server.py --gencert` on the server. ' +
            'It reuses the existing CA, so no re-import is needed - only the server certificate ' +
            'is re-issued.\n' +
            '- The private keys (`key.pem`, `ca.key`) are never served by this application and are ' +
            'blocked from the file browser. Only the CA certificate is downloadable.')
        }))
      ]));
    }).catch(function (err) {
      clear(host);
      append(host, errorPanel(err, function () { render(); }));
    });
  }

  /* ============================================================== audit log */

  /* Audit Log is the "what has this system been doing" tab. The mutation trail is live today;
     the remaining panels are deliberate skeletons - each states plainly whether it is wired to
     real data or waiting on a backend endpoint, so nothing here reads as working when it is not. */

  /* An audit detail is MACHINE output - a JSON blob from common.audit(), a filesystem path, a
     comma list of edited fields, an error string. It is never prose, so nothing in it may be
     re-read as markup: a path with underscores would come out italicised and a value holding an
     asterisk would swallow the rest of the line. Every VALUE therefore leaves here inside a code
     span or a fence and only the keys of a decoded JSON object are allowed to be markdown.
     renderMarkdown() escapes the lot on the way in regardless, so this is a legibility guard and
     not the XSS boundary. */

  /* A backtick run one longer than the longest already inside `text`, never shorter than `min`.
     Without this a detail containing a backtick would close the span it was put in. */
  function mdFence(text, min) {
    var longest = 0;
    (String(text === null || text === undefined ? '' : text).match(/`+/g) || [])
      .forEach(function (run) { if (run.length > longest) longest = run.length; });
    var n = Math.max(min || 1, longest + 1);
    return new Array(n + 1).join('`');
  }

  function mdCode(s) {
    var text = String(s === null || s === undefined ? '' : s);
    /* An empty span (``) is not code at all - renderInline needs a character between the
       fences - so say so in words rather than emitting two literal backticks. */
    if (!text) return '(empty)';
    /* renderInline strips one leading and one trailing space back off, which is exactly the
       padding needed when the text itself starts or ends in a backtick or a space. */
    var edge = /^[ `]|[ `]$/.test(text) ? ' ' : '';
    var f = mdFence(text, 1);
    return f + edge + text + edge + f;
  }

  function auditValueMd(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (typeof v === 'object') {
      try { return mdCode(JSON.stringify(v)); } catch (e) { return mdCode(String(v)); }
    }
    return mdCode(v);
  }

  /* Markdown source for one detail cell. Returns '' for an absent detail so the caller can
     decide what an empty cell looks like. */
  function auditDetailMd(detail) {
    var raw = String(detail === null || detail === undefined ? '' : detail);
    if (!raw.trim()) return '';

    var parsed = null;
    try { parsed = JSON.parse(raw); } catch (e) { parsed = null; }
    /* Only a CONTAINER is decoded. A bare "300" is valid JSON too, and reading it as a number
       would say nothing the raw string does not - the typeof test is what leaves it alone. */
    if (parsed && typeof parsed === 'object') {
      var lines = [];
      if (Array.isArray(parsed)) {
        parsed.forEach(function (v) { lines.push('- ' + auditValueMd(v)); });
      } else {
        Object.keys(parsed).forEach(function (k) {
          /* The key is the ONLY part rendered as markdown, so drop the characters that would
             end the bold run early or open a block of their own. */
          lines.push('**' + String(k).replace(/[*`|\\\n]/g, ' ') + ':** ' + auditValueMd(parsed[k]));
        });
      }
      if (lines.length) return lines.join('\n');
    }
    /* Multi-line output has a shape worth keeping, and a fence is the only construct that
       keeps it. Single-line output is a path, an id or a short message: one code span. */
    if (raw.indexOf('\n') >= 0) {
      var f = mdFence(raw, 3);
      return f + '\n' + raw + '\n' + f;
    }
    return mdCode(raw);
  }

  /* "leads #12", or '' when the row names no entity - a login and a reindex both do. */
  function auditEntityLabel(row) {
    var r = row || {};
    if (!r.entity) return '';
    var id = r.entity_id;
    return String(r.entity) + (id === null || id === undefined || id === '' ? '' : ' #' + id);
  }

  /* The tab that entity opens, or null when there is none. Audit rows name entities the UI has
     no list for ("file", "upload", "hackerone"), so a missing tab is normal, not an error. */
  function auditEntityHref(row) {
    var r = row || {};
    var id = r.entity_id;
    if (!r.entity || id === null || id === undefined || id === '') return null;
    var known = ENTITIES[r.entity] || ENTITIES[r.entity + 's'];
    if (!known) return null;
    return '#/' + known.entity + '/' + encodeURIComponent(id);
  }

  function auditEntityNode(row) {
    var label = auditEntityLabel(row);
    if (!label) return null;
    var href = auditEntityHref(row);
    return href ? el('a', { href: href, text: label }) : el('span', { text: label });
  }

  /* The columns the audit table has had since schema.sql was written. Anything else on a row
     came from a later migration, and auditMetaPairs shows it rather than dropping it: /api/audit
     is a SELECT *, so a new column reaches the pane without a change here. */
  /* Server-side `source` is a slug so it can be grouped and filtered; this is the reading of it.
     The fallback repeats common.audit_source's derivation rather than printing a blank, so a row
     written by something that predates the column still says where it came from. */
  var AUDIT_SOURCE_LABELS = {
    'web': 'Web UI', 'cron': 'Cron', 'cli': 'CLI', 'h1-api': 'H1 API'
  };

  function auditSourceLabel(r) {
    var s = String((r && r.source) || '').toLowerCase().trim();
    if (!s) {
      var actor = String((r && r.actor) || '').toLowerCase().trim();
      var remote = String((r && r.remote) || '').trim();
      /* A row with no source, no actor and no client address is not a row that came from the
         CLI - it is a row with nothing to derive from, and answering anyway would be inventing.
         Every real row has a source written by common.audit, so this only guards synthetic ones. */
      if (!actor && !remote) return '';
      s = (actor === 'cli' || actor === 'cron') ? actor : (remote ? 'web' : 'cli');
    }
    return AUDIT_SOURCE_LABELS[s] || s;
  }

  /* Kept on ONE line: both test suites extract this declaration with a single-line regex, the
     same constraint LEAD_STATUSES carries. */
  var AUDIT_META_KEYS = ['id', 'ts', 'actor', 'action', 'entity', 'entity_id', 'detail', 'remote', 'source'];

  /* Everything an audit row carries, in reading order, as [label, text] pairs. Absent fields are
     dropped rather than printed empty: a login has no entity, no detail and no entity id, and
     three rows reading "none" would be three claims where the truth is silence. Pure, so the
     pane's contents can be asserted without a DOM - see tests/test_render.js. */
  function auditMetaPairs(row) {
    var r = row || {};
    var pairs = [];
    if (r.id !== null && r.id !== undefined && r.id !== '') pairs.push(['Entry', '#' + r.id]);
    if (r.ts) pairs.push(['When', fmtTime(r.ts)]);
    if (r.actor) pairs.push(['Actor', String(r.actor)]);
    if (r.action) pairs.push(['Action', String(r.action)]);
    var ent = auditEntityLabel(r);
    if (ent) pairs.push(['Entity', ent]);
    var from = auditSourceLabel(r);
    if (from) pairs.push(['From', from]);
    if (r.remote) pairs.push(['Client', String(r.remote)]);
    Object.keys(r).forEach(function (k) {
      if (AUDIT_META_KEYS.indexOf(k) >= 0) return;
      var v = r[k];
      if (v === null || v === undefined || v === '') return;
      pairs.push([prettyKey(k), typeof v === 'object' ? JSON.stringify(v) : String(v)]);
    });
    return pairs;
  }

  function auditFilterBar(current, onChange) {
    var wrap = el('div', { class: 'tabrow' });
    [
      { id: '', label: 'All' },
      { id: 'login', label: 'Auth' },
      { id: 'update', label: 'Edits' },
      { id: 'upload', label: 'Uploads' },
      { id: 'advisory_sync', label: 'Advisory sync' },
      { id: 'reindex', label: 'Reindex' },
      { id: 'token', label: 'Tokens' }
    ].forEach(function (f) {
      var b = el('button', {
        class: 'btn btn-sm' + (f.id === current ? ' active' : ''),
        type: 'button', text: f.label
      });
      b.addEventListener('click', function () { onChange(f.id); });
      wrap.appendChild(b);
    });
    return wrap;
  }

  /* One audit entry in full. Laid out like the Leads pane - same .split, same .pane-head and
     .pane-body chrome, same metagrid - so the two tabs read as one app.

     Read-only BY CONSTRUCTION: the audit table is append-only and there is no endpoint that
     writes to it, so this pane offers copy and close and nothing else. Anything that looked like
     an edit control here would be a lie about what the log is. */
  function auditPane(row, onClose) {
    var wrap = el('section', { class: 'pane card' });
    var actions = [];
    /* The detail is what gets pasted into a note or a search; the raw string is copied, not the
       rendering of it. */
    if (row.detail) {
      actions.push(copyButton(function () { return String(row.detail); }, 'Copy detail'));
    }
    actions.push(el('button', {
      class: 'btn btn-sm btn-quiet', type: 'button', text: 'Close', onclick: onClose
    }));
    wrap.appendChild(el('div', { class: 'pane-head' }, [
      el('h2', { text: row.action || ('Entry #' + row.id) }),
      el('div', { class: 'pane-actions' }, actions)
    ]));

    var body = el('div', { class: 'pane-body' });
    /* The linked entity REPLACES its own text pair rather than being appended after it, so the
       pane shows one Entity row whether or not that entity has a tab to open. */
    var entNode = auditEntityNode(row);
    var grid = metaGrid(auditMetaPairs(row).map(function (p) {
      if (p[0] === 'Entity' && entNode) return ['Entity', entNode];
      return [p[0], p[1], (p[0] === 'Client' || p[0] === 'Entry') ? 'mono' : null];
    }));
    if (grid) body.appendChild(grid);

    var md = auditDetailMd(row.detail);
    if (md) {
      body.appendChild(el('div', { class: 'pane-label', text: 'Detail' }));
      body.appendChild(mdBlock(md));
    }
    wrap.appendChild(body);
    return wrap;
  }

  function auditTrailCard() {
    /* Selection is component state rather than a route. Clicking a row must not re-run the whole
       tab: the trail is the tallest table in the app now that Detail wraps, and a hash change
       would reload the advisory card and throw the reader back to the top of the page, away from
       the row just clicked. Nothing here is worth deep-linking either - the log is append-only
       and an entry is read once. */
    var split = el('div', { class: 'split no-detail' });
    var listCard = el('section', { class: 'pane card' });
    split.appendChild(listCard);

    var rows = [];
    var selected = null;
    var paneNode = null;
    var filter = state.auditFilter || '';

    /* Client-side: all 300 rows are already here, so switching filter is a redraw rather than a
       round trip, and the open pane survives it. */
    function shown() {
      if (!filter) return rows;
      return rows.filter(function (r) { return String(r.action || '').indexOf(filter) >= 0; });
    }

    function close() {
      selected = null;
      drawList();
      drawPane();
    }

    function drawPane() {
      if (paneNode) { split.removeChild(paneNode); paneNode = null; }
      if (selected) {
        paneNode = auditPane(selected, close);
        split.appendChild(paneNode);
      }
      split.className = 'split' + (selected ? '' : ' no-detail');
      /* Selection here is component state, not a route, so render() never runs and cannot do
         this. Same reason as there: on a phone the pane REPLACES the list rather than sitting
         beside it, so opening or closing one has to start at the top of the new screen. */
      if (isNarrow()) window.scrollTo(0, 0);
    }

    function drawList() {
      var items = shown();
      clear(listCard);
      listCard.appendChild(el('div', { class: 'pane-head' }, [
        el('h2', { text: 'Mutation trail' }),
        el('div', { class: 'pane-actions tiny dim',
                    text: items.length + (items.length === 1 ? ' entry' : ' entries') })
      ]));
      listCard.appendChild(el('div', { class: 'card-tools audit-tools' }, [
        auditFilterBar(filter, function (f) {
          filter = f;
          state.auditFilter = f;
          drawList();
        }),
        el('div', { class: 'tiny dim',
                    text: 'Every login, edit, upload, sync and token action. ' +
                          'Click a row for the whole entry.' })
      ]));

      if (!items.length) {
        listCard.appendChild(empty(filter ? 'No entries matching that filter' : 'No audit entries yet'));
        return;
      }

      listCard.appendChild(dataTable([
        { key: 'ts', label: 'When', cls: 'nowrap tiny dim',
          render: function (r) { return fmtTime(r.ts); } },
        { key: 'actor', label: 'Actor', cls: 'nowrap',
          render: function (r) { return r.actor || el('span', { class: 'muted', text: 'anon' }); } },
        /* Which channel the action arrived through. Derived where it was not recorded, and
           backfilled across the whole table, so this column is never blank - see
           common.audit_source. An empty origin column is one nobody filters on. */
        { key: 'source', label: 'From', cls: 'nowrap tiny',
          render: function (r) { return tag(auditSourceLabel(r)); } },
        { key: 'action', label: 'Action', cls: 'nowrap',
          render: function (r) { return tag(r.action); } },
        { key: 'entity', label: 'Entity', cls: 'nowrap',
          render: function (r) {
            return auditEntityNode(r) || el('span', { class: 'muted', text: '—' });
          } },
        /* The whole detail, wrapped and rendered, rather than one ellipsised line that only a
           hover could finish. Taller rows are the price of reading the trail at a glance; the
           bold keys a decoded JSON blob renders are what keep the cell scannable. */
        { key: 'detail', label: 'Detail', cls: 'cell-detail',
          render: function (r) {
            /* Gated on the RENDERED source, not on r.detail: a detail of pure whitespace is
               absent as far as a reader is concerned, and mdBlock would print "No content."
               into the cell rather than the placeholder every other empty cell uses. */
            var md = auditDetailMd(r.detail);
            return md ? mdBlock(md, 'md-cell') : el('span', { class: 'muted', text: '—' });
          } },
        { key: 'remote', label: 'Client', cls: 'nowrap tiny dim cell-mono',
          render: function (r) { return r.remote || '—'; } }
      ], items, {
        cards: true,
        onRow: function (r) { selected = r; drawList(); drawPane(); },
        selectedId: selected ? selected.id : null
      }));
    }

    function load() {
      clear(listCard);
      append(listCard, loading('Loading audit trail…'));
      api('/audit?limit=300').then(function (data) {
        rows = (data && data.items) || [];
        drawList();
        drawPane();
      }).catch(function (err) {
        clear(listCard);
        append(listCard, el('div', { class: 'pane-body' }, errorPanel(err, load)));
      });
    }

    load();
    return split;
  }

  function advisoryFeedCard() {
    var card = el('section', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('div', { class: 'card-title', text: 'Advisory feed' }),
        el('div', { class: 'card-sub', text: 'Cron polls the ExampleVendor RSS feed every 30 minutes.' })
      ])
    ]);
    var host = el('div', {});
    card.appendChild(host);
    append(host, loading('Checking feed…'));

    api('/advisories/status').then(function (d) {
      clear(host);
      var rows = [
        ['Advisories held', String(d.count)],
        ['With a CVE', String(d.with_cve)],
        ['Newest published', d.newest_published ? fmtTime(d.newest_published) : '—'],
        ['Last fetch', d.last_fetched ? fmtTime(d.last_fetched) : 'never'],
        ['Last manual sync', d.last_sync ? fmtTime(d.last_sync.ts) : '—']
      ];
      host.appendChild(metaGrid(rows));

      /* A feed that has not been fetched in over a day means cron is not firing. */
      if (d.last_fetched) {
        var age = (Date.now() - parseServerTime(d.last_fetched)) / 3600000;
        if (age > 24) {
          host.appendChild(el('div', { class: 'alert alert-warn' }, [
            el('strong', { class: 'alert-title', text: 'Feed looks stale.' }),
            el('div', { text: 'Last fetch was ' + Math.round(age) + ' hours ago. Check the cron ' +
                              'job: crontab -l, and your home/quarry/advisory-cron.log' })
          ]));
        }
      }

      var syncBtn = el('button', { class: 'btn btn-sm', type: 'button', text: 'Sync now' });
      syncBtn.addEventListener('click', function () {
        syncBtn.disabled = true;
        syncBtn.textContent = 'Syncing…';
        api('/advisories/sync', { method: 'POST', body: {} }).then(function (res) {
          toast('Advisories: ' + res['new'] + ' new, ' + res.updated + ' updated', 'ok');
          render();
        }).catch(function (err) {
          toastError(err);
          syncBtn.disabled = false;
          syncBtn.textContent = 'Sync now';
        });
      });
      host.appendChild(el('div', { class: 'form-actions' }, [
        syncBtn,
        el('a', { class: 'btn btn-sm btn-quiet', href: '#/advisories', text: 'View advisories' })
      ]));
    }).catch(function (err) {
      clear(host);
      append(host, errorPanel(err));
    });
    return card;
  }

  function skeletonCard(title, sub, lines, note) {
    var card = el('section', { class: 'card card-skeleton' }, [
      el('div', { class: 'card-head' }, [
        el('div', { class: 'card-title' }, [
          el('span', { text: title }),
          el('span', { class: 'pill pill-planned', text: 'planned' })
        ]),
        el('div', { class: 'card-sub', text: sub })
      ])
    ]);
    var ul = el('ul', { class: 'skeleton-list' });
    lines.forEach(function (l) { ul.appendChild(el('li', { text: l })); });
    card.appendChild(ul);
    if (note) card.appendChild(el('div', { class: 'card-note tiny dim', text: note }));
    return card;
  }

  function auditView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Audit log' })
      ])
    ]));

    var host = el('div', {});
    root.appendChild(host);

    host.appendChild(auditTrailCard());

    host.appendChild(el('div', { class: 'cards2' }, [
      advisoryFeedCard(),
      skeletonCard(
        'Scheduled job health',
        'Whether the cron jobs ran, and whether they failed.',
        [
          'Last run, exit status and duration per job',
          'Consecutive-failure count with an alert threshold',
          'Tail of advisory-cron.log surfaced inline',
          'Missed-window detection (job did not fire at all)'
        ],
        'Needs a job_runs table plus a wrapper that records start/exit. The advisory feed card ' +
        'above already infers staleness from last-fetch time as an interim signal.')
    ]));

    host.appendChild(el('div', { class: 'cards2' }, [
      skeletonCard(
        'New advisories since last visit',
        'Upstream changes worth looking at, rather than the full list.',
        [
          'Advisories first seen since your last session',
          'Filtered to products we actually hunt',
          'Highlight where an advisory touches an existing lead',
          'Flag any advisory whose CVE matches a submitted report'
        ],
        'Data is already present - advisories.fetched_at and indexed_at give first-seen. Needs a ' +
        'last-seen marker per user and an endpoint to diff against it.'),
      skeletonCard(
        'HackerOne report activity',
        'State changes on submitted reports, pulled from the H1 API.',
        [
          'Report state transitions (new -> triaged -> resolved)',
          'New bounty awards and totals',
          'Programs answered or went quiet',
          'Reports with no program activity for N days'
        ],
        'Blocked on the H1 integration. The API token authenticates and /v1/hackers/me/reports ' +
        'returns full report data; ingestion into the reports table is the next piece of work.')
    ]));

    host.appendChild(el('div', { class: 'cards2' }, [
      skeletonCard(
        'Index integrity',
        'Whether the database still matches the files on disk.',
        [
          'Files changed on disk but not re-indexed',
          'Index rows whose backing file has disappeared',
          'Notes that fail the header convention (status parses as unknown)',
          'Tracker rows with no matching report file, and vice versa'
        ],
        'The third item is live data today: 46 of 64 leads parse as unknown status. Needs a ' +
        'consistency-check endpoint that walks the workspaces and diffs against the index.'),
      skeletonCard(
        'Access and security events',
        'Who reached this instance, and what was refused.',
        [
          'Failed logins and rate-limit trips, grouped by source address',
          'Requests rejected by the client IP allowlist',
          'File-browser reads that hit the deny-list',
          'API token creation, use and revocation'
        ],
        'Logins and token actions are already recorded and visible in the trail above. Allowlist ' +
        'and deny-list refusals are returned to the client but not yet written to the audit table.')
    ]));
  }

  /* =========================================================== integrations
     Credential management for the outbound integrations. One card per provider, all built by a
     factory in INTEGRATIONS below - adding a second provider is a new entry in that array plus
     its own card function, with nothing else to restructure.

     The HackerOne token is write-only by design: PUT verifies it against the live API before
     storing it, it lands in secrets.json at mode 0600, and no endpoint can read it back. The
     status payload carries only a mask and a sha256 fingerprint. */

  function integrationRow(label, value, cls) {
    return [label, value, cls];
  }

  function hackeroneCard() {
    var card = el('section', { class: 'card integration' });
    var titleRow = el('div', { class: 'card-title' }, [el('span', { text: 'HackerOne' })]);
    var badgeHost = el('span', { class: 'int-badge' });
    titleRow.appendChild(badgeHost);
    card.appendChild(titleRow);

    var body = el('div', { class: 'pane-body' });
    card.appendChild(body);

    var statusHost = el('div', { class: 'int-status' });
    var actionsHost = el('div', { class: 'form-actions' });
    var outHost = el('div', { class: 'int-out' });
    var formHost = el('div', {});
    append(body, [statusHost, actionsHost, outHost, formHost]);

    var busy = false;

    /* ---------------------------------------------------------- status --- */
    function drawStatus(d) {
      d = d || {};
      clear(statusHost);
      clear(badgeHost);
      badgeHost.appendChild(d.configured
        ? el('span', { class: 'pill st-resolved', text: 'configured' })
        : el('span', { class: 'pill st-new', text: 'not configured' }));

      statusHost.appendChild(metaGrid([
        integrationRow('Configured', d.configured ? 'yes' : 'no'),
        integrationRow('Username', d.username || '—'),
        integrationRow('Token', d.masked_token || '—', 'mono'),
        integrationRow('Fingerprint', d.fingerprint || '—', 'mono'),
        /* Not a sync filter any more: the sync stores every program. This is the program reports
           are submitted to, and the one the Tracker shows by default. */
        integrationRow('Reports from H1',
          (d.reports_from_h1 === null || d.reports_from_h1 === undefined) ? '—' : String(d.reports_from_h1)),
        integrationRow('Last sync', d.last_sync ? fmtTime(d.last_sync) : 'never')
      ]) || el('div', { class: 'empty', text: 'No status returned.' }));

      if (d.reports_from_h1) {
        statusHost.appendChild(el('div', { class: 'form-actions' },
          /* The count above is every program's reports, so the link has to open every program. */
          el('a', { class: 'btn btn-sm btn-quiet',
                    href: '#/reports?' + qsFrom({ program: ALL_PROGRAMS }),
                    text: 'Open the Tracker' })));
      }

      drawActions(!!d.configured);
      drawForm(d);
    }

    function loadStatus() {
      clear(statusHost);
      append(statusHost, loading('Reading credential state…'));
      api('/integrations/hackerone')
        .then(drawStatus)
        .catch(function (err) {
          clear(statusHost);
          append(statusHost, errorPanel(err, loadStatus));
        });
    }

    /* --------------------------------------------------------- actions --- */
    function drawActions(configured) {
      clear(actionsHost);

      var testBtn = el('button', { class: 'btn', type: 'button', text: 'Test connection' });
      var syncBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Sync now' });
      if (!configured) { testBtn.disabled = true; syncBtn.disabled = true; }

      testBtn.addEventListener('click', function () {
        if (busy) return;
        busy = true;
        testBtn.disabled = true;
        testBtn.textContent = 'Testing…';
        clear(outHost);
        api('/integrations/hackerone/test', { method: 'POST', body: {} })
          .then(function (res) {
            busy = false;
            testBtn.disabled = false;
            testBtn.textContent = 'Test connection';
            var n = (res && res.sample_count !== undefined) ? res.sample_count : '?';
            toast('HackerOne credential works (' + n + ' report' + (n === 1 ? '' : 's') + ' in the probe page).', 'ok');
            append(outHost, el('div', { class: 'alert alert-ok' },
              'Authenticated. The probe page returned ' + n + ' report' + (n === 1 ? '' : 's') + '.'));
          })
          .catch(function (err) {
            busy = false;
            testBtn.disabled = false;
            testBtn.textContent = 'Test connection';
            toastError(err);
            append(outHost, errorPanel(err));
          });
      });

      syncBtn.addEventListener('click', function () {
        if (busy) return;
        busy = true;
        syncBtn.disabled = true;
        testBtn.disabled = true;
        syncBtn.textContent = 'Syncing…';
        clear(outHost);
        append(outHost, el('div', { class: 'int-progress' }, [
          loading('Two-phase sync running. The list endpoint carries no bounty or CVSS, so every ' +
                  'report is fetched again individually — a full run takes about a minute. ' +
                  'Leave this tab open.')
        ]));

        api('/integrations/hackerone/sync', { method: 'POST', body: {} })
          .then(function (res) {
            busy = false;
            syncBtn.disabled = false;
            testBtn.disabled = false;
            syncBtn.textContent = 'Sync now';
            res = res || {};
            var errs = Array.isArray(res.detail_errors) ? res.detail_errors.length : (res.detail_errors || 0);
            toast('H1 sync: ' + (res.fetched || 0) + ' fetched, ' + (res['new'] || 0) + ' new, ' +
                  (res.updated || 0) + ' updated' + (errs ? ', ' + errs + ' errors' : '') + '.',
                  errs ? 'err' : 'ok');
            clear(outHost);
            append(outHost, el('div', { class: 'alert ' + (errs ? 'alert-warn' : 'alert-ok') },
              'Sync finished in ' + Math.round((res.elapsed_ms || 0) / 100) / 10 + 's' +
              (res.program ? ' for program "' + res.program + '"' : '') + '.'));
            append(outHost, metaGrid([
              integrationRow('Fetched', String(res.fetched || 0)),
              integrationRow('New', String(res['new'] || 0)),
              integrationRow('Updated', String(res.updated || 0)),
              integrationRow('Unchanged', String(res.unchanged || 0)),
              integrationRow('Enriched', String(res.enriched || 0)),
              integrationRow('Body files written', String(res.written || 0)),
              integrationRow('Detail errors', String(errs)),
              integrationRow('Elapsed', ((res.elapsed_ms || 0) + ' ms'))
            ]));
            loadStatus();
          })
          .catch(function (err) {
            busy = false;
            syncBtn.disabled = false;
            testBtn.disabled = false;
            syncBtn.textContent = 'Sync now';
            clear(outHost);
            append(outHost, errorPanel(err));
            toastError(err);
          });
      });

      append(actionsHost, [
        testBtn,
        syncBtn,
        el('span', { class: 'tiny dim', text: configured
          ? 'A full sync is roughly 220 requests and takes about a minute.'
          : 'Store a credential first.' })
      ]);
    }

    /* ------------------------------------------------------------ form --- */
    function drawForm(d) {
      clear(formHost);
      d = d || {};

      var userInput = el('input', {
        type: 'text', value: d.username || '', spellcheck: 'false',
        autocomplete: 'off', placeholder: 'your HackerOne handle'
      });
      /* Never pre-filled, never read back, cleared on success. */
      var tokenInput = el('input', {
        type: 'password', autocomplete: 'off', spellcheck: 'false',
        placeholder: 'paste the API token'
      });
      var errHost = el('div', {});
      var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Save and verify' });

      saveBtn.addEventListener('click', function () {
        var username = userInput.value.trim();
        var token = tokenInput.value;
        clear(errHost);
        if (!username || !token) {
          append(errHost, el('div', { class: 'alert alert-warn', text: 'Username and API token are both required.' }));
          return;
        }
        saveBtn.disabled = true;
        saveBtn.textContent = 'Verifying…';
        api('/integrations/hackerone', {
          method: 'PUT',
          body: { username: username, api_token: token }
        }).then(function (res) {
          /* The token never goes back into the DOM: drop it the moment it is accepted. */
          tokenInput.value = '';
          token = null;
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save and verify';
          var v = res && res.verified;
          toast('Credential verified against HackerOne and stored.', 'ok');
          clear(outHost);
          append(outHost, el('div', { class: 'alert alert-ok' },
            'Verified and written to secrets.json (mode 0600)' +
            (v && v.sample_count !== undefined ? '. The probe page returned ' + v.sample_count + ' report' + (v.sample_count === 1 ? '' : 's') + '.' : '.')));
          drawStatus(res || {});
        }).catch(function (err) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save and verify';
          append(errHost, errorPanel(err));
        });
      });

      append(formHost, [
        el('h3', { class: 'int-formtitle', text: d.configured ? 'Replace the credential' : 'Store a credential' }),
        el('div', { class: 'alert alert-info tiny' }, [
          el('strong', { class: 'alert-title', text: 'How the token is handled.' }),
          el('div', { text:
            'It is verified against the live HackerOne API before anything is saved, so a typo ' +
            'cannot silently replace a working credential. It is then written to secrets.json at ' +
            'mode 0600 — never to config.json and never to the database. No endpoint can read it ' +
            'back: this page only ever receives a mask and a sha256 fingerprint. To rotate it, ' +
            'paste the new one here; to revoke it, delete it at hackerone.com/settings/api_token.' })
        ]),
        errHost,
        el('div', { class: 'form-grid' }, [
          field('Username', userInput, 'your H1 handle — it is the HTTP Basic username'),
          /* No 'primary program' field. The Tracker defaults to every program, and `h1.py
             --submit` now REQUIRES --program and cross-checks it against the scope's owner and
             the report's workspace, so nothing reads a stored handle any more. A field that
             decides nothing is a field that misleads. */
          field('API token', tokenInput, 'write-only; never displayed again')
        ]),
        el('div', { class: 'form-actions' }, saveBtn)
      ]);
    }

    loadStatus();
    return card;
  }

  /* =========================================================== invitations card
     Program invitations and report collaboration management via the H1 GraphQL API.
     Needs a session cookie (separate from the API token) because the hacker REST API
     has no invitation endpoints. */

  function invitationsCard() {
    var card = el('section', { class: 'card integration' });
    var titleRow = el('div', { class: 'card-title' }, [
      el('span', { text: 'Invitations and Collaborations' })
    ]);
    var badgeHost = el('span', { class: 'int-badge' });
    titleRow.appendChild(badgeHost);
    card.appendChild(titleRow);

    var body = el('div', { class: 'pane-body' });
    card.appendChild(body);
    var statusHost = el('div', { class: 'int-status' });
    var listHost = el('div', {});
    var formHost = el('div', {});
    append(body, [statusHost, listHost, formHost]);

    function loadStatus() {
      clear(statusHost);
      append(statusHost, loading('Checking session...'));
      api('/integrations/hackerone/session')
        .then(function (d) {
          clear(statusHost);
          clear(badgeHost);
          d = d || {};
          badgeHost.appendChild(d.configured
            ? el('span', { class: 'pill st-resolved', text: 'session active' })
            : el('span', { class: 'pill st-new', text: 'no session' }));
          statusHost.appendChild(metaGrid([
            integrationRow('Session', d.configured ? 'stored' : 'not set'),
            integrationRow('Masked', d.masked_session || '-')
          ]) || el('div', {}));
          drawSessionForm(d);
          if (d.configured) loadInvitations();
        })
        .catch(function (err) {
          clear(statusHost);
          if (err && err.status === 503) {
            append(statusHost, el('div', { class: 'empty dim', text: 'h1_graphql module unavailable.' }));
          } else {
            append(statusHost, errorPanel(err, loadStatus));
          }
        });
    }

    function drawSessionForm(d) {
      clear(formHost);
      var tokenInput = el('input', {
        type: 'password', autocomplete: 'off', spellcheck: 'false',
        placeholder: 'paste __Host-session cookie value'
      });
      var saveBtn = el('button', { class: 'btn btn-primary', type: 'button', text: 'Save and verify' });
      var errHost = el('div', {});

      saveBtn.addEventListener('click', function () {
        var token = tokenInput.value.trim();
        clear(errHost);
        if (!token) {
          append(errHost, el('div', { class: 'alert alert-warn', text: 'Session token is required.' }));
          return;
        }
        saveBtn.disabled = true;
        saveBtn.textContent = 'Verifying...';
        api('/integrations/hackerone/session', {
          method: 'PUT', body: { session_token: token }
        }).then(function (res) {
          tokenInput.value = '';
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save and verify';
          var v = res && res.verified;
          toast('Session verified' + (v && v.username ? ' as ' + v.username : '') + '.', 'ok');
          loadStatus();
        }).catch(function (err) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save and verify';
          append(errHost, errorPanel(err));
        });
      });

      append(formHost, [
        el('h3', { class: 'int-formtitle', text: d.configured ? 'Replace session' : 'Store session cookie' }),
        el('div', { class: 'alert alert-info tiny' }, [
          el('strong', { class: 'alert-title', text: 'Why a session cookie?' }),
          el('div', { text:
            'The REST API has no endpoints for invitations or collaborations. Those operations ' +
            'use the GraphQL API at hackerone.com/graphql, which needs the __Host-session cookie ' +
            'from a logged-in browser. Open DevTools > Application > Cookies on hackerone.com, ' +
            'copy the __Host-session value, and paste it here. It typically lasts several weeks.' })
        ]),
        errHost,
        el('div', { class: 'form-grid' }, [
          field('Session token', tokenInput, 'write-only; the __Host-session cookie value')
        ]),
        el('div', { class: 'form-actions' }, saveBtn)
      ]);
    }

    function loadInvitations() {
      clear(listHost);
      append(listHost, loading('Loading invitations...'));

      Promise.all([
        api('/h1/invitations').catch(function () { return { items: [] }; }),
        api('/h1/collabs').catch(function () { return { items: [] }; })
      ]).then(function (results) {
        clear(listHost);
        var programs = results[0].items || [];
        var collabs = results[1].items || [];

        if (programs.length) {
          append(listHost, el('h3', { class: 'int-formtitle', text: 'Program invitations (' + programs.length + ')' }));
          programs.forEach(function (inv) {
            var row = el('div', { class: 'inv-row' });
            var info = el('div', { class: 'inv-info' }, [
              el('strong', { text: inv.program_name || inv.program_handle }),
              el('span', { class: 'tiny dim', text: ' ' + (inv.offers_bounties ? 'bounty' : 'VDP') +
                (inv.expires_at ? ' - expires ' + inv.expires_at.substring(0, 10) : '') })
            ]);
            var acceptBtn = el('button', { class: 'btn btn-sm btn-primary', type: 'button', text: 'Accept' });
            var rejectBtn = el('button', { class: 'btn btn-sm btn-quiet', type: 'button', text: 'Reject' });

            acceptBtn.addEventListener('click', function () {
              acceptBtn.disabled = true;
              api('/h1/invitations/accept', { method: 'POST', body: { token: inv.token } })
                .then(function () { toast('Accepted ' + (inv.program_name || inv.program_handle), 'ok'); loadInvitations(); })
                .catch(function (err) { toastError(err); acceptBtn.disabled = false; });
            });
            rejectBtn.addEventListener('click', function () {
              rejectBtn.disabled = true;
              api('/h1/invitations/reject', { method: 'POST', body: { token: inv.token } })
                .then(function () { toast('Rejected ' + (inv.program_name || inv.program_handle), 'ok'); loadInvitations(); })
                .catch(function (err) { toastError(err); rejectBtn.disabled = false; });
            });
            append(row, [info, el('div', { class: 'inv-actions' }, [acceptBtn, rejectBtn])]);
            append(listHost, row);
          });
        }

        if (collabs.length) {
          append(listHost, el('h3', { class: 'int-formtitle', text: 'Collaboration invitations (' + collabs.length + ')' }));
          collabs.forEach(function (inv) {
            var row = el('div', { class: 'inv-row' });
            var info = el('div', { class: 'inv-info' }, [
              el('strong', { text: '#' + inv.report_id }),
              el('span', { text: ' ' + (inv.report_title || '').substring(0, 50) }),
              el('span', { class: 'tiny dim', text: ' from ' + inv.invited_by +
                (inv.split_percentage ? ' (' + inv.split_percentage + '% split)' : '') })
            ]);
            var acceptBtn = el('button', { class: 'btn btn-sm btn-primary', type: 'button', text: 'Accept' });
            acceptBtn.addEventListener('click', function () {
              acceptBtn.disabled = true;
              api('/h1/collabs/accept', { method: 'POST', body: { token: inv.token } })
                .then(function () { toast('Accepted collab on #' + inv.report_id, 'ok'); loadInvitations(); })
                .catch(function (err) { toastError(err); acceptBtn.disabled = false; });
            });
            append(row, [info, el('div', { class: 'inv-actions' }, [acceptBtn])]);
            append(listHost, row);
          });
        }

        if (!programs.length && !collabs.length) {
          append(listHost, el('div', { class: 'empty dim', text: 'No pending invitations.' }));
        }

        /* Collaborator invite form */
        append(listHost, el('h3', { class: 'int-formtitle', text: 'Invite collaborator' }));
        var reportInput = el('input', { type: 'text', placeholder: 'H1 report id (e.g. 3722980)', spellcheck: 'false' });
        var userInput = el('input', { type: 'text', placeholder: 'H1 username', spellcheck: 'false' });
        var pctInput = el('input', { type: 'number', placeholder: '50', min: '0', max: '100', value: '50' });
        var inviteBtn = el('button', { class: 'btn btn-sm', type: 'button', text: 'Invite' });
        var splitBtn = el('button', { class: 'btn btn-sm', type: 'button', text: 'Set split' });
        var collabErr = el('div', {});

        inviteBtn.addEventListener('click', function () {
          var rid = reportInput.value.trim();
          var user = userInput.value.trim();
          clear(collabErr);
          if (!rid || !user) { append(collabErr, el('div', { class: 'alert alert-warn', text: 'Report id and username required.' })); return; }
          inviteBtn.disabled = true;
          api('/h1/collabs/invite', { method: 'POST', body: { report_id: rid, username: user } })
            .then(function () { toast('Invited ' + user + ' to #' + rid, 'ok'); inviteBtn.disabled = false; })
            .catch(function (err) { toastError(err); inviteBtn.disabled = false; append(collabErr, errorPanel(err)); });
        });

        splitBtn.addEventListener('click', function () {
          var rid = reportInput.value.trim();
          var user = userInput.value.trim();
          var pct = pctInput.value.trim();
          clear(collabErr);
          if (!rid || !user || !pct) { append(collabErr, el('div', { class: 'alert alert-warn', text: 'All fields required.' })); return; }
          splitBtn.disabled = true;
          api('/h1/collabs/split', { method: 'POST', body: { report_id: rid, username: user, percentage: parseInt(pct) } })
            .then(function () { toast('Split set: ' + user + ' gets ' + pct + '% on #' + rid, 'ok'); splitBtn.disabled = false; })
            .catch(function (err) { toastError(err); splitBtn.disabled = false; append(collabErr, errorPanel(err)); });
        });

        append(listHost, [
          el('div', { class: 'form-grid' }, [
            field('Report ID', reportInput, 'the H1 report number'),
            field('Username', userInput, 'the collaborator handle'),
            field('Split %', pctInput, 'their share of the bounty')
          ]),
          collabErr,
          el('div', { class: 'form-actions' }, [inviteBtn, splitBtn])
        ]);
      });
    }

    loadStatus();
    return card;
  }

  var INTEGRATIONS = [
    { id: 'hackerone', label: 'HackerOne', card: hackeroneCard },
    { id: 'invitations', label: 'Invitations', card: invitationsCard }
  ];

  function integrationsView(root) {
    root.appendChild(el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title', text: 'Integrations' })
      ])
    ]));

    var host = el('div', { class: 'intlist' });
    root.appendChild(host);
    INTEGRATIONS.forEach(function (p) { host.appendChild(p.card()); });

    host.appendChild(el('section', { class: 'card card-skeleton' }, [
      el('div', { class: 'card-title' }, [
        el('span', { text: 'Another provider' }),
        el('span', { class: 'pill pill-planned', text: 'slot' })
      ]),
      el('div', { class: 'pane-body tiny dim' },
        'Each provider is one entry in the INTEGRATIONS array plus a card function that owns its ' +
        'own status, credential form and actions. Nothing else has to change to add a second one.')
    ]));
  }

  /* The research tools (Dashboard through Payloads) are the daily work. Everything an operator
     configures - the filesystem, credentials, the audit trail, users and settings - sits below a
     divider under a non-clickable ADMIN heading, so the two concerns read apart. Payloads is a
     research reference, not admin, so it stays in the top group right under Targets.

     A `heading` item is a plain label, never a link (see buildNav). `sep` draws the divider that
     opens the admin group; naming the item that STARTS the group means the line cannot drift when
     the top group grows. Certificates is not here: it is the seal icon in the rail footer now, and
     its `certs` route stays live like `search`. Status is kept in the admin group even though it is
     a read-only view - it answers "what is this system doing", which belongs with Audit. */
  var NAV = [
    { view: 'dashboard', label: 'Dashboard' },
    { view: 'leads', label: 'Leads' },
    { view: 'reports', label: 'Tracker' },
    /* Directly under the Tracker because it is the Tracker's back half: the same reports, after
       they closed. Its rail glyph is R, which Reports does not take - that tab is labelled
       Tracker. */
    { view: 'regression', label: 'Regression' },
    { view: 'advisories', label: 'Advisories' },
    { view: 'programs', label: 'Programs' },
    { view: 'targets', label: 'Targets' },
    { view: 'payloads', label: 'Payloads' },
    { heading: 'Admin', sep: true },
    { view: 'files', label: 'Files' },
    { view: 'tokens', label: 'Tokens' },
    { view: 'integrations', label: 'Integrations' },
    { view: 'audit', label: 'Audit log' },
    { view: 'status', label: 'Status' },
    { view: 'settings', label: 'Settings' }
  ];

  var VIEWS = {
    dashboard: function (root) { dashboardView(root); },
    leads: function (root, ctx) { entityListView(root, ENTITIES.leads, ctx); },
    reports: function (root, ctx) { entityListView(root, ENTITIES.reports, ctx); },
    regression: function (root, ctx) { regressionView(root, ctx); },
    advisories: function (root, ctx) { entityListView(root, ENTITIES.advisories, ctx); },
    programs: function (root, ctx) { programsView(root, ctx); },
    targets: function (root, ctx) { targetsView(root, ctx); },
    files: function (root, ctx) { filesView(root, ctx); },
    payloads: function (root, ctx) { payloadsView(root, ctx); },
    /* No nav entry any more, but the route stays: every [[wikilink]] in the workspace
       markdown resolves to #/search, and the Dashboard has a Search button. */
    search: function (root, ctx) { searchView(root, ctx); },
    tokens: function (root) { tokensView(root); },
    integrations: function (root) { integrationsView(root); },
    certs: function (root) { certificatesView(root); },
    audit: function (root) { auditView(root); },
    status: function (root) { statusView(root); },
    settings: function (root) { settingsView(root); }
  };

  function parseHash() {
    var h = String(location.hash || '').replace(/^#/, '');
    if (!h || h === '/') h = '/dashboard';
    var qi = h.indexOf('?');
    var pathPart = qi >= 0 ? h.slice(0, qi) : h;
    var query = new URLSearchParams(qi >= 0 ? h.slice(qi + 1) : '');
    var segs = pathPart.split('/').filter(function (s) { return s !== ''; });
    return {
      view: segs[0] || 'dashboard',
      id: segs.length > 1 ? decodeURIComponent(segs[1]) : null,
      q: query
    };
  }

  /* current query string, used by "Close" links so filters survive */
  function hashQuery() {
    var s = state.route.q.toString();
    return s ? '?' + s : '';
  }

  var NAV_COLLAPSE_KEY = 'nav-collapsed';

  /* Collapse state lives on .shell so one class drives the grid column width and every child
     transition together, and it is remembered across reloads - a sidebar that springs back open
     on every navigation is worse than no toggle at all. */
  function applyNavCollapsed(on) {
    var shell = document.querySelector('.shell');
    if (shell) shell.classList.toggle('nav-collapsed', !!on);
    var btn = $('#navToggle');
    if (btn) {
      btn.setAttribute('aria-expanded', on ? 'false' : 'true');
      btn.setAttribute('title', on ? 'Expand menu' : 'Collapse menu');
    }
    try { localStorage.setItem(NAV_COLLAPSE_KEY, on ? '1' : '0'); } catch (e) { /* private mode */ }
  }

  function navCollapsed() {
    try { return localStorage.getItem(NAV_COLLAPSE_KEY) === '1'; } catch (e) { return false; }
  }

  function buildNav() {
    var nav = $('#nav');
    if (!nav) return;
    clear(nav);

    var toggle = el('button', {
      id: 'navToggle', class: 'nav-toggle', type: 'button',
      'aria-label': 'Toggle menu', 'aria-expanded': 'true'
    }, [el('span', { class: 'nav-chevron', 'aria-hidden': 'true' })]);
    toggle.addEventListener('click', function () {
      applyNavCollapsed(!document.querySelector('.shell').classList.contains('nav-collapsed'));
    });
    nav.appendChild(toggle);

    NAV.forEach(function (item) {
      if (item.sep) nav.appendChild(el('div', { class: 'nav-sep' }));
      /* A heading is a section title, not a destination: no href, no active state, not focusable.
         Hidden when the rail is collapsed (the divider above it still marks the group). */
      if (item.heading) {
        nav.appendChild(el('div', { class: 'nav-heading navtext', text: item.heading }));
        return;
      }
      nav.appendChild(el('a', {
        class: 'navlink' + (state.route.view === item.view ? ' active' : ''),
        href: '#/' + item.view,
        title: item.label
      }, [
        /* Shown only when collapsed, so the rail stays navigable without labels. */
        el('span', { class: 'navmark', text: item.label.charAt(0).toUpperCase() }),
        el('span', { class: 'navtext', text: item.label })
      ]));
    });
    /* Pushed to the bottom of the rail by margin-top:auto, so the version sits in the
       bottom-left corner regardless of how many nav items there are. The certificate page moved
       off the nav into a small seal icon here, to the RIGHT of the version, linking the same
       #/certs route the tab used to. Stroked in currentColor so it follows the theme like the
       brand gem; aria-label carries the name the visible label used to. */
    nav.appendChild(el('div', { class: 'nav-foot' }, [
      el('span', { class: 'nav-version navtext', id: 'navVersion',
        text: state.version ? 'v' + state.version : '' }),
      el('a', {
        class: 'nav-cert' + (state.route.view === 'certs' ? ' active' : ''),
        href: '#/certs', title: 'Certificates', 'aria-label': 'Certificates'
      }, [el('span', {
        class: 'nav-cert-glyph', 'aria-hidden': 'true',
        html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
              'stroke-linecap="round" stroke-linejoin="round">' +
              '<circle cx="12" cy="9" r="6"/>' +
              '<path d="M9.2 8.9l1.9 1.9L15 7.2"/>' +
              '<path d="M8.8 13.7L7 20l5-2.8L17 20l-1.8-6.3"/></svg>'
      })])
    ]));
    /* buildNav can run after /health has already answered, so the topbar copy is refreshed here
       too rather than only in the health handler - otherwise a re-render leaves it blank. */
    var tv0 = $('#topversion');
    if (tv0 && state.version) tv0.textContent = 'v' + state.version;
    applyNavCollapsed(navCollapsed());
  }

  /* Every view builds a .page-head. Rather than editing each one, render() drops a Refresh
     control into whatever page-head the view produced. One place, every tab, and any view added
     later gets it for free. Views that render no page-head (none today) simply get nothing. */
  function injectRefresh(root) {
    var head = root.querySelector('.page-head');
    if (!head || head.querySelector('.refresh-btn')) return;

    var actions = head.querySelector('.page-actions');
    if (!actions) {
      actions = el('div', { class: 'page-actions' });
      head.appendChild(actions);
    }

    var btn = el('button', {
      class: 'btn btn-sm refresh-btn', type: 'button', title: 'Reload this view (r)'
    }, [el('span', { class: 'refresh-glyph', text: '↻' }), el('span', { text: ' Refresh' })]);

    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.classList.add('spinning');
      /* Refresh means "I have dealt with this". Acknowledging the section here is what lets the
         row tags be cleared deliberately rather than only by wandering away and coming back.
         Both watermarks move together and `.prev` is advanced to match, so the re-render that
         follows finds nothing to tag - the flags clear in front of you.

         Only for sections that HAVE watermarks; every other view refreshes as before. */
      var ACK = { leads: 'lead_updates', reports: 'report_updates', advisories: null };
      var view = state.route && state.route.view;
      if (Object.prototype.hasOwnProperty.call(ACK, view)) {
        var now = serverNowIso();
        markSeen(view, now);
        markSeenPrev(view, now);
        if (ACK[view]) { markSeen(ACK[view], now); markSeenPrev(ACK[view], now); }
      }
      // Views fetch on render, so re-rendering IS the refresh. The short delay is only so the
      // spin is visible on a fast local response - without it the button appears to do nothing.
      setTimeout(function () { render(); }, 120);
    });

    // Left-most in the action row, ahead of any view-specific buttons.
    if (actions.firstChild) {
      actions.insertBefore(btn, actions.firstChild);
    } else {
      actions.appendChild(btn);
    }
  }

  /* ---------------------------------------------------------------- redact mode

     Seth screenshots the Tracker and the Leads tab to show the work off. The numbers are the
     point of those screenshots; the titles are not, and they name unreported vulnerabilities in
     other people's software. Redact mode blurs what identifies a finding or a customer and
     leaves everything that makes the picture worth taking - counts, severities, dates, statuses,
     bounties - completely alone.

     It is presentation only. Nothing is fetched differently and no value is rewritten, so
     toggling it off restores the view exactly rather than requiring a reload. */
  var REDACT_KEY = 'quarry.redact';

  function redactOn() {
    try { return localStorage.getItem(REDACT_KEY) === '1'; } catch (e) { return false; }
  }

  function applyRedact(on) {
    document.body.classList.toggle('redacted', !!on);
    var btns = document.querySelectorAll('.redact-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      btns[i].setAttribute('title', on ? 'Show titles, programs and assets again'
                                      : 'Blur titles, programs and assets for a screenshot');
      btns[i].classList.toggle('on', !!on);
    }
    try { localStorage.setItem(REDACT_KEY, on ? '1' : '0'); } catch (e) { /* private mode */ }
  }

  function injectRedact(root, view) {
    /* Not on Programs: the conceal toggle already blurs the identifying columns there for a
       screenshot, and a second, broader redact button beside it is redundant and confusing. */
    if (view === 'programs') return;
    var head = root.querySelector('.page-head');
    if (!head || head.querySelector('.redact-btn')) return;
    var actions = head.querySelector('.page-actions');
    if (!actions) {
      actions = el('div', { class: 'page-actions' });
      head.appendChild(actions);
    }
    var btn = el('button', {
      class: 'btn btn-sm redact-btn', type: 'button', 'aria-pressed': 'false',
      'aria-label': 'Redact sensitive columns'
    }, [el('span', { class: 'redact-glyph', 'aria-hidden': 'true', text: '●' })]);
    btn.addEventListener('click', function () { applyRedact(!redactOn()); });
    actions.appendChild(btn);
    applyRedact(redactOn());
  }

  /* --------------------------------------------------- conceal private programs
     A narrower sibling of redact mode, living only on the Programs tab. Redact blurs everything
     that names a finding or customer, everywhere; this blurs ONLY the programs that are not
     public - private, soft-launched or never-synced - and only their identity (name, slug and the
     workspace path, which spells the program name out in a directory). Public programs stay
     readable, so a screenshot can show the public work while the private roster is sealed.

     Same presentation-only mechanism: a body class the Programs view's `prog-conceal` row tag and
     the table's own data-col stamps hang the blur off. Nothing is fetched or rewritten. */
  var CONCEAL_KEY = 'quarry.progconceal';

  function concealOn() {
    try { return localStorage.getItem(CONCEAL_KEY) === '1'; } catch (e) { return false; }
  }

  function applyConceal(on) {
    document.body.classList.toggle('prog-concealed', !!on);
    var btns = document.querySelectorAll('.conceal-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      btns[i].setAttribute('title', on ? 'Show private program names again'
                                      : 'Blur private and unlisted program names for a screenshot');
      btns[i].classList.toggle('on', !!on);
    }
    try { localStorage.setItem(CONCEAL_KEY, on ? '1' : '0'); } catch (e) { /* private mode */ }
  }

  function injectConceal(root, view) {
    if (view !== 'programs') return;
    var head = root.querySelector('.page-head');
    if (!head || head.querySelector('.conceal-btn')) return;
    var actions = head.querySelector('.page-actions');
    if (!actions) {
      actions = el('div', { class: 'page-actions' });
      head.appendChild(actions);
    }
    var btn = el('button', {
      class: 'btn btn-sm conceal-btn', type: 'button', 'aria-pressed': 'false',
      'aria-label': 'Conceal private program names'
    }, [el('span', { class: 'conceal-glyph', 'aria-hidden': 'true', text: '◐' })]);
    btn.addEventListener('click', function () { applyConceal(!concealOn()); });
    actions.appendChild(btn);
    applyConceal(concealOn());
  }

  function render() {
    var root = $('#view');
    if (!root) return;
    state.route = parseHash();
    buildNav();
    clear(root);

    var fn = VIEWS[state.route.view];
    if (!fn) {
      append(root, [
        el('div', { class: 'page-head' }, el('h1', { class: 'page-title', text: 'Not found' })),
        el('div', { class: 'alert alert-warn' }, 'No view called "' + state.route.view + '".'),
        el('a', { class: 'btn', href: '#/dashboard', text: 'Back to dashboard' })
      ]);
      return;
    }

    try {
      fn(root, state.route);
    } catch (e) {
      append(root, errorPanel({ message: 'Render failed: ' + e.message }));
      if (window.console) window.console.error(e);
    }

    injectRefresh(root);
    injectRedact(root, state.route.view);
    injectConceal(root, state.route.view);

    /* Opening a watched section IS reading it, however you got there - tile, nav or a
       bookmarked URL. Advance the watermark so the badge does not reappear next visit. */
    if (state.route.view === 'advisories' || state.route.view === 'reports'
        || state.route.view === 'leads') {
      markSeen(state.route.view);
    }

    var input = $('#globalsearch-input');
    if (input && state.route.view === 'search') input.value = state.route.q.get('q') || '';
    root.scrollTop = 0;
    /* On a phone the list and the detail pane are two SCREENS rather than two columns - app.css
       hides the list while a pane is open - so a navigation that swaps them has to put the new
       screen at the top or it opens halfway down. Desktop is untouched and keeps whatever scroll
       position it had, which is what it has always done: root.scrollTop is a no-op there because
       #view is not the scrolling element. */
    if (isNarrow()) window.scrollTo(0, 0);
  }

  /* ============================================================ auth + boot */

  function showLogin(message) {
    var app = $('#app'), login = $('#login'), boot = $('#boot');
    if (boot) boot.hidden = true;
    if (app) app.hidden = true;
    if (login) login.hidden = false;
    var errBox = $('#login-error');
    if (errBox) {
      if (message) { errBox.textContent = message; errBox.hidden = false; }
      else { errBox.textContent = ''; errBox.hidden = true; }
    }
    var user = $('#login-user');
    if (user) user.focus();
  }

  function showApp() {
    var app = $('#app'), login = $('#login'), boot = $('#boot');
    if (boot) boot.hidden = true;
    if (login) login.hidden = true;
    if (app) app.hidden = false;
  }

  function setUserChip() {
    var chip = $('#userchip');
    if (!chip) return;
    if (state.user) {
      /* Username only. The scope suffix - "· write" - told Seth something he already knows on
         the one account this app has, and on a phone it competed for width with the name. */
      chip.textContent = state.user.username;
      chip.hidden = false;
    } else {
      chip.textContent = '';
      chip.hidden = true;
    }
  }

  function enterApp() {
    showApp();
    setUserChip();
    /* Programs load alongside targets so the Tracker's picker is populated on first paint
       rather than appearing empty until a second render. */
    return Promise.all([loadTargets(), loadPrograms()]).then(function () { render(); });
  }

  function themeLabel(mode) {
    return mode === 'auto' ? 'Theme: auto' : (mode === 'light' ? 'Theme: light' : 'Theme: dark');
  }

  function wireChrome() {
    var themeBtn = $('#themebtn');
    if (themeBtn) {
      themeBtn.textContent = themeLabel(readTheme());
      themeBtn.addEventListener('click', function () {
        var order = ['auto', 'light', 'dark'];
        var next = order[(order.indexOf(readTheme()) + 1) % order.length];
        try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* ignore */ }
        applyTheme(next);
        themeBtn.textContent = themeLabel(next);
      });
    }

    var logout = $('#logoutbtn');
    if (logout) {
      logout.addEventListener('click', function () {
        logout.disabled = true;
        api('/logout', { method: 'POST', noAuthRedirect: true })
          .catch(function () { /* logging out is best-effort */ })
          .then(function () {
            logout.disabled = false;
            state.user = null;
            state.targetsLoaded = false;
            state.lastNewToken = null;
            setUserChip();
            showLogin('Signed out.');
          });
      });
    }

    var gform = $('#globalsearch');
    if (gform) {
      gform.addEventListener('submit', function (e) {
        e.preventDefault();
        var v = $('#globalsearch-input').value.trim();
        location.hash = '#/search' + (v ? '?' + qsFrom({ q: v }) : '');
      });
    }

    var lform = $('#login-form');
    if (lform) {
      lform.addEventListener('submit', function (e) {
        e.preventDefault();
        var btn = $('#login-submit');
        var u = $('#login-user').value;
        var p = $('#login-pass').value;
        btn.disabled = true;
        btn.textContent = 'Signing in…';
        var errBox = $('#login-error');
        errBox.hidden = true;
        api('/login', { method: 'POST', body: { username: u, password: p }, noAuthRedirect: true })
          .then(function () {
            $('#login-pass').value = '';
            btn.disabled = false;
            btn.textContent = 'Sign in';
            return api('/me', { noAuthRedirect: true }).catch(function () { return { username: u }; });
          })
          .then(function (me) {
            state.user = me || { username: u };
            state.targetsLoaded = false;
            return enterApp();
          })
          .catch(function (err) {
            btn.disabled = false;
            btn.textContent = 'Sign in';
            errBox.textContent = err.message || 'Login failed.';
            errBox.hidden = false;
          });
      });
    }

    /* '/' focuses the global search box; Escape closes an open detail pane */
    document.addEventListener('keydown', function (e) {
      var t = e.target;
      var typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
      if ((e.key === 'r' || e.key === 'R') && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        render();
        return;
      }
      if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        var gi = $('#globalsearch-input');
        if (gi) { e.preventDefault(); gi.focus(); gi.select(); }
        return;
      }
      if (e.key === 'Escape' && !typing) {
        var r = state.route;
        if (r.id && ENTITIES[r.view]) location.hash = '#/' + r.view + hashQuery();
      }
    });

    window.addEventListener('hashchange', function () {
      if ($('#app') && !$('#app').hidden) render();
    });
  }

  /* ---------------------------------------------------------------- branding
     The product name lives in config.json on the server (`app_name`). It is fetched from the
     public /api/health endpoint so the LOGIN screen is branded too, before any credential
     exists. Renaming the product therefore needs no front-end change at all. */
  var APP_NAME = 'Console';

  function faviconDataURI(name) {
    var letter = (name || '?').trim().charAt(0).toUpperCase();
    /* The same gem as the sidebar brand, so the tab and the app read as one thing. Hardcoded
       colours rather than currentColor: a favicon is rendered outside the page and inherits
       nothing from it. The initial stays, because a favicon is identified at a glance in a strip
       of other tabs and the letter does that faster than a shape shared with any other tool. */
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
      '<rect width="64" height="64" rx="14" fill="#11161d"/>' +
      '<g transform="translate(11 6) scale(1.75)" fill="none" stroke="#37c2a8" ' +
      'stroke-width="1.9" stroke-linejoin="round">' +
      '<path d="M7 3h10l4.5 6L12 21.5 2.5 9z"/><path d="M2.5 9h19"/>' +
      '<path d="M7 3 9.5 9 12 21.5 14.5 9 17 3"/></g>' +
      '<text x="32" y="61" font-family="monospace" font-size="12" font-weight="bold" ' +
      'fill="#8fa3b8" text-anchor="middle">' + letter + '</text></svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }

  function applyBranding(name) {
    APP_NAME = name || APP_NAME;
    document.title = APP_NAME;
    var brand = document.querySelector('.brand-text');
    if (brand) brand.textContent = APP_NAME;
    var lt = document.querySelector('.login-title');
    if (lt) lt.textContent = APP_NAME;
    var bootMsg = document.querySelector('#boot .boot-msg');
    if (bootMsg) bootMsg.textContent = 'Starting ' + APP_NAME + '\u2026';
    var icon = document.querySelector('link[rel="icon"]');
    if (!icon) {
      icon = document.createElement('link');
      icon.setAttribute('rel', 'icon');
      document.head.appendChild(icon);
    }
    icon.setAttribute('type', 'image/svg+xml');
    icon.setAttribute('href', faviconDataURI(APP_NAME));
  }

  function boot() {
    wireChrome();

    /* public endpoint - brands the login screen before authentication */
    api('/health', { noAuthRedirect: true })
      .then(function (h) {
        applyBranding(h && h.app_name);
        state.version = (h && h.version) || '';
        /* Two elements, one source. The rail's copy is the desktop's; the topbar's is the
           phone's, and CSS decides which is visible rather than either one guessing. */
        var vn = $('#navVersion');
        if (vn && state.version) vn.textContent = 'v' + state.version;
        var tv = $('#topversion');
        if (tv && state.version) tv.textContent = 'v' + state.version;
      })
      .catch(function () { applyBranding(null); });

    onUnauthorized = function () {
      state.user = null;
      setUserChip();
      showLogin('Your session has expired. Sign in again.');
    };

    api('/me', { noAuthRedirect: true })
      .then(function (me) {
        state.user = me || null;
        return enterApp();
      })
      .catch(function (err) {
        if (err.status === 401) { showLogin(null); return; }
        /* Server down, or /api/me not implemented yet: show the app with a clear error. */
        showApp();
        setUserChip();
        var root = $('#view');
        if (root) {
          clear(root);
          append(root, errorPanel(err, function () { location.reload(); }));
        }
        buildNav();
        toastError(err);
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
