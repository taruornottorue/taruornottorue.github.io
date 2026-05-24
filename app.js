
(() => {
  const PASSWORD = 'Stacy';
  const READINGS_PATH = 'readings';
  const FIREBASE_CONFIG = {
    apiKey: 'AIzaSyCxhiw5V3epzzWeFxlMGQ8SH4QjWDjH_1A',
    authDomain: 'taruornottorue.firebaseapp.com',
    projectId: 'taruornottorue',
    storageBucket: 'taruornottorue.firebasestorage.app',
    messagingSenderId: '458061841918',
    appId: '1:458061841918:web:1cc68c086bcbf81ee3acaf'
  };

  if (window.pdfjsLib) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.16.105/pdf.worker.min.js';
  }

  firebase.initializeApp(FIREBASE_CONFIG);
  const db = firebase.firestore();

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const el = (tag, attrs = {}, html = '') => {
    const node = document.createElement(tag);
    Object.assign(node, attrs);
    if (html) node.innerHTML = html;
    return node;
  };

  function escapeHtml(s) {
    return String(s ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function normalizeForMatching(s) {
    return String(s ?? '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/[\u2018\u2019]/g, "'")
      .replace(/[\u201C\u201D]/g, '"')
      .replace(/\u00A0/g, ' ')
      .replace(/\s+/g, ' ');
  }

  function normalizePath(p) {
    return !p ? p : String(p).startsWith('/') ? String(p).slice(1) : String(p);
  }

  function extOf(path) {
    const p = String(path || '');
    const i = p.lastIndexOf('.');
    return i >= 0 ? p.slice(i + 1).toLowerCase() : '';
  }

  function inferKind(item) {
    const ext = extOf(item.path || item.download_url || item.title || '');
    return ext === 'pdf' ? 'pdf' : 'text';
  }

  function parseTaruPrefix(raw) {
    if (!raw) return { text: raw, author: undefined };
    const m = String(raw).match(/^\s*(Taru)\s+(.*)$/i);
    if (m) return { text: m[2].trim(), author: m[1] };
    return { text: raw, author: undefined };
  }

  function getFileKey() {
    return `candle_annot_anns::${normalizePath(state.current.filePath || 'unknown')}`;
  }

  const state = {
    unlocked: false,
    readings: [],
    current: {
      filePath: null,
      title: null,
      kind: 'text',
      raw: '',
      displayText: '',
      displayToRawMap: [],
      pdf: null,
      pdfUrl: null,
      pdfScale: 1.25,
      pdfBaseScale: 1.25,
      pdfAutoFit: true,
      pdfPageEls: new Map(),
      pdfPageSizes: new Map(),
      pdfRenderToken: 0
    },
    pendingSelection: null,
    pendingTool: 'box',
    openCommentFor: null,
    commentCache: {},
    loadingTimers: {},
    unsubscribeRealtime: null,
    pollingFallback: null,
    pointerState: null
  };

  const STORAGE_PREFIX = 'candle_comment_draft::';
  const commentDrafts = {};
  function draftKey(remoteId) {
    const fp = state.current.filePath || 'unknown';
    return `${STORAGE_PREFIX}${fp}::${remoteId}`;
  }
  function saveDraftToStorage(remoteId, value, selStart, selEnd) {
    try {
      const key = draftKey(remoteId);
      const payload = { value: value || '', selStart: selStart ?? null, selEnd: selEnd ?? null, updated: Date.now() };
      localStorage.setItem(key, JSON.stringify(payload));
      commentDrafts[key] = payload;
    } catch (e) {
      console.warn('saveDraftToStorage failed', e);
    }
  }
  function loadDraftFromStorage(remoteId) {
    try {
      const key = draftKey(remoteId);
      if (commentDrafts[key]) return commentDrafts[key];
      const raw = localStorage.getItem(key);
      if (!raw) return { value: '', selStart: null, selEnd: null };
      const parsed = JSON.parse(raw);
      commentDrafts[key] = parsed;
      return parsed;
    } catch (e) {
      console.warn('loadDraftFromStorage failed', e);
      return { value: '', selStart: null, selEnd: null };
    }
  }
  function clearDraft(remoteId) {
    try {
      const key = draftKey(remoteId);
      localStorage.removeItem(key);
      delete commentDrafts[key];
    } catch (e) {
      console.warn('clearDraft failed', e);
    }
  }

  function isUnlocked() {
    try { return sessionStorage.getItem('candle_unlocked') === '1'; } catch { return false; }
  }
  function setUnlocked() {
    try { sessionStorage.setItem('candle_unlocked', '1'); } catch {}
  }

  function showOverlay() {
    $('#pw-overlay').style.display = 'flex';
    document.body.style.overflow = 'hidden';
    $('#pw-input').focus();
  }
  function hideOverlay() {
    $('#pw-overlay').style.display = 'none';
    document.body.style.overflow = '';
  }

  function setViewerMeta() {
    const meta = $('#viewer-meta');
    if (state.current.kind === 'pdf') {
      const base = state.current.pdfBaseScale || 1;
      const pct = base > 0 ? Math.round((state.current.pdfScale / base) * 100) : Math.round(state.current.pdfScale * 100);
      meta.textContent = `PDF • zoom ${pct}%`;
    } else {
      meta.textContent = '';
    }
  }

  function setTool(tool) {
    state.pendingTool = tool;
    $$('.tool-btn[data-tool]').forEach(btn => btn.classList.toggle('active', btn.dataset.tool === tool));
    const toolbar = $('#pdf-toolbar');
    if (toolbar) toolbar.dataset.mode = tool;
  }

  function showAnnotationEditor(payload) {
    const editor = $('#annotation-editor');
    $('#selection-preview').textContent = payload.preview || '';
    $('#annotation-text').value = payload.note || '';
    editor.classList.remove('hidden');
    editor.dataset.editing = payload.editingId || '';
    editor.dataset.remoteId = payload.remoteId || '';
    editor.dataset.payload = JSON.stringify(payload);
    $('#delete-annotation').classList.toggle('hidden', !payload.editingId);
    $('#right-col').classList.remove('collapsed');
    $('#right-col').scrollTop = 0;
  }

  function hideAnnotationEditor() {
    const editor = $('#annotation-editor');
    editor.classList.add('hidden');
    editor.dataset.editing = '';
    editor.dataset.remoteId = '';
    editor.dataset.payload = '';
    $('#delete-annotation').classList.add('hidden');
  }

  function hideFabAndLookup() {
    $('#annot-fab').style.display = 'none';
    $('#lookup-btn').style.display = 'none';
  }

  function applyPdfFocusMode(enabled) {
    const body = document.body;
    body.classList.toggle('pdf-mode', !!enabled);
    const left = $('#left-col');
    const right = $('#right-col');
    if (!left || !right) return;
    if (enabled) {
      left.classList.add('collapsed');
      right.classList.add('collapsed');
    } else {
      left.classList.remove('collapsed');
      right.classList.remove('collapsed');
    }
  }

  async function fitPdfToViewport(doc) {
    if (!doc) return;
    const page = await doc.getPage(1);
    const baseViewport = page.getViewport({ scale: 1 });
    const center = $('#center-content');
    const availableWidth = Math.max(520, Math.floor((center?.clientWidth || window.innerWidth || 1200) - 32));
    const rawScale = availableWidth / Math.max(1, baseViewport.width);
    const scale = Math.max(0.8, Math.min(2.5, Math.round(rawScale * 100) / 100));
    state.current.pdfBaseScale = scale;
    state.current.pdfScale = scale;
    state.current.pdfAutoFit = true;
    return scale;
  }

  function showFloatingButtons(rect, canLookup) {
    const fab = $('#annot-fab');
    const lookup = $('#lookup-btn');
    if (!rect) return hideFabAndLookup();
    const scrollY = window.scrollY || window.pageYOffset;
    const left = Math.max(8, rect.left + (rect.width / 2) - 40);
    const top = rect.top + scrollY - 44;
    fab.style.left = `${left}px`;
    fab.style.top = `${top}px`;
    fab.style.display = 'block';
    lookup.style.left = `${left + 96}px`;
    lookup.style.top = `${top}px`;
    lookup.style.display = canLookup ? 'block' : 'none';
  }

  function showFixedFloatingButtons() {
    const fab = $('#annot-fab');
    const lookup = $('#lookup-btn');
    fab.style.right = '14px';
    fab.style.bottom = '110px';
    fab.style.left = '';
    fab.style.top = '';
    fab.style.display = 'block';
    lookup.style.right = '14px';
    lookup.style.bottom = '150px';
    lookup.style.left = '';
    lookup.style.top = '';
    lookup.style.display = 'none';
  }

  function collectTextNodes(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
    const out = [];
    let n;
    while ((n = walker.nextNode())) out.push(n);
    return out;
  }

  function displayOffsetFromRange(range) {
    try {
      if (!range) return null;
      const container = $('#article');
      if (!container.contains(range.startContainer)) return null;
      const r = document.createRange();
      r.setStart(container, 0);
      try {
        r.setEnd(range.startContainer, range.startOffset);
      } catch {
        const nodes = collectTextNodes(container);
        let chars = 0;
        for (const node of nodes) {
          if (node === range.startContainer) return chars + range.startOffset;
          chars += node.textContent.length;
        }
        return null;
      }
      return r.toString().length;
    } catch (e) {
      console.warn('displayOffsetFromRange error', e);
      return null;
    }
  }

  function buildDisplayMapping(raw) {
    const map = [];
    let display = '';
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i];
      if (ch === '\n') continue;
      map.push(i);
      display += ch;
    }
    return { displayText: display, displayToRawMap: map };
  }

  function displayToRawRange(displayStart, length) {
    const map = state.current.displayToRawMap || [];
    const displayText = state.current.displayText || '';
    if (displayStart === null || displayStart === undefined) return null;
    const start = Math.max(0, Math.min(displayText.length, displayStart));
    const lastIndexUnclamped = displayStart + Math.max(0, length) - 1;
    const lastIndex = Math.max(0, Math.min(displayText.length - 1, lastIndexUnclamped));
    let rawStart = map[start];
    if (rawStart === undefined) {
      for (let i = start + 1; i < Math.min(map.length, start + 8); i++) {
        if (map[i] !== undefined) { rawStart = map[i]; break; }
      }
      if (rawStart === undefined) {
        for (let i = start - 1; i >= Math.max(0, start - 8); i--) {
          if (map[i] !== undefined) { rawStart = map[i]; break; }
        }
      }
    }
    const rawEndBase = map[lastIndex];
    let rawEnd;
    if (rawEndBase !== undefined) rawEnd = rawEndBase + 1;
    else if (rawStart !== undefined) rawEnd = rawStart + length;
    else rawEnd = undefined;
    if (rawStart === undefined || rawEnd === undefined || rawEnd <= rawStart) return null;
    return { start_idx: rawStart, end_idx: rawEnd };
  }

  function findAllIndicesInDisplay(display, needle) {
    const res = [];
    if (!needle) return res;
    let pos = 0;
    while (true) {
      const idx = display.indexOf(needle, pos);
      if (idx === -1) break;
      res.push(idx);
      pos = idx + Math.max(1, needle.length);
    }
    return res;
  }

  function domRangeForDisplayIndex(container, displayIndex, length) {
    const nodes = collectTextNodes(container);
    let chars = 0;
    const range = document.createRange();
    for (const node of nodes) {
      const next = chars + node.textContent.length;
      if (displayIndex < next) {
        const startOffset = Math.max(0, displayIndex - chars);
        range.setStart(node, startOffset);
        if (length <= node.textContent.length - startOffset) {
          range.setEnd(node, startOffset + length);
          return range;
        }
        let remaining = length - (node.textContent.length - startOffset);
        let reachedStartNode = false;
        const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null, false);
        let n;
        while ((n = walker.nextNode())) {
          if (!reachedStartNode) {
            if (n === node) reachedStartNode = true;
            continue;
          }
          if (remaining <= n.textContent.length) {
            range.setEnd(n, remaining);
            return range;
          }
          remaining -= n.textContent.length;
        }
        range.setEnd(node, node.textContent.length);
        return range;
      }
      chars = next;
    }
    return null;
  }

  function rectDistance(a, b) {
    const ax = a.left + a.width / 2, ay = a.top + a.height / 2;
    const bx = b.left + b.width / 2, by = b.top + b.height / 2;
    return Math.hypot(ax - bx, ay - by);
  }

  function selectionTextToPending(range) {
    const selText = range.toString();
    if (!selText || !state.current.raw) return null;
    const displayStart = displayOffsetFromRange(range);
    if (displayStart !== null && displayStart !== undefined) {
      const dr = displayToRawRange(displayStart, selText.length);
      if (dr) {
        return {
          kind: 'text',
          type: 'highlight',
          start_idx: dr.start_idx,
          end_idx: dr.end_idx,
          text: state.current.raw.slice(dr.start_idx, dr.end_idx)
        };
      }
    }
    const displayText = normalizeForMatching(state.current.displayText || '');
    const needle = normalizeForMatching(selText);
    const indices = findAllIndicesInDisplay(displayText, needle);
    if (indices.length === 0) return null;
    const selRect = range.getBoundingClientRect();
    let best = null;
    let bestDist = Infinity;
    for (const idx of indices) {
      const drange = domRangeForDisplayIndex($('#article'), idx, selText.length);
      if (!drange) continue;
      const r = drange.getBoundingClientRect();
      if (!r || (r.width === 0 && r.height === 0)) continue;
      const d = rectDistance(selRect, r);
      if (d < bestDist) { bestDist = d; best = { idx, rect: r }; }
    }
    if (!best) return null;
    const rawRange = displayToRawRange(best.idx, selText.length);
    if (!rawRange) return null;
    return {
      kind: 'text',
      type: 'highlight',
      start_idx: rawRange.start_idx,
      end_idx: rawRange.end_idx,
      text: state.current.raw.slice(rawRange.start_idx, rawRange.end_idx)
    };
  }

  function groupByTarget(anns) {
    const groups = [];
    for (const ann of anns) {
      const page = Number(ann.page ?? ann.page_num ?? ann.pageNumber ?? 0) || 0;
      const start = Number(ann.start_idx ?? ann.start ?? -1);
      const end = Number(ann.end_idx ?? ann.end ?? -1);
      const key = state.current.kind === 'pdf'
        ? `${ann.type || 'highlight'}::${page}::${JSON.stringify(ann.rects || ann.box || ann.path || [])}`
        : `${start}:${end}`;
      const last = groups[groups.length - 1];
      if (last && last.key === key) last.items.push(ann);
      else groups.push({ key, items: [ann] });
    }
    return groups;
  }

  function annDisplayLabel(ann) {
    if (state.current.kind === 'pdf') {
      const page = Number(ann.page ?? ann.page_num ?? 0) || 0;
      const typ = ann.type || 'highlight';
      return `${typ.toUpperCase()} • page ${page}`;
    }
    const s = Number(ann.start_idx ?? ann.start ?? 0);
    const e = Number(ann.end_idx ?? ann.end ?? 0);
    return `TEXT • ${e - s} chars`;
  }

  function annotationExcerpt(ann) {
    if (state.current.kind === 'pdf') {
      const page = Number(ann.page ?? ann.page_num ?? 0) || 0;
      const typ = ann.type || 'highlight';
      const parts = [];
      parts.push(`${typ} on page ${page}`);
      if (ann.type === 'ink' && Array.isArray(ann.path)) parts.push(`${ann.path.length} points`);
      if (ann.type === 'box' && Array.isArray(ann.rects)) parts.push('region');
      return parts.join(' • ');
    }
    const text = String(ann.text || '').trim();
    return text.length > 220 ? `${text.slice(0, 220)}…` : text;
  }

  function annRemoteId(ann) {
    return ann._remoteId || ann.remoteId || ann.id;
  }

  function loadAnnsLocal(fp) {
    try {
      const raw = localStorage.getItem(`candle_annot_anns::${normalizePath(fp)}`);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  function saveAnnsLocal(fp, arr) {
    localStorage.setItem(`candle_annot_anns::${normalizePath(fp)}`, JSON.stringify(arr));
  }

  async function pushAnnotationToFirestore(payload) {
    try {
      const doc = {
        file: normalizePath(payload.file),
        kind: payload.kind || 'text',
        type: payload.type || 'highlight',
        start_idx: Number.isFinite(Number(payload.start_idx)) ? Number(payload.start_idx) : null,
        end_idx: Number.isFinite(Number(payload.end_idx)) ? Number(payload.end_idx) : null,
        text: payload.text || '',
        note: payload.note || '',
        author: payload.author || 'Stacy',
        page: Number.isFinite(Number(payload.page)) ? Number(payload.page) : null,
        rects: payload.rects || null,
        path: payload.path || null,
        created_at: firebase.firestore.FieldValue.serverTimestamp()
      };
      const ref = await db.collection('annotations').add(doc);
      return { ok: true, id: ref.id };
    } catch (e) {
      console.error('pushAnnotation error', e);
      return { ok: false, error: e };
    }
  }

  async function updateAnnotationRemote(remoteId, updateObj) {
    try { await db.collection('annotations').doc(remoteId).update(updateObj); return { ok: true }; }
    catch (e) { console.warn('updateAnnotationRemote failed', e); return { ok: false, error: e }; }
  }

  async function deleteAnnotationRemote(remoteId) {
    try { await db.collection('annotations').doc(remoteId).delete(); return { ok: true }; }
    catch (e) { console.warn('deleteAnnotationRemote failed', e); return { ok: false, error: e }; }
  }

  async function fetchAnnotationsOnce(filePath) {
    if (!filePath) return;
    try {
      const snap = await db.collection('annotations').where('file', '==', normalizePath(filePath)).get();
      const anns = [];
      snap.forEach(doc => {
        const d = doc.data();
        d._remoteId = doc.id;
        d.id = d.id || doc.id;
        anns.push(d);
      });
      anns.sort((a, b) => {
        const ta = a.created_at?.toDate ? a.created_at.toDate().toISOString() : (a.created_at || a.createdAt || '');
        const tb = b.created_at?.toDate ? b.created_at.toDate().toISOString() : (b.created_at || b.createdAt || '');
        return String(ta || '').localeCompare(String(tb || ''));
      });
      saveAnnsLocal(filePath, anns);
      renderAnnotations();
      return anns;
    } catch (e) {
      console.error('fetchAnnotationsOnce error', e);
      return null;
    }
  }

  function subscribeRealtime(filePath) {
    if (state.unsubscribeRealtime) {
      try { state.unsubscribeRealtime(); } catch {}
      state.unsubscribeRealtime = null;
    }
    if (state.pollingFallback) {
      clearInterval(state.pollingFallback);
      state.pollingFallback = null;
    }
    try {
      state.unsubscribeRealtime = db.collection('annotations')
        .where('file', '==', normalizePath(filePath))
        .orderBy('created_at')
        .onSnapshot(snapshot => {
          const anns = [];
          snapshot.forEach(doc => {
            const d = doc.data();
            d._remoteId = doc.id;
            d.id = d.id || doc.id;
            anns.push(d);
          });
          anns.sort((a, b) => {
            const ta = a.created_at?.toDate ? a.created_at.toDate().toISOString() : (a.created_at || a.createdAt || '');
            const tb = b.created_at?.toDate ? b.created_at.toDate().toISOString() : (b.created_at || b.createdAt || '');
            return String(ta || '').localeCompare(String(tb || ''));
          });
          saveAnnsLocal(filePath, anns);
          renderAnnotations();
        }, err => {
          console.error('onSnapshot error', err);
          if (state.pollingFallback) clearInterval(state.pollingFallback);
          state.pollingFallback = setInterval(() => fetchAnnotationsOnce(filePath), 6000);
        });
    } catch (e) {
      console.warn('subscribeRealtime error', e);
      if (state.pollingFallback) clearInterval(state.pollingFallback);
      state.pollingFallback = setInterval(() => fetchAnnotationsOnce(filePath), 6000);
    }
  }

  async function discoverReadings() {
    const indexPath = `/${READINGS_PATH}/index.json`;
    try {
      const r = await fetch(indexPath, { cache: 'no-store' });
      if (!r.ok) throw new Error('index fetch failed');
      const arr = await r.json();
      state.readings = arr.map(item => {
        if (typeof item === 'string') {
          return { path: item, title: item.split('/').pop(), kind: inferKind({ path: item }) };
        }
        return {
          path: item.path,
          title: item.title || item.path.split('/').pop(),
          download_url: item.download_url,
          kind: item.kind || inferKind(item)
        };
      });
      renderReadingList();
    } catch (e) {
      console.warn('discoverReadings error', e);
      $('#reading-list').innerHTML = '<div class="muted">No readings found. Add /readings/index.json</div>';
    }
  }

  function renderReadingList() {
    const cont = $('#reading-list');
    cont.innerHTML = '';
    state.readings.forEach(r => {
      const item = el('div', { className: 'reading-item' });
      item.innerHTML = `<div class="reading-title">${escapeHtml(r.title)}</div>`;
      item.addEventListener('click', () => loadReading(r));
      cont.appendChild(item);
    });
  }

  function resetCenterState() {
    $('#article').classList.remove('hidden');
    $('#pdf-viewer').classList.add('hidden');
    $('#pdf-viewer').innerHTML = '';
    $('#pdf-toolbar').classList.add('hidden');
    $('#article').innerHTML = '<div class="muted">Open a reading from the left.</div>';
    state.current.pdf = null;
    state.current.pdfUrl = null;
    state.current.pdfPageEls.clear();
    state.current.pdfPageSizes.clear();
    state.current.pdfRenderToken++;
  }

  function renderTextArticle() {
    const raw = state.current.raw || '';
    const mapping = buildDisplayMapping(raw);
    state.current.displayText = mapping.displayText;
    state.current.displayToRawMap = mapping.displayToRawMap;
    const anns = loadAnnsLocal(state.current.filePath) || [];
    const sorted = anns.slice().map(a => ({ ...a, start_idx: Number(a.start_idx ?? a.start), end_idx: Number(a.end_idx ?? a.end) }))
      .filter(a => Number.isFinite(a.start_idx) && Number.isFinite(a.end_idx) && a.end_idx > a.start_idx)
      .sort((a, b) => a.start_idx - b.start_idx);

    let out = '';
    let cursor = 0;
    for (const a of sorted) {
      if (a.start_idx > cursor) out += escapeHtml(raw.slice(cursor, a.start_idx));
      const excerpt = escapeHtml(raw.slice(a.start_idx, a.end_idx));
      out += `<span class="hl" data-kind="text" data-ann-id="${escapeHtml(a.id)}" data-start="${a.start_idx}" data-end="${a.end_idx}">${excerpt}</span>`;
      cursor = a.end_idx;
    }
    if (cursor < raw.length) out += escapeHtml(raw.slice(cursor));
    out = out.replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>');
    $('#article').innerHTML = `<p>${out}</p>`;
  }

  function renderTextHighlightsOnly() {
    const anns = loadAnnsLocal(state.current.filePath) || [];
    renderAnnotations();
    return anns;
  }

  async function loadTextReading(r, url) {
    state.current.kind = 'text';
    applyPdfFocusMode(false);
    $('#post-title').textContent = r.title || r.path.split('/').pop();
    $('#viewer-meta').textContent = '';
    $('#pdf-toolbar').classList.add('hidden');
    $('#pdf-viewer').classList.add('hidden');
    $('#article').classList.remove('hidden');
    try {
      const res = await fetch(url, { cache: 'no-store' });
      if (!res.ok) throw new Error('fetch failed');
      state.current.raw = await res.text();
      state.current.filePath = normalizePath(r.path);
      state.current.title = r.title || r.path.split('/').pop();
      await fetchAnnotationsOnce(state.current.filePath);
      renderTextArticle();
      subscribeRealtime(state.current.filePath);
      setViewerMeta();
    } catch (e) {
      console.error('loadTextReading error', e);
      $('#article').innerHTML = `<div class="muted">Error loading ${escapeHtml(url)}</div>`;
    }
  }

  function computePdfPageBox(pageView) {
    return { width: Math.floor(pageView.width), height: Math.floor(pageView.height) };
  }

  async function renderPdfPages() {
    const token = ++state.current.pdfRenderToken;
    const doc = state.current.pdf;
    if (!doc) return;
    const viewer = $('#pdf-viewer');
    viewer.innerHTML = '';
    viewer.classList.remove('hidden');
    $('#article').classList.add('hidden');
    $('#pdf-toolbar').classList.remove('hidden');
    setTool(state.pendingTool || 'box');
    state.current.pdfPageEls.clear();
    state.current.pdfPageSizes.clear();

    for (let pageNum = 1; pageNum <= doc.numPages; pageNum++) {
      if (token !== state.current.pdfRenderToken) return;
      const page = await doc.getPage(pageNum);
      const viewport = page.getViewport({ scale: state.current.pdfScale });
      const pageEl = el('section', { className: 'pdf-page' });
      pageEl.dataset.pageNum = String(pageNum);
      pageEl.style.width = `${viewport.width}px`;
      pageEl.style.height = `${viewport.height}px`;

      const canvas = el('canvas', { className: 'pdf-canvas' });
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      canvas.style.width = `${viewport.width}px`;
      canvas.style.height = `${viewport.height}px`;
      const ctx = canvas.getContext('2d');

      const textLayer = el('div', { className: 'textLayer pdf-text-layer' });
      const overlay = el('canvas', { className: 'pdf-overlay' });
      overlay.width = viewport.width;
      overlay.height = viewport.height;
      overlay.style.width = `${viewport.width}px`;
      overlay.style.height = `${viewport.height}px`;
      overlay.dataset.pageNum = String(pageNum);

      pageEl.appendChild(canvas);
      pageEl.appendChild(textLayer);
      pageEl.appendChild(overlay);
      viewer.appendChild(pageEl);

      state.current.pdfPageEls.set(pageNum, { pageEl, canvas, overlay, textLayer, viewport, page });
      state.current.pdfPageSizes.set(pageNum, { width: viewport.width, height: viewport.height });

      await page.render({ canvasContext: ctx, viewport }).promise;
      try {
        const textContent = await page.getTextContent();
        if (window.pdfjsLib && pdfjsLib.renderTextLayer) {
          const textLayerTask = pdfjsLib.renderTextLayer({
            textContent,
            textContentSource: textContent,
            container: textLayer,
            viewport,
            textDivs: []
          });
          if (textLayerTask?.promise && typeof textLayerTask.promise.then === 'function') {
            await textLayerTask.promise;
          } else if (textLayerTask?.render && typeof textLayerTask.render === 'function') {
            await textLayerTask.render();
          }
        }
      } catch (textLayerError) {
        console.warn('PDF text layer render failed; continuing with canvas view only.', textLayerError);
      }
      setupPdfPageInteractions(pageNum, overlay);
    }
    renderPdfAnnotations();
    setViewerMeta();
  }

  async function loadPdfReading(r, url) {
    state.current.kind = 'pdf';
    state.current.filePath = normalizePath(r.path);
    state.current.title = r.title || r.path.split('/').pop();
    state.current.pdfUrl = url;
    state.current.raw = '';
    state.current.displayText = '';
    state.current.pdfAutoFit = true;
    $('#post-title').textContent = state.current.title;
    $('#article').classList.add('hidden');
    $('#pdf-viewer').classList.remove('hidden');
    $('#pdf-toolbar').classList.remove('hidden');
    $('#pdf-viewer').innerHTML = '<div class="muted">Loading PDF…</div>';
    applyPdfFocusMode(true);
    try {
      const task = pdfjsLib.getDocument({ url });
      const doc = await task.promise;
      state.current.pdf = doc;
      await fitPdfToViewport(doc);
      await fetchAnnotationsOnce(state.current.filePath);
      subscribeRealtime(state.current.filePath);
      await renderPdfPages();
    } catch (e) {
      console.error('loadPdfReading error', e);
      $('#pdf-viewer').innerHTML = `<div class="muted">Error loading PDF: ${escapeHtml(String(e.message || e))}</div>`;
    }
  }

  async function loadReading(r) {
    hideAnnotationEditor();
    hideFabAndLookup();
    state.pendingSelection = null;
    state.openCommentFor = null;
    setTool('box');
    const url = r.download_url || `/${r.path}`;
    setViewerMeta();
    resetCenterState();
    if ((r.kind || inferKind(r)) === 'pdf') await loadPdfReading(r, url);
    else await loadTextReading(r, url);
  }

  function renderAnnotationComments(remoteId, comments) {
    const listEl = document.getElementById(`comments-list-${remoteId}`);
    if (!listEl) return;
    const cache = state.commentCache[remoteId] || { status: 'idle', items: [], lastRenderedHash: '' };
    const items = comments || cache.items || [];
    const hash = JSON.stringify(items.map(i => [i.author || '', i.text || '']));
    if (listEl.dataset.renderedHash === hash) return;
    cache.lastRenderedHash = hash;
    state.commentCache[remoteId] = cache;
    listEl.dataset.renderedHash = hash;
    if (!items.length) {
      listEl.innerHTML = '<div class="muted small">No comments yet.</div>';
      return;
    }
    listEl.innerHTML = '';
    items.forEach(c => {
      const div = el('div', { className: 'comment-item' });
      div.innerHTML = `<div class="comment-author">${escapeHtml(c.author || 'Anonymous')}</div><div>${escapeHtml(c.text || '')}</div>`;
      listEl.appendChild(div);
    });
  }

  async function fetchAndRenderCommentsFor(remoteId, force = false) {
    if (!remoteId) return;
    const now = Date.now();
    if (!state.commentCache[remoteId]) state.commentCache[remoteId] = { status: 'idle', items: [], lastFetched: 0, lastRenderedHash: '' };
    const cache = state.commentCache[remoteId];
    if (!force && cache.status === 'loaded' && now - (cache.lastFetched || 0) < 5000) {
      renderAnnotationComments(remoteId, cache.items);
      return;
    }
    if (cache.status === 'loading' && !force) {
      renderAnnotationComments(remoteId, cache.items);
      return;
    }
    cache.status = 'loading';
    if (state.loadingTimers[remoteId]) clearTimeout(state.loadingTimers[remoteId]);
    state.loadingTimers[remoteId] = setTimeout(() => {
      const listEl = document.getElementById(`comments-list-${remoteId}`);
      if (listEl && state.commentCache[remoteId]?.status === 'loading' && (!state.commentCache[remoteId].items || state.commentCache[remoteId].items.length === 0)) {
        listEl.innerHTML = '<div class="muted small">Loading comments…</div>';
      }
    }, 220);
    try {
      const snap = await db.collection('annotations').doc(remoteId).collection('comments').orderBy('created_at', 'asc').get();
      const comments = [];
      snap.forEach(d => comments.push({ id: d.id, ...d.data() }));
      cache.items = comments.map(c => ({ author: c.author || 'Anonymous', text: c.text || '' }));
      cache.status = 'loaded';
      cache.lastFetched = Date.now();
      renderAnnotationComments(remoteId, cache.items);
    } catch (e) {
      console.error('fetch comments error', e);
      cache.status = 'error';
    } finally {
      if (state.loadingTimers[remoteId]) {
        clearTimeout(state.loadingTimers[remoteId]);
        delete state.loadingTimers[remoteId];
      }
    }
  }

  function renderAnnotationCard(ann, idx, group, anns) {
    const card = el('div', { className: 'ann-group' });
    const authorLabel = escapeHtml(ann.author || 'Stacy');
    const locLabel = annDisplayLabel(ann);
    const excerpt = annotationExcerpt(ann);
    const noteHtml = marked?.parseInline ? marked.parseInline(ann.note || '') : escapeHtml(ann.note || '');
    card.innerHTML = `
      <div class="ann-head">
        <div>
          <div class="ann-title">${locLabel}</div>
          <div class="ann-excerpt">${escapeHtml(excerpt)}</div>
        </div>
        <div class="ann-meta">${authorLabel}</div>
      </div>
    `;
    if (group.items.length > 1) {
      const tabs = el('div', { className: 'ann-tabs' });
      group.items.forEach((it, tabIdx) => {
        const t = el('button', { className: 'ann-tab' }, escapeHtml(it.author || 'Stacy'));
        if (tabIdx === 0) t.classList.add('ann-active');
        t.addEventListener('click', () => {
          tabs.querySelectorAll('.ann-tab').forEach(n => n.classList.remove('ann-active'));
          t.classList.add('ann-active');
          body.innerHTML = renderBodyHtml(it);
        });
        tabs.appendChild(t);
      });
      card.appendChild(tabs);
    }
    const body = el('div', { className: 'ann-body' });
    body.innerHTML = renderBodyHtml(ann);
    card.appendChild(body);

    const actions = el('div', { className: 'ann-actions' });
    const btn = (label, action) => {
      const b = el('button', { className: 'pill-btn' }, label);
      b.dataset.action = action;
      b.dataset.id = ann.id;
      b.addEventListener('click', onAnnotationAction);
      return b;
    };
    actions.append(btn('Jump', 'jump'), btn('Edit', 'edit'), btn('Comment', 'comment'), btn('Delete', 'delete'));
    card.appendChild(actions);

    const remoteId = annRemoteId(ann);
    const commentBlock = el('div', { className: 'comment-block', id: `comments-for-${remoteId}` });
    const open = state.openCommentFor === remoteId;
    commentBlock.style.display = open ? '' : 'none';
    commentBlock.appendChild(el('div', { className: 'muted small', style: 'margin-bottom:8px;font-weight:600' }, `Commenting on: ${escapeHtml(excerpt.slice(0, 120))}${excerpt.length > 120 ? '…' : ''}`));
    const commentsList = el('div', { className: 'comments-list', id: `comments-list-${remoteId}` });
    commentsList.dataset.renderedHash = '';
    const cache = state.commentCache[remoteId];
    if (cache && (cache.status === 'loaded' || (cache.items && cache.items.length))) {
      renderAnnotationComments(remoteId, cache.items);
    } else {
      commentsList.innerHTML = '<div class="muted small">No comments yet.</div>';
    }
    commentBlock.appendChild(commentsList);

    const inputRow = el('div', { className: 'comment-input' });
    const ta = el('textarea', { id: `comment-input-${remoteId}`, placeholder: 'Write a comment...' });
    const draft = loadDraftFromStorage(remoteId);
    if (draft?.value) ta.value = draft.value;
    ta.addEventListener('input', () => saveDraftToStorage(remoteId, ta.value, ta.selectionStart ?? null, ta.selectionEnd ?? null));
    ta.addEventListener('keyup', () => saveDraftToStorage(remoteId, ta.value, ta.selectionStart ?? null, ta.selectionEnd ?? null));
    const postBtn = el('button', { className: 'pill-btn' }, 'Post');
    postBtn.dataset.remoteId = remoteId;
    postBtn.addEventListener('click', onPostComment);
    inputRow.appendChild(ta);
    inputRow.appendChild(postBtn);
    commentBlock.appendChild(inputRow);
    card.appendChild(commentBlock);

    return card;
  }

  function renderBodyHtml(ann) {
    const note = String(ann.note || '');
    const rendered = marked?.parseInline ? marked.parseInline(note) : escapeHtml(note);
    if (state.current.kind === 'pdf') {
      return `<div>${rendered}</div>`;
    }
    return `${rendered}`;
  }

  function renderAnnotations() {
    const anns = loadAnnsLocal(state.current.filePath) || [];
    const cont = $('#annotations-list');
    cont.innerHTML = '';
    if (!anns.length) {
      cont.innerHTML = '<div class="muted">No annotations yet.</div>';
      if (state.current.kind === 'pdf') renderPdfAnnotations();
      return;
    }
    const normalized = anns.slice().map(a => ({ ...a, start_idx: Number(a.start_idx ?? a.start), end_idx: Number(a.end_idx ?? a.end) }));
    const groups = groupByTarget(normalized);
    groups.forEach((group, idx) => {
      const card = renderAnnotationCard(group.items[0], idx, group, normalized);
      cont.appendChild(card);
    });
    if (state.openCommentFor) {
      const cache = state.commentCache[state.openCommentFor];
      if (cache) renderAnnotationComments(state.openCommentFor, cache.items);
    }
    if (state.current.kind === 'pdf') renderPdfAnnotations();
  }

  function openCommentsFor(remoteId) {
    state.openCommentFor = remoteId;
    const anns = loadAnnsLocal(state.current.filePath) || [];
    renderAnnotations();
    fetchAndRenderCommentsFor(remoteId);
    setTimeout(() => {
      const ta = document.getElementById(`comment-input-${remoteId}`);
      if (ta) ta.focus();
    }, 120);
  }

  function setPendingSelection(payload) {
    state.pendingSelection = payload;
    if (!payload) return;
    const preview = payload.preview || payload.text || payload.kind || '';
    $('#selection-preview').textContent = preview.length > 120 ? `${preview.slice(0, 120)}…` : preview;
    $('#annotation-text').value = payload.note || '';
    showAnnotationEditor(payload);
  }

  function snapshotCurrentSelection() {
    const sel = window.getSelection();
    if (!sel || sel.rangeCount === 0) return null;
    const text = sel.toString().trim();
    if (!text) return null;
    const range = sel.getRangeAt(0);
    if (state.current.kind === 'text') {
      return selectionTextToPending(range);
    }
    if (state.current.kind === 'pdf' && state.pendingTool === 'select') {
      return capturePdfSelection();
    }
    return null;
  }

  function pageBoxFromRelativeRect(pageNum, rect) {
    const box = state.current.pdfPageSizes.get(pageNum);
    if (!box) return null;
    return {
      left: rect.left * box.width,
      top: rect.top * box.height,
      width: rect.width * box.width,
      height: rect.height * box.height
    };
  }

  function normalizeRectToPage(rect, viewport) {
    return {
      left: rect.left / viewport.width,
      top: rect.top / viewport.height,
      width: rect.width / viewport.width,
      height: rect.height / viewport.height
    };
  }

  function normalizePointToPage(x, y, viewport) {
    return { x: x / viewport.width, y: y / viewport.height };
  }

  function denormRect(rect, viewport) {
    return {
      left: rect.left * viewport.width,
      top: rect.top * viewport.height,
      width: rect.width * viewport.width,
      height: rect.height * viewport.height
    };
  }

  function denormPoint(p, viewport) {
    return { x: p.x * viewport.width, y: p.y * viewport.height };
  }

  function currentPdfPageEntry(pageNum) {
    return state.current.pdfPageEls.get(pageNum) || null;
  }

  function renderPdfAnnotations() {
    if (state.current.kind !== 'pdf') return;
    const anns = loadAnnsLocal(state.current.filePath) || [];
    for (const [pageNum, entry] of state.current.pdfPageEls.entries()) {
      const overlay = entry.overlay;
      const ctx = overlay.getContext('2d');
      ctx.clearRect(0, 0, overlay.width, overlay.height);
      const pageAnns = anns.filter(a => Number(a.page ?? 0) === Number(pageNum));
      pageAnns.forEach(ann => {
        const color = 'rgba(179,107,44,0.22)';
        const stroke = 'rgba(179,107,44,0.9)';
        if (ann.type === 'ink' && Array.isArray(ann.path)) {
          ctx.save();
          ctx.lineWidth = Math.max(2, overlay.width * 0.0025);
          ctx.strokeStyle = stroke;
          ctx.lineJoin = 'round';
          ctx.lineCap = 'round';
          ctx.beginPath();
          const path = ann.path.map(p => denormPoint(p, entry.viewport));
          if (!path.length) return;
          ctx.moveTo(path[0].x, path[0].y);
          for (let i = 1; i < path.length; i++) ctx.lineTo(path[i].x, path[i].y);
          ctx.stroke();
          ctx.restore();
        } else if (Array.isArray(ann.rects) && ann.rects.length) {
          ann.rects.forEach(r => {
            const rr = denormRect(r, entry.viewport);
            ctx.save();
            ctx.fillStyle = color;
            ctx.strokeStyle = stroke;
            ctx.lineWidth = 2;
            ctx.fillRect(rr.left, rr.top, rr.width, rr.height);
            ctx.strokeRect(rr.left, rr.top, rr.width, rr.height);
            ctx.restore();
          });
        } else if (ann.start_idx !== null && ann.start_idx !== undefined && ann.end_idx !== null && ann.end_idx !== undefined) {
          // highlights already live in the text layer, but we add a small label pin for sidebar/jump clarity.
          const pin = document.createElement('div');
          pin.className = 'pdf-note-pin';
          pin.style.left = '18px';
          pin.style.top = '18px';
          overlay.appendChild(pin);
        }
      });
    }
  }

  function clearTemporaryPdfOverlay(pageNum) {
    const entry = currentPdfPageEntry(pageNum);
    if (!entry) return;
    const overlay = entry.overlay;
    const ctx = overlay.getContext('2d');
    ctx.clearRect(0, 0, overlay.width, overlay.height);
    renderPdfAnnotations();
  }

  function getPdfPoint(evt, overlay) {
    const rect = overlay.getBoundingClientRect();
    return { x: evt.clientX - rect.left, y: evt.clientY - rect.top };
  }

  function setupPdfPageInteractions(pageNum, overlay) {
    overlay.classList.toggle('active', state.pendingTool !== 'select');
    overlay.onpointerdown = null;
    overlay.onpointermove = null;
    overlay.onpointerup = null;
    overlay.onpointercancel = null;

    overlay.style.pointerEvents = state.pendingTool === 'select' ? 'none' : 'auto';

    overlay.onpointerdown = evt => {
      if (state.current.kind !== 'pdf') return;
      if (state.pendingTool === 'select') return;
      evt.preventDefault();
      overlay.setPointerCapture(evt.pointerId);
      const start = getPdfPoint(evt, overlay);
      const entry = currentPdfPageEntry(pageNum);
      if (!entry) return;
      if (state.pendingTool === 'box') {
        state.pointerState = { tool: 'box', pageNum, overlay, start, current: start };
      } else if (state.pendingTool === 'pen') {
        state.pointerState = { tool: 'pen', pageNum, overlay, points: [start], current: start };
      }
    };

    overlay.onpointermove = evt => {
      if (!state.pointerState || state.pointerState.pageNum !== pageNum) return;
      const pos = getPdfPoint(evt, overlay);
      state.pointerState.current = pos;
      const entry = currentPdfPageEntry(pageNum);
      if (!entry) return;
      const ctx = overlay.getContext('2d');
      ctx.clearRect(0, 0, overlay.width, overlay.height);
      renderPdfAnnotations();
      ctx.save();
      ctx.strokeStyle = 'rgba(179,107,44,0.95)';
      ctx.fillStyle = 'rgba(179,107,44,0.14)';
      ctx.lineWidth = 2;
      if (state.pointerState.tool === 'box') {
        const x = Math.min(state.pointerState.start.x, pos.x);
        const y = Math.min(state.pointerState.start.y, pos.y);
        const w = Math.abs(pos.x - state.pointerState.start.x);
        const h = Math.abs(pos.y - state.pointerState.start.y);
        ctx.setLineDash([8, 6]);
        ctx.fillRect(x, y, w, h);
        ctx.strokeRect(x, y, w, h);
      } else if (state.pointerState.tool === 'pen') {
        state.pointerState.points.push(pos);
        ctx.beginPath();
        const pts = state.pointerState.points;
        if (pts.length > 0) {
          ctx.moveTo(pts[0].x, pts[0].y);
          for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
        }
        ctx.stroke();
      }
      ctx.restore();
    };

    overlay.onpointerup = evt => {
      if (!state.pointerState || state.pointerState.pageNum !== pageNum) return;
      const entry = currentPdfPageEntry(pageNum);
      if (!entry) return;
      const pos = getPdfPoint(evt, overlay);
      const viewport = entry.viewport;
      if (state.pointerState.tool === 'box') {
        const x = Math.min(state.pointerState.start.x, pos.x);
        const y = Math.min(state.pointerState.start.y, pos.y);
        const w = Math.abs(pos.x - state.pointerState.start.x);
        const h = Math.abs(pos.y - state.pointerState.start.y);
        if (w < 8 || h < 8) {
          state.pointerState = null;
          clearTemporaryPdfOverlay(pageNum);
          return;
        }
        const rect = { left: x / viewport.width, top: y / viewport.height, width: w / viewport.width, height: h / viewport.height };
        const payload = {
          kind: 'pdf',
          type: 'box',
          page: pageNum,
          rects: [rect],
          preview: `Box annotation • page ${pageNum}`,
          text: ''
        };
        state.pointerState = null;
        clearTemporaryPdfOverlay(pageNum);
        setPendingSelection(payload);
      } else if (state.pointerState.tool === 'pen') {
        const pts = state.pointerState.points.slice();
        pts.push(pos);
        if (pts.length < 3) {
          state.pointerState = null;
          clearTemporaryPdfOverlay(pageNum);
          return;
        }
        const path = pts.map(p => normalizePointToPage(p.x, p.y, viewport));
        const payload = {
          kind: 'pdf',
          type: 'ink',
          page: pageNum,
          path,
          preview: `Pen annotation • page ${pageNum}`,
          text: ''
        };
        state.pointerState = null;
        clearTemporaryPdfOverlay(pageNum);
        setPendingSelection(payload);
      }
    };

    overlay.onpointercancel = () => {
      state.pointerState = null;
      clearTemporaryPdfOverlay(pageNum);
    };
  }

  function capturePdfSelection() {
    if (state.current.kind !== 'pdf' || state.pendingTool !== 'select') return null;
    const sel = window.getSelection();
    if (!sel || sel.rangeCount === 0) return null;
    const text = sel.toString().trim();
    if (!text) return null;
    const range = sel.getRangeAt(0);
    const pageEl = range.commonAncestorContainer.nodeType === Node.ELEMENT_NODE
      ? range.commonAncestorContainer.closest?.('.pdf-page')
      : range.commonAncestorContainer.parentElement?.closest?.('.pdf-page');
    if (!pageEl) return null;
    const pageNum = Number(pageEl.dataset.pageNum || 0);
    const entry = currentPdfPageEntry(pageNum);
    if (!entry) return null;
    const rects = Array.from(range.getClientRects())
      .filter(r => r.width > 0 && r.height > 0)
      .map(r => {
        const pageRect = pageEl.getBoundingClientRect();
        return {
          left: (r.left - pageRect.left) / pageRect.width,
          top: (r.top - pageRect.top) / pageRect.height,
          width: r.width / pageRect.width,
          height: r.height / pageRect.height
        };
      });
    if (!rects.length) return null;
    return {
      kind: 'pdf',
      type: 'highlight',
      page: pageNum,
      rects,
      text,
      preview: `Highlight • page ${pageNum}`
    };
  }

  function pdfSelectionRect() {
    const sel = window.getSelection();
    if (!sel || sel.rangeCount === 0) return null;
    const range = sel.getRangeAt(0);
    const rect = range.getBoundingClientRect();
    if (!rect || rect.width === 0 || rect.height === 0) return null;
    return rect;
  }

  function onSelectionChange() {
    if ($('#annotation-editor').dataset.editing) return;
    const sel = window.getSelection();
    if (!sel || sel.rangeCount === 0) {
      if (!state.pointerState) hideFabAndLookup();
      return;
    }
    if (state.current.kind === 'text') {
      const text = sel.toString();
      if (!text || !state.current.raw) {
        hideFabAndLookup();
        return;
      }
      const range = sel.getRangeAt(0);
      const cap = selectionTextToPending(range);
      if (!cap) {
        hideFabAndLookup();
        return;
      }
      state.pendingSelection = cap;
      const rect = range.getBoundingClientRect();
      const canLookup = /^\S+$/.test(text.trim());
      if (window.innerWidth < 980) showFixedFloatingButtons(); else showFloatingButtons(rect, canLookup);
      if (!canLookup) $('#lookup-btn').style.display = 'none';
    } else if (state.current.kind === 'pdf' && state.pendingTool === 'select') {
      const cap = capturePdfSelection();
      if (!cap) {
        hideFabAndLookup();
        return;
      }
      state.pendingSelection = cap;
      const rect = pdfSelectionRect();
      if (rect) showFloatingButtons(rect, false);
    }
  }

  function jumpToAnnotation(ann) {
    if (state.current.kind === 'pdf') {
      const pageNum = Number(ann.page ?? 0);
      const entry = currentPdfPageEntry(pageNum);
      if (!entry) return;
      entry.pageEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      entry.pageEl.animate([{ transform: 'scale(0.995)' }, { transform: 'scale(1)' }], { duration: 500 });
      return;
    }
    const sp = document.querySelector(`[data-ann-id="${CSS.escape(String(ann.id))}"]`) || document.querySelector(`[data-start="${ann.start_idx}"]`);
    if (sp) {
      sp.scrollIntoView({ behavior: 'smooth', block: 'center' });
      sp.animate([{ boxShadow: '0 0 0 rgba(0,0,0,0)' }, { boxShadow: '0 10px 40px rgba(179,107,44,0.22)' }], { duration: 900 });
    }
  }

  function editAnnotation(ann) {
    const preview = state.current.kind === 'pdf'
      ? `Page ${Number(ann.page || 0)} • ${ann.type || 'highlight'}`
      : (ann.text || '').slice(0, 120);
    const payload = {
      kind: ann.kind || state.current.kind,
      type: ann.type || 'highlight',
      text: state.current.kind === 'pdf' ? '' : (ann.text || ''),
      note: ann.note || '',
      preview,
      editingId: ann.id,
      remoteId: annRemoteId(ann)
    };
    state.pendingSelection = ann;
    showAnnotationEditor(payload);
    $('#delete-annotation').classList.remove('hidden');
  }

  async function onAnnotationAction(ev) {
    const action = ev.currentTarget.dataset.action;
    const id = ev.currentTarget.dataset.id;
    const anns = loadAnnsLocal(state.current.filePath) || [];
    const ann = anns.find(a => String(a.id) === String(id)) || anns.find(a => String(a._remoteId) === String(id));
    if (!ann) return alert('Not found');
    if (action === 'jump') {
      jumpToAnnotation(ann);
    } else if (action === 'edit') {
      editAnnotation(ann);
    } else if (action === 'comment') {
      const rid = annRemoteId(ann);
      if (!rid) return alert('This annotation has not been saved remotely yet. Save first to enable comments.');
      state.openCommentFor = rid;
      renderAnnotations();
      fetchAndRenderCommentsFor(rid);
      setTimeout(() => {
        const t = document.getElementById(`comment-input-${rid}`);
        if (t) t.focus();
      }, 120);
    } else if (action === 'delete') {
      if (!confirm('Delete this annotation?')) return;
      const idx = anns.findIndex(a => String(a.id) === String(ann.id));
      if (idx !== -1) {
        anns.splice(idx, 1);
        saveAnnsLocal(state.current.filePath, anns);
        renderAnnotations();
      }
      try { if (ann._remoteId) await deleteAnnotationRemote(ann._remoteId); } catch (e) { console.warn('remote delete failed', e); alert('Remote delete failed'); }
    }
  }

  async function onPostComment(ev) {
    const remoteId = ev.currentTarget.dataset.remoteId;
    const ta = document.getElementById(`comment-input-${remoteId}`);
    if (!ta) return alert('Comment input not found.');
    const raw = ta.value.trim();
    if (!raw) return alert('Write something');
    const parsed = parseTaruPrefix(raw);
    const finalText = parsed.text;
    const finalAuthor = parsed.author || 'Stacy';
    try {
      await db.collection('annotations').doc(remoteId).collection('comments').add({
        text: finalText,
        author: finalAuthor,
        created_at: firebase.firestore.FieldValue.serverTimestamp()
      });
      if (!state.commentCache[remoteId]) state.commentCache[remoteId] = { status: 'loaded', items: [], lastFetched: Date.now(), lastRenderedHash: '' };
      state.commentCache[remoteId].items = state.commentCache[remoteId].items || [];
      state.commentCache[remoteId].items.push({ author: finalAuthor, text: finalText });
      state.commentCache[remoteId].lastFetched = Date.now();
      renderAnnotationComments(remoteId, state.commentCache[remoteId].items);
      ta.value = '';
      clearDraft(remoteId);
    } catch (e) {
      console.error('post comment failed', e);
      alert('Comment failed');
    }
  }

  async function saveCurrentAnnotation() {
    if (!state.current.filePath) return alert('Open a reading first.');
    const noteRaw = $('#annotation-text').value.trim();
    if (!noteRaw) return alert('Write a note.');
    const parsed = parseTaruPrefix(noteRaw);
    const finalNote = parsed.text;
    const finalAuthor = parsed.author || 'Stacy';
    const editingId = $('#annotation-editor').dataset.editing;
    const payload = state.pendingSelection;
    let anns = loadAnnsLocal(state.current.filePath) || [];

    if (editingId) {
      const idx = anns.findIndex(a => String(a.id) === String(editingId));
      if (idx === -1) return alert('Annotation not found.');
      anns[idx].note = finalNote;
      anns[idx].author = finalAuthor;
      anns[idx].edited_at = new Date().toISOString();
      saveAnnsLocal(state.current.filePath, anns);
      renderAnnotations();
      try {
        const remoteId = anns[idx]._remoteId;
        if (remoteId) {
          const updateObj = { note: finalNote, author: finalAuthor, edited_at: anns[idx].edited_at };
          const upd = await updateAnnotationRemote(remoteId, updateObj);
          if (!upd.ok) {
            try { await deleteAnnotationRemote(remoteId); } catch {}
            const newPush = await pushAnnotationToFirestore(anns[idx]);
            if (newPush.ok) {
              anns[idx]._remoteId = newPush.id;
              saveAnnsLocal(state.current.filePath, anns);
              renderAnnotations();
            }
          }
        } else {
          const res = await pushAnnotationToFirestore(anns[idx]);
          if (res.ok) {
            anns[idx]._remoteId = res.id;
            saveAnnsLocal(state.current.filePath, anns);
            renderAnnotations();
          }
        }
      } catch (e) {
        console.warn('remote edit failed', e);
      }
    } else {
      if (!payload) return alert('Select text or make a PDF mark first.');
      const nowISO = new Date().toISOString();
      const newAnn = {
        id: `${Date.now()}-${Math.floor(Math.random() * 9999)}`,
        file: state.current.filePath,
        kind: payload.kind || state.current.kind,
        type: payload.type || 'highlight',
        start_idx: payload.start_idx ?? null,
        end_idx: payload.end_idx ?? null,
        text: payload.text || '',
        page: payload.page ?? null,
        rects: payload.rects || null,
        path: payload.path || null,
        note: finalNote,
        author: finalAuthor,
        created_at: nowISO
      };
      anns.push(newAnn);
      saveAnnsLocal(state.current.filePath, anns);
      renderAnnotations();
      const res = await pushAnnotationToFirestore(newAnn);
      if (!res.ok) {
        console.warn('Firestore write failed', res.error);
        alert('Firestore write failed; saved locally.');
      } else {
        const loc = loadAnnsLocal(state.current.filePath);
        const li = loc.find(a => a.id === newAnn.id);
        if (li) {
          li._remoteId = res.id;
          saveAnnsLocal(state.current.filePath, loc);
          renderAnnotations();
        }
      }
    }

    $('#annotation-editor').classList.add('hidden');
    $('#annotation-editor').dataset.editing = '';
    state.pendingSelection = null;
    window.getSelection().removeAllRanges();
    hideFabAndLookup();
    hideAnnotationEditor();
  }

  function renderPdfJumpFlash(pageNum) {
    const entry = currentPdfPageEntry(pageNum);
    if (!entry) return;
    entry.pageEl.animate([{ boxShadow: '0 18px 40px rgba(0,0,0,0.35)' }, { boxShadow: '0 0 0 4px rgba(179,107,44,0.3)' }, { boxShadow: '0 18px 40px rgba(0,0,0,0.35)' }], { duration: 800 });
  }

  function jumpToPdfPage(pageNum) {
    const entry = currentPdfPageEntry(pageNum);
    if (!entry) return;
    entry.pageEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    renderPdfJumpFlash(pageNum);
  }

  function onDocumentClick(ev) {
    const t = ev.target;
    if (t && t.matches && t.matches('.hl')) {
      const annId = t.getAttribute('data-ann-id');
      const anns = loadAnnsLocal(state.current.filePath) || [];
      const ann = anns.find(a => String(a.id) === String(annId));
      if (ann) {
        if (state.current.kind === 'pdf') jumpToPdfPage(Number(ann.page ?? 0));
        else jumpToAnnotation(ann);
      }
    }
  }

  function onPdfHighlightClick(ev) {
    const ann = ev.target?.closest?.('[data-ann-id]');
    if (ann) {
      const anns = loadAnnsLocal(state.current.filePath) || [];
      const found = anns.find(a => String(a.id) === String(ann.dataset.annId));
      if (found) jumpToPdfPage(Number(found.page ?? 0));
    }
  }

  async function lookupDefinition(word) {
    $('#define-content').innerHTML = '<div class="muted">Looking up…</div>';
    $('#define-modal').style.display = 'block';
    try {
      const res = await fetch(`https://api.dictionaryapi.dev/api/v2/entries/en/${encodeURIComponent(word)}`);
      if (!res.ok) throw new Error('Not found');
      const data = await res.json();
      const entry = data[0] || {};
      const meanings = entry.meanings || [];
      let html = `<div style="font-weight:700">${escapeHtml(entry.word || word)} ${entry.phonetics && entry.phonetics[0] ? '(' + escapeHtml(entry.phonetics[0].text) + ')' : ''}</div>`;
      if (meanings.length > 0) {
        const m = meanings[0];
        html += `<div style="margin-top:6px;font-size:13px">${escapeHtml(m.partOfSpeech || '')}</div>`;
        const defs = m.definitions || [];
        if (defs.length > 0) {
          html += `<div style="margin-top:6px">${escapeHtml(defs[0].definition || '')}</div>`;
          if (defs[0].example) html += `<div class="muted small" style="margin-top:6px">Example: ${escapeHtml(defs[0].example)}</div>`;
        }
      } else {
        html += `<div class="muted">No meaning found.</div>`;
      }
      $('#define-content').innerHTML = html;
    } catch (e) {
      $('#define-content').innerHTML = `<div class="muted">No definition found for "${escapeHtml(word)}".</div>`;
    }
  }

  function getQuery(name) {
    return new URLSearchParams(window.location.search).get(name);
  }

  function bindEvents() {
    $('#pw-submit').addEventListener('click', () => {
      if ($('#pw-input').value === PASSWORD) {
        setUnlocked();
        hideOverlay();
        initApp();
      } else alert('Wrong password');
    });
    $('#pw-input').addEventListener('keydown', e => { if (e.key === 'Enter') $('#pw-submit').click(); });

    $('#close-define').addEventListener('click', () => { $('#define-modal').style.display = 'none'; });

    $('#cancel-annotation').addEventListener('click', () => {
      state.pendingSelection = null;
      hideAnnotationEditor();
      window.getSelection().removeAllRanges();
      hideFabAndLookup();
    });

    $('#delete-annotation').addEventListener('click', async () => {
      const editingId = $('#annotation-editor').dataset.editing;
      if (!editingId) return alert('No annotation selected for deletion');
      if (!confirm('Delete this annotation?')) return;
      let anns = loadAnnsLocal(state.current.filePath) || [];
      const idx = anns.findIndex(a => String(a.id) === String(editingId));
      const ann = anns[idx];
      if (idx !== -1) {
        anns.splice(idx, 1);
        saveAnnsLocal(state.current.filePath, anns);
        renderAnnotations();
      }
      $('#annotation-editor').dataset.editing = '';
      state.pendingSelection = null;
      try { if (ann && ann._remoteId) await deleteAnnotationRemote(ann._remoteId); } catch (e) { console.warn('remote delete failed', e); alert('Remote delete failed'); }
      hideAnnotationEditor();
    });

    $('#save-annotation').addEventListener('click', saveCurrentAnnotation);

    $('#collapse-left').addEventListener('click', async () => {
      $('#left-col').classList.toggle('collapsed');
      if (state.current.kind === 'pdf' && state.current.pdf && state.current.pdfAutoFit) {
        await fitPdfToViewport(state.current.pdf);
        setViewerMeta();
        await renderPdfPages();
      }
    });
    $('#collapse-right').addEventListener('click', async () => {
      $('#right-col').classList.toggle('collapsed');
      if (state.current.kind === 'pdf' && state.current.pdf && state.current.pdfAutoFit) {
        await fitPdfToViewport(state.current.pdf);
        setViewerMeta();
        await renderPdfPages();
      }
    });

    $('#annot-fab').addEventListener('pointerdown', ev => {
      ev.preventDefault();
      const snap = snapshotCurrentSelection();
      if (snap) state.pendingSelection = snap;
    });
    $('#annot-fab').addEventListener('click', () => {
      const payload = state.pendingSelection || snapshotCurrentSelection();
      if (!payload) return alert('No selection or mark.');
      state.pendingSelection = payload;
      const preview = payload.preview || (payload.kind === 'text' ? payload.text : `${payload.type || 'annotation'} on page ${payload.page || ''}`);
      showAnnotationEditor({ ...payload, preview, editingId: '', remoteId: '' });
      $('#annotation-text').value = '';
      $('#delete-annotation').classList.add('hidden');
      $('#right-col').classList.remove('collapsed');
      hideFabAndLookup();
    });
    $('#lookup-btn').addEventListener('pointerdown', ev => ev.preventDefault());
    $('#lookup-btn').addEventListener('click', () => {
      const sel = window.getSelection();
      if (!sel || sel.rangeCount === 0) return;
      const text = sel.toString().trim();
      if (!text) return alert('No selection.');
      lookupDefinition(text);
      hideFabAndLookup();
    });

    $$('.tool-btn[data-tool]').forEach(btn => btn.addEventListener('click', () => {
      setTool(btn.dataset.tool);
      if (state.current.kind === 'pdf') {
        $$('.pdf-overlay').forEach(ov => { ov.style.pointerEvents = state.pendingTool === 'select' ? 'none' : 'auto'; ov.classList.toggle('active', state.pendingTool !== 'select'); });
      }
      if (state.pendingTool !== 'select') {
        window.getSelection().removeAllRanges();
        hideFabAndLookup();
      }
    }));

    $('#zoom-in').addEventListener('click', async () => {
      if (state.current.kind !== 'pdf' || !state.current.pdf) return;
      state.current.pdfAutoFit = false;
      state.current.pdfScale = Math.min(2.5, Math.round((state.current.pdfScale + 0.15) * 100) / 100);
      setViewerMeta();
      await renderPdfPages();
    });
    $('#zoom-out').addEventListener('click', async () => {
      if (state.current.kind !== 'pdf' || !state.current.pdf) return;
      state.current.pdfAutoFit = false;
      state.current.pdfScale = Math.max(0.75, Math.round((state.current.pdfScale - 0.15) * 100) / 100);
      setViewerMeta();
      await renderPdfPages();
    });
    $('#zoom-reset').addEventListener('click', async () => {
      if (state.current.kind !== 'pdf' || !state.current.pdf) return;
      await fitPdfToViewport(state.current.pdf);
      setViewerMeta();
      await renderPdfPages();
    });

    document.addEventListener('selectionchange', onSelectionChange);
    document.addEventListener('pointerup', onSelectionChange);
    document.addEventListener('click', onDocumentClick);
    document.addEventListener('mousedown', e => {
      const fab = $('#annot-fab');
      const lookup = $('#lookup-btn');
      if (e.target === fab || fab.contains(e.target) || e.target === lookup || lookup.contains(e.target)) return;
      const sel = window.getSelection();
      if (!sel || sel.toString().trim() === '') hideFabAndLookup();
    });

    window.addEventListener('resize', async () => {
      if (state.current.kind === 'pdf' && state.current.pdf) {
        if (state.current.pdfAutoFit) {
          await fitPdfToViewport(state.current.pdf);
          setViewerMeta();
          await renderPdfPages();
        } else {
          renderPdfAnnotations();
        }
      }
    });
  }

  async function initApp() {
    await discoverReadings();
    const fileQuery = getQuery('file');
    if (fileQuery) {
      const match = state.readings.find(r => normalizePath(r.path) === normalizePath(fileQuery) || r.path === fileQuery);
      if (match) return loadReading(match);
      const synthetic = { path: fileQuery, title: fileQuery.split('/').pop(), download_url: `/${fileQuery}`, kind: inferKind({ path: fileQuery }) };
      return loadReading(synthetic);
    }
    if (state.readings.length > 0) return loadReading(state.readings[0]);
    $('#article').innerHTML = '<div class="muted">No readings found in /readings/. Add files or index.json.</div>';
  }

  function initPdfToolbarState() {
    setTool('box');
  }

  function enhanceTextModeHtmlHover() {
    // no-op placeholder kept for future expansion
  }

  bindEvents();
  initPdfToolbarState();
  if (!isUnlocked()) showOverlay(); else initApp();
})();
