const APP_PASSWORD = "Stacy";
const READINGS_PATH = "readings";

const state = {
  locked: false,
  readings: [],
  filteredReadings: [],
  current: null,
  currentType: null,
  currentRaw: "",
  textDisplayMap: [],
  textDisplay: "",
  annotations: [],
  selectedAnnotationId: null,
  draft: null,
  mode: "select",
  zoom: 1,
  pdfDoc: null,
  pageBoxes: new Map(),
  renderToken: 0,
  libraryFilter: "all",
  replyingTo: null,
  pageInteraction: null,
  firebase: {
    enabled: false,
    db: null,
    unsubscribe: null,
    syncTimer: null,
    syncInFlight: false,
    hydrateToken: 0,
    hydrateCache: new Map(),
    lastRemoteHash: ""
  }
};

const DOM = {};
function $(sel, root = document) { return root.querySelector(sel); }
function $all(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }
function ce(tag, className = "", html = "") {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (html) el.innerHTML = html;
  return el;
}
function uid(prefix = "id") {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}_${Date.now().toString(36)}`;
}
function nowISO() { return new Date().toISOString(); }
function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
function normalizePath(p) {
  return String(p || "").replace(/^\/+/, "");
}
function extOf(path) {
  const clean = normalizePath(path);
  const m = clean.toLowerCase().match(/\.([a-z0-9]+)$/);
  return m ? m[1] : "";
}
function fileDocType(path) {
  return extOf(path) === "pdf" ? "pdf" : "text";
}
function fileStorageKey(path) {
  return `reading-annotations::${normalizePath(path)}`;
}
function formatDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}
function toast(msg) {
  const el = DOM.toast;
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.style.display = "none"; }, 1800);
}
function currentReadingUrl(item) {
  if (!item) return "";
  if (item.download_url) return item.download_url;
  return `./${normalizePath(item.path)}`;
}
function loadLocalAnnotations(path) {
  try {
    const raw = localStorage.getItem(fileStorageKey(path));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn("loadLocalAnnotations failed", err);
    return [];
  }
}
function saveLocalAnnotations(path, annotations) {
  try {
    localStorage.setItem(fileStorageKey(path), JSON.stringify(annotations));
  } catch (err) {
    console.warn("saveLocalAnnotations failed", err);
  }
}
function persistAnnotations() {
  if (!state.current) return;
  saveLocalAnnotations(state.current.path, state.annotations.map(a => JSON.parse(JSON.stringify(a))));
  queueRemoteAnnotationSync();
}

function hasRealFirebaseConfig(config) {
  if (!config || typeof config !== "object") return false;
  const required = ["apiKey", "authDomain", "projectId", "appId"];
  return required.every((key) => {
    const value = String(config[key] || "").trim();
    return value && !/^YOUR_|^FILL_ME_IN/i.test(value);
  });
}

function normalizeFirebaseConfig(config) {
  if (!config || typeof config !== "object") return null;
  return { ...config };
}

function canUseFirestore() {
  return Boolean(state.firebase.enabled && state.firebase.db && state.current);
}

function fileAnnotationQuery(path) {
  return state.firebase.db.collection("annotations").where("file", "==", normalizePath(path));
}

function commentSnapshotToArray(snapshot) {
  const items = [];
  snapshot.forEach((doc) => {
    const data = doc.data() || {};
    items.push({
      id: data.id || doc.id,
      author: data.author || "Anonymous",
      text: data.text || "",
      replyTo: data.replyTo || null,
      createdAt: data.createdAt || data.created_at?.toDate?.()?.toISOString?.() || data.created_at || nowISO(),
      updatedAt: data.updatedAt || data.createdAt || nowISO()
    });
  });
  items.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  return items;
}

function commentPayloadForFirestore(comment) {
  return {
    id: comment.id || uid("c"),
    author: comment.author || "Anonymous",
    text: comment.text || "",
    replyTo: comment.replyTo || null,
    createdAt: comment.createdAt || nowISO(),
    updatedAt: comment.updatedAt || comment.createdAt || nowISO()
  };
}

function annotationPayloadForFirestore(ann) {
  const geometry = ann.geometry ? JSON.parse(JSON.stringify(ann.geometry)) : null;
  const comments = Array.isArray(ann.comments) ? ann.comments.map(commentPayloadForFirestore) : [];
  const payload = {
    id: ann.id,
    file: normalizePath(ann.file || state.current?.path || ""),
    docType: ann.docType || fileDocType(ann.file || state.current?.path || ""),
    type: ann.type || "highlight",
    page: ann.page ?? null,
    geometry,
    excerpt: ann.excerpt || "",
    note: ann.note || "",
    author: ann.author || "Stacy",
    color: ann.color || "#b46b2d",
    resolved: Boolean(ann.resolved),
    createdAt: ann.createdAt || nowISO(),
    updatedAt: ann.updatedAt || nowISO(),
    comments,
    start_idx: geometry?.start_idx ?? geometry?.start ?? null,
    end_idx: geometry?.end_idx ?? geometry?.end ?? null,
    text: ann.excerpt || "",
    created_at: ann.createdAt || nowISO(),
    updated_at: ann.updatedAt || nowISO()
  };
  return JSON.parse(JSON.stringify(payload));
}

function normalizeRemoteAnnotation(docSnap, comments = []) {
  const data = docSnap.data() || {};
  const createdAt = data.createdAt || data.created_at?.toDate?.()?.toISOString?.() || data.created_at || nowISO();
  const updatedAt = data.updatedAt || data.updated_at?.toDate?.()?.toISOString?.() || data.updated_at || createdAt;
  const geometry = data.geometry || null;
  const inferredType = data.type || (data.page ? "rect" : (geometry?.points ? "pen" : "highlight"));
  return normalizeAnnotation({
    id: docSnap.id,
    file: data.file || state.current?.path || "",
    docType: data.docType || fileDocType(data.file || state.current?.path || ""),
    type: inferredType,
    page: data.page ?? null,
    geometry,
    excerpt: data.excerpt || data.text || "",
    note: data.note || "",
    author: data.author || "Stacy",
    color: data.color || "#b46b2d",
    resolved: Boolean(data.resolved),
    createdAt,
    updatedAt,
    comments: comments.length ? comments : (Array.isArray(data.comments) ? data.comments : [])
  });
}

async function loadLegacyComments(docSnap) {
  try {
    const subSnap = await docSnap.ref.collection("comments").get();
    if (subSnap.empty) return [];
    return commentSnapshotToArray(subSnap);
  } catch (err) {
    console.warn("loadLegacyComments failed", err);
    return [];
  }
}

async function hydrateRemoteAnnotation(docSnap) {
  const data = docSnap.data() || {};
  if (Array.isArray(data.comments) && data.comments.length) {
    return normalizeRemoteAnnotation(docSnap, data.comments);
  }
  const legacyComments = await loadLegacyComments(docSnap);
  return normalizeRemoteAnnotation(docSnap, legacyComments);
}

async function syncAnnotationCommentsToRemote(ann) {
  if (!canUseFirestore()) return;
  const comments = Array.isArray(ann.comments) ? ann.comments : [];
  const commentsCol = state.firebase.db.collection("annotations").doc(String(ann.id)).collection("comments");
  await Promise.allSettled(comments.map((comment) => {
    const payload = commentPayloadForFirestore(comment);
    return commentsCol.doc(String(payload.id)).set(payload, { merge: true });
  }));
}


async function deleteAnnotationRemote(annotationId) {
  if (!canUseFirestore()) return;
  const docRef = state.firebase.db.collection("annotations").doc(String(annotationId));
  try {
    const commentsSnap = await docRef.collection("comments").get();
    await Promise.all(commentsSnap.docs.map((doc) => doc.ref.delete()));
  } catch (err) {
    console.warn("deleteAnnotationRemote comments cleanup failed", err);
  }
  await docRef.delete();
}

async function syncOneAnnotationToRemote(ann) {
  if (!canUseFirestore()) return;
  const docRef = state.firebase.db.collection("annotations").doc(String(ann.id));
  const payload = annotationPayloadForFirestore(ann);
  await docRef.set(payload, { merge: true });
  await syncAnnotationCommentsToRemote(ann);
}

async function syncAllAnnotationsToRemoteNow() {
  if (!canUseFirestore() || state.firebase.syncInFlight) return;
  state.firebase.syncInFlight = true;
  try {
    await Promise.allSettled(state.annotations.map(syncOneAnnotationToRemote));
    state.firebase.lastRemoteHash = JSON.stringify(state.annotations.map(a => [a.id, a.updatedAt, a.resolved, (a.comments || []).length]));
  } catch (err) {
    console.warn("syncAllAnnotationsToRemoteNow failed", err);
  } finally {
    state.firebase.syncInFlight = false;
  }
}

function queueRemoteAnnotationSync() {
  if (!canUseFirestore()) return;
  clearTimeout(state.firebase.syncTimer);
  state.firebase.syncTimer = setTimeout(() => {
    syncAllAnnotationsToRemoteNow();
  }, 250);
}

function clearRemoteAnnotationSync() {
  if (state.firebase.unsubscribe) {
    try { state.firebase.unsubscribe(); } catch (err) { console.warn(err); }
  }
  state.firebase.unsubscribe = null;
  clearTimeout(state.firebase.syncTimer);
  state.firebase.syncTimer = null;
}

function startRemoteAnnotationSync(path) {
  clearRemoteAnnotationSync();
  if (!state.current || !state.firebase.enabled || !state.firebase.db || !path) return;
  const filePath = normalizePath(path);
  const token = ++state.firebase.hydrateToken;
  try {
    state.firebase.unsubscribe = fileAnnotationQuery(filePath).onSnapshot(async (snapshot) => {
      const hydrated = await Promise.all(snapshot.docs.map(hydrateRemoteAnnotation));
      if (token !== state.firebase.hydrateToken) return;
      hydrated.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      const currentHash = JSON.stringify(hydrated.map(a => [a.id, a.updatedAt, a.resolved, (a.comments || []).length]));
      if (currentHash === state.firebase.lastRemoteHash) return;
      state.firebase.lastRemoteHash = currentHash;
      state.annotations = hydrated.map(normalizeAnnotation);
      saveLocalAnnotations(filePath, state.annotations);
      renderAnnotationList();
      rerenderViewer();
      if (state.draft) {
        const live = state.annotations.find(a => String(a.id) === String(state.draft.id));
        if (live) state.draft = live;
      }
    }, (err) => {
      console.error("Firestore snapshot error", err);
      toast("Firestore sync paused; using local cache.");
    });
  } catch (err) {
    console.warn("startRemoteAnnotationSync failed", err);
  }
}

async function initFirebase() {
  const cfg = normalizeFirebaseConfig(window.FIREBASE_CONFIG);
  if (!cfg || !hasRealFirebaseConfig(cfg) || !window.firebase) {
    state.firebase.enabled = false;
    state.firebase.db = null;
    console.info("Firebase sync disabled: add real Firebase config in index.html to enable Firestore.");
    return;
  }
  try {
    if (!firebase.apps || !firebase.apps.length) firebase.initializeApp(cfg);
    state.firebase.db = firebase.firestore();
    state.firebase.enabled = true;
  } catch (err) {
    console.warn("Firebase initialization failed", err);
    state.firebase.enabled = false;
    state.firebase.db = null;
  }
}
function showPasswordIfNeeded() {
  const passed = sessionStorage.getItem("reading-unlocked") === "1";
  if (APP_PASSWORD && !passed) {
    DOM.passwordModal.style.display = "flex";
    state.locked = true;
  } else {
    DOM.passwordModal.style.display = "none";
    state.locked = false;
  }
}
function unlock() {
  sessionStorage.setItem("reading-unlocked", "1");
  state.locked = false;
  DOM.passwordModal.style.display = "none";
  init();
}
function selectionTextWithin(el) {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0) return null;
  const range = selection.getRangeAt(0);
  if (!range || !el.contains(range.commonAncestorContainer)) return null;
  const text = selection.toString();
  if (!text.trim()) return null;
  return { selection, range, text };
}

function buildDisplayMapping(raw) {
  const displayToRawMap = [];
  let displayText = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "\n") continue;
    displayText += ch;
    displayToRawMap.push(i);
  }
  return { displayText, displayToRawMap };
}
function buildAnnotatedHtml(text, annotations) {
  const anns = (annotations || [])
    .map(a => ({ ...a, start_idx: Number(a.start_idx ?? a.start), end_idx: Number(a.end_idx ?? a.end) }))
    .filter(a => Number.isFinite(a.start_idx) && Number.isFinite(a.end_idx) && a.end_idx > a.start_idx)
    .sort((a, b) => a.start_idx - b.start_idx || String(a.id).localeCompare(String(b.id)));

  let html = "";
  let cursor = 0;
  for (const ann of anns) {
    if (ann.start_idx > cursor) html += escapeHtml(text.slice(cursor, ann.start_idx)).replaceAll("\n", "<br>");
    const excerpt = text.slice(ann.start_idx, ann.end_idx);
    const active = String(ann.id) === String(state.selectedAnnotationId) ? " active" : "";
    html += `<span class="highlight${active}" data-ann-id="${escapeHtml(ann.id)}">${escapeHtml(excerpt).replaceAll("\n", "<br>")}</span>`;
    cursor = ann.end_idx;
  }
  if (cursor < text.length) html += escapeHtml(text.slice(cursor)).replaceAll("\n", "<br>");
  return html || "";
}
function displayOffsetFromRange(range, root) {
  try {
    const container = root || DOM.viewerHost;
    const r = document.createRange();
    r.setStart(container, 0);
    r.setEnd(range.startContainer, range.startOffset);
    return r.toString().length;
  } catch {
    return null;
  }
}
function displayToRawRange(displayStart, length) {
  const map = state.textDisplayMap || [];
  const text = state.textDisplay || "";
  if (displayStart == null) return null;
  const start = Math.max(0, Math.min(text.length, displayStart));
  const endIndex = Math.max(0, Math.min(text.length - 1, displayStart + Math.max(0, length) - 1));
  const rawStart = map[start];
  const rawEndBase = map[endIndex];
  const rawEnd = rawEndBase == null ? undefined : rawEndBase + 1;
  if (rawStart == null || rawEnd == null || rawEnd <= rawStart) return null;
  return { start_idx: rawStart, end_idx: rawEnd };
}
function rangeToRawSelection(range) {
  const displayStart = displayOffsetFromRange(range, DOM.viewerHost);
  if (displayStart == null) return null;
  const rawRange = displayToRawRange(displayStart, range.toString().length);
  if (!rawRange) return null;
  const text = state.currentRaw.slice(rawRange.start_idx, rawRange.end_idx);
  return { ...rawRange, text };
}
function commentsFlat(ann) {
  return Array.isArray(ann.comments) ? ann.comments.slice() : [];
}
function commentCount(ann) {
  return commentsFlat(ann).length;
}
function makeDefaultAnnotation(partial) {
  return {
    id: uid("ann"),
    file: state.current.path,
    docType: state.currentType,
    type: partial.type || "highlight",
    page: partial.page || null,
    geometry: partial.geometry || null,
    excerpt: partial.excerpt || "",
    note: partial.note || "",
    author: partial.author || "Stacy",
    color: partial.color || "#b46b2d",
    resolved: Boolean(partial.resolved),
    createdAt: partial.createdAt || nowISO(),
    updatedAt: nowISO(),
    comments: Array.isArray(partial.comments) ? partial.comments : []
  };
}
function normalizeAnnotation(ann) {
  const copy = JSON.parse(JSON.stringify(ann));
  copy.id = copy.id || uid("ann");
  copy.file = copy.file || (state.current?.path || "");
  copy.docType = copy.docType || fileDocType(copy.file);
  copy.type = copy.type || (copy.geometry?.points ? "pen" : copy.page ? "rect" : "highlight");
  copy.page = copy.page || null;
  copy.geometry = copy.geometry || null;
  copy.excerpt = copy.excerpt || "";
  copy.note = copy.note || "";
  copy.author = copy.author || "Stacy";
  copy.color = copy.color || "#b46b2d";
  copy.resolved = Boolean(copy.resolved);
  copy.createdAt = copy.createdAt || nowISO();
  copy.updatedAt = copy.updatedAt || copy.createdAt;
  copy.comments = Array.isArray(copy.comments) ? copy.comments : [];
  return copy;
}
function selectedAnnotation() {
  return state.annotations.find(a => String(a.id) === String(state.selectedAnnotationId)) || null;
}
function summarizeAnnotation(ann) {
  const loc = ann.page ? `Page ${ann.page}` : "Text selection";
  const type = ann.type ? ann.type[0].toUpperCase() + ann.type.slice(1) : "Highlight";
  const snippet = ann.excerpt || ann.note || "No preview yet";
  return `${type} · ${loc} · ${snippet.slice(0, 160)}${snippet.length > 160 ? "…" : ""}`;
}
function annotationLabel(ann) {
  const page = ann.page ? `p. ${ann.page}` : "text";
  const type = ann.type || "highlight";
  const author = ann.author ? ` · ${ann.author}` : "";
  return `${page} · ${type}${author}`;
}
function annotationExcerpt(ann) {
  const base = ann.excerpt || ann.note || "";
  if (base.length <= 180) return base;
  return base.slice(0, 180) + "…";
}
function closeEditor() {
  state.draft = null;
  state.selectedAnnotationId = null;
  DOM.editor.hidden = true;
  DOM.deleteAnn.hidden = true;
  DOM.editorPreview.textContent = "Select an annotation to edit.";
  DOM.annNote.value = "";
  DOM.annAuthor.value = "";
  DOM.annType.value = "highlight";
  DOM.annStatus.value = "open";
  DOM.annColor.value = "#b46b2d";
  DOM.annLocationTag.textContent = "No annotation selected";
  DOM.commentThread.innerHTML = "";
  DOM.commentBody.value = "";
  DOM.commentAuthor.value = "";
  DOM.commentReplyTarget.textContent = "";
  state.replyingTo = null;
  clearSelectionBubble();
  rerenderViewer();
  renderAnnotationList();
}
function openEditor(ann, { focus = false } = {}) {
  if (!ann) return;
  state.selectedAnnotationId = ann.id;
  state.draft = JSON.parse(JSON.stringify(ann));
  DOM.editor.hidden = false;
  DOM.deleteAnn.hidden = false;
  DOM.editorPreview.textContent = summarizeAnnotation(ann);
  DOM.annAuthor.value = ann.author || "";
  DOM.annColor.value = ann.color || "#b46b2d";
  DOM.annType.value = ann.type || "highlight";
  DOM.annStatus.value = ann.resolved ? "resolved" : "open";
  DOM.annNote.value = ann.note || "";
  DOM.annLocationTag.textContent = annotationLabel(ann);
  renderAnnotationList();
  renderAnnotationEditorPanel();
  rerenderViewer();
  if (focus) DOM.annNote.focus();
}
function renderAnnotationEditorPanel() {
  const ann = selectedAnnotation();
  if (!ann) {
    DOM.editor.hidden = true;
    return;
  }
  DOM.editor.hidden = false;
  DOM.editorPreview.textContent = summarizeAnnotation(ann);
  DOM.annAuthor.value = ann.author || "";
  DOM.annColor.value = ann.color || "#b46b2d";
  DOM.annType.value = ann.type || "highlight";
  DOM.annStatus.value = ann.resolved ? "resolved" : "open";
  DOM.annNote.value = ann.note || "";
  DOM.annLocationTag.textContent = annotationLabel(ann);
  DOM.deleteAnn.hidden = false;
  DOM.commentThread.innerHTML = "";
  const comments = commentsTree(ann);
  if (comments.length === 0) {
    DOM.commentThread.appendChild(ce("div", "empty-state", "No comments yet."));
  } else {
    comments.forEach(c => DOM.commentThread.appendChild(c));
  }
}
function commentsTree(ann) {
  const comments = commentsFlat(ann).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const byId = new Map(comments.map(c => [String(c.id), c]));
  const children = new Map();
  for (const c of comments) {
    if (!c.replyTo) continue;
    const key = String(c.replyTo);
    if (!children.has(key)) children.set(key, []);
    children.get(key).push(c);
  }
  const roots = comments.filter(c => !c.replyTo);
  function renderComment(c, depth = 0) {
    const wrap = ce("div", `comment${depth > 0 ? " reply" : ""}`);
    if (c.replyTo) {
      const target = byId.get(String(c.replyTo));
      if (target) wrap.appendChild(ce("div", "reply-indicator", `Replying to ${escapeHtml(target.author || "someone")}`));
    }
    const meta = ce("div", "meta");
    meta.innerHTML = `<div class="author">${escapeHtml(c.author || "Anonymous")}</div><div>${escapeHtml(formatDate(c.createdAt))}</div>`;
    wrap.appendChild(meta);
    wrap.appendChild(ce("div", "body", escapeHtml(c.text || "").replaceAll("\n", "<br>")));
    const actions = ce("div", "actions");
    const replyBtn = ce("button", "mini", "Reply");
    replyBtn.addEventListener("click", () => {
      state.replyingTo = c.id;
      DOM.commentReplyTarget.textContent = `Replying to ${c.author || "Anonymous"}`;
      DOM.commentBody.focus();
      toast("Reply target set");
    });
    actions.appendChild(replyBtn);
    wrap.appendChild(actions);
    const kids = children.get(String(c.id)) || [];
    kids.forEach(k => wrap.appendChild(renderComment(k, depth + 1)));
    return wrap;
  }
  return roots.map(renderComment);
}
function updateAnnotationFromDraft() {
  const ann = state.draft;
  if (!ann) return null;
  ann.author = DOM.annAuthor.value.trim() || "Stacy";
  ann.type = DOM.annType.value;
  ann.color = DOM.annColor.value || "#b46b2d";
  ann.resolved = DOM.annStatus.value === "resolved";
  ann.note = DOM.annNote.value.trim();
  ann.updatedAt = nowISO();
  const idx = state.annotations.findIndex(a => String(a.id) === String(ann.id));
  if (idx >= 0) state.annotations[idx] = ann;
  else state.annotations.push(ann);
  persistAnnotations();
  renderAnnotationList();
  rerenderViewer();
  return ann;
}
function addCommentToAnnotation(annotationId, payload) {
  const ann = state.annotations.find(a => String(a.id) === String(annotationId));
  if (!ann) return null;
  ann.comments = Array.isArray(ann.comments) ? ann.comments : [];
  ann.comments.push({
    id: uid("c"),
    author: payload.author || "Anonymous",
    text: payload.text || "",
    replyTo: payload.replyTo || null,
    createdAt: nowISO()
  });
  ann.updatedAt = nowISO();
  persistAnnotations();
  renderAnnotationList();
  rerenderViewer();
  return ann;
}
async function removeAnnotation(annotationId) {
  const idx = state.annotations.findIndex(a => String(a.id) === String(annotationId));
  if (idx < 0) return;
  const [removed] = state.annotations.splice(idx, 1);
  persistAnnotations();
  if (canUseFirestore() && removed) {
    try {
      await deleteAnnotationRemote(removed.id);
    } catch (err) {
      console.warn("deleteAnnotationRemote failed", err);
    }
  }
  state.selectedAnnotationId = null;
  state.draft = null;
  renderAnnotationList();
  rerenderViewer();
  closeEditor();
}
function renderAnnotationList() {
  const list = DOM.annotationList;
  list.innerHTML = "";
  if (!state.current) {
    list.appendChild(ce("div", "empty-state", "Open a reading to see annotations."));
    return;
  }
  const filters = {
    type: DOM.filterType.value,
    status: DOM.filterStatus.value,
    page: DOM.filterPage.value.trim(),
    search: DOM.filterSearch.value.trim().toLowerCase()
  };
  let items = state.annotations.slice().sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  if (filters.type !== "all") items = items.filter(a => a.type === filters.type);
  if (filters.status !== "all") items = items.filter(a => (a.resolved ? "resolved" : "open") === filters.status);
  if (filters.page) {
    const pageNum = Number(filters.page);
    if (Number.isFinite(pageNum)) items = items.filter(a => Number(a.page) === pageNum);
  }
  if (filters.search) {
    items = items.filter(a => {
      const hay = [
        a.note,
        a.excerpt,
        a.author,
        a.type,
        a.page,
        ...(a.comments || []).flatMap(c => [c.text, c.author])
      ].join(" ").toLowerCase();
      return hay.includes(filters.search);
    });
  }
  if (items.length === 0) {
    list.appendChild(ce("div", "empty-state", "No annotations match the current filters."));
    return;
  }
  for (const ann of items) {
    const card = ce("div", `annotation-card${String(ann.id) === String(state.selectedAnnotationId) ? " active" : ""}`);
    card.dataset.id = ann.id;
    const head = ce("div", "head");
    const left = ce("div");
    left.innerHTML = `<div class="name">${escapeHtml(ann.type?.toUpperCase() || "ANNOTATION")}</div><div class="page">${escapeHtml(annotationLabel(ann))}</div>`;
    const right = ce("div");
    right.innerHTML = `<span class="tag ${ann.resolved ? "resolved" : "open"}">${ann.resolved ? "Resolved" : "Open"}</span>`;
    head.appendChild(left);
    head.appendChild(right);
    card.appendChild(head);
    card.appendChild(ce("div", "excerpt", escapeHtml(annotationExcerpt(ann)).replaceAll("\n", "<br>")));
    const foot = ce("div", "foot");
    foot.appendChild(ce("span", "tag", `${commentCount(ann)} comments`));
    if (ann.page) foot.appendChild(ce("span", "tag", `Page ${ann.page}`));
    if (ann.author) foot.appendChild(ce("span", "tag", ann.author));
    card.appendChild(foot);
    const actions = ce("div", "toolbar");
    const jump = ce("button", "btn", "Jump");
    jump.addEventListener("click", (e) => { e.stopPropagation(); jumpToAnnotation(ann); });
    const edit = ce("button", "btn", "Edit");
    edit.addEventListener("click", (e) => { e.stopPropagation(); openEditor(ann, { focus: true }); });
    const reply = ce("button", "btn", "Comment");
    reply.addEventListener("click", (e) => { e.stopPropagation(); openEditor(ann, { focus: true }); DOM.commentBody.focus(); });
    const resolve = ce("button", "btn", ann.resolved ? "Reopen" : "Resolve");
    resolve.addEventListener("click", (e) => {
      e.stopPropagation();
      ann.resolved = !ann.resolved;
      ann.updatedAt = nowISO();
      persistAnnotations();
      renderAnnotationList();
      rerenderViewer();
    });
    const del = ce("button", "btn danger", "Delete");
    del.addEventListener("click", (e) => { e.stopPropagation(); if (confirm("Delete this annotation?")) Promise.resolve(removeAnnotation(ann.id)); });
    actions.append(jump, edit, reply, resolve, del);
    card.appendChild(actions);
    card.addEventListener("click", () => openEditor(ann, { focus: false }));
    list.appendChild(card);
  }
  renderAnnotationEditorPanel();
}
function jumpToAnnotation(ann) {
  if (!ann) return;
  state.selectedAnnotationId = ann.id;
  renderAnnotationList();
  rerenderViewer();
  if (state.currentType === "text") {
    const el = DOM.viewerHost.querySelector(`[data-ann-id="${CSS.escape(String(ann.id))}"]`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.animate([{ boxShadow: "0 0 0 rgba(0,0,0,0)" }, { boxShadow: "0 0 0 4px rgba(180,107,45,0.18)" }], { duration: 500 });
    }
  } else if (state.currentType === "pdf") {
    const page = DOM.viewerHost.querySelector(`[data-page="${ann.page}"]`);
    if (page) {
      page.scrollIntoView({ behavior: "smooth", block: "center" });
      setTimeout(() => {
        const mark = page.querySelector(`[data-ann-id="${CSS.escape(String(ann.id))}"]`);
        if (mark) mark.animate([{ transform: "scale(1)" }, { transform: "scale(1.02)" }, { transform: "scale(1)" }], { duration: 500 });
      }, 500);
    }
  }
}
function clearSelectionBubble() {
  DOM.selectionBubble.hidden = true;
}
function showSelectionBubble(x, y) {
  DOM.selectionBubble.hidden = false;
  DOM.selectionBubble.style.left = `${Math.max(12, x)}px`;
  DOM.selectionBubble.style.top = `${Math.max(12, y)}px`;
}
function pdfPointToLocal(pageWrap, clientX, clientY) {
  const rect = pageWrap.getBoundingClientRect();
  return { x: clientX - rect.left, y: clientY - rect.top, width: rect.width, height: rect.height };
}
function rectFromPoints(a, b) {
  return { x: Math.min(a.x, b.x), y: Math.min(a.y, b.y), w: Math.abs(b.x - a.x), h: Math.abs(b.y - a.y) };
}
function normalizeRect(rect, width, height) {
  return { x: rect.x / width, y: rect.y / height, w: rect.w / width, h: rect.h / height };
}
function denormalizeRect(rect, width, height) {
  return { x: rect.x * width, y: rect.y * height, w: rect.w * width, h: rect.h * height };
}
function normalizePoint(pt, width, height) {
  return { x: pt.x / width, y: pt.y / height };
}
function denormalizePoint(pt, width, height) {
  return { x: pt.x * width, y: pt.y * height };
}
function pointDistance(a, b) {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

async function loadReadings() {
  const indexUrl = `./${READINGS_PATH}/index.json`;
  try {
    const res = await fetch(indexUrl, { cache: "no-store" });
    if (!res.ok) throw new Error(`failed to load ${indexUrl}`);
    const list = await res.json();
    state.readings = list.map(item => {
      if (typeof item === "string") {
        return { path: item, title: item.split("/").pop(), type: fileDocType(item) };
      }
      const path = item.path || "";
      return { path, title: item.title || path.split("/").pop(), download_url: item.download_url || "", type: item.type || fileDocType(path) };
    });
    state.filteredReadings = state.readings.slice();
    renderLibrary();
  } catch (err) {
    console.error(err);
    DOM.readingList.innerHTML = `<div class="empty-state">No readings found in <code>${escapeHtml(indexUrl)}</code>.</div>`;
  }
}
function filterReadings() {
  const q = DOM.librarySearch.value.trim().toLowerCase();
  const type = state.libraryFilter;
  state.filteredReadings = state.readings.filter(item => {
    const matchesQ = !q || `${item.title} ${item.path}`.toLowerCase().includes(q);
    const matchesType = type === "all" || item.type === type;
    return matchesQ && matchesType;
  });
  renderLibrary();
}
function renderLibrary() {
  const host = DOM.readingList;
  host.innerHTML = "";
  if (!state.filteredReadings.length) {
    host.appendChild(ce("div", "empty-state", "No readings match this filter."));
    return;
  }
  for (const item of state.filteredReadings) {
    const card = ce("div", `doc-card${state.current && state.current.path === item.path ? " active" : ""}`);
    card.innerHTML = `
      <div class="doc-title">${escapeHtml(item.title)}</div>
      <div class="doc-meta">
        <span class="pill">${escapeHtml(item.type || fileDocType(item.path))}</span>
        <span class="pill">${escapeHtml(item.path.split("/").pop())}</span>
      </div>
    `;
    card.addEventListener("click", () => openReading(item));
    host.appendChild(card);
  }
}
function showPdfToolbar(show) {
  DOM.pdfToolbar.hidden = !show;
}
function setTool(tool) {
  state.mode = tool;
  $all('[data-tool]', DOM.pdfToolbar).forEach(btn => btn.classList.toggle("active", btn.dataset.tool === tool));
  if (state.currentType === "pdf") {
    DOM.viewerHost.querySelectorAll(".pdf-overlay").forEach(overlay => {
      overlay.classList.toggle("interactive", tool !== "select");
    });
  }
}
async function openReading(item) {
  if (!item) return;
  state.current = item;
  state.currentType = item.type || fileDocType(item.path);
  state.selectedAnnotationId = null;
  state.draft = null;
  state.replyingTo = null;
  state.annotations = loadLocalAnnotations(item.path).map(normalizeAnnotation);
  DOM.commentReplyTarget.textContent = "";
  DOM.commentBody.value = "";
  DOM.commentAuthor.value = "";
  DOM.centerBody.scrollTop = 0;
  DOM.viewerHost.innerHTML = "";
  setDocMeta(item.title || item.path.split("/").pop(), normalizePath(item.path));
  DOM.docKindBadge.textContent = state.currentType === "pdf" ? "PDF document" : "Text reading";
  DOM.editor.hidden = true;
  clearSelectionBubble();
  renderAnnotationList();
  if (state.currentType === "pdf") {
    setBadge("PDF mode");
    showPdfToolbar(true);
    setTool(state.mode || "select");
    await openPdfReading(item);
  } else {
    setBadge("Text mode");
    showPdfToolbar(false);
    setTool("select");
    await openTextReading(item);
  }
  if (state.firebase.enabled && state.firebase.db) {
    startRemoteAnnotationSync(item.path);
  } else {
    clearRemoteAnnotationSync();
  }
  renderLibrary();
}
async function openTextReading(item) {
  const url = currentReadingUrl(item);
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`Failed to load ${url}`);
    const raw = await res.text();
    state.currentRaw = raw;
    const mapping = buildDisplayMapping(raw);
    state.textDisplay = mapping.displayText;
    state.textDisplayMap = mapping.displayToRawMap;
    renderTextViewer();
    attachTextSelectionHandlers();
    toast("Text reading loaded");
  } catch (err) {
    console.error(err);
    DOM.viewerHost.innerHTML = `<div class="text-empty">Unable to load <code>${escapeHtml(url)}</code>.</div>`;
  }
}
function renderTextViewer() {
  const host = DOM.viewerHost;
  const anns = state.annotations.filter(a => a.docType !== "pdf");
  const wrap = ce("div", "text-document");
  wrap.innerHTML = buildAnnotatedHtml(state.currentRaw, anns) || `<div class="text-empty">No text found in this reading.</div>`;
  host.innerHTML = "";
  host.appendChild(wrap);
}
function attachTextSelectionHandlers() {
  const host = DOM.viewerHost;
  host.onmouseup = () => {
    if (!state.current || state.currentType !== "text") return;
    const sel = selectionTextWithin(host);
    if (!sel) {
      clearSelectionBubble();
      return;
    }
    const rawSel = rangeToRawSelection(sel.range);
    if (!rawSel) {
      clearSelectionBubble();
      return;
    }
    const rect = sel.range.getBoundingClientRect();
    const x = rect.left + window.scrollX + rect.width / 2 - 70;
    const y = rect.top + window.scrollY - 52;
    state.pageInteraction = { kind: "text", ...rawSel };
    showSelectionBubble(x, y);
  };
}
function createTextAnnotationFromSelection() {
  const draft = state.pageInteraction;
  if (!draft || draft.kind !== "text") return;
  const ann = makeDefaultAnnotation({
    docType: "text",
    type: "highlight",
    page: null,
    geometry: { start_idx: draft.start_idx, end_idx: draft.end_idx },
    excerpt: draft.text,
    note: "",
    comments: []
  });
  ann.start_idx = draft.start_idx;
  ann.end_idx = draft.end_idx;
  ann.excerpt = draft.text;
  state.annotations.push(ann);
  persistAnnotations();
  state.selectedAnnotationId = ann.id;
  state.draft = ann;
  state.pageInteraction = null;
  clearSelectionBubble();
  renderAnnotationList();
  renderTextViewer();
  openEditor(ann, { focus: true });
  toast("Annotation created");
}
async function openPdfReading(item) {
  try {
    if (!window.pdfjsLib) throw new Error("PDF.js failed to load");
    const url = currentReadingUrl(item);
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`Failed to load PDF: ${url}`);
    const bytes = await res.arrayBuffer();
    const loadingTask = pdfjsLib.getDocument({ data: bytes });
    state.pdfDoc = await loadingTask.promise;
    state.pageBoxes.clear();
    await renderPdfDocument();
    toast("PDF loaded");
  } catch (err) {
    console.error(err);
    DOM.viewerHost.innerHTML = `<div class="text-empty">Unable to render this PDF.</div>`;
  }
}
async function renderPdfDocument() {
  const token = ++state.renderToken;
  const host = DOM.viewerHost;
  host.innerHTML = "";
  const stack = ce("div", "pdf-stack");
  host.appendChild(stack);
  for (let pageNum = 1; pageNum <= state.pdfDoc.numPages; pageNum++) {
    if (token !== state.renderToken) return;
    await renderPdfPage(pageNum, stack, token);
  }
  rerenderPdfOverlays();
  setTool(state.mode || "select");
}
async function renderPdfPage(pageNum, stack, token) {
  const page = await state.pdfDoc.getPage(pageNum);
  if (token !== state.renderToken) return;
  const dpr = window.devicePixelRatio || 1;
  const displayViewport = page.getViewport({ scale: state.zoom });
  const renderViewport = page.getViewport({ scale: state.zoom * dpr });
  const shell = ce("div", "pdf-page-shell");
  shell.dataset.page = String(pageNum);
  const pageWrap = ce("div", "pdf-page");
  pageWrap.style.width = `${displayViewport.width}px`;
  pageWrap.style.height = `${displayViewport.height}px`;
  const canvas = ce("canvas");
  const ctx = canvas.getContext("2d", { alpha: false });
  canvas.width = Math.floor(renderViewport.width);
  canvas.height = Math.floor(renderViewport.height);
  canvas.style.width = `${displayViewport.width}px`;
  canvas.style.height = `${displayViewport.height}px`;
  const num = ce("div", "page-number", `Page ${pageNum}`);
  const overlay = ce("div", "pdf-overlay");
  overlay.dataset.page = String(pageNum);
  overlay.style.width = `${displayViewport.width}px`;
  overlay.style.height = `${displayViewport.height}px`;
  pageWrap.appendChild(canvas);
  pageWrap.appendChild(overlay);
  pageWrap.appendChild(num);
  shell.appendChild(pageWrap);
  stack.appendChild(shell);
  state.pageBoxes.set(pageNum, { pageNum, shell, pageWrap, overlay, width: displayViewport.width, height: displayViewport.height });
  const renderTask = page.render({ canvasContext: ctx, viewport: renderViewport, transform: [1, 0, 0, 1, 0, 0] });
  await renderTask.promise;
  if (token !== state.renderToken) return;
  attachPdfOverlayHandlers(overlay, pageNum);
}
function rerenderPdfOverlays() {
  if (state.currentType !== "pdf") return;
  for (const [pageNum, box] of state.pageBoxes.entries()) {
    renderPdfAnnotationsForPage(pageNum, box);
  }
}
function currentPdfAnnotationsForPage(pageNum) {
  return state.annotations.filter(a => Number(a.page) === Number(pageNum));
}
function renderPdfAnnotationsForPage(pageNum, box) {
  const anns = currentPdfAnnotationsForPage(pageNum);
  box.overlay.innerHTML = "";
  for (const ann of anns) {
    if (ann.type === "pen" && ann.geometry?.points?.length) {
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", `0 0 ${box.width} ${box.height}`);
      svg.setAttribute("preserveAspectRatio", "none");
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      const pts = ann.geometry.points.map(p => denormalizePoint(p, box.width, box.height));
      const d = pts.length ? `M ${pts[0].x} ${pts[0].y} ` + pts.slice(1).map(p => `L ${p.x} ${p.y}`).join(" ") : "";
      path.setAttribute("d", d);
      path.setAttribute("stroke", ann.color || "#b46b2d");
      if (String(ann.id) === String(state.selectedAnnotationId)) path.classList.add("annotation-active");
      svg.appendChild(path);
      const wrap = ce("div", "pdf-ink");
      wrap.dataset.annId = ann.id;
      wrap.style.position = "absolute";
      wrap.style.inset = "0";
      wrap.style.pointerEvents = "auto";
      wrap.appendChild(svg);
      wrap.addEventListener("click", (e) => { e.stopPropagation(); openEditor(ann); });
      box.overlay.appendChild(wrap);
      continue;
    }
    if (ann.type === "note" && ann.geometry?.point) {
      const pt = denormalizePoint(ann.geometry.point, box.width, box.height);
      const pin = ce("div", `pdf-note-pin${String(ann.id) === String(state.selectedAnnotationId) ? " annotation-active" : ""}`);
      pin.dataset.annId = ann.id;
      pin.style.left = `${pt.x}px`;
      pin.style.top = `${pt.y}px`;
      pin.title = ann.note || "Note";
      pin.addEventListener("click", (e) => { e.stopPropagation(); openEditor(ann); });
      box.overlay.appendChild(pin);
      continue;
    }
    const rects = Array.isArray(ann.geometry?.rects) ? ann.geometry.rects : ann.geometry?.rect ? [ann.geometry.rect] : [];
    for (const rect of rects) {
      const px = denormalizeRect(rect, box.width, box.height);
      const div = ce("div", ann.type === "highlight" ? "pdf-highlight" : "pdf-rect");
      if (String(ann.id) === String(state.selectedAnnotationId)) div.classList.add("annotation-active");
      div.dataset.annId = ann.id;
      div.style.left = `${px.x}px`;
      div.style.top = `${px.y}px`;
      div.style.width = `${Math.max(2, px.w)}px`;
      div.style.height = `${Math.max(2, px.h)}px`;
      if (ann.type === "highlight") {
        const color = ann.color || "#b46b2d";
        div.style.background = `${color}33`;
        div.style.borderColor = color;
      } else {
        div.style.borderColor = ann.color || "#b46b2d";
      }
      div.addEventListener("click", (e) => { e.stopPropagation(); openEditor(ann); });
      box.overlay.appendChild(div);
    }
  }
}
function attachPdfOverlayHandlers(overlay, pageNum) {
  if (!overlay) return;
  overlay.classList.toggle("interactive", state.mode !== "select");
  overlay.onpointerdown = null;
  overlay.onpointermove = null;
  overlay.onpointerup = null;
  overlay.onpointercancel = null;
  if (state.mode === "select") {
    overlay.style.pointerEvents = "none";
    return;
  }
  overlay.style.pointerEvents = "auto";
  let drawing = null;
  overlay.onpointerdown = (e) => {
    const box = state.pageBoxes.get(pageNum);
    if (!box) return;
    const p = pdfPointToLocal(box.pageWrap, e.clientX, e.clientY);
    if (state.mode === "note") {
      drawing = { pageNum, tool: "note", start: p };
      return;
    }
    if (state.mode === "pen") {
      drawing = { pageNum, tool: "pen", points: [normalizePoint({ x: p.x, y: p.y }, box.width, box.height)] };
      overlay.setPointerCapture(e.pointerId);
      drawPdfDraft(box, drawing);
      return;
    }
    if (state.mode === "rect" || state.mode === "highlight") {
      drawing = { pageNum, tool: state.mode, start: p, current: p };
      overlay.setPointerCapture(e.pointerId);
      drawPdfDraft(box, drawing);
      return;
    }
  };
  overlay.onpointermove = (e) => {
    if (!drawing) return;
    const box = state.pageBoxes.get(pageNum);
    if (!box) return;
    const p = pdfPointToLocal(box.pageWrap, e.clientX, e.clientY);
    if (drawing.tool === "pen") {
      const last = drawing.points[drawing.points.length - 1];
      const newPoint = normalizePoint({ x: p.x, y: p.y }, box.width, box.height);
      if (!last || pointDistance(denormalizePoint(last, box.width, box.height), p) >= 3) {
        drawing.points.push(newPoint);
        drawPdfDraft(box, drawing);
      }
      return;
    }
    drawing.current = p;
    drawPdfDraft(box, drawing);
  };
  overlay.onpointerup = async (e) => {
    if (!drawing) return;
    const box = state.pageBoxes.get(pageNum);
    if (!box) return;
    if (drawing.tool === "note") {
      const p = pdfPointToLocal(box.pageWrap, e.clientX, e.clientY);
      const noteAnn = makeDefaultAnnotation({
        docType: "pdf",
        type: "note",
        page: pageNum,
        geometry: { point: normalizePoint({ x: p.x, y: p.y }, box.width, box.height) },
        excerpt: `Page ${pageNum} note`,
        note: "",
        comments: []
      });
      state.annotations.push(noteAnn);
      persistAnnotations();
      state.selectedAnnotationId = noteAnn.id;
      state.draft = noteAnn;
      renderAnnotationList();
      rerenderViewer();
      openEditor(noteAnn, { focus: true });
      drawing = null;
      return;
    }
    if (drawing.tool === "pen") {
      if (drawing.points.length < 2) {
        drawing = null;
        rerenderPdfOverlays();
        return;
      }
      const penAnn = makeDefaultAnnotation({
        docType: "pdf",
        type: "pen",
        page: pageNum,
        geometry: { points: drawing.points },
        excerpt: `Pen mark on page ${pageNum}`,
        note: "",
        comments: []
      });
      state.annotations.push(penAnn);
      persistAnnotations();
      state.selectedAnnotationId = penAnn.id;
      state.draft = penAnn;
      renderAnnotationList();
      rerenderViewer();
      openEditor(penAnn, { focus: true });
      drawing = null;
      return;
    }
    if (drawing.tool === "rect" || drawing.tool === "highlight") {
      const rect = rectFromPoints({ x: drawing.start.x, y: drawing.start.y }, { x: drawing.current.x, y: drawing.current.y });
      if (rect.w < 5 || rect.h < 5) {
        drawing = null;
        rerenderPdfOverlays();
        return;
      }
      const rectAnn = makeDefaultAnnotation({
        docType: "pdf",
        type: drawing.tool,
        page: pageNum,
        geometry: { rects: [normalizeRect(rect, box.width, box.height)] },
        excerpt: `Page ${pageNum} ${drawing.tool}`,
        note: "",
        comments: []
      });
      state.annotations.push(rectAnn);
      persistAnnotations();
      state.selectedAnnotationId = rectAnn.id;
      state.draft = rectAnn;
      renderAnnotationList();
      rerenderViewer();
      openEditor(rectAnn, { focus: true });
      drawing = null;
      return;
    }
  };
  overlay.onpointercancel = () => {
    drawing = null;
    rerenderPdfOverlays();
  };
}
function drawPdfDraft(box, drawing) {
  rerenderPdfOverlays();
  if (!drawing) return;
  const draft = ce("div", `pdf-draft ${drawing.tool || "rect"}`);
  if (drawing.tool === "pen") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${box.width} ${box.height}`);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    const pts = drawing.points.map(p => denormalizePoint(p, box.width, box.height));
    const d = pts.length ? `M ${pts[0].x} ${pts[0].y} ` + pts.slice(1).map(p => `L ${p.x} ${p.y}`).join(" ") : "";
    path.setAttribute("d", d);
    svg.appendChild(path);
    draft.appendChild(svg);
    draft.style.left = "0";
    draft.style.top = "0";
    draft.style.right = "0";
    draft.style.bottom = "0";
    draft.style.position = "absolute";
    draft.style.inset = "0";
    box.overlay.appendChild(draft);
    return;
  }
  const rect = rectFromPoints(drawing.start, drawing.current);
  draft.style.left = `${rect.x}px`;
  draft.style.top = `${rect.y}px`;
  draft.style.width = `${rect.w}px`;
  draft.style.height = `${rect.h}px`;
  box.overlay.appendChild(draft);
}
function rerenderViewer() {
  if (!state.current) return;
  if (state.currentType === "text") renderTextViewer();
  if (state.currentType === "pdf") rerenderPdfOverlays();
  renderAnnotationEditorPanel();
  $all(".annotation-card", DOM.annotationList).forEach(card => card.classList.toggle("active", String(card.dataset.id) === String(state.selectedAnnotationId)));
}
function setZoom(next) {
  const value = Math.min(3, Math.max(0.5, Number(next) || 1));
  state.zoom = Math.round(value * 10) / 10;
  DOM.zoomValue.value = String(state.zoom);
  if (state.currentType === "pdf" && state.pdfDoc) renderPdfDocument();
}
function handleSelectedAnnotationBubble() {
  if (!state.pageInteraction) return;
  if (state.pageInteraction.kind === "text") createTextAnnotationFromSelection();
}
function bindEvents() {
  if (state.eventsBound) return;
  state.eventsBound = true;
  DOM.toggleLeft.addEventListener("click", () => { DOM.leftPanel.style.display = DOM.leftPanel.style.display === "none" ? "" : "none"; });
  DOM.toggleRight.addEventListener("click", () => { DOM.rightPanel.style.display = DOM.rightPanel.style.display === "none" ? "" : "none"; });
  DOM.collapseLeft.addEventListener("click", () => { DOM.leftPanel.style.display = "none"; });
  DOM.collapseRight.addEventListener("click", () => { DOM.rightPanel.style.display = "none"; });
  DOM.librarySearch.addEventListener("input", filterReadings);
  $all("#library-types .chip").forEach(chip => {
    chip.addEventListener("click", () => {
      state.libraryFilter = chip.dataset.type || "all";
      $all("#library-types .chip").forEach(c => c.classList.toggle("active", c === chip));
      filterReadings();
    });
  });
  DOM.filterType.addEventListener("change", renderAnnotationList);
  DOM.filterStatus.addEventListener("change", renderAnnotationList);
  DOM.filterPage.addEventListener("input", renderAnnotationList);
  DOM.filterSearch.addEventListener("input", renderAnnotationList);
  DOM.saveAnn.addEventListener("click", () => {
    if (!state.draft) return;
    updateAnnotationFromDraft();
    toast("Annotation saved");
  });
  DOM.cancelAnn.addEventListener("click", closeEditor);
  DOM.deleteAnn.addEventListener("click", () => {
    const ann = selectedAnnotation();
    if (!ann) return;
    if (!confirm("Delete this annotation?")) return;
    Promise.resolve(removeAnnotation(ann.id)).then(() => toast("Annotation deleted"));
  });
  DOM.bubbleAnnotate.addEventListener("click", handleSelectedAnnotationBubble);
  DOM.bubbleCancel.addEventListener("click", () => {
    state.pageInteraction = null;
    clearSelectionBubble();
    const sel = window.getSelection();
    if (sel) sel.removeAllRanges();
  });
  DOM.zoomIn.addEventListener("click", () => setZoom(state.zoom + 0.1));
  DOM.zoomOut.addEventListener("click", () => setZoom(state.zoom - 0.1));
  DOM.fitWidth.addEventListener("click", () => {
    if (state.currentType !== "pdf" || !state.pdfDoc) return;
    const first = state.pageBoxes.values().next().value;
    if (!first) return;
    const centerWidth = DOM.centerBody.clientWidth - 36;
    const docWidthAtZoom1 = first.width / state.zoom;
    const target = Math.max(0.5, Math.min(3, centerWidth / docWidthAtZoom1));
    setZoom(target);
  });
  $all("[data-tool]", DOM.pdfToolbar).forEach(btn => {
    btn.addEventListener("click", () => {
      setTool(btn.dataset.tool);
      rerenderPdfOverlays();
    });
  });
  DOM.zoomValue.addEventListener("change", () => setZoom(Number(DOM.zoomValue.value)));
  DOM.passwordInput.addEventListener("keydown", e => { if (e.key === "Enter") DOM.passwordSubmit.click(); });
  DOM.passwordSubmit.addEventListener("click", () => {
    if (DOM.passwordInput.value === APP_PASSWORD) unlock();
    else { toast("Wrong password"); DOM.passwordInput.value = ""; }
  });
  window.addEventListener("resize", () => {
    if (state.currentType === "pdf" && state.pdfDoc) renderPdfDocument();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      clearSelectionBubble();
      const sel = window.getSelection();
      if (sel) sel.removeAllRanges();
    }
  });
  document.addEventListener("mousedown", (e) => {
    if (DOM.selectionBubble.hidden) return;
    if (DOM.selectionBubble.contains(e.target)) return;
    if (DOM.viewerHost.contains(e.target)) return;
    clearSelectionBubble();
  });
  DOM.viewerHost.addEventListener("click", (e) => {
    const annId = e.target?.dataset?.annId;
    if (!annId) return;
    const ann = state.annotations.find(a => String(a.id) === String(annId));
    if (ann) openEditor(ann);
  });
}
function openReadingByQuery() {
  const params = new URLSearchParams(location.search);
  const file = params.get("file");
  if (!file) return null;
  const clean = normalizePath(file);
  return state.readings.find(r => normalizePath(r.path) === clean || r.download_url === file) || null;
}
async function init() {
  await initFirebase();
  showPasswordIfNeeded();
  if (state.locked) return;
  await loadReadings();
  const q = openReadingByQuery();
  if (q) await openReading(q);
  else if (state.readings[0]) await openReading(state.readings[0]);
}
function bindGlobals() {
  DOM.leftPanel = $("#left-panel");
  DOM.rightPanel = $("#right-panel");
  DOM.toggleLeft = $("#toggle-left");
  DOM.toggleRight = $("#toggle-right");
  DOM.collapseLeft = $("#collapse-left");
  DOM.collapseRight = $("#collapse-right");
  DOM.librarySearch = $("#library-search");
  DOM.readingList = $("#reading-list");
  DOM.viewerHost = $("#viewer-host");
  DOM.centerBody = $("#center-body");
  DOM.docTitle = $("#doc-title");
  DOM.docSubtitle = $("#doc-subtitle");
  DOM.docKindBadge = $("#doc-kind-badge");
  DOM.pdfToolbar = $("#pdf-toolbar");
  DOM.zoomOut = $("#zoom-out");
  DOM.zoomIn = $("#zoom-in");
  DOM.zoomValue = $("#zoom-value");
  DOM.fitWidth = $("#fit-width");
  DOM.annotationList = $("#annotation-list");
  DOM.editor = $("#editor");
  DOM.editorPreview = $("#editor-preview");
  DOM.annAuthor = $("#ann-author");
  DOM.annColor = $("#ann-color");
  DOM.annType = $("#ann-type");
  DOM.annStatus = $("#ann-status");
  DOM.annNote = $("#ann-note");
  DOM.annLocationTag = $("#ann-location-tag");
  DOM.saveAnn = $("#save-ann");
  DOM.cancelAnn = $("#cancel-ann");
  DOM.deleteAnn = $("#delete-ann");
  DOM.filterType = $("#filter-type");
  DOM.filterStatus = $("#filter-status");
  DOM.filterPage = $("#filter-page");
  DOM.filterSearch = $("#filter-search");
  DOM.selectionBubble = $("#selection-bubble");
  DOM.bubbleAnnotate = $("#bubble-annotate");
  DOM.bubbleCancel = $("#bubble-cancel");
  DOM.passwordModal = $("#password-modal");
  DOM.passwordInput = $("#password-input");
  DOM.passwordSubmit = $("#password-submit");
  DOM.toast = $("#toast");
  DOM.commentThread = $("#comment-thread");
  DOM.commentBody = $("#comment-body");
  DOM.commentAuthor = $("#comment-author");
  DOM.commentReplyTarget = $("#reply-target");
}
function bindCommentComposer() {
  const addBtn = $("#add-comment");
  const clearBtn = $("#clear-reply");
  addBtn.addEventListener("click", () => {
    const ann = selectedAnnotation();
    if (!ann) return;
    const text = DOM.commentBody.value.trim();
    if (!text) return toast("Write a comment");
    addCommentToAnnotation(ann.id, {
      author: DOM.commentAuthor.value.trim() || "Anonymous",
      text,
      replyTo: state.replyingTo || null
    });
    if (canUseFirestore()) queueRemoteAnnotationSync();
    DOM.commentBody.value = "";
    state.replyingTo = null;
    DOM.commentReplyTarget.textContent = "";
    DOM.commentBody.focus();
    renderAnnotationEditorPanel();
  });
  clearBtn.addEventListener("click", () => {
    state.replyingTo = null;
    DOM.commentReplyTarget.textContent = "";
  });
}
document.addEventListener("DOMContentLoaded", async () => {
  bindGlobals();
  bindCommentComposer();
  bindEvents();
  showPasswordIfNeeded();
  if (state.locked) return;
  renderAnnotationEditorPanel();
  await init();
});
