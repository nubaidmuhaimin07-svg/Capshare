/* CapShare browser transfer page. Plain JavaScript, no framework, no inline handlers
   (the Content-Security-Policy forbids inline scripts).
   Every button calls a real backend route; nothing here decides permissions - the
   server does, and the page only displays what the server returned. */
"use strict";

const $ = (id) => document.getElementById(id);
const state = { csrf: null, user: null, timer: null };

// ---------------------------------------------------------------- helpers
function toast(message, bad) {
  const el = $("toast");
  el.textContent = message;
  el.className = "toast" + (bad ? " bad" : "");
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, bad ? 7000 : 3500);
}

async function api(path, options = {}) {
  const opts = Object.assign({ credentials: "same-origin", headers: {} }, options);
  if (opts.method && opts.method !== "GET" && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
  if (opts.json !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) {
    const msg = data && data.error ? data.error.message : "request failed (" + res.status + ")";
    const err = new Error(msg);
    err.status = res.status;
    err.code = data && data.error ? data.error.code : "";
    throw err;
  }
  return data;
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KiB";
  return (n / 1048576).toFixed(1) + " MiB";
}
function el(tag, props, ...kids) {
  const node = document.createElement(tag);
  Object.assign(node, props || {});
  kids.flat().forEach((k) => node.append(k));
  return node;
}
function chip(text, cls) { return el("span", { className: "chip " + (cls || ""), textContent: text }); }

// ---------------------------------------------------------------- session
async function boot() {
  try {
    const me = await api("/api/me");
    if (me.user) enter(me); else $("loginView").hidden = false;
  } catch (e) {
    $("loginView").hidden = false;
  }
}

function enter(me) {
  state.csrf = me.csrf_token;
  state.user = me.user;
  $("whoName").textContent = me.user.display_name;
  $("who").hidden = false;
  $("loginView").hidden = true;
  $("appView").hidden = false;
  refresh();
  clearInterval(state.timer);
  state.timer = setInterval(refresh, 2000);
}

$("loginForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("loginError").textContent = "";
  try {
    const res = await api("/api/login", { method: "POST",
      json: { username: $("username").value, password: $("password").value } });
    $("password").value = "";
    enter(res);
  } catch (e) {
    $("loginError").textContent = e.message;
  }
});

$("logoutBtn").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) { /* ignore */ }
  clearInterval(state.timer);
  state.csrf = null;
  $("appView").hidden = true;
  $("who").hidden = true;
  $("loginView").hidden = false;
});

// ---------------------------------------------------------------- rendering
async function refresh() {
  if (!state.csrf) return;                 // signed out
  try {
    const [files, transfers, grants] = await Promise.all([
      api("/api/files"), api("/api/transfers"), api("/api/grants")]);
    renderFiles(files.files);
    renderTransfers(transfers.transfers);
    renderGrants(grants.grants);
  } catch (e) {
    if (e.status === 401) { location.reload(); }
  }
}

function renderFiles(files) {
  const box = $("fileList");
  if (!files.length) {
    box.replaceChildren(el("p", { className: "muted", textContent: "No files are shared with you yet." }));
    return;
  }
  box.replaceChildren(...files.map((f) => {
    const perms = f.my_actions.length
      ? f.my_actions.map((a) => chip(a, "ok")) : [chip("no active access", "bad")];
    const expiries = Object.entries(f.my_expiry || {}).map(([action, t]) =>
      chip(action + (t === null ? " · permanent" : " · until t=" + t), "warn"));
    const actions = el("div", { className: "actions" });
    const dl = el("button", { className: "primary", textContent: "Download",
                              disabled: !f.my_actions.includes("READ") });
    dl.addEventListener("click", () => download(f));
    actions.append(dl);
    if (f.my_actions.includes("WRITE")) {
      const label = el("label", { className: "file-btn", textContent: "Replace content" });
      const input = el("input", { type: "file", hidden: true });
      input.addEventListener("change", () => input.files[0] && upload(input.files[0],
        "/api/files/" + f.id + "/content", "PUT"));
      label.append(input);
      actions.append(label);
    }
    return el("div", { className: "file" },
      el("div", { className: "name", textContent: f.name }),
      el("div", { className: "meta" },
        el("span", { textContent: "owner: " + f.owner_display }),
        el("span", { textContent: fmtSize(f.size) }),
        el("span", { textContent: "owner clock: t=" + f.clock })),
      el("div", { className: "chips" }, ...perms, ...expiries),
      actions);
  }));
}

function renderTransfers(rows) {
  const body = $("transferTable").querySelector("tbody");
  body.replaceChildren(...rows.slice(0, 15).map((t) => {
    const pct = t.bytes_total ? Math.min(100, Math.round(100 * t.bytes_done / t.bytes_total)) : (t.state === "completed" ? 100 : 0);
    const cls = t.state === "completed" ? "ok" : (t.state === "active" ? "" : "bad");
    return el("tr", {},
      el("td", { textContent: t.file_name }),
      el("td", { textContent: t.direction === "download" ? "download" : "upload" }),
      el("td", {}, chip(t.state, cls)),
      el("td", { textContent: pct + "% (" + fmtSize(t.bytes_done) + ")" }),
      el("td", { textContent: t.note || "" }));
  }));
}

function renderGrants(rows) {
  const mine = rows.filter((g) => g.recipient_id === state.user.id);
  const body = $("grantTable").querySelector("tbody");
  body.replaceChildren(...mine.map((g) => el("tr", {},
    el("td", { textContent: "#" + g.id }),
    el("td", { textContent: g.file_name }),
    el("td", { textContent: g.grantor_name }),
    el("td", { textContent: g.actions.join(" + ") }),
    el("td", { textContent: g.can_delegate ? "yes" : "no" }),
    el("td", { textContent: g.expires_at === null ? "never" : "t=" + g.expires_at }),
    el("td", {}, chip(g.status, g.status === "active" ? "ok" : "bad")))));
}

// ---------------------------------------------------------------- actions
async function download(f) {
  try {
    // Ask the SAME decision function the download route uses, so a denial is explained
    // in-page instead of the browser showing a raw JSON error page.
    const d = await api("/api/access/check", { method: "POST",
      json: { file_id: f.id, user_id: state.user.id, action: "READ" } });
    if (!d.allowed) { toast(d.reason, true); return; }
    window.location.href = "/api/files/" + f.id + "/download";
  } catch (e) { toast(e.message, true); }
}

function upload(file, url, method) {
  const xhr = new XMLHttpRequest();
  const bar = $("uploadProgress");
  bar.hidden = false;
  bar.firstElementChild.style.width = "0";
  xhr.upload.onprogress = (ev) => {
    if (ev.lengthComputable) bar.firstElementChild.style.width = (100 * ev.loaded / ev.total) + "%";
  };
  xhr.onload = () => {
    bar.hidden = true;
    if (xhr.status >= 200 && xhr.status < 300) toast("Upload finished: " + file.name);
    else {
      let msg = "upload failed";
      try { msg = JSON.parse(xhr.responseText).error.message; } catch (e) { /* keep default */ }
      toast(msg, true);
    }
    refresh();
  };
  xhr.onerror = () => { bar.hidden = true; toast("Upload interrupted (the capability may have been revoked).", true); refresh(); };
  xhr.open(method, url);
  xhr.setRequestHeader("X-CSRF-Token", state.csrf);
  xhr.setRequestHeader("Content-Type", "application/octet-stream");
  xhr.send(file);
}

$("newFile").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (f) upload(f, "/api/files?name=" + encodeURIComponent(f.name), "POST");
  ev.target.value = "";
});

boot();
