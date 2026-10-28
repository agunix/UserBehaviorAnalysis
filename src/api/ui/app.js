/*
 * UBA dashboard
 * WARNING (security): event fields (username, command line, file path...)
 * can be controlled by the attacker. For this reason, only textContent / title should be used for writing to the DOM;
 * do not use innerHTML, insertAdjacentHTML or similar.
 */
(() => {
  "use strict";

  const REFRESH_MS = 15000;
  const EVENT_LIMIT = 300;
  const FAIL_EVENTS = new Set(["LogonFailure", "LinuxLoginFailure"]);
  const CAT_CLASSES = new Set([
    "auth", "process", "filesystem", "network",
    "privilege", "persistence", "process_injection", "account_mgmt",
  ]);

  const $ = (id) => document.getElementById(id);
  const nf = new Intl.NumberFormat();

  let timer = null;
  let loading = false;
  let pending = false;
  let events = [];
  let lastMeta = null;

  // ---------- DOM helpers ----------
  function clear(node) { node.textContent = ""; }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function cell(text, cls, title) {
    const td = el("td", cls || "", text);
    if (title) td.title = String(title);
    return td;
  }

  function badgeCell(text, cls) {
    const td = document.createElement("td");
    td.appendChild(el("span", "badge " + cls, text));
    return td;
  }

  // ---------- Format ----------
  function fmtTime(ts) {
    const d = new Date(ts);
    if (!ts || isNaN(d.getTime())) return { text: ts || "–", title: "" };
    return { text: d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }), title: d.toISOString() };
  }

  function fmtBucket(iso, seconds) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    if (seconds >= 3600) return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" });
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function catClass(cat) { return "cat-" + (CAT_CLASSES.has(cat) ? cat : "other"); }

  function detailText(ev) {
    const proc = ev.process_name || "";
    if (ev.destination_ip) {
      return (proc ? proc + " → " : "") + ev.destination_ip + (ev.destination_port ? ":" + ev.destination_port : "");
    }
    if (ev.dns_query) return (proc ? proc + " → " : "") + ev.dns_query;
    if (ev.command_line) return ev.command_line;
    if (ev.target_filename) return ev.target_filename;
    if (ev.target_object) return ev.target_object;
    return proc;
  }

  // ---------- Status / banner ----------
  function setStatus(kind, text) {
    $("status-dot").className = "dot dot-" + kind;
    $("status-text").textContent = text;
  }

  function setBanner(kind, msg) {
    const b = $("banner");
    if (!msg) { b.hidden = true; b.textContent = ""; b.className = "banner"; return; }
    b.className = "banner " + kind;
    b.textContent = msg;
    b.hidden = false;
  }

  // ---------- Network ----------
  async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" });
    if (!r.ok) {
      let msg = r.status + " " + r.statusText;
      try {
        const j = await r.json();
        if (typeof j.detail === "string") msg = j.detail;
        else if (Array.isArray(j.detail)) msg = j.detail.map((d) => d.msg).join("; ");
      } catch (_) { /* body not JSON */ }
      throw new Error(msg);
    }
    return r.json();
  }

  // ---------- Render ----------
  function renderKpis(summary) {
    $("kpi-total").textContent = nf.format(summary.total);
    $("kpi-sources").textContent = "Windows " + nf.format(summary.by_source.windows) + " · Linux " + nf.format(summary.by_source.linux);
    $("kpi-fail").textContent = nf.format(summary.kpis.auth_failures);
    $("kpi-users").textContent = nf.format(summary.kpis.unique_users);
    $("kpi-ips").textContent = nf.format(summary.kpis.unique_source_ips);
  }

  function renderBars(id, items) {
    const box = $(id);
    clear(box);
    if (!items.length) { box.appendChild(el("p", "empty", "Məlumat yoxdur")); return; }
    const max = Math.max(1, ...items.map((i) => i.count));
    for (const it of items) {
      const row = el("div", "bar-row");
      const label = el("span", "bar-label", it.name);
      label.title = it.name;
      const track = el("div", "bar-track");
      const fill = el("div", "bar-fill");
      fill.style.width = ((100 * it.count) / max).toFixed(1) + "%";
      track.appendChild(fill);
      row.append(label, track, el("span", "bar-count", nf.format(it.count)));
      box.appendChild(row);
    }
  }

  function renderTimeline(tl) {
    const box = $("timeline");
    const axis = $("timeline-axis");
    clear(box);
    clear(axis);
    const buckets = tl.buckets || [];
    const max = Math.max(1, ...buckets.map((b) => b.total));
    for (const b of buckets) {
      const col = el("div", "tl-col");
      col.title = fmtBucket(b.t, tl.bucket_seconds) + " — " + nf.format(b.total) + " event, " + nf.format(b.auth_failures) + " failed login";
      const bad = el("div", "tl-seg tl-bad");
      bad.style.height = ((100 * b.auth_failures) / max).toFixed(1) + "%";
      const ok = el("div", "tl-seg tl-ok");
      ok.style.height = ((100 * (b.total - b.auth_failures)) / max).toFixed(1) + "%";
      col.append(bad, ok);
      box.appendChild(col);
    }
    if (buckets.length) {
      const mid = buckets[Math.floor(buckets.length / 2)];
      for (const b of [buckets[0], mid, buckets[buckets.length - 1]]) {
        axis.appendChild(el("span", "", fmtBucket(b.t, tl.bucket_seconds)));
      }
    }
  }

  function toggleRaw(tr, ev) {
    if (tr._rawRow) { tr._rawRow.remove(); tr._rawRow = null; return; }
    const { _hay, ...rest } = ev;
    const raw = el("tr", "raw");
    const td = el("td");
    td.colSpan = 8;
    td.appendChild(el("pre", "", JSON.stringify(rest, null, 2)));
    raw.appendChild(td);
    tr.after(raw);
    tr._rawRow = raw;
  }

  function buildRow(ev) {
    const tr = el("tr", "ev" + (FAIL_EVENTS.has(ev.event_name) ? " row-bad" : ""));
    tr.tabIndex = 0;
    const t = fmtTime(ev.timestamp);
    tr.appendChild(cell(t.text, "nowrap", t.title));
    tr.appendChild(badgeCell(ev.source === "linux" ? "Linux" : "Windows", ev.source === "linux" ? "src-linux" : "src-windows"));
    tr.appendChild(badgeCell(ev.category || "–", catClass(ev.category)));
    tr.appendChild(cell(ev.event_name || "–"));
    tr.appendChild(cell(ev.user || "–"));
    tr.appendChild(cell(ev.source_ip || "–"));
    const d = detailText(ev);
    tr.appendChild(cell(d || "–", "detail", d));
    tr.appendChild(cell(ev.computer || "–"));
    tr.addEventListener("click", () => toggleRaw(tr, ev));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleRaw(tr, ev); }
    });
    return tr;
  }

  function renderEvents() {
    const q = $("search").value.trim().toLowerCase();
    const rows = q ? events.filter((e) => e._hay.includes(q)) : events;
    const body = $("events-body");
    clear(body);
    $("events-count").textContent = "(" + nf.format(rows.length) + (q ? " / " + nf.format(events.length) : "") + ")";
    if (!rows.length) {
      const tr = el("tr");
      const td = cell(events.length ? "Filtrə uyğun event yoxdur" : "Bu pəncərədə event tapılmadı", "empty");
      td.colSpan = 8;
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    const frag = document.createDocumentFragment();
    for (const ev of rows) frag.appendChild(buildRow(ev));
    body.appendChild(frag);
  }

  function render(data) {
    lastMeta = data.meta;
    renderKpis(data.summary);
    renderTimeline(data.summary.timeline);
    renderBars("categories", data.summary.by_category);
    renderBars("top-users", data.summary.top_users);
    renderBars("top-ips", data.summary.top_source_ips);
    renderBars("top-hosts", data.summary.top_hosts);
    events = data.events.map((e) => {
      e._hay = [e.timestamp, e.source, e.category, e.event_name, e.user, e.source_ip, e.computer,
        e.process_name, e.command_line, e.target_filename, e.target_object, e.dns_query, e.destination_ip]
        .filter(Boolean).join(" ").toLowerCase();
      return e;
    });
    renderEvents();
  }

  // ---------- Installation ----------
  async function load() {
    if (loading) { pending = true; return; }
    loading = true;
    setStatus("load", "Loading…");
    const minutes = $("sel-window").value;
    const source = $("sel-source").value;
    const url = "/api/overview?minutes=" + encodeURIComponent(minutes) + "&source=" + encodeURIComponent(source) + "&limit=" + EVENT_LIMIT;
    try {
      const [ov, hl] = await Promise.allSettled([getJSON(url), getJSON("/api/health")]);
      if (ov.status === "fulfilled") {
        render(ov.value);
        const idx = hl.status === "fulfilled" ? hl.value.indexer : null;
        setStatus("ok", idx && idx.ok ? "Indexer OK" + (idx.version ? " · " + idx.version : "") : "Indexer OK");
        const m = ov.value.meta;
        if (m.truncated) {
          setBanner("warn", "Pəncərədə " + nf.format(m.total_in_window) + " event var; yalnız ən yeni " + nf.format(m.analyzed_events) + " təhlil olundu. Daha dəqiq nəticə üçün pəncərəni daraldın.");
        } else {
          setBanner("", "");
        }
        $("updated").textContent = "· yeniləndi " + new Date().toLocaleTimeString();
      } else {
        setStatus("err", "Error");
        setBanner("err", ov.reason && ov.reason.message ? ov.reason.message : "Unknown error");
      }
    } catch (e) {
      setStatus("err", "Error");
      setBanner("err", e && e.message ? e.message : "Unknown error");
    } finally {
      loading = false;
      if (pending) { pending = false; load(); }
    }
  }

  function setAuto() {
    if (timer) { clearInterval(timer); timer = null; }
    if ($("chk-auto").checked) {
      timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    }
  }

  function init() {
    $("sel-window").addEventListener("change", load);
    $("sel-source").addEventListener("change", load);
    $("btn-refresh").addEventListener("click", load);
    $("chk-auto").addEventListener("change", setAuto);
    $("search").addEventListener("input", renderEvents);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && $("chk-auto").checked) load();
    });
    setAuto();
    load();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
