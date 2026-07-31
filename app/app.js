// SPDX-License-Identifier: AGPL-3.0-or-later
// habitable — thin, accessible shell over the loopback JSON API. No frameworks.
"use strict";

(function () {
  var LANG_KEY = "habitable.lang";
  var TOKEN_KEY = "habitable.token";
  var SUPPORTED = ["en", "es"];
  var DEFAULT_LANG = "en";
  // Right-to-left scripts. When one of these is active we flip the document
  // direction so the (logical-property) CSS mirrors correctly. Currently no RTL
  // bundle ships, but the plumbing is in place ahead of one (R-48).
  var RTL_LANGS = ["ar", "he", "fa", "ur"];

  var strings = {}; // active dictionary
  var lang = DEFAULT_LANG;
  var sessionToken = ""; // per-session API auth token (FIX-03)

  // ---- i18n ----------------------------------------------------------------

  function t(key) {
    return Object.prototype.hasOwnProperty.call(strings, key) ? strings[key] : key;
  }

  // Real pluralization + locale formatting (FIX-12). Dictionary values may use
  // an ICU-MessageFormat subset — "{name}" placeholders and
  // "{name, plural, =N {...} one {...} many {...} other {...}}" with "#" for
  // the formatted count — rendered against the browser's CLDR data via
  // Intl.PluralRules / Intl.NumberFormat / Intl.DateTimeFormat. No library:
  // the app stays dependency-free and the browser already ships the rules.

  function pluralCategory(n) {
    try {
      return new Intl.PluralRules(lang).select(n);
    } catch (e) {
      return n === 1 ? "one" : "other"; // last-resort English-ish fallback
    }
  }

  function formatNumber(n) {
    try {
      return new Intl.NumberFormat(lang).format(n);
    } catch (e) {
      return String(n);
    }
  }

  // Human-readable byte size using decimal (SI) units, mirroring the Python
  // side (habitable.vault.human_bytes): 6100000 -> "6.1 MB". The numeric part is
  // locale-formatted so the decimal separator matches the active language.
  function humanBytes(n) {
    if (typeof n !== "number" || !isFinite(n) || n < 0) { n = 0; }
    if (n < 1000) { return formatNumber(n) + " bytes"; }
    var size = n;
    var units = ["KB", "MB", "GB", "TB"];
    for (var i = 0; i < units.length; i++) {
      size /= 1000;
      if (size < 1000) {
        return formatNumber(Math.round(size * 10) / 10) + " " + units[i];
      }
    }
    return formatNumber(Math.round(size * 10) / 10) + " PB";
  }

  function formatDateTime(value) {
    // gen_time and friends arrive as ISO 8601 UTC strings.
    var date = value instanceof Date ? value : new Date(value);
    if (isNaN(date.getTime())) {
      return String(value);
    }
    try {
      return new Intl.DateTimeFormat(lang, {
        dateStyle: "medium",
        timeStyle: "short",
        timeZone: "UTC",
        timeZoneName: "short"
      }).format(date);
    } catch (e) {
      return String(value);
    }
  }

  // Index of the "}" matching the "{" at `start`, or -1 when unbalanced.
  function matchBrace(text, start) {
    var depth = 0;
    for (var i = start; i < text.length; i++) {
      if (text.charAt(i) === "{") { depth++; }
      else if (text.charAt(i) === "}") {
        depth--;
        if (depth === 0) { return i; }
      }
    }
    return -1;
  }

  // "one {# link} other {# links}" -> { one: "# link", other: "# links" }
  function parsePluralBranches(source) {
    var branches = {};
    var i = 0;
    while (i < source.length) {
      if (/\s/.test(source.charAt(i))) { i++; continue; }
      var start = i;
      while (i < source.length && !/\s/.test(source.charAt(i)) && source.charAt(i) !== "{") { i++; }
      var selector = source.slice(start, i);
      while (i < source.length && /\s/.test(source.charAt(i))) { i++; }
      if (!selector || source.charAt(i) !== "{") { return null; }
      var end = matchBrace(source, i);
      if (end < 0) { return null; }
      branches[selector] = source.slice(i + 1, end);
      i = end + 1;
    }
    return Object.prototype.hasOwnProperty.call(branches, "other") ? branches : null;
  }

  function renderArgument(body, values) {
    var comma = body.indexOf(",");
    if (comma < 0) {
      var name = body.trim();
      if (!Object.prototype.hasOwnProperty.call(values, name)) {
        return "{" + body + "}";
      }
      var value = values[name];
      return typeof value === "number" ? formatNumber(value) : String(value);
    }
    var argName = body.slice(0, comma).trim();
    var rest = body.slice(comma + 1);
    var comma2 = rest.indexOf(",");
    var kind = (comma2 < 0 ? rest : rest.slice(0, comma2)).trim();
    if (kind !== "plural" || comma2 < 0) {
      return "{" + body + "}"; // unsupported type: degrade visibly, never crash
    }
    var branches = parsePluralBranches(rest.slice(comma2 + 1));
    if (!branches) {
      return "{" + body + "}";
    }
    var n = Number(values[argName]);
    if (isNaN(n)) { n = 0; }
    var branch;
    if (Object.prototype.hasOwnProperty.call(branches, "=" + n)) {
      branch = branches["=" + n];
    } else {
      var category = pluralCategory(n);
      branch = Object.prototype.hasOwnProperty.call(branches, category)
        ? branches[category]
        : branches.other;
    }
    return renderIcu(branch, values, formatNumber(n));
  }

  function renderIcu(message, values, hashText) {
    var out = "";
    var i = 0;
    while (i < message.length) {
      var ch = message.charAt(i);
      if (ch === "{") {
        var end = matchBrace(message, i);
        if (end < 0) { return message; } // malformed: show the raw string
        out += renderArgument(message.slice(i + 1, end), values);
        i = end + 1;
      } else if (ch === "#" && typeof hashText === "string") {
        out += hashText;
        i++;
      } else {
        out += ch;
        i++;
      }
    }
    return out;
  }

  // t() + ICU rendering: fm("custody_links", { count: 3 }) -> "3 links" / "3 enlaces".
  function fm(key, values) {
    return renderIcu(t(key), values || {});
  }

  function applyTranslations(root) {
    var scope = root || document;
    var textNodes = scope.querySelectorAll("[data-i18n]");
    var i;
    for (i = 0; i < textNodes.length; i++) {
      var el = textNodes[i];
      var key = el.getAttribute("data-i18n");
      if (Object.prototype.hasOwnProperty.call(strings, key)) {
        el.textContent = strings[key];
      }
    }
    var ariaNodes = scope.querySelectorAll("[data-i18n-aria]");
    for (i = 0; i < ariaNodes.length; i++) {
      var ael = ariaNodes[i];
      var akey = ael.getAttribute("data-i18n-aria");
      if (Object.prototype.hasOwnProperty.call(strings, akey)) {
        ael.setAttribute("aria-label", strings[akey]);
      }
    }
  }

  function loadStrings(which) {
    return fetch("i18n/" + which + ".json", { headers: { Accept: "application/json" } })
      .then(function (res) {
        if (!res.ok) {
          throw new Error("i18n http " + res.status);
        }
        return res.json();
      });
  }

  function setLanguage(which) {
    if (SUPPORTED.indexOf(which) === -1) {
      which = DEFAULT_LANG;
    }
    return loadStrings(which).then(function (dict) {
      strings = dict;
      lang = which;
      document.documentElement.setAttribute("lang", which);
      document.documentElement.setAttribute(
        "dir",
        RTL_LANGS.indexOf(which) !== -1 ? "rtl" : "ltr"
      );
      try {
        localStorage.setItem(LANG_KEY, which);
      } catch (e) {
        /* private mode: ignore */
      }
      applyTranslations(document);
      updateLangButtons();
      // Re-render dynamic content so it picks up the new language.
      if (lastStatus) {
        renderStatus(lastStatus);
      }
      document.title = t("app_title");
    });
  }

  function updateLangButtons() {
    var btns = document.querySelectorAll(".lang-btn");
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      b.setAttribute("aria-pressed", b.getAttribute("data-lang") === lang ? "true" : "false");
    }
  }

  // ---- Announcer (aria-live) ----------------------------------------------

  var announcer;

  function announce(message, kind) {
    if (!announcer) {
      return;
    }
    announcer.classList.remove("is-error", "is-ok");
    if (kind === "error") {
      announcer.classList.add("is-error");
    } else if (kind === "ok") {
      announcer.classList.add("is-ok");
    }
    // Clear first so repeated identical messages are still announced.
    announcer.textContent = "";
    // Microtask gap keeps assistive tech reliable.
    window.setTimeout(function () {
      announcer.textContent = message;
    }, 30);
  }

  function announceError(err) {
    var msg = (err && err.message) ? err.message : "";
    announce(msg ? t("error_prefix") + " " + msg : t("error_fallback"), "error");
  }

  // Non-auditory equivalents for the "success" cue (R-10): a short haptic buzz
  // where the device supports it, plus a brief visual pulse on the announcer.
  // Both are supplementary — the aria-live text stays the primary signal, so a
  // user who has neither vibration nor sight of the pulse still hears/reads the
  // announcement. The pulse honours prefers-reduced-motion via CSS.
  function signalSuccess() {
    if (navigator.vibrate) {
      try {
        navigator.vibrate(35);
      } catch (e) {
        /* vibration may be blocked by policy; the visual pulse still fires */
      }
    }
    if (!announcer) {
      return;
    }
    announcer.classList.remove("flash-ok");
    // Force a reflow so the animation restarts on rapid, repeated successes.
    void announcer.offsetWidth;
    announcer.classList.add("flash-ok");
    window.setTimeout(function () {
      if (announcer) {
        announcer.classList.remove("flash-ok");
      }
    }, 600);
  }

  // ---- API -----------------------------------------------------------------

  // The server prints an opaque URL whose fragment carries a per-process session token
  // (e.g. .../#token=abc). Move it into memory + sessionStorage and scrub it from the
  // address bar, so it is never sent to the server as a query or leaked via Referer.
  // sessionStorage keeps reloads in this tab working without turning the credential
  // into a persistent cross-session secret. Every /api/* call presents it as a header.
  function captureToken() {
    var hash = window.location.hash || "";
    var match = /(?:^#|&)token=([^&]+)/.exec(hash);
    if (match) {
      try {
        sessionToken = decodeURIComponent(match[1]);
      } catch (e) {
        // A malformed percent escape must not abort boot or preserve an older token.
        sessionToken = "";
      }
      try {
        if (sessionToken) {
          window.sessionStorage.setItem(TOKEN_KEY, sessionToken);
        } else {
          window.sessionStorage.removeItem(TOKEN_KEY);
        }
      } catch (e) {
        /* sessionStorage may be unavailable; the in-memory token still works */
      }
      if (window.history && window.history.replaceState) {
        try {
          window.history.replaceState(null, "", window.location.pathname + window.location.search);
        } catch (e) {
          /* best-effort scrub; URL fragments are not sent in HTTP or Referer */
        }
      }
    } else {
      try {
        sessionToken = window.sessionStorage.getItem(TOKEN_KEY) || "";
      } catch (e) {
        sessionToken = "";
      }
    }
  }

  function apiHeaders(extra) {
    var headers = { Accept: "application/json" };
    var key;
    if (extra) {
      for (key in extra) {
        if (Object.prototype.hasOwnProperty.call(extra, key)) {
          headers[key] = extra[key];
        }
      }
    }
    if (sessionToken) {
      headers["X-Habitable-Token"] = sessionToken;
    }
    return headers;
  }

  function apiGet(path) {
    return fetch(path, { headers: apiHeaders() }).then(handleJson);
  }

  function apiPost(path, body) {
    return fetch(path, {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body || {})
    }).then(handleJson);
  }

  function handleJson(res) {
    return res.json().then(
      function (data) {
        if (!res.ok) {
          var detail = data && data.error ? data.error : ("HTTP " + res.status);
          throw new Error(detail);
        }
        return data;
      },
      function () {
        throw new Error("HTTP " + res.status);
      }
    );
  }

  // ---- Rendering -----------------------------------------------------------

  var lastStatus = null;
  var currentAtlasPoints = [];
  var selectedPointId = "";
  var storyIndex = -1;

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  }

  function issueLabel(issue) {
    return issue.title || issue.category || issue.issue_id || t("issue_untitled");
  }

  function eventLabel(entry) {
    if (entry.event_type === "other" && entry.other_label) {
      return entry.other_label;
    }
    var key = "event_" + (entry.event_type || "other");
    var translated = t(key);
    return translated === key ? (entry.event_type || t("event_other")) : translated;
  }

  function sourceLabel(source) {
    if (source === "capture") { return t("source_capture"); }
    var key = "source_" + (source || "other");
    var translated = t(key);
    return translated === key ? (source || t("source_other")) : translated;
  }

  function atlasDate(value) {
    if (!value) { return "—"; }
    var date = new Date(value.length === 10 ? value + "T00:00:00Z" : value);
    if (isNaN(date.getTime())) { return value; }
    try {
      return new Intl.DateTimeFormat(lang, {
        dateStyle: "medium",
        timeZone: "UTC"
      }).format(date);
    } catch (e) {
      return value;
    }
  }

  function atlasTime(value, fallback) {
    var parsed = Date.parse(value || "");
    return isNaN(parsed) ? fallback : parsed;
  }

  function buildAtlasPoints(status) {
    var points = [];
    var issues = status.issues || [];
    var order = 0;
    for (var i = 0; i < issues.length; i++) {
      var issue = issues[i];
      var captures = issue.capture_items || [];
      var timeline = issue.timeline || [];
      for (var c = 0; c < captures.length; c++) {
        var capture = captures[c];
        points.push({
          id: capture.capture_id,
          issueId: issue.issue_id,
          issueLabel: issueLabel(issue),
          room: issue.room || "",
          kind: "capture",
          eventType: "capture",
          label: t("inspector_capture_title"),
          text: capture.transcript || "",
          date: capture.captured_at || "",
          recordedAt: capture.captured_at || "",
          source: "capture",
          timestamped: !!capture.timestamped,
          authorities: capture.timestamp_authorities || 0,
          custodyEntries: capture.custody_entries || 0,
          hash: capture.content_hash || "",
          links: [],
          time: atlasTime(capture.captured_at, order++)
        });
      }
      for (var e = 0; e < timeline.length; e++) {
        var entry = timeline[e];
        var links = (entry.capture_ids || []).slice();
        var namedLinks = [entry.notice_entry_id, entry.receipt_entry_id, entry.response_entry_id];
        for (var n = 0; n < namedLinks.length; n++) {
          if (namedLinks[n]) { links.push(namedLinks[n]); }
        }
        points.push({
          id: entry.entry_id,
          issueId: issue.issue_id,
          issueLabel: issueLabel(issue),
          room: issue.room || "",
          kind: "event",
          eventType: entry.event_type || entry.kind || "other",
          label: eventLabel(entry),
          text: entry.text || "",
          date: entry.occurred_at || entry.recorded_at || "",
          recordedAt: entry.recorded_at || "",
          source: entry.source || "other",
          timestamped: false,
          authorities: 0,
          custodyEntries: 1,
          hash: "",
          links: links,
          time: atlasTime(entry.occurred_at || entry.recorded_at, order++)
        });
      }
    }
    points.sort(function (a, b) {
      return a.time === b.time ? a.id.localeCompare(b.id) : a.time - b.time;
    });

    // A relationship reads both ways in the explorer even though the canonical
    // record stores it on the authored timeline entry.
    var byId = {};
    for (var p = 0; p < points.length; p++) { byId[points[p].id] = points[p]; }
    for (var x = 0; x < points.length; x++) {
      for (var l = 0; l < points[x].links.length; l++) {
        var target = byId[points[x].links[l]];
        if (target && target.links.indexOf(points[x].id) === -1) {
          target.links.push(points[x].id);
        }
      }
    }
    return points;
  }

  function visibleAtlasPoints(points) {
    var filter = document.getElementById("atlas-filter-issue");
    var issueId = filter ? filter.value : "";
    return points.filter(function (point) { return !issueId || point.issueId === issueId; });
  }

  function trailEventClass(point) {
    if (point.eventType === "notice_sent") { return "event-notice"; }
    if (point.eventType === "delivery_confirmed") { return "event-delivery"; }
    if (point.eventType === "repair") { return "event-repair"; }
    if (point.eventType === "recurrence") { return "event-recurrence"; }
    return point.kind === "capture" ? "event-capture" : "event-update";
  }

  function appendTrailTableRow(table, point) {
    var tr = document.createElement("tr");
    var reportedCell = document.createElement("td");
    reportedCell.textContent = atlasDate(point.date);
    var issueCell = document.createElement("td");
    issueCell.textContent = point.issueLabel;
    var eventCell = document.createElement("td");
    var selectButton = document.createElement("button");
    selectButton.type = "button";
    selectButton.className = "table-select";
    selectButton.setAttribute("data-point-id", point.id);
    selectButton.textContent = point.label + (point.text ? ": " + point.text : "");
    selectButton.addEventListener("click", function () {
      selectAtlasPoint(this.getAttribute("data-point-id") || "");
    });
    eventCell.appendChild(selectButton);
    var sourceCell = document.createElement("td");
    sourceCell.textContent = sourceLabel(point.source);
    var securedCell = document.createElement("td");
    securedCell.textContent = atlasDate(point.recordedAt || point.date);
    tr.appendChild(reportedCell);
    tr.appendChild(issueCell);
    tr.appendChild(eventCell);
    tr.appendChild(sourceCell);
    tr.appendChild(securedCell);
    table.appendChild(tr);
  }

  function resetAtlasInspector() {
    var inspector = document.getElementById("atlas-inspector");
    var heading = document.getElementById("inspector-h");
    var report = document.getElementById("inspector-report");
    var content = document.getElementById("inspector-content");
    if (heading) { heading.textContent = t("inspector_empty_heading"); }
    if (report) { report.textContent = t("inspector_empty_body"); }
    if (content) {
      content.textContent = "";
      var label = document.createElement("span");
      label.className = "fold-label";
      label.textContent = t("secured_layer_label");
      content.appendChild(label);
    }
    if (inspector) { inspector.open = false; }
  }

  function renderAtlas(status) {
    var nodes = document.getElementById("atlas-nodes");
    var empty = document.getElementById("atlas-empty");
    var summary = document.getElementById("atlas-summary");
    var table = document.getElementById("atlas-table-body");
    if (!nodes || !table) { return; }

    currentAtlasPoints = buildAtlasPoints(status);
    var points = visibleAtlasPoints(currentAtlasPoints);
    var filter = document.getElementById("atlas-filter-issue");
    var issues = status.issues || [];
    var activeIssue = null;
    for (var issueIndex = 0; issueIndex < issues.length; issueIndex++) {
      if (!activeIssue || (filter && issues[issueIndex].issue_id === filter.value)) {
        activeIssue = issues[issueIndex];
      }
      if (filter && issues[issueIndex].issue_id === filter.value) { break; }
    }
    setText("trail-room", activeIssue && activeIssue.room
      ? activeIssue.room
      : t("current_condition"));
    setText("trail-condition", activeIssue
      ? issueLabel(activeIssue)
      : t("atlas_empty"));

    nodes.textContent = "";
    table.textContent = "";
    if (empty) { empty.hidden = points.length > 0; }
    if (summary) {
      summary.textContent = points.length
        ? fm("atlas_summary", { count: points.length })
        : t("atlas_summary_empty");
    }
    if (!points.length) {
      selectedPointId = "";
      resetAtlasInspector();
      return;
    }

    var selectionVisible = points.some(function (point) {
      return point.id === selectedPointId;
    });
    if (!selectionVisible) { selectedPointId = points[points.length - 1].id; }
    var selectedLinks = [];
    for (var selectedIndex = 0; selectedIndex < points.length; selectedIndex++) {
      if (points[selectedIndex].id === selectedPointId) {
        selectedLinks = points[selectedIndex].links;
        break;
      }
    }

    for (var p = 0; p < points.length; p++) {
      var point = points[p];
      var button = document.createElement("button");
      button.type = "button";
      button.className = "atlas-node " + trailEventClass(point);
      if (point.kind === "capture" && !point.timestamped) {
        button.classList.add("node-awaiting");
      }
      if (point.id === selectedPointId) { button.classList.add("node-selected"); }
      if (selectedLinks.indexOf(point.id) !== -1) { button.classList.add("node-linked"); }
      button.setAttribute("data-point-id", point.id);
      button.setAttribute(
        "aria-label",
        point.label + ", " + point.issueLabel + ", " +
        t("reported_date_label") + " " + atlasDate(point.date) + ", " +
        t("secured_date_label") + " " + atlasDate(point.recordedAt || point.date)
      );

      var reported = document.createElement("span");
      reported.className = "trail-reported";
      reported.setAttribute("data-clock-label", t("reported_date_label"));
      reported.textContent = atlasDate(point.date);
      button.appendChild(reported);

      var mark = document.createElement("span");
      mark.className = "trail-mark";
      mark.setAttribute("aria-hidden", "true");
      mark.appendChild(document.createElement("i"));
      button.appendChild(mark);

      var copy = document.createElement("span");
      copy.className = "trail-copy";
      var label = document.createElement("strong");
      label.textContent = point.label;
      copy.appendChild(label);
      if (point.text) {
        var note = document.createElement("span");
        note.textContent = point.text;
        copy.appendChild(note);
      }
      var proof = document.createElement("span");
      proof.className = "trail-proof";
      proof.textContent = point.kind === "capture"
        ? (point.timestamped ? t("proof_timestamped") : t("proof_awaiting"))
        : t("proof_timeline_bound");
      copy.appendChild(proof);
      button.appendChild(copy);

      var secured = document.createElement("span");
      secured.className = "trail-secured";
      secured.setAttribute("data-clock-label", t("secured_date_label"));
      secured.textContent = atlasDate(point.recordedAt || point.date);
      button.appendChild(secured);

      button.addEventListener("click", function () {
        selectAtlasPoint(this.getAttribute("data-point-id") || "");
      });
      nodes.appendChild(button);
      appendTrailTableRow(table, point);
    }

    renderAtlasInspector(selectedPointId);
  }

  function appendDefinition(list, label, value, className) {
    var dt = document.createElement("dt");
    dt.textContent = label;
    var dd = document.createElement("dd");
    dd.textContent = value || "—";
    if (className) { dd.className = className; }
    list.appendChild(dt);
    list.appendChild(dd);
  }

  function renderAtlasInspector(pointId) {
    var point = null;
    for (var i = 0; i < currentAtlasPoints.length; i++) {
      if (currentAtlasPoints[i].id === pointId) { point = currentAtlasPoints[i]; break; }
    }
    if (!point) { return; }
    var heading = document.getElementById("inspector-h");
    var report = document.getElementById("inspector-report");
    var content = document.getElementById("inspector-content");
    if (!heading || !report || !content) { return; }
    heading.textContent = point.label;
    report.textContent = point.text || "—";
    content.textContent = "";
    var checkLabel = document.createElement("span");
    checkLabel.className = "fold-label";
    checkLabel.textContent = t("secured_layer_label");
    content.appendChild(checkLabel);
    var dl = document.createElement("dl");
    appendDefinition(dl, t("inspector_label_issue"), point.issueLabel);
    appendDefinition(dl, t("inspector_label_date"), atlasDate(point.date));
    if (point.recordedAt && point.recordedAt !== point.date) {
      appendDefinition(dl, t("inspector_label_recorded"), atlasDate(point.recordedAt));
    }
    appendDefinition(dl, t("inspector_label_source"), sourceLabel(point.source));
    var proof = point.kind === "capture"
      ? (point.timestamped ? t("proof_timestamped") : t("proof_awaiting"))
      : t("proof_timeline_bound");
    appendDefinition(dl, t("inspector_label_proof"), proof, "inspector-proof");
    appendDefinition(
      dl,
      t("inspector_label_links"),
      point.links.length ? fm("proof_linked", { count: point.links.length }) : t("proof_no_links")
    );
    if (point.hash) { appendDefinition(dl, t("capture_hash_label"), point.hash, "mono"); }
    content.appendChild(dl);
  }

  function selectAtlasPoint(pointId) {
    selectedPointId = pointId;
    var nodes = document.querySelectorAll(".atlas-node");
    var selected = null;
    var linked = [];
    for (var i = 0; i < currentAtlasPoints.length; i++) {
      if (currentAtlasPoints[i].id === pointId) { linked = currentAtlasPoints[i].links; break; }
    }
    for (var n = 0; n < nodes.length; n++) {
      var id = nodes[n].getAttribute("data-point-id");
      nodes[n].classList.toggle("node-selected", id === pointId);
      nodes[n].classList.toggle("node-linked", linked.indexOf(id) !== -1);
      if (id === pointId) { selected = nodes[n]; }
    }
    renderAtlasInspector(pointId);
    var inspector = document.getElementById("atlas-inspector");
    if (inspector) { inspector.open = true; }
    return selected;
  }

  function renderStatus(status) {
    lastStatus = status;
    var unit = status.unit || "—";
    setText("st-unit", unit);
    setText("header-unit", unit);
    setText("masthead-unit", unit);
    setText("st-fingerprint", status.fingerprint || "—");
    setText("st-issues", formatNumber((status.issues || []).length));
    setText("st-captures", formatNumber(status.capture_count || 0));
    setText("st-timestamped", formatNumber(status.timestamped || 0));
    var deferred = status.deferred || 0;
    setText("st-awaiting", formatNumber(deferred));

    // Plain, reassuring status copy (R-01, R-17): when items are still waiting
    // for a timestamp token, explain that the photo is already sealed and the
    // wait does not weaken the evidence; when nothing is pending, confirm there
    // is nothing left to do rather than leaving the reader unsure.
    var awaitingHelp = document.getElementById("st-awaiting-help");
    if (awaitingHelp) {
      awaitingHelp.textContent = deferred > 0
        ? t("status_awaiting_help")
        : t("status_timestamped_help");
    }

    var custody = document.getElementById("st-custody");
    if (custody) {
      var ok = !!status.custody_ok;
      var label = ok
        ? t("custody_intact")
        : t("custody_broken");
      var len = status.custody_length;
      var suffix = (typeof len === "number")
        ? " (" + fm("custody_links", { count: len }) + ")"
        : "";
      custody.textContent = label + suffix;
      custody.className = ok ? "custody-ok" : "custody-bad";
      setText("rail-custody", label);
    }

    var storage = document.getElementById("st-storage");
    if (storage) {
      var s = status.storage || {};
      storage.textContent = fm("storage_summary", {
        total: humanBytes(s.total_bytes || 0),
        sealed: humanBytes(s.sealed_originals_bytes || 0),
        shared: humanBytes(s.shared_copies_bytes || 0)
      });
      var sealed = s.sealed_originals_bytes || 0;
      var shared = s.shared_copies_bytes || 0;
      var visualTotal = sealed + shared;
      var sealedBar = document.getElementById("storage-sealed");
      var sharedBar = document.getElementById("storage-shared");
      if (sealedBar) { sealedBar.style.flexBasis = (visualTotal ? sealed / visualTotal * 100 : 0) + "%"; }
      if (sharedBar) { sharedBar.style.flexBasis = (visualTotal ? shared / visualTotal * 100 : 0) + "%"; }
    }

    setText(
      "st-network",
      status.allow_metered === false ? t("network_wifi_only") : t("network_metered_ok")
    );

    setText("rail-stamp", fm("rail_awaiting", { count: deferred }));
    var ring = document.getElementById("readiness-ring");
    var total = status.evidence_count || status.capture_count || 0;
    var timestamped = status.timestamped || 0;
    if (ring) { ring.style.setProperty("--coverage", (total ? timestamped / total * 360 : 0) + "deg"); }
    setText("readiness-value", formatNumber(timestamped) + "/" + formatNumber(total));
    setText(
      "readiness-copy",
      total ? fm("readiness_progress", { timestamped: timestamped, total: total }) : t("readiness_empty")
    );

    populateAtlasFilter(status.issues || []);
    renderIssues(status.issues || []);
    populateIssueSelects(status.issues || []);
    populateProfiles(status.profiles || [], status.profile || "");
    populateTimelineLinks(status.issues || []);
    renderAtlas(status);
  }

  function populateAtlasFilter(issues) {
    var select = document.getElementById("atlas-filter-issue");
    if (!select) { return; }
    var previous = select.value;
    select.textContent = "";
    if (!issues.length) {
      var empty = document.createElement("option");
      empty.value = "";
      empty.textContent = t("issue_none_available");
      empty.disabled = true;
      empty.selected = true;
      select.appendChild(empty);
      return;
    }
    for (var i = 0; i < issues.length; i++) {
      var option = document.createElement("option");
      option.value = issues[i].issue_id;
      option.textContent = issueLabel(issues[i]);
      select.appendChild(option);
    }
    var previousStillExists = false;
    for (var j = 0; j < issues.length; j++) {
      if (issues[j].issue_id === previous) {
        previousStillExists = true;
        break;
      }
    }
    select.value = previousStillExists ? previous : (issues.length ? issues[0].issue_id : "");
  }

  function renderIssues(issues) {
    var list = document.getElementById("issues-list");
    var empty = document.getElementById("issues-empty");
    if (!list) {
      return;
    }
    list.textContent = "";
    if (!issues.length) {
      if (empty) {
        empty.hidden = false;
      }
      return;
    }
    if (empty) {
      empty.hidden = true;
    }
    for (var i = 0; i < issues.length; i++) {
      list.appendChild(issueItem(issues[i], i));
    }
  }

  function issueItem(issue, index) {
    var li = document.createElement("li");
    li.className = "issue";
    var select = document.createElement("button");
    select.type = "button";
    select.className = "issue-select";
    select.setAttribute("data-issue-id", issue.issue_id);
    var filter = document.getElementById("atlas-filter-issue");
    var isSelected = filter
      ? filter.value === issue.issue_id
      : index === 0;
    select.setAttribute("aria-pressed", isSelected ? "true" : "false");

    var name = document.createElement("span");
    var room = document.createElement("span");
    room.className = "issue-room";
    room.textContent = issue.room || t("issue_label_room");
    var strong = document.createElement("strong");
    strong.textContent = issueLabel(issue);
    name.appendChild(room);
    name.appendChild(strong);
    select.appendChild(name);

    var total = (typeof issue.captures === "number" ? issue.captures : 0) +
      (issue.artifacts || []).length + (issue.timeline || []).length;
    var count = document.createElement("span");
    count.className = "issue-count";
    count.textContent = formatNumber(total);
    select.appendChild(count);

    var latest = document.createElement("span");
    latest.className = "issue-state";
    var timeline = issue.timeline || [];
    latest.textContent = timeline.length
      ? eventLabel(timeline[timeline.length - 1])
      : t("atlas_summary_empty");
    select.appendChild(latest);

    select.addEventListener("click", function () {
      var issueId = this.getAttribute("data-issue-id") || "";
      var issueFilter = document.getElementById("atlas-filter-issue");
      if (issueFilter) { issueFilter.value = issueId; }
      selectedPointId = "";
      var buttons = document.querySelectorAll(".issue-select");
      for (var b = 0; b < buttons.length; b++) {
        buttons[b].setAttribute(
          "aria-pressed",
          buttons[b].getAttribute("data-issue-id") === issueId ? "true" : "false"
        );
      }
      if (lastStatus) { renderAtlas(lastStatus); }
    });
    li.appendChild(select);
    return li;
  }

  function badge(text, extraClass) {
    var li = document.createElement("li");
    var span = document.createElement("span");
    span.className = extraClass ? "badge " + extraClass : "badge";
    span.textContent = text;
    li.appendChild(span);
    return li;
  }

  // Decomposed documentation coverage: facts, never a composite legal score.
  function strengthBadge(rs) {
    var level = rs.level || "minimal";
    var timestamped = (rs.strong_count || 0) + (rs.developing_count || 0);
    var label = formatNumber(timestamped) + "/" + formatNumber(rs.item_count || 0) + " " +
      t("status_timestamped").toLocaleLowerCase(lang);
    var li = badge(label, "strength-" + level);
    var span = li.firstChild;
    if (span) {
      span.title = fm("strength_detail", {
        strong: rs.strong_count || 0,
        developing: rs.developing_count || 0,
        minimal: rs.minimal_count || 0,
        timeline: rs.timeline_entries || 0
      });
    }
    return li;
  }

  function populateIssueSelects(issues) {
    var selects = [
      { el: document.getElementById("cap-issue"), allowEmpty: false },
      { el: document.getElementById("art-issue"), allowEmpty: false },
      { el: document.getElementById("rel-issue"), allowEmpty: false },
      { el: document.getElementById("tl-issue"), allowEmpty: false },
      { el: document.getElementById("ex-issue"), allowEmpty: true, wholeCaseOnly: true }
    ];
    for (var s = 0; s < selects.length; s++) {
      var sel = selects[s].el;
      if (!sel) { continue; }
      var prev = sel.value;
      sel.textContent = "";
      if (selects[s].allowEmpty) {
        var blank = document.createElement("option");
        blank.value = "";
        blank.textContent = t("issue_all");
        sel.appendChild(blank);
      } else if (!issues.length) {
        var none = document.createElement("option");
        none.value = "";
        none.textContent = t("issue_none_available");
        none.disabled = true;
        sel.appendChild(none);
      }
      if (selects[s].wholeCaseOnly) { continue; }
      for (var i = 0; i < issues.length; i++) {
        var opt = document.createElement("option");
        opt.value = issues[i].issue_id;
        var labelText = issues[i].title || issues[i].category || issues[i].issue_id;
        opt.textContent = labelText;
        sel.appendChild(opt);
      }
      // Restore prior selection when still present.
      if (prev) {
        sel.value = prev;
      }
    }
  }

  function populateProfiles(profiles, selectedProfile) {
    var selects = [document.getElementById("profile-select"), document.getElementById("ex-profile")];
    for (var s = 0; s < selects.length; s++) {
      var select = selects[s];
      if (!select) { continue; }
      var prior = select.value;
      select.textContent = "";
      if (select.id === "ex-profile") {
        var generic = document.createElement("option");
        generic.value = "";
        generic.textContent = t("profile_generic");
        select.appendChild(generic);
      }
      for (var i = 0; i < profiles.length; i++) {
        var option = document.createElement("option");
        option.value = profiles[i].profile_id;
        var names = profiles[i].name || {};
        option.textContent = names[lang] || names.en || profiles[i].profile_id;
        if (profiles[i].external_review_required) {
          option.textContent += " — " + t("profile_external_review");
        }
        select.appendChild(option);
      }
      select.value = prior || selectedProfile || "";
    }
  }

  function populateTimelineLinks(issues) {
    var issueSelect = document.getElementById("tl-issue");
    if (!issueSelect) { return; }
    var issue = null;
    for (var i = 0; i < issues.length; i++) {
      if (issues[i].issue_id === issueSelect.value) {
        issue = issues[i];
        break;
      }
    }
    populateCaptureLinks((issue && issue.capture_items) || []);
    populateEventLink("tl-notice", (issue && issue.timeline) || [], "notice_sent");
    populateEventLink("tl-receipt", (issue && issue.timeline) || [], "delivery_confirmed");
    populateEventLink("tl-response", (issue && issue.timeline) || [], "response_received");
  }

  function populateCaptureLinks(captures) {
    var select = document.getElementById("tl-captures");
    if (!select) { return; }
    var selected = selectedValues(select);
    select.textContent = "";
    for (var i = 0; i < captures.length; i++) {
      var option = document.createElement("option");
      option.value = captures[i].capture_id;
      option.textContent = (captures[i].captured_at || t("capture_date_unknown")) +
        " · " + (captures[i].media_type || t("capture_media_unknown"));
      option.selected = selected.indexOf(option.value) >= 0;
      select.appendChild(option);
    }
  }

  function populateEventLink(id, entries, eventType) {
    var select = document.getElementById(id);
    if (!select) { return; }
    var previous = select.value;
    select.textContent = "";
    var blank = document.createElement("option");
    blank.value = "";
    blank.textContent = t("link_none");
    select.appendChild(blank);
    for (var i = 0; i < entries.length; i++) {
      if (entries[i].event_type !== eventType) { continue; }
      var option = document.createElement("option");
      option.value = entries[i].entry_id;
      option.textContent = (entries[i].occurred_at || entries[i].recorded_at || "—") +
        " · " + entries[i].text;
      select.appendChild(option);
    }
    select.value = previous;
  }

  function selectedValues(select) {
    var values = [];
    if (!select || !select.options) { return values; }
    for (var i = 0; i < select.options.length; i++) {
      if (select.options[i].selected) { values.push(select.options[i].value); }
    }
    return values;
  }

  function refreshStatus() {
    return apiGet("/api/status").then(
      function (status) {
        renderStatus(status);
        return status;
      },
      function (err) {
        announceError(err);
        throw err;
      }
    );
  }

  // ---- Form helpers --------------------------------------------------------

  function withBusy(button, fn) {
    if (button) {
      button.disabled = true;
    }
    return fn().then(
      function (v) {
        if (button) { button.disabled = false; }
        return v;
      },
      function (e) {
        if (button) { button.disabled = false; }
        throw e;
      }
    );
  }

  function readFileAsBase64(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        var result = String(reader.result || "");
        var comma = result.indexOf(",");
        resolve(comma >= 0 ? result.slice(comma + 1) : result);
      };
      reader.onerror = function () {
        reject(new Error(t("error_file_read")));
      };
      reader.readAsDataURL(file);
    });
  }

  // ---- Form wiring ---------------------------------------------------------

  function wireAddIssue() {
    var form = document.getElementById("add-issue-form");
    if (!form) { return; }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var category = document.getElementById("ai-category");
      if (!category.value.trim()) {
        announce(t("error_category_required"), "error");
        category.focus();
        return;
      }
      var body = {
        category: category.value.trim(),
        room: document.getElementById("ai-room").value.trim(),
        title: document.getElementById("ai-title").value.trim(),
        severity: document.getElementById("ai-severity").value,
        description: document.getElementById("ai-description").value.trim()
      };
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () {
        return apiPost("/api/issues", body);
      }).then(function () {
        form.reset();
        announce(t("msg_issue_added"), "ok");
        return refreshStatus().then(function (status) {
          closeOwningDialog(form);
          return status;
        });
      }, announceError);
    });
  }

  function wireCapture() {
    var form = document.getElementById("capture-form");
    if (!form) { return; }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var issueSel = document.getElementById("cap-issue");
      var fileInput = document.getElementById("cap-file");
      if (!issueSel.value) {
        announce(t("error_issue_required"), "error");
        issueSel.focus();
        return;
      }
      if (!fileInput.files || !fileInput.files.length) {
        announce(t("error_photo_required"), "error");
        fileInput.focus();
        return;
      }
      var file = fileInput.files[0];
      var devTsa = document.getElementById("cap-devtsa").checked;
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () {
        return readFileAsBase64(file).then(function (b64) {
          return apiPost("/api/capture", {
            issue_id: issueSel.value,
            filename: file.name || "upload.jpg",
            media_b64: b64,
            dev_tsa: devTsa
          });
        });
      }).then(function (res) {
        form.reset();
        var stamp = res.timestamped
          ? (t("capture_timestamped_yes") + (res.gen_time ? " (" + formatDateTime(res.gen_time) + ")" : ""))
          : t("capture_timestamped_no");
        var message =
          t("msg_capture_done") + " " +
          t("capture_hash_label") + ": " + res.content_hash + ". " +
          t("capture_timestamp_label") + ": " + stamp + ".";
        // No dead-ends: an offline (not-yet-timestamped) capture is already safe; say so
        // and say what to do next, rather than leaving an alarming "not timestamped".
        if (!res.timestamped) {
          message += " " + t("capture_awaiting_reassure");
        }
        announce(message, "ok");
        signalSuccess();
        return refreshStatus().then(function (status) {
          closeOwningDialog(form);
          return status;
        });
      }, announceError);
    });
  }

  function wireTimeline() {
    var form = document.getElementById("timeline-form");
    if (!form) { return; }
    var issueSel = document.getElementById("tl-issue");
    var eventType = document.getElementById("tl-type");
    var source = document.getElementById("tl-source");
    var occurred = document.getElementById("tl-occurred");
    function updateConditionalFields() {
      document.getElementById("tl-other-field").hidden = eventType.value !== "other";
      document.getElementById("tl-source-other-field").hidden = source.value !== "other";
    }
    issueSel.addEventListener("change", function () {
      populateTimelineLinks((lastStatus && lastStatus.issues) || []);
    });
    eventType.addEventListener("change", updateConditionalFields);
    source.addEventListener("change", updateConditionalFields);
    if (!occurred.value) {
      var now = new Date();
      var local = new Date(now.getTime() - now.getTimezoneOffset() * 60000);
      occurred.value = local.toISOString().slice(0, 10);
    }
    updateConditionalFields();
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var text = document.getElementById("tl-text");
      if (!issueSel.value) {
        announce(t("error_issue_required"), "error");
        issueSel.focus();
        return;
      }
      if (!eventType.value) {
        announce(t("error_event_type_required"), "error");
        eventType.focus();
        return;
      }
      var otherLabel = document.getElementById("tl-other");
      if (eventType.value === "other" && !otherLabel.value.trim()) {
        announce(t("error_other_label_required"), "error");
        otherLabel.focus();
        return;
      }
      if (!occurred.value) {
        announce(t("error_occurred_at_required"), "error");
        occurred.focus();
        return;
      }
      var sourceOther = document.getElementById("tl-source-other");
      if (source.value === "other" && !sourceOther.value.trim()) {
        announce(t("error_source_detail_required"), "error");
        sourceOther.focus();
        return;
      }
      if (!text.value.trim()) {
        announce(t("error_text_required"), "error");
        text.focus();
        return;
      }
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () {
        return apiPost("/api/issues/" + encodeURIComponent(issueSel.value) + "/timeline", {
          event_type: eventType.value,
          other_label: otherLabel.value.trim(),
          occurred_at: occurred.value,
          source: source.value,
          source_detail: sourceOther.value.trim(),
          text: text.value.trim(),
          capture_ids: selectedValues(document.getElementById("tl-captures")),
          notice_entry_id: document.getElementById("tl-notice").value,
          receipt_entry_id: document.getElementById("tl-receipt").value,
          response_entry_id: document.getElementById("tl-response").value
        });
      }).then(function () {
        form.reset();
        var now = new Date();
        var local = new Date(now.getTime() - now.getTimezoneOffset() * 60000);
        occurred.value = local.toISOString().slice(0, 10);
        updateConditionalFields();
        announce(t("msg_timeline_added"), "ok");
        return refreshStatus().then(function (status) {
          closeOwningDialog(form);
          return status;
        });
      }, announceError);
    });
  }

  function wireArtifact() {
    var form = document.getElementById("artifact-form");
    if (!form) { return; }
    var date = document.getElementById("art-date");
    if (!date.value) { date.value = new Date().toISOString().slice(0, 10); }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var issue = document.getElementById("art-issue");
      var fileInput = document.getElementById("art-file");
      var title = document.getElementById("art-title");
      var source = document.getElementById("art-source");
      if (!issue.value || !fileInput.files || !fileInput.files.length ||
          !title.value.trim() || !source.value.trim() || !date.value) {
        announce(t("error_artifact_required"), "error");
        return;
      }
      var file = fileInput.files[0];
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () {
        return readFileAsBase64(file).then(function (b64) {
          return apiPost("/api/artifacts", {
            issue_id: issue.value,
            filename: file.name || "document.bin",
            media_b64: b64,
            artifact_type: document.getElementById("art-type").value,
            title: title.value.trim(),
            source: source.value.trim(),
            issuer: document.getElementById("art-issuer").value.trim(),
            occurred_at: date.value
          });
        });
      }).then(function () {
        form.reset();
        date.value = new Date().toISOString().slice(0, 10);
        announce(t("msg_artifact_added"), "ok");
        signalSuccess();
        return refreshStatus().then(function (status) {
          closeOwningDialog(form);
          return status;
        });
      }, announceError);
    });
  }

  function wireRelationship() {
    var form = document.getElementById("relationship-form");
    if (!form) { return; }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var body = {
        issue_id: document.getElementById("rel-issue").value,
        relationship_type: document.getElementById("rel-type").value,
        source_id: document.getElementById("rel-source").value.trim(),
        target_id: document.getElementById("rel-target").value.trim(),
        assertion: document.getElementById("rel-assertion").value.trim()
      };
      if (!body.issue_id || !body.source_id || !body.target_id) {
        announce(t("error_relationship_required"), "error");
        return;
      }
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () { return apiPost("/api/relationships", body); })
        .then(function () {
          form.reset();
          announce(t("msg_relationship_added"), "ok");
          return refreshStatus();
        }, announceError);
    });
  }

  function wireProfile() {
    var form = document.getElementById("profile-form");
    if (!form) { return; }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var select = document.getElementById("profile-select");
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () {
        return apiPost("/api/profile", { profile_id: select.value });
      }).then(function (res) {
        announce(
          res.external_review_required ? t("msg_profile_review_required") : t("msg_profile_selected"),
          "ok"
        );
        return refreshStatus();
      }, announceError);
    });
  }

  function wireExport() {
    var form = document.getElementById("export-form");
    if (!form) { return; }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var issueSel = document.getElementById("ex-issue");
      var originals = document.getElementById("ex-originals").checked;
      var btn = form.querySelector('button[type="submit"]');
      withBusy(btn, function () {
        return apiPost("/api/export", {
          issue_id: issueSel.value || undefined,
          include_originals: originals,
          handoff_profile: document.getElementById("ex-profile").value || undefined
        });
      }).then(function (res) {
        renderExportResult(res);
        // Four honest outcomes: evidence-ready; structurally intact but authority
        // trust not established; awaiting timestamps; or an integrity/token failure.
        // Token presence alone is never announced as evidence-ready.
        if (res.evidence_ready || res.verified) {
          announce(t("msg_export_done_ok"), "ok");
          signalSuccess();
        } else if (res.awaiting_only) {
          announce(
            fm("msg_export_done_awaiting", { count: exportAwaitingCount(res) }) +
            " " + t("export_awaiting_next")
          );
        } else if (res.verification_status === "timestamp_authority_untrusted") {
          announce(t("msg_export_done_untrusted"));
        } else {
          announce(t("msg_export_done_warn"), "error");
        }
        return refreshStatus();
      }, announceError);
    });
  }

  function exportAwaitingCount(res) {
    if (typeof res.awaiting === "number") {
      return res.awaiting;
    }
    var items = res.item_count != null ? res.item_count : 0;
    var stamped = res.timestamped_count != null ? res.timestamped_count : 0;
    return Math.max(items - stamped, 0);
  }

  function renderExportResult(res) {
    var box = document.getElementById("export-result");
    if (!box) { return; }
    box.textContent = "";
    box.hidden = false;

    var h3 = document.createElement("h3");
    h3.textContent = t("export_result_heading");
    box.appendChild(h3);

    var ready = !!(res.evidence_ready || res.verified);
    var awaitingOnly = !ready && !!res.awaiting_only;
    var intactUntrusted =
      !ready && res.verification_status === "timestamp_authority_untrusted";
    var verdict = document.createElement("p");
    var v = document.createElement("span");
    v.className = ready
      ? "verdict-ok"
      : ((awaitingOnly || intactUntrusted) ? "verdict-warn" : "verdict-bad");
    v.textContent = ready
      ? t("verify_ready")
      : (awaitingOnly
        ? t("verify_awaiting")
        : (intactUntrusted ? t("verify_intact_untrusted") : t("verify_failed")));
    verdict.appendChild(v);
    box.appendChild(verdict);

    if (awaitingOnly) {
      var next = document.createElement("p");
      next.textContent =
        fm("msg_export_done_awaiting", { count: exportAwaitingCount(res) }) +
        " " + t("export_awaiting_next");
      box.appendChild(next);
    } else if (intactUntrusted) {
      var trustNext = document.createElement("p");
      trustNext.textContent = t("msg_export_done_untrusted");
      box.appendChild(trustNext);
    }

    var ul = document.createElement("ul");
    ul.appendChild(line(t("export_out_dir") + ": " + (res.out_dir || "—")));
    ul.appendChild(line(t("export_items") + ": " + formatNumber(res.item_count != null ? res.item_count : 0)));
    ul.appendChild(line(t("export_timestamped") + ": " + formatNumber(res.timestamped_count != null ? res.timestamped_count : 0)));
    if (res.summary) {
      ul.appendChild(line(t("export_summary") + ": " + res.summary));
    }
    box.appendChild(ul);

    // Surface the honest "what this proves / does not" framing at the moment it matters —
    // the same upper-bound semantics the packet itself carries (see disclosure.py).
    renderProof(box, res.proof);

    var disclosures = res.disclosures || [];
    if (disclosures.length) {
      var dh = document.createElement("p");
      dh.className = "muted";
      dh.textContent = t("export_disclosures") + ":";
      box.appendChild(dh);
      var dul = document.createElement("ul");
      for (var i = 0; i < disclosures.length; i++) {
        dul.appendChild(line(String(disclosures[i])));
      }
      box.appendChild(dul);
    }
  }

  function line(text) {
    var li = document.createElement("li");
    li.textContent = text;
    return li;
  }

  function bulletList(items) {
    var ul = document.createElement("ul");
    var arr = items || [];
    for (var i = 0; i < arr.length; i++) {
      ul.appendChild(line(String(arr[i])));
    }
    return ul;
  }

  // The localized "what this packet proves — and what it does not" statement, supplied
  // by the server (the very text the exported packet carries). Showing it in-app at
  // export time keeps the upper-bound/limits framing unmissable, never overstated.
  function renderProof(box, proof) {
    if (!proof || typeof proof !== "object") {
      return;
    }
    var sec = document.createElement("section");
    sec.className = "proof";

    if (proof.heading) {
      var h = document.createElement("h4");
      h.textContent = proof.heading;
      sec.appendChild(h);
    }
    if (proof.proves_heading) {
      sec.appendChild(strongLine(proof.proves_heading));
    }
    sec.appendChild(bulletList(proof.proves));
    if (proof.not_heading) {
      sec.appendChild(strongLine(proof.not_heading));
    }
    sec.appendChild(bulletList(proof.not_proves));
    if (proof.verify_line) {
      var v = document.createElement("p");
      v.className = "muted";
      v.textContent = proof.verify_line;
      sec.appendChild(v);
    }
    box.appendChild(sec);
  }

  function strongLine(text) {
    var p = document.createElement("p");
    p.className = "proof-sub";
    var s = document.createElement("strong");
    s.textContent = text;
    p.appendChild(s);
    return p;
  }

  function activeIssueId() {
    var filter = document.getElementById("atlas-filter-issue");
    return filter ? filter.value : "";
  }

  function openEntryDialog(dialogId) {
    var dialog = document.getElementById(dialogId);
    if (!dialog) { return; }
    var issueId = activeIssueId();
    var issueFields = ["cap-issue", "tl-issue", "art-issue", "rel-issue"];
    for (var i = 0; i < issueFields.length; i++) {
      var field = document.getElementById(issueFields[i]);
      if (field && issueId) { field.value = issueId; }
    }
    if (dialogId === "timeline-dialog") {
      populateTimelineLinks((lastStatus && lastStatus.issues) || []);
    }
    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }
    var first = dialog.querySelector("select, input, textarea, button");
    if (first) { first.focus(); }
  }

  function closeOwningDialog(element) {
    var dialog = element && element.closest ? element.closest("dialog") : null;
    if (!dialog) { return; }
    if (typeof dialog.close === "function") {
      dialog.close();
    } else {
      dialog.removeAttribute("open");
    }
  }

  function wireEntryDialogs() {
    var openers = document.querySelectorAll("[data-open-dialog]");
    for (var i = 0; i < openers.length; i++) {
      openers[i].addEventListener("click", function () {
        openEntryDialog(this.getAttribute("data-open-dialog") || "");
      });
    }
    var closers = document.querySelectorAll("[data-close-dialog]");
    for (var c = 0; c < closers.length; c++) {
      closers[c].addEventListener("click", function () {
        closeOwningDialog(this);
      });
    }
    var nextSteps = document.querySelectorAll("[data-timeline-type]");
    for (var n = 0; n < nextSteps.length; n++) {
      nextSteps[n].addEventListener("click", function () {
        var type = document.getElementById("tl-type");
        if (type) {
          type.value = this.getAttribute("data-timeline-type") || "";
          type.dispatchEvent(new Event("change", { bubbles: true }));
        }
        openEntryDialog("timeline-dialog");
      });
    }
  }

  function wireAtlas() {
    var filter = document.getElementById("atlas-filter-issue");
    var zoom = document.getElementById("atlas-zoom");
    var zoomValue = document.getElementById("atlas-zoom-value");
    var links = document.getElementById("atlas-show-links");
    var proof = document.getElementById("atlas-show-proof");
    var fit = document.getElementById("atlas-fit");
    var story = document.getElementById("atlas-story");

    function rerender() {
      if (lastStatus) { renderAtlas(lastStatus); }
    }
    if (filter) {
      filter.addEventListener("change", function () {
        storyIndex = -1;
        selectedPointId = "";
        if (lastStatus) { renderIssues(lastStatus.issues || []); }
        rerender();
      });
    }
    if (zoom) {
      zoom.addEventListener("input", function () {
        if (zoomValue) { zoomValue.textContent = zoom.value + "%"; }
        rerender();
      });
    }
    if (links) { links.addEventListener("change", rerender); }
    if (proof) { proof.addEventListener("change", rerender); }
    if (fit) {
      fit.addEventListener("click", function () {
        if (zoom) { zoom.value = "100"; }
        if (zoomValue) { zoomValue.textContent = "100%"; }
        storyIndex = -1;
        rerender();
      });
    }
    if (story) {
      story.addEventListener("click", function () {
        var points = visibleAtlasPoints(currentAtlasPoints);
        if (!points.length) { return; }
        storyIndex = (storyIndex + 1) % points.length;
        selectedPointId = points[storyIndex].id;
        rerender();
        story.textContent = t("atlas_story_next");
        var node = document.querySelector('.atlas-node[data-point-id="' + selectedPointId + '"]');
        if (node) { node.focus(); }
      });
    }

    var resizeTimer = null;
    window.addEventListener("resize", function () {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(rerender, 120);
    });
  }

  function wireLang() {
    var btns = document.querySelectorAll(".lang-btn");
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener("click", function (ev) {
        var which = ev.currentTarget.getAttribute("data-lang");
        setLanguage(which).catch(function () {
          // Translation file failed to load; keep current language.
          announce(t("error_lang_load"), "error");
        });
      });
    }
  }

  function wireRefresh() {
    var btn = document.getElementById("refresh-btn");
    if (!btn) { return; }
    btn.addEventListener("click", function () {
      withBusy(btn, function () {
        return refreshStatus().then(function () {
          announce(t("msg_refreshed"), "ok");
        });
      });
    });
  }

  function wireResolve() {
    var btn = document.getElementById("resolve-btn");
    if (!btn) { return; }
    btn.addEventListener("click", function () {
      withBusy(btn, function () {
        return apiPost("/api/resolve", {});
      }).then(function (res) {
        var n = (res && typeof res.resolved === "number") ? res.resolved : 0;
        announce(fm("msg_resolved", { count: n }), "ok");
        signalSuccess();
        return refreshStatus();
      }, announceError);
    });
  }

  // ---- Service worker ------------------------------------------------------

  function registerServiceWorker() {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("service-worker.js").catch(function () {
        /* offline support is best-effort; ignore registration failures */
      });
    }
  }

  // ---- Boot ----------------------------------------------------------------

  function detectInitialLang() {
    var stored = null;
    try {
      stored = localStorage.getItem(LANG_KEY);
    } catch (e) {
      stored = null;
    }
    if (stored && SUPPORTED.indexOf(stored) !== -1) {
      return stored;
    }
    var nav = (navigator.language || "").slice(0, 2).toLowerCase();
    return SUPPORTED.indexOf(nav) !== -1 ? nav : DEFAULT_LANG;
  }

  function init() {
    announcer = document.getElementById("announcer");
    captureToken();
    wireLang();
    wireEntryDialogs();
    wireAtlas();
    wireRefresh();
    wireResolve();
    wireAddIssue();
    wireCapture();
    wireTimeline();
    wireArtifact();
    wireRelationship();
    wireProfile();
    wireExport();

    setLanguage(detectInitialLang())
      .catch(function () {
        // Fall back to English if the chosen file is unreachable.
        if (lang !== DEFAULT_LANG) {
          return setLanguage(DEFAULT_LANG);
        }
      })
      .then(function () {
        return refreshStatus();
      })
      .catch(function () {
        /* refreshStatus already announced its error */
      });

    registerServiceWorker();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
