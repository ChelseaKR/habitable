// SPDX-License-Identifier: AGPL-3.0-or-later
// habitable — thin, accessible shell over the loopback JSON API. No frameworks.
"use strict";

(function () {
  var LANG_KEY = "habitable.lang";
  var SUPPORTED = ["en", "es"];
  var DEFAULT_LANG = "en";

  var strings = {}; // active dictionary
  var lang = DEFAULT_LANG;

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

  function apiGet(path) {
    return fetch(path, { headers: { Accept: "application/json" } }).then(handleJson);
  }

  function apiPost(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
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

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  }

  function renderStatus(status) {
    lastStatus = status;
    setText("st-unit", status.unit || "—");
    setText("st-fingerprint", status.fingerprint || "—");
    setText("st-issues", formatNumber((status.issues || []).length));
    setText("st-captures", formatNumber(status.capture_count || 0));
    setText("st-timestamped", formatNumber(status.timestamped || 0));
    var deferred = status.deferred || 0;
    setText("st-awaiting", formatNumber(deferred));

    // Plain, reassuring status copy (R-01, R-17): when items are still waiting
    // for a trusted timestamp, explain that the photo is already sealed and the
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
    }

    renderIssues(status.issues || []);
    populateIssueSelects(status.issues || []);
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
      list.appendChild(issueItem(issues[i]));
    }
  }

  function issueItem(issue) {
    var li = document.createElement("li");
    li.className = "issue";

    var h3 = document.createElement("h3");
    h3.textContent = issue.title || issue.category || t("issue_untitled");
    li.appendChild(h3);

    var meta = document.createElement("p");
    meta.className = "issue-meta";
    var parts = [];
    if (issue.category) { parts.push(t("issue_label_category") + ": " + issue.category); }
    if (issue.room) { parts.push(t("issue_label_room") + ": " + issue.room); }
    if (issue.status) { parts.push(t("issue_label_status") + ": " + issue.status); }
    if (issue.severity) { parts.push(t("issue_label_severity") + ": " + issue.severity); }
    meta.textContent = parts.join(" · ");
    li.appendChild(meta);

    var counts = document.createElement("ul");
    counts.className = "issue-counts";
    var captureCount = (typeof issue.captures === "number") ? issue.captures : 0;
    var timelineCount = (issue.timeline || []).length;
    counts.appendChild(badge(fm("issue_captures_count", { count: captureCount })));
    counts.appendChild(badge(fm("issue_timeline_count", { count: timelineCount })));
    li.appendChild(counts);

    return li;
  }

  function badge(text) {
    var li = document.createElement("li");
    var span = document.createElement("span");
    span.className = "badge";
    span.textContent = text;
    li.appendChild(span);
    return li;
  }

  function populateIssueSelects(issues) {
    var selects = [
      { el: document.getElementById("cap-issue"), allowEmpty: false },
      { el: document.getElementById("tl-issue"), allowEmpty: false },
      { el: document.getElementById("ex-issue"), allowEmpty: true }
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
        return refreshStatus();
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
        announce(
          t("msg_capture_done") + " " +
          t("capture_hash_label") + ": " + res.content_hash + ". " +
          t("capture_timestamp_label") + ": " + stamp,
          "ok"
        );
        signalSuccess();
        return refreshStatus();
      }, announceError);
    });
  }

  function wireTimeline() {
    var form = document.getElementById("timeline-form");
    if (!form) { return; }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var issueSel = document.getElementById("tl-issue");
      var kind = document.getElementById("tl-kind");
      var text = document.getElementById("tl-text");
      if (!issueSel.value) {
        announce(t("error_issue_required"), "error");
        issueSel.focus();
        return;
      }
      if (!kind.value.trim()) {
        announce(t("error_kind_required"), "error");
        kind.focus();
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
          kind: kind.value.trim(),
          text: text.value.trim()
        });
      }).then(function () {
        form.reset();
        announce(t("msg_timeline_added"), "ok");
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
          include_originals: originals
        });
      }).then(function (res) {
        renderExportResult(res);
        announce(
          res.verified ? t("msg_export_done_ok") : t("msg_export_done_warn"),
          res.verified ? "ok" : "error"
        );
        if (res.verified) {
          signalSuccess();
        }
        return refreshStatus();
      }, announceError);
    });
  }

  function renderExportResult(res) {
    var box = document.getElementById("export-result");
    if (!box) { return; }
    box.textContent = "";
    box.hidden = false;

    var h3 = document.createElement("h3");
    h3.textContent = t("export_result_heading");
    box.appendChild(h3);

    var verdict = document.createElement("p");
    var v = document.createElement("span");
    v.className = res.verified ? "verdict-ok" : "verdict-bad";
    v.textContent = res.verified ? t("verify_intact") : t("verify_failed");
    verdict.appendChild(v);
    box.appendChild(verdict);

    var ul = document.createElement("ul");
    ul.appendChild(line(t("export_out_dir") + ": " + (res.out_dir || "—")));
    ul.appendChild(line(t("export_items") + ": " + formatNumber(res.item_count != null ? res.item_count : 0)));
    ul.appendChild(line(t("export_timestamped") + ": " + formatNumber(res.timestamped_count != null ? res.timestamped_count : 0)));
    if (res.summary) {
      ul.appendChild(line(t("export_summary") + ": " + res.summary));
    }
    box.appendChild(ul);

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
    wireLang();
    wireRefresh();
    wireResolve();
    wireAddIssue();
    wireCapture();
    wireTimeline();
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
