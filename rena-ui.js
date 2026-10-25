(function () {
  'use strict';
  var FLAGS = {
    it: 'https://renadeveloper.altervista.org/bandierait.png',
    en: 'https://renadeveloper.altervista.org/bandieraen.png'
  };
  var R = (window.RenaUI = { lang: document.documentElement.lang === 'en' ? 'en' : 'it' });
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  R.$ = $; R.$$ = $$;

  R.el = function (tag, props) {
    var e = document.createElement(tag);
    Object.keys(props || {}).forEach(function (k) {
      if (k === 'class') e.className = props[k];
      else if (k === 'text') e.textContent = props[k];
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), props[k]);
      else if (props[k] !== false && props[k] != null) e.setAttribute(k, props[k] === true ? '' : props[k]);
    });
    (function add(list) {
      for (var i = 0; i < list.length; i++) {
        var c = list[i];
        if (c == null || c === false) continue;
        if (Array.isArray(c)) add(c);
        else e.append(c.nodeType ? c : document.createTextNode(c));
      }
    })(Array.prototype.slice.call(arguments, 2));
    return e;
  };
  R.icon = function (name, cls) {
    var s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('class', 'i ' + (cls || '')); s.setAttribute('aria-hidden', 'true');
    var u = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    u.setAttribute('href', '#i-' + name); s.appendChild(u); return s;
  };

  R.t = function (it, en) { return R.lang === 'en' ? en : it; };
  R.pick = function (m) { return m && typeof m === 'object' ? (m[R.lang] || m.it || '') : (m || ''); };
  R.translate = function (lang) {
    R.lang = lang === 'en' ? 'en' : 'it';
    document.documentElement.lang = R.lang;
    $$('[data-translate-it]').forEach(function (e) {
      var v = e.getAttribute('data-translate-' + R.lang); if (v !== null) e.textContent = v;
    });
    $$('[data-placeholder-it]').forEach(function (e) {
      var v = e.getAttribute('data-placeholder-' + R.lang); if (v !== null) e.placeholder = v;
    });
    var flag = $('#langFlag'), code = $('#langCode');
    if (flag) { flag.src = FLAGS[R.lang]; }
    if (code) code.textContent = R.lang.toUpperCase();
    $$('.lang-opt').forEach(function (b) { b.classList.toggle('active', b.dataset.lang === R.lang); });
    document.dispatchEvent(new CustomEvent('rena:lang', { detail: R.lang }));
  };
  R.initLang = function (serverLang, fixed) {
    var saved = null;
    try { saved = localStorage.getItem('preferredLanguage'); } catch (e) {}
    var lang = fixed ? serverLang : (saved === 'it' || saved === 'en' ? saved : serverLang);
    R.translate(lang);
  };
  R.setLang = function (lang) {
    try { localStorage.setItem('preferredLanguage', lang); } catch (e) {}
    R.translate(lang);
  };

  R.toast = function (msg, type, ms) {
    var region = $('#toasts'); if (!region) return;
    var t = R.el('div', { class: 'toast ' + (type || '') }, R.icon(type === 'ok' ? 'check-circle' : type === 'error' ? 'alert-circle' : 'info'), R.el('span', { text: R.pick(msg) }));
    region.append(t);
    setTimeout(function () { t.remove(); }, ms || 6000);
  };
  R.api = function (url, payload, opts) {
    opts = opts || {};
    var init = { credentials: 'same-origin', cache: 'no-store' };
    if (payload) { init.method = 'POST'; init.headers = { 'Content-Type': 'application/json' }; init.body = JSON.stringify(payload); }
    return fetch(url, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok || d.success === false) { var e = new Error(d.error || R.t('Operazione non riuscita', 'Something went wrong')); e.data = d; e.status = r.status; throw e; }
        return d;
      });
    });
  };
  R.busy = function (btn, on) {
    if (!btn) return;
    if (on) { btn.dataset.html = btn.innerHTML; btn.disabled = true; btn.setAttribute('aria-busy', 'true'); btn.prepend(R.icon('loader', 'spin')); }
    else { btn.disabled = false; btn.removeAttribute('aria-busy'); var s = btn.querySelector('.spin'); if (s) s.remove(); }
  };

  R.open = function (id) { var d = typeof id === 'string' ? document.getElementById(id) : id; if (d && !d.open) d.showModal(); return d; };
  R.close = function (id) { var d = typeof id === 'string' ? document.getElementById(id) : id; if (d && d.open) d.close(); };
  R.ask = function (opts) {
    return new Promise(function (resolve) {
      var done = false, form = R.el('form', { novalidate: false });
      var dlg = R.el('dialog', { 'aria-label': opts.title });
      var first = null;
      (opts.fields || []).forEach(function (f, i) {
        var id = 'ask-' + Date.now() + '-' + i;
        var input = R.el('input', { id: id, name: f.name, type: f.type || 'text', value: f.value || '', required: f.required !== false, autocomplete: f.autocomplete || 'off', inputmode: f.inputmode, maxlength: f.maxlength, pattern: f.pattern });
        if (f.otp) input.classList.add('otp');
        var wrap = R.el('div', { class: 'input' }, input);
        if (f.type === 'password') wrap.append(pwToggle());
        form.append(R.el('div', { class: 'field' }, R.el('label', { for: id, text: f.label }), wrap, f.hint ? R.el('p', { class: 'hint', text: f.hint }) : null));
        if (!first) first = input;
      });
      var cancel = R.el('button', { type: 'button', class: 'btn btn-ghost', text: opts.cancelLabel || R.t('Annulla', 'Cancel') });
      var ok = R.el('button', { type: 'submit', class: 'btn ' + (opts.danger ? 'btn-danger' : ''), text: opts.confirmLabel || R.t('Conferma', 'Confirm') });
      form.append(R.el('div', { class: 'dlg-actions' }, cancel, ok));
      dlg.append(R.el('div', { class: 'dlg' }, R.el('h2', { text: opts.title }), opts.text ? R.el('p', { class: 'dlg-text', text: opts.text }) : null, form));
      function finish(v) { if (done) return; done = true; dlg.close(); dlg.remove(); resolve(v); }
      form.addEventListener('submit', function (e) {
        e.preventDefault(); var v = {};
        $$('input', form).forEach(function (i) { v[i.name] = i.value; });
        finish(v);
      });
      cancel.addEventListener('click', function () { finish(null); });
      dlg.addEventListener('cancel', function (e) { e.preventDefault(); finish(null); });
      dlg.addEventListener('click', function (e) { if (e.target === dlg) finish(null); });
      document.body.append(dlg); dlg.showModal();
      (first || ok).focus();
    });
  };
  R.confirm = function (opts) { opts.fields = []; return R.ask(opts).then(function (v) { return v !== null; }); };

  function pwToggle() {
    return R.el('button', { type: 'button', class: 'pw-toggle', 'data-pw-toggle': true, 'aria-pressed': 'false', 'aria-label': R.t('Mostra password', 'Show password') }, R.icon('eye'));
  }
  R.pwToggle = pwToggle;
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-pw-toggle]'); if (!b) return;
    var input = b.parentElement.querySelector('input'); if (!input) return;
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    b.setAttribute('aria-pressed', show ? 'true' : 'false');
    b.setAttribute('aria-label', show ? R.t('Nascondi password', 'Hide password') : R.t('Mostra password', 'Show password'));
    var u = b.querySelector('use'); if (u) u.setAttribute('href', show ? '#i-eye-off' : '#i-eye');
  });
  document.addEventListener('input', function (e) {
    var o = e.target.closest && e.target.closest('[data-otp]'); if (!o) return;
    o.value = o.value.replace(/\D/g, '').slice(0, 6);
    if (o.value.length === 6 && o.hasAttribute('data-autosubmit') && o.form) o.form.requestSubmit();
  });
  R.pwRules = function (p) {
    var r = { length: p.length >= 8, number: /[0-9]/.test(p), special: /[\/\-_]/.test(p) };
    r.ok = r.length && r.number && r.special; return r;
  };
  R.paintRules = function (list, p) {
    var r = R.pwRules(p);
    $$('li', list).forEach(function (li) {
      var ok = r[li.dataset.rule]; li.classList.toggle('ok', !!ok);
      var u = li.querySelector('use'); if (u) u.setAttribute('href', ok ? '#i-check-circle' : '#i-circle');
    });
    return r;
  };
  document.addEventListener('submit', function (e) {
    var f = e.target; if (!f.matches || !f.matches('form[data-busy]') || e.defaultPrevented) return;
    setTimeout(function () { $$('button[type=submit]', f).forEach(function (b) { R.busy(b, true); }); }, 0);
  });
  window.addEventListener('pageshow', function (e) { if (e.persisted) $$('button[aria-busy]').forEach(function (b) { R.busy(b, false); }); });

  R.pkDecode = function (v) { var s = v.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - v.length % 4) % 4); return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); };
  R.pkEncode = function (b) { return btoa(String.fromCharCode.apply(null, new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  R.passkeyLogin = function (endpoint, optionsBody) {
    if (!window.PublicKeyCredential || !navigator.credentials) return Promise.reject(new Error(R.t('Questo browser non supporta le passkey.', 'This browser does not support passkeys.')));
    return R.api(endpoint, optionsBody).then(function (d) {
      var o = d.options; o.challenge = R.pkDecode(o.challenge);
      o.allowCredentials = (o.allowCredentials || []).map(function (c) { return Object.assign({}, c, { id: R.pkDecode(c.id) }); });
      return navigator.credentials.get({ publicKey: o });
    }).then(function (c) {
      if (!c) throw new Error(R.t('Accesso annullato', 'Sign-in cancelled'));
      return R.api(endpoint, { action: 'login_verify', id: c.id, rawId: R.pkEncode(c.rawId), response: {
        clientDataJSON: R.pkEncode(c.response.clientDataJSON), authenticatorData: R.pkEncode(c.response.authenticatorData),
        signature: R.pkEncode(c.response.signature), userHandle: c.response.userHandle ? R.pkEncode(c.response.userHandle) : '' } });
    });
  };

  document.addEventListener('DOMContentLoaded', function () {
    var lb = $('#langBtn'), ld = $('#langDialog');
    if (lb && ld) {
      lb.addEventListener('click', function () { ld.showModal(); });
      $$('.lang-opt', ld).forEach(function (b) { b.addEventListener('click', function () { R.setLang(b.dataset.lang); ld.close(); }); });
    }
    var fl = $('#langFlag'); if (fl) fl.addEventListener('error', function () { fl.style.display = 'none'; });
    document.addEventListener('click', function (e) {
      var c = e.target.closest('[data-close]'); if (c) { var d = c.closest('dialog'); if (d) d.close(); }
      if (e.target.tagName === 'DIALOG' && !e.target.hasAttribute('data-modal-lock')) e.target.close();
    });
    var menu = $('#custom-menu');
    if (menu) {
      document.addEventListener('contextmenu', function (e) {
        if (window.innerWidth <= 768) return;
        if (e.target.closest('input,textarea,select,[contenteditable],dialog,a[href]')) return;
        if (String(window.getSelection()).length) return;
        e.preventDefault(); menu.hidden = false;
        var x = Math.min(e.clientX, window.innerWidth - menu.offsetWidth - 8), y = Math.min(e.clientY, window.innerHeight - menu.offsetHeight - 8);
        menu.style.left = x + 'px'; menu.style.top = y + 'px';
      });
      var hide = function () { menu.hidden = true; };
      document.addEventListener('click', hide); window.addEventListener('scroll', hide, { passive: true });
      document.addEventListener('keydown', function (e) { if (e.key === 'Escape') hide(); });
    }
  });
})();
