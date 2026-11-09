"use strict";
const $ = id => document.getElementById(id);
const POLL = 5000;
let page = "traffic", range = "10m", timer = null, last = null, ytData = null;

// ---------- форматирование ----------
function num(v, d) { return v.toLocaleString("ru-RU", { maximumFractionDigits: d }); }
function bits(v) {
  if (v == null) return "нет данных";
  const u = ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с"];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return num(v, v < 10 && i ? 1 : 0) + " " + u[i];
}
function bytes(v) {
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return num(v, i >= 2 ? 1 : 0) + " " + u[i];
}
function ago(sec) {
  if (sec < 60) return "только что";
  if (sec < 3600) return Math.floor(sec / 60) + " мин назад";
  if (sec < 86400) return Math.floor(sec / 3600) + " ч назад";
  return Math.floor(sec / 86400) + " дн назад";
}
function uptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600);
  return d ? d + " дн " + h + " ч" : h + " ч " + Math.floor(s % 3600 / 60) + " мин";
}
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// ---------- запросы ----------
async function api(path, opt) {
  opt = opt || {};
  const init = { method: opt.method || "GET", headers: { "X-AWGC": "1" } };
  if (opt.body) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opt.body); }
  const r = await fetch("api/" + path, init);
  let data = null;
  try { data = await r.json(); } catch (_) { /* пустой ответ */ }
  if (r.status === 401 && path !== "login") { showLogin(); throw new Error("Нужен вход"); }
  if (!r.ok) {
    const m = (data && data.error) || "Сервер не ответил. Повтори через минуту.";
    throw new Error(m[0].toUpperCase() + m.slice(1));
  }
  return data;
}

function toast(text, undo) {
  const t = $("toast");
  t.replaceChildren(el("span", "", text));
  if (undo) {
    const b = el("button", "small", "Отменить");
    b.type = "button";
    b.onclick = () => { t.hidden = true; undo(); };
    t.append(b);
  }
  t.hidden = false;
  clearTimeout(t._t);
  t._t = setTimeout(() => { t.hidden = true; }, undo ? 7000 : 3500);
}

function confirmBox(title, text, yes) {
  return new Promise(res => {
    const d = $("confirm-dialog");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-yes").textContent = yes;
    $("confirm-yes").onclick = () => { d.close(); res(true); };
    $("confirm-no").onclick = () => { d.close(); res(false); };
    d.showModal();
  });
}

// ---------- вход ----------
let needUser = false, setupToken = null, setupTimer = null;
function showOnly(id) { ["setup", "login", "app"].forEach(x => { $(x).hidden = x !== id; }); }
function showSetup(part) {
  showOnly("setup");
  ["setup-wait", "admin-form", "exit-form", "setup-run"].forEach(x => { $(x).hidden = x !== part; });
}
function showLogin() {
  stopPoll();
  clearTimeout(setupTimer);
  showOnly("login");
  $("login-user-box").hidden = !needUser;
  $("login-user").required = needUser;
  (needUser ? $("login-user") : $("login-pass")).focus();
}
function showApp() {
  showOnly("app");
  go(location.hash.slice(1) || "traffic");
}
async function enter() {
  const m = await api("me");
  $("side-version").textContent = "Версия " + m.version;
  if (m.stage === "pending") await pollSetup(); else showApp();
}
$("login-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("login-error");
  err.hidden = true;
  try {
    await api("login", { method: "POST", body: { user: $("login-user").value.trim(), password: $("login-pass").value } });
    $("login-pass").value = "";
    await enter();
  } catch (e) { err.textContent = e.message; err.hidden = false; }
};
$("admin-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("admin-error");
  err.hidden = true;
  try {
    if ($("admin-pass").value !== $("admin-pass2").value) throw new Error("Пароли не совпадают");
    await api("setup/admin", { method: "POST", body: { token: setupToken, user: $("admin-user").value.trim(), password: $("admin-pass").value } });
    needUser = true;
    setupToken = null;
    ev.target.reset();
    await enter();
  } catch (e) { err.textContent = e.message; err.hidden = false; }
};

// ---------- подключение сервера 2 ----------
const RUN_STEPS = ["Данные", "Сервер 1", "Установка на сервер 2", "Туннели и маршруты", "Проверка связи"];
function renderRun(s) {
  const done = s.stage === "ready" && !s.running;
  $("run-steps").replaceChildren(...RUN_STEPS.map((name, i) => {
    const n = i + 1;
    const li = el("li", done || n < s.step ? "done" : n === s.step ? "now" : "", name);
    if (n === s.step && !done) li.setAttribute("aria-current", "step");
    return li;
  }));
  const log = $("run-log");
  log.hidden = !s.log || !s.log.length;
  log.textContent = (s.log || []).join("\n");
  log.scrollTop = log.scrollHeight;
  $("run-title").textContent = done ? (s.failed ? "Каскад установлен, но проверка нашла проблему" : "Каскад работает") : "Настраиваю каскад";
  $("run-text").textContent = done
    ? (s.failed ? "Открой раздел «Серверы» и запусти проверку. Чаще всего закрыт UDP-порт у хостера." : "Создай первого пользователя и подключи устройство.")
    : "Обычно это занимает до 10 минут. Страницу можно закрыть: установка продолжится.";
  $("run-done").hidden = !done;
}
async function pollSetup() {
  clearTimeout(setupTimer);
  let s;
  try { s = await api("setup/state"); }
  catch (e) { if ($("login").hidden) setupTimer = setTimeout(pollSetup, 4000); return; }
  if (s.running || s.stage === "ready") {
    showSetup("setup-run");
    renderRun(s);
    if (s.running) setupTimer = setTimeout(pollSetup, 1500);
    return;
  }
  showSetup("exit-form");
  const err = $("exit-error");
  err.hidden = !s.failed;
  err.textContent = s.error ? s.error[0].toUpperCase() + s.error.slice(1) : "";
}
$("exit-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("exit-error"), btn = ev.target.querySelector("button");
  err.hidden = true;
  btn.disabled = true;
  try {
    await api("setup/connect", { method: "POST", body: { ip: $("exit-ip").value.trim(), port: Number($("exit-port").value), password: $("exit-pass").value } });
    $("exit-pass").value = "";
    await pollSetup();
  } catch (e) { err.textContent = e.message; err.hidden = false; }
  btn.disabled = false;
};
$("run-done").onclick = () => { location.hash = "users"; showApp(); };

async function logout() { await api("logout", { method: "POST" }); showLogin(); }
$("logout").onclick = logout;
$("logout-m").onclick = logout;

// ---------- навигация ----------
function stopPoll() { clearTimeout(timer); timer = null; }
function go(name) {
  if (!["users", "traffic", "servers", "youtube", "routes", "updates", "telegram"].includes(name)) name = "traffic";
  page = name;
  history.replaceState(null, "", "#" + name);
  document.querySelectorAll(".tab[data-page]").forEach(t => {
    if (t.dataset.page === name) t.setAttribute("aria-current", "page"); else t.removeAttribute("aria-current");
  });
  document.querySelectorAll(".page").forEach(p => { p.hidden = p.id !== "page-" + name; });
  if (["servers", "updates", "telegram"].includes(name)) $("more-tab").setAttribute("aria-current", "page"); else $("more-tab").removeAttribute("aria-current");
  closeSheet();
  refresh();
}
async function refresh(force = false) {
  stopPoll();
  const at = page;
  try {
    if (at === "users") renderUsers(await api("users"), force);
    else if (at === "youtube") {
      const y = await api("youtube");
      if (page !== at) return;
      renderYoutube(y);
      if ((y.auto && y.auto.state === "running") || (y.search && y.search.state === "running")) {
        timer = setTimeout(refresh, 1500);
        return;
      }
    }
    else if (at === "routes") {
      const d = await api("routes");
      if (page === at) renderRoutes(d);
      return; // страница не обновляется сама: на ней вводят адреса
    }
    else if (at === "telegram") {
      const t = await api("telegram");
      if (page !== at) return;
      renderTelegram(t);
      if (t.enabled) { timer = setTimeout(refresh, 3000); return; }
    }
    else if (at === "updates") {
      const s = await api("update");
      if (page !== at) return;
      renderUpdate(s);
      if (s.state === "running") { timer = setTimeout(refresh, 2000); return; }
    }
    else {
      const d = await api("traffic?range=" + range);
      last = d;
      if (page !== at) return;
      if (at === "traffic") { ytData = ytData || await api("youtube"); renderTraffic(d); }
      else renderServers(d);
    }
  } catch (_) {
    if ($("app").hidden) return;
    if (at === "updates" && updWaiting) { timer = setTimeout(refresh, 2000); return; } // панель перезапускается
  }
  if (!$("app").hidden) timer = setTimeout(refresh, POLL);
}
document.querySelectorAll(".tab[data-page]").forEach(t => { t.onclick = () => go(t.dataset.page); });
document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("app").hidden) refresh(); });

// ---------- «Ещё» на телефоне ----------
function closeSheet() { $("more-sheet").hidden = true; $("more-tab").setAttribute("aria-expanded", "false"); }
$("more-tab").onclick = () => {
  const open = $("more-sheet").hidden;
  $("more-sheet").hidden = !open;
  $("more-tab").setAttribute("aria-expanded", String(open));
  if (open) $("more-sheet").querySelector("button").focus();
};
$("more-sheet").onclick = ev => { if (ev.target === ev.currentTarget) closeSheet(); };
document.addEventListener("keydown", ev => { if (ev.key === "Escape" && !$("more-sheet").hidden) { closeSheet(); $("more-tab").focus(); } });
document.querySelectorAll("[data-go]").forEach(b => { b.onclick = () => go(b.dataset.go); });

// ---------- маршруты ----------
const TARGETS = [["auto", "Как обычно"], ["1", "Сервер 1"], ["2", "Сервер 2"]];
const targetName = t => t === "1" ? "Сервер 1" : t === "2" ? "Сервер 2" : "Как обычно";
let ruleTarget = "1", routesBusy = false;
function count(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  const w = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
  return n.toLocaleString("ru-RU") + " " + w;
}
function when(sec) {
  const d = new Date(sec * 1000);
  return d.toLocaleDateString("ru-RU", { day: "numeric", month: "short" }) + " в " + d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
}
function renderRoutes(d) {
  $("routes-services").replaceChildren(...d.services.map(s => {
    const row = el("div", "route-row" + (s.target !== "auto" ? " set" : ""));
    const info = el("div", "route-info");
    info.append(el("strong", "", s.name), el("span", "route-desc", s.desc));
    let meta = "Списки загрузятся, когда выберешь сервер";
    if (s.updated) {
      meta = [s.nets ? count(s.nets, "сеть", "сети", "сетей") : "", count(s.domains, "домен", "домена", "доменов"), "обновлено " + when(s.updated)].filter(Boolean).join(" · ");
      if (s.error) meta += " · источник не ответил, оставлен прежний список";
    }
    info.append(el("span", "route-meta" + (s.error ? " warn" : ""), meta));
    const pills = el("div", "pills");
    pills.setAttribute("role", "group");
    pills.setAttribute("aria-label", "Маршрут: " + s.name);
    TARGETS.forEach(([v, label]) => {
      const b = el("button", "", label);
      b.type = "button";
      b.setAttribute("aria-pressed", String(s.target === v));
      b.onclick = () => { if (s.target !== v) setRoute(s, v); };
      pills.append(b);
    });
    row.append(info, pills);
    return row;
  }));
  const rules = $("rules");
  if (!d.rules.length) rules.replaceChildren(el("li", "empty small-empty", "Своих правил пока нет"));
  else rules.replaceChildren(...d.rules.map(r => {
    const li = el("li", "rule");
    const del = el("button", "small", "Удалить");
    del.type = "button";
    del.setAttribute("aria-label", "Удалить правило " + r.value);
    del.onclick = () => delRule(r);
    li.append(el("code", "", r.value), el("span", "tag " + (r.target === "1" ? "on" : "brand"), targetName(r.target)), del);
    return li;
  }));
}
function lockRoutes(on) {
  routesBusy = on;
  document.querySelectorAll("#page-routes button").forEach(b => { b.disabled = on; });
}
async function routesDo(path, body, done, wait) {
  if (routesBusy) return false;
  lockRoutes(true);
  if (wait) toast(wait);
  let ok = true;
  try {
    await api(path, { method: "POST", body });
    if (done) toast(done);
  } catch (e) { ok = false; toast(e.message); }
  lockRoutes(false);
  try { renderRoutes(await api("routes")); } catch (_) { /* покажет следующий заход */ }
  return ok;
}
function setRoute(s, v) {
  routesDo("routes/service", { id: s.id, target: v }, s.name + ": " + targetName(v).toLowerCase(),
    s.updated ? "Применяю маршрут" : "Загружаю списки " + s.name + ", это займёт до минуты");
}
async function delRule(r) {
  if (await routesDo("routes/rule/delete", { value: r.value })) {
    toast("Правило " + r.value + " удалено", () => routesDo("routes/rule", { value: r.value, target: r.target }, "Правило возвращено"));
  }
}
document.querySelectorAll("[data-rule-target]").forEach(b => {
  b.onclick = () => {
    ruleTarget = b.dataset.ruleTarget;
    document.querySelectorAll("[data-rule-target]").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
  };
});
$("rule-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("rule-error"), v = $("rule-value").value.trim();
  err.hidden = true;
  if (routesBusy) return;
  lockRoutes(true);
  try {
    await api("routes/rule", { method: "POST", body: { value: v, target: ruleTarget } });
    $("rule-value").value = "";
    toast("Правило добавлено: " + targetName(ruleTarget).toLowerCase());
  } catch (e) { err.textContent = e.message; err.hidden = false; }
  lockRoutes(false);
  try { renderRoutes(await api("routes")); } catch (_) { /* покажет следующий заход */ }
};
$("route-check-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("route-check-error"), list = $("route-check"), btn = ev.target.querySelector("button");
  err.hidden = true;
  btn.disabled = true;
  try {
    const r = await api("routes/check", { method: "POST", body: { host: $("route-check-host").value.trim() } });
    list.replaceChildren(...r.results.map(x => {
      const li = el("li", "");
      li.append(el("code", "", x.ip), el("span", "tag " + (x.target === "1" ? "on" : "brand"), targetName(x.target)), el("span", "route-desc", x.reason));
      return li;
    }));
  } catch (e) { list.replaceChildren(); err.textContent = e.message; err.hidden = false; }
  btn.disabled = false;
};
$("btn-routes-update").onclick = () => routesDo("routes/update", null, "Списки обновлены", "Обновляю списки сервисов, это займёт до минуты");

// ---------- обновления ----------
let updInfo = null, updWaiting = false;
function renderUpdate(s) {
  $("upd-current").textContent = s.current;
  $("side-version").textContent = "Версия " + s.current;
  const running = s.state === "running";
  updWaiting = running;
  const run = $("upd-run");
  run.hidden = s.state === "idle";
  $("upd-log").textContent = s.log.join("\n");
  $("upd-log").scrollTop = $("upd-log").scrollHeight;
  const text = $("upd-run-text");
  text.className = "upd-msg " + (s.state === "done" ? "ok" : s.state === "failed" ? "bad" : "");
  if (running) {
    $("upd-run-title").textContent = "Идёт обновление";
    text.textContent = "Панель перезапустится и откроется сама. Страницу можно не закрывать.";
  } else {
    $("upd-run-title").textContent = "Последнее обновление";
    text.textContent = s.state === "done" ? "Обновлено до версии " + s.to
      : (s.rolledBack ? "Новая версия не заработала, вернулась прежняя. " : "Обновление не удалось. ") + cap(s.error || "");
  }
  $("btn-upd-check").disabled = running;
  // уже поставленная версия: панель могла ещё не перезапуститься
  const have = v => v === s.current || (s.state === "done" && v === s.to);
  const can = !running && updInfo && updInfo.newer && !have(updInfo.latest);
  $("btn-upd-start").hidden = !can;
  if (can) $("btn-upd-start").textContent = "Обновить до " + updInfo.latest;
  const found = $("upd-found");
  found.hidden = !updInfo || running;
  if (updInfo) {
    const fresh = updInfo.newer && !have(updInfo.latest);
    found.className = "upd-msg " + (fresh ? "" : "ok");
    found.textContent = fresh ? "Доступна версия " + updInfo.latest : "Установлена последняя версия";
    $("upd-notes").hidden = !fresh || !updInfo.notes || running;
    $("upd-notes").replaceChildren(...updInfo.notes.split("\n").map(l => l.trim()).filter(Boolean)
      .map(l => el("p", "", l.replace(/^[-*]\s+/, "• ").replace(/^#+\s*/, ""))));
  }
}
function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }
$("btn-upd-check").onclick = async ev => {
  const btn = ev.currentTarget, err = $("upd-error");
  err.hidden = true;
  btn.disabled = true;
  try { updInfo = await api("update/check", { method: "POST" }); renderUpdate(await api("update")); }
  catch (e) { err.textContent = e.message; err.hidden = false; }
  btn.disabled = false;
};
$("btn-upd-start").onclick = async ev => {
  const btn = ev.currentTarget, err = $("upd-error");
  err.hidden = true;
  btn.disabled = true;
  try {
    await api("update/start", { method: "POST", body: { tag: updInfo.tag } });
    updWaiting = true;
    await refresh();
  } catch (e) { err.textContent = e.message; err.hidden = false; }
  btn.disabled = false;
};

// ---------- пользователи ----------
function stateOf(u) {
  if (!u.enabled) return ["off", "Отключён"];
  if (u.online) return ["on", "На связи"];
  if (u.lastHandshake) return ["", "Был " + ago(Date.now() / 1000 - u.lastHandshake)];
  return ["", "Не подключался"];
}
function copyText(text, msg = "Скопировано") {
  if (!text) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
  } else {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(msg);
}

async function toggleUserTG(u, proto, btnEl) {
  const enc = encodeURIComponent(u.name);
  const newMtproto = proto === "tg" ? !u.tgMtproto : u.tgMtproto;
  const newWeb = proto === "web" ? !u.tgWeb : u.tgWeb;
  const targetVal = proto === "tg" ? newMtproto : newWeb;

  // Мгновенный визуальный отклик
  if (btnEl) {
    btnEl.className = "tag-btn " + (targetVal ? "on" : "off");
    btnEl.title = (proto === "tg" ? "MTProto Proxy: " : "Web-мост: ") + (targetVal ? "включен" : "отключен") + " (нажми для переключения)";
    btnEl.blur();
  }

  try {
    const info = await api("users/" + enc + "/telegram");
    await api("users/" + enc + "/telegram", {
      method: "POST",
      body: { mtproto: newMtproto, web: newWeb, secret: info.secret }
    });
    u.tgMtproto = newMtproto;
    u.tgWeb = newWeb;
    toast((proto === "tg" ? "MTProto Proxy " : "Web мост ") + (targetVal ? "включен" : "отключен") + " для " + u.name);
    refresh(true);
  } catch (e) {
    // При ошибке возвращаем прежний цвет
    if (btnEl) {
      btnEl.className = "tag-btn " + (!targetVal ? "on" : "off");
      btnEl.title = (proto === "tg" ? "MTProto Proxy: " : "Web-мост: ") + (!targetVal ? "включен" : "отключен") + " (нажми для переключения)";
    }
    toast("Ошибка: " + e.message);
  }
}

function renderUsers(list, force = false) {
  const box = $("users-list");
  if (!force && document.querySelector("#users-list button:focus")) return; // не сбивать фокус при фоновом обновлении
  if (!list.length) {
    box.replaceChildren(el("p", "empty", "Пользователей пока нет. Впиши имя и нажми «Создать»."));
    return;
  }
  const root = el("div", "users");
  for (const u of list) {
    const row = el("div", "user");
    const a = el("div");
    a.append(el("span", "user-name", u.name), el("span", "user-ip", u.ip));

    const tgCol = el("div", "user-tg-col");
    const btnTG = el("button", "tag-btn " + (u.tgMtproto ? "on" : "off"), "TG");
    btnTG.type = "button";
    btnTG.title = "MTProto Proxy: " + (u.tgMtproto ? "включен" : "отключен") + " (нажми для переключения)";
    btnTG.onclick = () => toggleUserTG(u, "tg", btnTG);

    const btnWeb = el("button", "tag-btn " + (u.tgWeb ? "on" : "off"), "WEB");
    btnWeb.type = "button";
    btnWeb.title = "Web-мост: " + (u.tgWeb ? "включен" : "отключен") + " (нажми для переключения)";
    btnWeb.onclick = () => toggleUserTG(u, "web", btnWeb);

    tgCol.append(btnTG, btnWeb);

    const [cls, text] = stateOf(u);
    const st = el("div");
    st.append(el("span", "tag " + cls, text));
    const sp = el("div");
    sp.append(el("span", "cap", "Скорость"), el("span", "", u.online ? bits(u.downBps + u.upBps) : "нет"));
    const tot = el("div");
    tot.append(el("span", "cap", "За месяц"), el("span", "", bytes(u.monthDown + u.monthUp)));
    const act = el("div", "actions");
    act.append(btn("QR-код", () => openQR(u.name, "wg")));
    act.append(btn("Секрет", () => openSecretDialog(u.name)));
    act.append(btn(u.enabled ? "Отключить" : "Включить", () => toggle(u)));
    act.append(btn("Удалить", () => remove(u)));
    row.append(a, tgCol, st, sp, tot, act);
    root.append(row);
  }
  box.replaceChildren(root);
}
function btn(text, fn) {
  const b = el("button", "small", text);
  b.type = "button";
  b.onclick = async () => {
    b.disabled = true;
    try { await fn(); } catch (e) { toast(e.message); }
    b.disabled = false;
    b.blur();
  };
  return b;
}

let curQRUser = "";
let curQRTab = "wg";
let curQRTGInfo = null;

async function switchQRTab(tab) {
  curQRTab = tab;
  $("qr-tab-wg").setAttribute("aria-pressed", tab === "wg");
  $("qr-tab-tg").setAttribute("aria-pressed", tab === "tg");
  $("qr-tab-web").setAttribute("aria-pressed", tab === "web");

  const enc = encodeURIComponent(curQRUser);
  const img = $("qr-img");
  const hint = $("qr-hint");
  const fileBtn = $("qr-file");
  const tgConnect = $("qr-tg-connect");
  const tgCopy = $("qr-tg-copy");
  const linkBox = $("qr-link-box");
  const linkInp = $("qr-link-input");
  const emptyCard = $("qr-empty-card");
  const emptyTitle = $("qr-empty-title");
  const emptyDesc = $("qr-empty-desc");
  const emptyAction = $("qr-empty-action");

  if (tab === "wg") {
    img.hidden = false;
    img.src = "api/users/" + enc + "/qr.svg";
    emptyCard.hidden = true;
    hint.hidden = false;
    hint.textContent = "Отсканируй код в приложении AmneziaVPN или AmneziaWG либо скачай файл настроек.";
    hint.style.color = "";
    fileBtn.hidden = false;
    tgConnect.hidden = true;
    tgCopy.hidden = true;
    linkBox.hidden = true;
    return;
  }

  // Load telegram info if not loaded yet
  if (!curQRTGInfo || curQRTGInfo.name !== curQRUser) {
    try {
      curQRTGInfo = await api("users/" + enc + "/telegram");
    } catch (e) {
      img.hidden = true;
      emptyCard.hidden = false;
      emptyTitle.textContent = "Ошибка загрузки";
      emptyDesc.textContent = "Не удалось загрузить данные Telegram: " + e.message;
      emptyAction.hidden = true;
      hint.hidden = true;
      fileBtn.hidden = true;
      tgConnect.hidden = true;
      tgCopy.hidden = true;
      linkBox.hidden = true;
      return;
    }
  }

  fileBtn.hidden = true;

  if (tab === "tg") {
    const link = curQRTGInfo.mtproto_link || "";
    if (link && curQRTGInfo.mtproto) {
      img.hidden = false;
      img.src = "api/users/" + enc + "/telegram/qr.svg?type=mtproto";
      emptyCard.hidden = true;
      hint.hidden = false;
      hint.textContent = curQRTGInfo.server_mtproto_enabled
        ? "Отсканируй в Telegram или камерой для быстрого подключения."
        : "Внимание: MTProto прокси отключен на сервере (раздел Telegram).";
      hint.style.color = curQRTGInfo.server_mtproto_enabled ? "" : "var(--warn)";
      linkBox.hidden = false;
      linkInp.value = link;
      tgConnect.hidden = false;
      tgConnect.href = link;
      tgCopy.hidden = false;
      tgCopy.onclick = () => copyText(link, "MTProto ссылка скопирована");
    } else {
      img.hidden = true;
      emptyCard.hidden = false;
      if (!curQRTGInfo.mtproto) {
        emptyTitle.textContent = "MTProto прокси отключен";
        emptyDesc.textContent = "MTProto выключен для этого пользователя.";
        emptyAction.hidden = false;
        emptyAction.className = "small primary";
        emptyAction.textContent = "Включить";
        emptyAction.onclick = async () => {
          emptyAction.disabled = true;
          try {
            await api("users/" + enc + "/telegram", {
              method: "POST",
              body: { mtproto: true, web: curQRTGInfo.web, secret: curQRTGInfo.secret }
            });
            curQRTGInfo.mtproto = true;
            toast("MTProto Proxy включен для " + curQRUser);
            refresh(true);
            curQRTGInfo = null;
            await switchQRTab("tg");
          } catch (e) {
            toast("Ошибка: " + e.message);
          } finally {
            emptyAction.disabled = false;
          }
        };
      } else {
        emptyTitle.textContent = "MTProto отключен на сервере";
        emptyDesc.textContent = "MTProto выключен в основных настройках Telegram.";
        emptyAction.hidden = false;
        emptyAction.className = "small";
        emptyAction.textContent = "Настройки Telegram";
        emptyAction.onclick = () => {
          $("qr-dialog").close();
          go("telegram");
        };
      }
      hint.hidden = true;
      linkBox.hidden = true;
      tgConnect.hidden = true;
      tgCopy.hidden = true;
    }
  } else if (tab === "web") {
    const link = curQRTGInfo.web_link || "";
    if (link && curQRTGInfo.web && curQRTGInfo.web_domain_configured) {
      img.hidden = false;
      img.src = "api/users/" + enc + "/telegram/qr.svg?type=web";
      emptyCard.hidden = true;
      hint.hidden = false;
      hint.textContent = curQRTGInfo.server_web_enabled
        ? "Отсканируй в Telegram или камерой для быстрого подключения."
        : "Внимание: Web-мост выключен в основных настройках Telegram.";
      hint.style.color = curQRTGInfo.server_web_enabled ? "" : "var(--warn)";
      linkBox.hidden = false;
      linkInp.value = link;
      tgConnect.hidden = false;
      tgConnect.href = link;
      tgCopy.hidden = false;
      tgCopy.onclick = () => copyText(link, "Ссылка Web-прокси скопирована");
    } else {
      img.hidden = true;
      emptyCard.hidden = false;
      if (!curQRTGInfo.web) {
        emptyTitle.textContent = "Web-мост отключен";
        emptyDesc.textContent = "Доступ к Web-мосту выключен для этого пользователя.";
        emptyAction.hidden = false;
        emptyAction.className = "small primary";
        emptyAction.textContent = "Включить";
        emptyAction.onclick = async () => {
          emptyAction.disabled = true;
          try {
            await api("users/" + enc + "/telegram", {
              method: "POST",
              body: { mtproto: curQRTGInfo.mtproto, web: true, secret: curQRTGInfo.secret }
            });
            curQRTGInfo.web = true;
            toast("Web мост включен для " + curQRUser);
            refresh(true);
            curQRTGInfo = null;
            await switchQRTab("web");
          } catch (e) {
            toast("Ошибка: " + e.message);
          } finally {
            emptyAction.disabled = false;
          }
        };
      } else if (!curQRTGInfo.web_domain_configured) {
        emptyTitle.textContent = "Домен не настроен";
        emptyDesc.textContent = "Чтобы веб-мост заработал, укажи публичный домен в разделе Telegram (например, tg.example.com).";
        emptyAction.hidden = false;
        emptyAction.className = "small";
        emptyAction.textContent = "Настроить домен в Telegram";
        emptyAction.onclick = () => {
          $("qr-dialog").close();
          go("telegram");
        };
      } else {
        emptyTitle.textContent = "Веб-мост не активен";
        emptyDesc.textContent = "Включи Web-мост в разделе Telegram.";
        emptyAction.hidden = false;
        emptyAction.className = "small";
        emptyAction.textContent = "Открыть настройки Telegram";
        emptyAction.onclick = () => {
          $("qr-dialog").close();
          go("telegram");
        };
      }
      hint.hidden = true;
      linkBox.hidden = true;
      tgConnect.hidden = true;
      tgCopy.hidden = true;
    }
  }
}

async function openQR(name, initialTab = "wg") {
  curQRUser = name;
  curQRTGInfo = null;
  const tabs = document.querySelector(".qr-tabs");
  if (tabs) tabs.hidden = false;
  $("qr-file").style.display = "";
  const enc = encodeURIComponent(name);
  $("qr-title").textContent = name;
  $("qr-file").href = "api/users/" + enc + "/conf";
  $("qr-file").setAttribute("download", name + ".conf");
  await switchQRTab(initialTab);
  $("qr-dialog").showModal();
}

$("qr-tab-wg").onclick = () => switchQRTab("wg");
$("qr-tab-tg").onclick = () => switchQRTab("tg");
$("qr-tab-web").onclick = () => switchQRTab("web");
$("qr-close").onclick = () => $("qr-dialog").close();

let curSecUser = "";

async function openSecretDialog(name) {
  curSecUser = name;
  $("sec-name").textContent = name;
  const err = $("sec-error");
  err.hidden = true;
  try {
    const info = await api("users/" + encodeURIComponent(name) + "/telegram");
    $("sec-input").value = info.secret || "";
    $("secret-dialog").showModal();
  } catch (e) {
    toast("Ошибка: " + e.message);
  }
}

$("sec-close").onclick = () => $("secret-dialog").close();

$("sec-random").onclick = async () => {
  if (!curSecUser) return;
  try {
    const info = await api("users/" + encodeURIComponent(curSecUser) + "/telegram/secret", { method: "POST" });
    $("sec-input").value = info.secret || "";
    toast("Секрет сгенерирован");
  } catch (e) {
    toast("Ошибка: " + e.message);
  }
};

$("sec-save").onclick = async () => {
  if (!curSecUser) return;
  const err = $("sec-error");
  err.hidden = true;
  const secret = $("sec-input").value.trim().toLowerCase();

  if (secret.length !== 32 || !/^[0-9a-f]{32}$/.test(secret)) {
    err.textContent = "Секрет должен состоять ровно из 32 шестнадцатеричных символов (0-9, a-f)";
    err.hidden = false;
    return;
  }

  try {
    const info = await api("users/" + encodeURIComponent(curSecUser) + "/telegram");
    await api("users/" + encodeURIComponent(curSecUser) + "/telegram", {
      method: "POST",
      body: { mtproto: info.mtproto, web: info.web, secret }
    });
    toast("Секрет сохранён");
    $("secret-dialog").close();
    refresh(true);
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
};

async function toggle(u) {
  if (document.activeElement) document.activeElement.blur();
  const name = encodeURIComponent(u.name);
  if (u.enabled) {
    await api("users/" + name + "/disable", { method: "POST" });
    toast("Пользователь " + u.name + " отключён", async () => {
      await api("users/" + name + "/enable", { method: "POST" });
      refresh(true);
    });
  } else {
    await api("users/" + name + "/enable", { method: "POST" });
    toast("Пользователь " + u.name + " включён");
  }
  refresh(true);
}
async function remove(u) {
  const yes = await confirmBox("Удалить " + u.name + "?",
    "Его файл настроек перестанет работать навсегда. Чтобы вернуть доступ, придётся создать пользователя заново.", "Удалить");
  if (!yes) return;
  await api("users/" + encodeURIComponent(u.name), { method: "DELETE" });
  toast("Пользователь " + u.name + " удалён");
  refresh(true);
}
let addTGOn = true;
let addWebOn = true;

if ($("add-tg-btn")) {
  $("add-tg-btn").onclick = () => {
    addTGOn = !addTGOn;
    $("add-tg-btn").className = "tag-btn " + (addTGOn ? "on" : "off");
  };
}

if ($("add-web-btn")) {
  $("add-web-btn").onclick = () => {
    addWebOn = !addWebOn;
    $("add-web-btn").className = "tag-btn " + (addWebOn ? "on" : "off");
  };
}

$("add-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("add-error"), inp = $("add-name"), b = ev.target.querySelector("button[type=submit]");
  err.hidden = true;
  b.disabled = true;
  try {
    const name = inp.value.trim();
    await api("users", { method: "POST", body: { name, tg_mtproto: addTGOn, tg_web: addWebOn } });
    inp.value = "";
    await refresh(true);
    openQR(name);
  } catch (e) { err.textContent = e.message; err.hidden = false; }
  b.disabled = false;
};

// ---------- график ----------
const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs) {
  const e = document.createElementNS(SVG, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function niceMax(v) {
  if (v <= 0) return 1000;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function timeLabel(t, span) {
  const d = new Date(t * 1000);
  const two = n => String(n).padStart(2, "0");
  if (span > 2 * 86400) return two(d.getDate()) + "." + two(d.getMonth() + 1);
  const hm = two(d.getHours()) + ":" + two(d.getMinutes());
  return span < 1200 ? hm + ":" + two(d.getSeconds()) : hm;
}
function legend(series) {
  const l = el("div", "legend");
  for (const x of series) {
    const k = el("span");
    const icon = s("svg", { width: x.bar ? 10 : 18, height: x.bar ? 10 : 6 });
    if (x.bar) icon.append(s("rect", { width: 10, height: 10, rx: 2, class: "f-" + x.c + "-c" }));
    else icon.append(s("line", { x1: 0, x2: 18, y1: 3, y2: 3, class: "line c-" + x.c + (x.dash ? " dash" : "") }));
    k.append(icon, document.createTextNode(x.name));
    l.append(k);
  }
  return l;
}
function drawChart(box, points, step, series) {
  box.classList.remove("loading");
  const usable = points.filter(p => series.some(x => p[x.k] != null));
  if (usable.length < 2) {
    box.replaceChildren(el("p", "no-data", "Данные появятся через несколько минут"));
    return;
  }
  const W = Math.max(280, box.clientWidth), H = 210, L = 74, R = 74, T = 10, B = 24;
  const max = niceMax(Math.max(...points.flatMap(p => series.map(x => p[x.k] || 0))));
  const t0 = points[0].t, t1 = points[points.length - 1].t;
  const X = t => L + (t - t0) / Math.max(1, t1 - t0) * (W - L - R);
  const Y = v => T + (1 - v / max) * (H - T - B);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, height: H, tabindex: 0, role: "img", "aria-label": "График скорости. Стрелками влево и вправо можно перемещаться по точкам." });
  for (let i = 0; i <= 2; i++) {
    const v = max * i / 2, y = Y(v);
    svg.append(s("line", { x1: L, x2: W - R, y1: y, y2: y, class: "grid-l" }));
    const t = s("text", { x: L - 8, y: y + 4, "text-anchor": "end", class: "axis" });
    t.textContent = bits(v);
    svg.append(t);
  }
  const ticks = Math.max(2, Math.min(6, Math.floor((W - L - R) / 90)));
  for (let i = 0; i <= ticks; i++) {
    const tt = t0 + (t1 - t0) * i / ticks;
    const t = s("text", { x: X(tt), y: H - 6, "text-anchor": i === 0 ? "start" : i === ticks ? "end" : "middle", class: "axis" });
    t.textContent = timeLabel(tt, t1 - t0);
    svg.append(t);
  }
  const ends = [];
  for (const x of series) {
    let d = "", prev = null, lastPt = null;
    for (const p of points) {
      const v = p[x.k];
      if (v == null) { prev = null; continue; }
      d += (prev != null && p.t - prev <= step * 2.5 ? "L" : "M") + X(p.t).toFixed(1) + " " + Y(v).toFixed(1);
      prev = p.t;
      lastPt = p;
    }
    if (!x.dash) {
      for (const seg of d.split("M").filter(Boolean)) {
        const nums = seg.split("L").map(q => q.trim().split(" "));
        if (nums.length < 2) continue;
        svg.append(s("path", { d: "M" + seg + "L" + nums[nums.length - 1][0] + " " + Y(0) + "L" + nums[0][0] + " " + Y(0) + "Z", class: "area f-" + x.c + (x.c === "via" || x.c === "dir" ? "-c" : "") }));
      }
    }
    svg.append(s("path", { d, class: "line c-" + x.c + (x.dash ? " dash" : "") }));
    if (lastPt) ends.push({ x, y: Y(lastPt[x.k]), px: X(lastPt.t) });
  }
  ends.sort((a, b) => a.y - b.y);
  for (let i = 1; i < ends.length; i++) if (ends[i].y - ends[i - 1].y < 14) ends[i].y = ends[i - 1].y + 14;
  for (const e of ends) {
    const t = s("text", { x: e.px + 8, y: Math.min(e.y + 4, H - B), class: "tag-t" });
    t.textContent = e.x.short;
    svg.append(t);
  }
  const hair = s("line", { y1: T, y2: H - B, class: "hair", visibility: "hidden" });
  svg.append(hair);
  const dots = series.map(x => {
    const c = s("circle", { r: 4, class: "dot f-" + x.c + (x.c === "via" || x.c === "dir" ? "-c" : ""), visibility: "hidden" });
    svg.append(c);
    return c;
  });
  let cur = -1;
  const tip = $("tip");
  const show = (i, cx, cy) => {
    cur = i;
    const p = points[i], px = X(p.t);
    hair.setAttribute("x1", px); hair.setAttribute("x2", px); hair.setAttribute("visibility", "visible");
    const kids = [el("time", "", new Date(p.t * 1000).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }))];
    series.forEach((x, n) => {
      const v = p[x.k];
      if (v == null) dots[n].setAttribute("visibility", "hidden");
      else { dots[n].setAttribute("cx", px); dots[n].setAttribute("cy", Y(v)); dots[n].setAttribute("visibility", "visible"); }
      const row = el("div");
      const icon = s("svg", { viewBox: "0 0 16 4" });
      icon.append(s("line", { x1: 0, x2: 16, y1: 2, y2: 2, class: "line c-" + x.c + (x.dash ? " dash" : "") }));
      row.append(icon, document.createTextNode(x.name), el("b", "", bits(v)));
      kids.push(row);
    });
    tip.replaceChildren(...kids);
    tip.hidden = false;
    const r = svg.getBoundingClientRect();
    const ax = cx != null ? cx : r.left + px / W * r.width, ay = cy != null ? cy : r.top + 20;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.max(8, Math.min(innerWidth - w - 8, ax + 14)) + "px";
    tip.style.top = Math.max(8, Math.min(innerHeight - h - 8, ay - h - 10)) + "px";
  };
  const hide = () => {
    hair.setAttribute("visibility", "hidden");
    dots.forEach(c => c.setAttribute("visibility", "hidden"));
    tip.hidden = true;
    cur = -1;
  };
  const near = ev => {
    const r = svg.getBoundingClientRect();
    const t = t0 + ((ev.clientX - r.left) / r.width * W - L) / Math.max(1, W - L - R) * (t1 - t0);
    let best = 0;
    points.forEach((p, i) => { if (Math.abs(p.t - t) < Math.abs(points[best].t - t)) best = i; });
    return best;
  };
  svg.addEventListener("pointermove", ev => show(near(ev), ev.clientX, ev.clientY));
  svg.addEventListener("pointerleave", hide);
  svg.addEventListener("blur", hide);
  svg.addEventListener("keydown", ev => {
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    ev.preventDefault();
    const i = cur < 0 ? points.length - 1 : cur + (ev.key === "ArrowLeft" ? -1 : 1);
    show(Math.max(0, Math.min(points.length - 1, i)));
  });
  box.replaceChildren(legend(series), svg);
}

const S_RX = { k: "rx", c: "rx", name: "Принято", short: "принято" };
const S_TX = { k: "tx", c: "tx", name: "Отдано", short: "отдано", dash: true };
function renderCharts(d) {
  const pts = d.points;
  const s1 = pts.map(p => ({ t: p.t, rx: p.s1Rx, tx: p.s1Tx }));
  const s2 = pts.map(p => ({ t: p.t, rx: p.s2Rx, tx: p.s2Tx }));
  const split = pts.map(p => ({ t: p.t, via: p.via, dir: p.direct }));
  drawChart($("chart-s1"), s1, d.step, [S_RX, S_TX]);
  drawChart($("chart-s2"), s2, d.step, [S_RX, S_TX]);
  drawChart($("chart-split"), split, d.step, [
    { k: "via", c: "via", name: "Через сервер 2", short: "сервер 2" },
    { k: "dir", c: "dir", name: "Напрямую, Россия", short: "напрямую", dash: true },
  ]);
}

// ---------- страница трафика ----------
function setAll(key, text, bad) {
  document.querySelectorAll(`[data-v="${key}"]`).forEach(e => {
    e.textContent = text;
    e.classList.toggle("bad-state", !!bad);
  });
}
function setFlow(key, bps) {
  const on = bps > 1000;
  document.querySelectorAll(`[data-flow="${key}"]`).forEach(e => {
    e.classList.toggle("on", on);
    e.classList.toggle("fast", bps > 20e6);
    e.style.strokeWidth = on ? String(Math.min(6, 2.5 + Math.log10(Math.max(1, bps / 1e5)))) : "";
  });
}
function fitPills() {
  document.querySelectorAll(".pill").forEach(g => {
    const t = g.querySelector("text"), r = g.querySelector("rect");
    let w = 0;
    try { w = t.getComputedTextLength(); } catch (_) { return; }
    if (!w) return;
    const cx = Number(t.getAttribute("x"));
    r.setAttribute("width", w + 22);
    r.setAttribute("x", cx - (w + 22) / 2);
  });
}
function renderRoute(d) {
  const n = d.summary.now, s2On = !!n.s2;
  const s2Bps = s2On ? n.s2Rx + n.s2Tx : 0;
  setAll("dev", bits(n.devices));
  setAll("via", bits(n.via));
  setAll("direct", bits(n.direct));
  setAll("s2", s2On ? bits(s2Bps) : "нет данных");
  setAll("online", "подключено: " + d.online);
  setAll("s2state", d.uplink.ok ? "на связи" : "нет связи", !d.uplink.ok);
  const yt = ytData && ytData.mode !== "exit";
  setAll("direct-name", yt ? "российские сайты и YouTube" : "российские сайты");
  setAll("direct-short", yt ? "Россия и YouTube" : "российские сайты");
  setFlow("dev", n.devices);
  setFlow("via", n.via);
  setFlow("direct", n.direct);
  setFlow("s2", s2Bps);
  fitPills();
}
function tile(label, value, sub) {
  const t = el("div", "tile");
  t.append(el("span", "t-label", label), el("span", "t-value", value), el("span", "t-sub", sub));
  return t;
}
function renderTiles(d) {
  const S = d.summary, n = S.now;
  const dev = S.today.via + S.today.direct;
  $("tiles").replaceChildren(
    tile("Сервер 1 сейчас", bits(n.s1Rx + n.s1Tx), "за месяц " + bytes(S.month.s1Rx + S.month.s1Tx)),
    tile("Сервер 2 сейчас", n.s2 ? bits(n.s2Rx + n.s2Tx) : "нет данных", "за месяц " + bytes(S.month.s2Rx + S.month.s2Tx)),
    tile("Устройства сегодня", bytes(dev), "за месяц " + bytes(S.month.via + S.month.direct)),
    tile("Подключено", String(d.online), "пользователей всего: " + d.users.length),
  );
}
function table(id, head, rows) {
  const t = $(id);
  const thead = el("tr");
  head.forEach((h, i) => thead.append(el("th", i ? "num" : "", h)));
  const body = rows.map(r => {
    const tr = el("tr");
    r.forEach((c, i) => tr.append(el("td", i ? "num" : "", c)));
    return tr;
  });
  t.replaceChildren(thead, ...body);
}
function hbars(id, rows, empty) {
  const box = $(id);
  if (!rows.length) { box.replaceChildren(el("p", "no-data", empty)); return; }
  const max = Math.max(1, ...rows.map(r => r.v));
  const g = el("div", "hbars");
  for (const r of rows) {
    const track = el("span", "h-track"), fill = el("span", "h-fill " + (r.c || ""));
    fill.style.width = Math.max(0.8, r.v / max * 100) + "%";
    track.append(fill);
    g.append(el("span", "h-label", r.label), track, el("span", "h-val", bytes(r.v)));
  }
  box.replaceChildren(g);
}
function dailyChart(days) {
  const box = $("chart-daily");
  if (!days.some(d => d.via + d.direct > 0)) {
    box.replaceChildren(el("p", "no-data", "Данные появятся в течение суток"));
    return;
  }
  const W = Math.max(280, box.clientWidth || 560), H = 200, L = 58, R = 6, T = 8, B = 22;
  const vals = days.map(d => d.via + d.direct);
  const unit = Math.pow(1024, 3);
  const niceB = v => { const p = Math.pow(1024, Math.floor(Math.log(Math.max(v, 1)) / Math.log(1024))); const q = v / p; for (const m of [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000]) if (m >= q) return m * p; return 1000 * p; };
  const max = niceB(Math.max(...vals));
  const Y = v => T + (1 - v / max) * (H - T - B);
  const step = (W - L - R) / days.length, bw = Math.max(3, step - 2);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": "Трафик устройств по дням, столбцы" });
  for (let i = 0; i <= 2; i++) {
    const v = max * i / 2, y = Y(v);
    svg.append(s("line", { x1: L, x2: W - R, y1: y, y2: y, class: "grid-l" }));
    const t = s("text", { x: L - 8, y: y + 4, "text-anchor": "end", class: "axis" });
    t.textContent = bytes(v);
    svg.append(t);
  }
  const tip = $("tip");
  days.forEach((d, i) => {
    const x = L + i * step + 1;
    const yVia = Y(d.via), yAll = Y(d.via + d.direct);
    if (d.via > 0) svg.append(s("rect", { x, y: yVia, width: bw, height: Math.max(1, Y(0) - yVia), rx: 2, class: "f-via-c" }));
    if (d.direct > 0) svg.append(s("rect", { x, y: yAll, width: bw, height: Math.max(1, yVia - yAll - 2), rx: 2, class: "f-dir-c" }));
    if (i % Math.ceil(days.length / Math.floor((W - L) / 54)) === 0) {
      const t = s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle", class: "axis" });
      t.textContent = d.day.slice(8) + "." + d.day.slice(5, 7);
      svg.append(t);
    }
    const hit = s("rect", { x: L + i * step, y: T, width: step, height: H - T - B, class: "bar-hit" });
    hit.addEventListener("pointermove", ev => {
      const row = (name, c, v) => { const r = el("div"); const ic = s("svg", { viewBox: "0 0 16 4" }); ic.append(s("line", { x1: 0, x2: 16, y1: 2, y2: 2, class: "line c-" + c })); r.append(ic, document.createTextNode(name), el("b", "", bytes(v))); return r; };
      tip.replaceChildren(el("time", "", d.day.slice(8) + "." + d.day.slice(5, 7) + "." + d.day.slice(0, 4)), row("Через сервер 2", "via", d.via), row("Напрямую", "dir", d.direct));
      tip.hidden = false;
      tip.style.left = Math.max(8, Math.min(innerWidth - tip.offsetWidth - 8, ev.clientX + 14)) + "px";
      tip.style.top = Math.max(8, ev.clientY - tip.offsetHeight - 10) + "px";
    });
    hit.addEventListener("pointerleave", () => { tip.hidden = true; });
    svg.append(hit);
  });
  box.replaceChildren(legend([{ c: "via", name: "Через сервер 2", bar: true }, { c: "dir", name: "Напрямую, Россия", bar: true }]), svg);
}
function renderTotals(d) {
  const S = d.summary, M = S.month;
  dailyChart(S.daily);
  hbars("month-bars", [
    { label: "Сервер 1 принял", v: M.s1Rx, c: "rx" },
    { label: "Сервер 1 отдал", v: M.s1Tx, c: "tx" },
    { label: "Сервер 2 принял", v: M.s2Rx, c: "rx" },
    { label: "Сервер 2 отдал", v: M.s2Tx, c: "tx" },
    { label: "Через сервер 2", v: M.via, c: "via" },
    { label: "Напрямую", v: M.direct, c: "dir" },
  ], "За месяц данных пока нет");
  hbars("user-bars", d.users.map(u => ({ label: u.name, v: u.monthDown + u.monthUp })).sort((a, b) => b.v - a.v), "Пользователей пока нет");
  const row = (name, f) => [name, f(S.today), f(S.month), f(S.prevMonth)];
  table("totals", ["", "Сегодня", "Этот месяц", "Прошлый месяц"], [
    row("Сервер 1, принято", t => bytes(t.s1Rx)),
    row("Сервер 1, отдано", t => bytes(t.s1Tx)),
    row("Сервер 2, принято", t => bytes(t.s2Rx)),
    row("Сервер 2, отдано", t => bytes(t.s2Tx)),
    row("Устройства через сервер 2", t => bytes(t.via)),
    row("Устройства напрямую", t => bytes(t.direct)),
  ]);
  table("user-totals", ["Пользователь", "Скорость", "Сегодня", "За месяц"],
    d.users.map(u => [u.name, u.online ? bits(u.downBps + u.upBps) : "нет",
      bytes(u.todayDown + u.todayUp), bytes(u.monthDown + u.monthUp)]));
  table("daily-rows", ["День", "Через сервер 2", "Напрямую"],
    S.daily.filter(x => x.via + x.direct > 0).reverse().map(x => [x.day.slice(8) + "." + x.day.slice(5, 7), bytes(x.via), bytes(x.direct)]));
}
function renderTraffic(d) {
  renderRoute(d);
  renderTiles(d);
  // Пока открыта подсказка, графики не перерисовываем: иначе она останется висеть без своего столбца.
  if ($("tip").hidden) {
    renderCharts(d);
    renderTotals(d);
  }
  document.querySelectorAll("[data-range]").forEach(b => b.setAttribute("aria-pressed", b.dataset.range === range));
}
document.querySelectorAll("[data-table]").forEach(b => {
  b.onclick = () => { const t = $(b.dataset.table); t.hidden = !t.hidden; b.textContent = t.hidden ? "Таблица" : "Скрыть таблицу"; };
});
document.querySelectorAll("[data-range]").forEach(b => {
  b.onclick = () => {
    range = b.dataset.range;
    document.querySelectorAll(".chart").forEach(c => c.classList.add("loading"));
    refresh();
  };
});
let rz = null;
addEventListener("resize", () => {
  clearTimeout(rz);
  rz = setTimeout(() => { if (page === "traffic" && last) { renderCharts(last); renderTotals(last); fitPills(); } }, 150);
});

// ---------- страница серверов ----------
function meter(label, value, share) {
  const m = el("div", "meter"), top = el("div", "meter-top"), bar = el("div", "meter-bar"), fill = el("i", share > 0.85 ? "high" : "");
  top.append(el("span", "", label), el("b", "", value));
  fill.style.width = Math.min(100, Math.max(1, share * 100)) + "%";
  bar.append(fill);
  m.append(top, bar);
  return m;
}
function hostCard(id, title, h, wanRx, wanTx, emptyText, state) {
  const box = $(id);
  const head = el("div", "host-head");
  head.append(el("h2", "", title), el("span", "tag " + state[0], state[1]));
  const kids = [head];
  if (!h) {
    kids.push(el("p", "", emptyText));
    box.replaceChildren(...kids);
    return;
  }
  const row = el("div", "host-rows");
  const pair = (k, v) => { const s1 = el("span", "", k + " "); s1.append(el("b", "", v)); return s1; };
  row.append(pair("Принимает", bits(wanRx)), pair("Отдаёт", bits(wanTx)));
  const cpu = h.load1 / Math.max(1, h.cpus);
  kids.push(row, meter("Процессор", num(Math.min(100, cpu * 100), 0) + " %", cpu));
  kids.push(meter("Память", bytes(h.memTotal - h.memAvail) + " из " + bytes(h.memTotal), (h.memTotal - h.memAvail) / Math.max(1, h.memTotal)));
  kids.push(meter("Диск занят", bytes(h.diskTotal - h.diskFree) + " из " + bytes(h.diskTotal), (h.diskTotal - h.diskFree) / Math.max(1, h.diskTotal)));
  const up = el("div", "host-rows");
  up.append(pair("Без перезагрузки", uptime(h.uptime)));
  kids.push(up);
  box.replaceChildren(...kids);
}
function renderServers(d) {
  const n = d.summary.now;
  hostCard("host-1", "Сервер 1", n.s1, n.s1Rx, n.s1Tx, "", ["on", "Работает"]);
  hostCard("host-2", "Сервер 2", n.s2, n.s2Rx, n.s2Tx,
    "Данных нет. Если сбор статистики ещё не ставился, выполни на сервере 1 команду awg-cascade agent-install.",
    d.uplink.ok ? ["on", "На связи"] : ["off", "Нет связи"]);
  $("uplink-state").textContent = d.uplink.ok
    ? "Связь есть, последнее рукопожатие " + ago(d.uplink.handshakeAge) + "."
    : "Связи нет. Нажми «Переподключить сервер 2» и проверь, включён ли сервер 2.";
}

// ---------- страница YouTube ----------
const MARK = { good: ["on", "Помогло"], bad: ["off", "Не помогло"] };
function optRow(o) {
  const row = el("div", "opt" + (o.active ? " active" : ""));
  const info = el("div"), title = el("div", "opt-title");
  title.append(document.createTextNode(o.name));
  if (o.active) title.append(el("span", "tag brand", "Сейчас включено"));
  if (MARK[o.mark]) title.append(el("span", "tag " + MARK[o.mark][0], MARK[o.mark][1]));
  info.append(title, el("div", "opt-desc", o.desc));
  const side = el("div", "opt-side");
  if (!o.active) side.append(ytBtn("Включить", o.run));
  else if (o.markId) {
    side.append(ytBtn("Помогло", () => setMark(o.markId, "good")));
    side.append(ytBtn(o.next ? "Не помогло, следующий" : "Не помогло", async () => {
      await setMark(o.markId, "bad");
      if (o.next) await o.next();
    }));
  }
  row.append(info, side);
  return row;
}
function ytBtn(text, fn) {
  const b = el("button", "small", text);
  b.type = "button";
  b.onclick = async () => {
    const err = $("yt-error");
    err.hidden = true;
    document.querySelectorAll("#page-youtube button").forEach(x => { x.disabled = true; });
    try { await fn(); } catch (e) { err.textContent = e.message; err.hidden = false; }
    await refresh();
    document.querySelectorAll("#page-youtube button").forEach(x => { x.disabled = false; });
  };
  return b;
}
async function setMark(id, mark) { await api("youtube/mark", { method: "POST", body: { id, mark } }); }
async function setMode(mode) {
  await api("youtube/mode", { method: "POST", body: { mode } });
  toast("Режим изменён. Переподключи VPN на устройстве и проверь видео.");
}
async function setPreset(id) {
  if (id === "warp") toast("Подключаю WARP, это может занять до двух минут");
  await api("youtube/preset", { method: "POST", body: { id } });
  toast("Способ включён. Переподключи VPN на устройстве и проверь видео.");
}
function renderYoutube(y) {
  ytData = y;
  if (document.querySelector("#page-youtube button:focus")) return;
  $("yt-base").replaceChildren(
    optRow({ name: "Через сервер 2", desc: "Самый надёжный вариант. Российский сервер не участвует в обходе.", active: y.mode === "exit", run: () => setMode("exit") }),
    optRow({ name: "С сервера 1 без обхода", desc: "YouTube идёт напрямую. Подойдёт, если хостер его не замедляет.", active: y.mode === "direct", mark: y.directMark, markId: "direct", run: () => setMode("direct"), next: () => setPreset(y.presets[0].id) }),
  );
  renderAuto(y.auto || { state: "idle", items: [] }, y);
  const blocks = [];
  let box = null, head = null;
  y.presets.forEach((p, i) => {
    if (p.group !== head) {
      head = p.group;
      box = el("div", "card opts");
      blocks.push(el("h3", "opt-group", head), box);
    }
    const nxt = y.presets[i + 1];
    box.append(optRow({ name: p.name, desc: p.desc, mark: p.mark, markId: p.id, active: y.mode === "bypass" && y.preset === p.id,
      run: () => setPreset(p.id), next: nxt ? () => setPreset(nxt.id) : () => setMode("exit") }));
  });
  $("yt-presets").replaceChildren(...blocks);
  renderSearch(y.search || { state: "idle" });
}
let autoShowDetails = false;
function renderAuto(a, y) {
  const box = $("yt-auto");
  if (!box) return;
  const row = el("div", "opt" + (a.state === "running" ? " active" : ""));
  const info = el("div"), title = el("div", "opt-title");
  title.append(document.createTextNode("Автоподбор стратегии (быстрый)"));
  let desc = "За 1–2 минуты проверяет все готовые стратегии (tpws, zapret2 nfqws2, ByeDPI) на соединениях к YouTube и Google Video и сразу включает лучшую по отклику.";
  if (a.state === "running") {
    const pct = a.total > 0 ? Math.round((a.current / a.total) * 100) : 0;
    title.append(el("span", "tag brand", `Проверка ${a.current || 1} из ${a.total || 16}`));
    desc = (a.currentName ? `Сейчас проверяется: «${a.currentName}» (${a.currentId}). ` : "Подготовка к проверке... ") + "Страницу можно не закрывать — результаты обновляются на ходу.";
    const bar = el("div", "meter-bar auto-bar"), fill = el("i", "");
    fill.style.width = Math.max(4, pct) + "%";
    bar.append(fill);
    info.append(title, el("div", "opt-desc", desc), bar);
  } else {
    if (a.state === "done" && a.result === "found") {
      title.append(el("span", "tag on", "Подобрана: " + (a.bestName || a.best)));
      desc = `Лучшая стратегия «${a.bestName || a.best}» автоматически включена и отмечена «Помогло». Если длинное видео всё же буферизуется, выбери другую из прошедших проверку ниже.`;
    } else if (a.state === "done" && a.result === "nobypass") {
      title.append(el("span", "tag on", "Обход не нужен"));
      desc = "Сервер 1 открывает YouTube и Google Video напрямую без замедления. Включён режим «С сервера 1 без обхода».";
    } else if (a.state === "done") {
      title.append(el("span", "tag warn", "Стратегия не найдена"));
      desc = "Ни один из быстрых способов не дал стабильного ответа от серверов YouTube. Рекомендуется режим «Через сервер 2» или глубокий подбор blockcheck2.";
    } else if (a.state === "failed") {
      title.append(el("span", "tag warn", "Прервался"));
      desc = "Автоподбор был прерван. Можно запустить его заново.";
    }
    info.append(title, el("div", "opt-desc", desc));
  }
  const side = el("div", "opt-side");
  if (a.state === "running") {
    const stopBtn = el("button", "small danger", "Остановить");
    stopBtn.type = "button";
    stopBtn.onclick = async () => {
      stopBtn.disabled = true;
      try {
        await api("youtube/stop", { method: "POST" });
        toast("Автоподбор остановлен");
        renderAuto({ ...a, state: "failed" }, y);
      } catch (err) {
        toast("Ошибка остановки: " + err.message);
      }
    };
    side.append(stopBtn);
  } else {
    if (Array.isArray(a.items) && a.items.length > 0) {
      const toggle = el("button", "small ghost", autoShowDetails ? "Скрыть отчёт" : `Отчёт (${a.items.filter(x => x.status === "ok").length}/${a.items.length})`);
      toggle.type = "button";
      toggle.onclick = () => { autoShowDetails = !autoShowDetails; renderAuto(a, y); };
      side.append(toggle);
    }
    side.append(ytBtn(a.state === "idle" ? "Подобрать автоматически" : "Проверить заново", async () => {
      autoShowDetails = true;
      await api("youtube/auto", { method: "POST" });
      toast("Быстрый автоподбор запущен (1–2 мин)");
    }));
  }
  row.append(info, side);
  const kids = [row];
  if (Array.isArray(a.items) && a.items.length > 0 && (a.state === "running" || autoShowDetails)) {
    const list = el("div", "auto-items");
    a.items.forEach(it => {
      const item = el("div", "auto-item");
      const left = el("div", "auto-item-left");
      const badge = el("span", "tag " + (it.status === "ok" ? "on" : "off"), it.status === "ok" ? `${it.ms} мс` : "Сбой");
      left.append(badge, el("strong", "", it.name), el("span", "dim", it.group));
      const right = el("div", "auto-item-right");
      const isActive = (it.id === "direct" && y.mode === "direct") || (it.id !== "direct" && y.mode === "bypass" && y.preset === it.id);
      if (isActive) {
        right.append(el("span", "tag brand", "Активно"));
      } else if (a.state !== "running" && it.status === "ok") {
        right.append(ytBtn("Включить", () => it.id === "direct" ? setMode("direct") : setPreset(it.id)));
      }
      item.append(left, right);
      list.append(item);
    });
    kids.push(list);
  }
  box.replaceChildren(...kids);
}
let searchAsk = false;
function renderSearch(s) {
  const row = el("div", "opt" + (s.state === "running" ? " active" : ""));
  const info = el("div"), title = el("div", "opt-title");
  title.append(document.createTextNode("Автоподбор через blockcheck2"));
  let desc = "Проверяет десятки вариантов zapret2 против YouTube прямо с сервера 1. Занимает до 50 минут, на это время YouTube идёт с сервера 1 без обхода.";
  if (s.state === "running") {
    title.append(el("span", "tag brand", "Идёт подбор"));
    const t = s.started ? new Date(s.started * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) : "";
    desc = "Начат" + (t ? " в " + t : "") + ". Страницу можно закрыть. Пока идёт подбор, не обновляй программу: обновление его прервёт.";
  } else if (s.state === "done" && s.result === "found") {
    title.append(el("span", "tag on", "Найден способ"));
    desc = "Он появился выше в группе «Подбор» → «Подобранный на этом сервере». Включи его и проверь видео.";
  } else if (s.state === "done" && s.result === "nobypass") {
    title.append(el("span", "tag on", "Обход не нужен"));
    desc = "YouTube с этого сервера открывается без обхода. Выбери «С сервера 1 без обхода».";
  } else if (s.state === "done") {
    title.append(el("span", "tag warn", "Не найден"));
    desc = "Рабочий способ не нашёлся. Попробуй способы из списка выше или «Через сервер 2».";
  } else if (s.state === "failed") {
    title.append(el("span", "tag warn", "Прервался"));
    desc = "Подбор не закончился, например из-за перезагрузки или обновления. Можно запустить снова.";
  }
  info.append(title, el("div", "opt-desc", desc));
  const side = el("div", "opt-side");
  if (s.state === "running") {
    const stopBtn = el("button", "small danger", "Остановить");
    stopBtn.type = "button";
    stopBtn.onclick = async () => {
      stopBtn.disabled = true;
      try {
        await api("youtube/stop", { method: "POST" });
        toast("Подбор остановлен");
        renderSearch({ ...s, state: "failed" });
      } catch (err) {
        toast("Ошибка остановки: " + err.message);
      }
    };
    side.append(stopBtn);
  } else {
    if (!searchAsk) {
      const b = el("button", "small", s.state === "idle" ? "Запустить подбор" : "Подобрать заново");
      b.type = "button";
      b.onclick = () => { searchAsk = true; renderSearch(s); };
      side.append(b);
    } else {
      info.append(el("div", "opt-desc search-warn", "На время подбора YouTube пойдёт без обхода, видео может тормозить. Запустить?"));
      side.append(ytBtn("Да, запустить", async () => {
        searchAsk = false;
        await api("youtube/search", { method: "POST" });
        toast("Подбор запущен, займёт до 50 минут");
      }));
      const no = el("button", "small", "Отмена");
      no.type = "button";
      no.onclick = () => { searchAsk = false; renderSearch(s); };
      side.append(no);
    }
  }
  row.append(info, side);
  $("yt-search").replaceChildren(row);
}

$("btn-check").onclick = async ev => {
  const b = ev.target, box = $("check-result");
  b.disabled = true;
  try {
    const r = await api("check", { method: "POST" });
    box.replaceChildren(...r.lines.filter(l => l.text !== "все проверки пройдены").map(l => el("li", l.ok ? "ok" : "no", l.text)));
    box.hidden = false;
    toast(r.ok ? "Все проверки пройдены" : "Есть непройденные проверки");
  } catch (e) { toast(e.message); }
  b.disabled = false;
};
$("btn-reconnect").onclick = async ev => {
  const b = ev.target;
  if (!await confirmBox("Переподключить сервер 2?", "Зарубежные сайты на устройствах пропадут на несколько секунд.", "Переподключить")) return;
  b.disabled = true;
  try { await api("reconnect", { method: "POST" }); toast("Связь с сервером 2 восстановлена"); refresh(); }
  catch (e) { toast(e.message); }
  b.disabled = false;
};
$("pass-form").onsubmit = async ev => {
  ev.preventDefault();
  const err = $("pass-error");
  err.hidden = true;
  try {
    await api("password", { method: "POST", body: { old: $("pass-old").value, new: $("pass-new").value } });
    ev.target.reset();
    toast("Пароль изменён");
  } catch (e) { err.textContent = e.message; err.hidden = false; }
};

// ---------- запуск ----------
(async () => {
  const tok = new URLSearchParams(location.search).get("setup");
  if (tok) {
    setupToken = tok;
    history.replaceState(null, "", location.pathname + location.hash); // ключ не остаётся в адресе и истории
  }
  const h = await api("hello");
  needUser = h.needUser;
  if (!h.admin) { showSetup(setupToken ? "admin-form" : "setup-wait"); return; }
  await enter();
})().catch(() => {});

// ---------- telegram ----------
let tgData = null;
let tgUpstream = "direct";

function renderTelegram(t) {
  tgData = t;
  const isEditing = document.activeElement && [
    $("tg-port"), $("tg-tls-domain"), $("tg-secret"), $("tg-web-domain"), $("tg-web-port")
  ].includes(document.activeElement);

  // MTProto Header Tag & Toggle Button
  const tag = $("tg-status-tag");
  const toggleBtn = $("tg-toggle-btn");
  if (t.running) {
    tag.textContent = "Работает";
    tag.className = "tag on";
    toggleBtn.textContent = "Отключить";
    toggleBtn.className = "small danger";
  } else if (t.enabled) {
    tag.textContent = "Запуск...";
    tag.className = "tag warn";
    toggleBtn.textContent = "Отключить";
    toggleBtn.className = "small danger";
  } else {
    tag.textContent = "Отключен";
    tag.className = "tag off";
    toggleBtn.textContent = "Включить";
    toggleBtn.className = "small";
  }

  // Web Header Tag & Toggle Button
  const webTag = $("tg-web-status-tag");
  const webToggleBtn = $("tg-web-toggle-btn");
  if (t.web_running) {
    webTag.textContent = "Работает";
    webTag.className = "tag on";
    webToggleBtn.textContent = "Отключить";
    webToggleBtn.className = "small danger";
  } else if (t.web_enabled && t.enabled) {
    webTag.textContent = "Запуск...";
    webTag.className = "tag warn";
    webToggleBtn.textContent = "Отключить";
    webToggleBtn.className = "small danger";
  } else {
    webTag.textContent = "Отключен";
    webTag.className = "tag off";
    webToggleBtn.textContent = "Включить";
    webToggleBtn.className = "small";
  }

  $("tg-conn").textContent = t.connections || 0;

  if (!isEditing) {
    $("tg-port").value = t.port || 8443;
    $("tg-tls-domain").value = t.tls_domain || "ya.ru";
    $("tg-secret").value = t.secret || "";
    $("tg-web-domain").value = t.web_domain || "";
    $("tg-web-port").value = t.web_port || 8085;
    setUpstreamPills(t.upstream || "direct");
  }

  // Connect box
  const cbox = $("tg-connect-box");
  if (t.enabled && t.mtproto_link) {
    cbox.hidden = false;
    $("tg-app-link").href = t.mtproto_link;
    $("tg-preview-link").value = t.mtproto_link;
  } else {
    cbox.hidden = true;
  }

  // Web connect box
  const wbox = $("tg-web-connect-box");
  if (t.enabled && t.web_enabled && t.web_link) {
    wbox.hidden = false;
    if ($("tg-web-app-link")) $("tg-web-app-link").href = t.web_link;
    $("tg-web-preview").value = t.web_link;
  } else {
    wbox.hidden = true;
  }
}

function setUpstreamPills(up) {
  tgUpstream = up;
  $("tg-up-direct").setAttribute("aria-pressed", String(up !== "cascade"));
  $("tg-up-cascade").setAttribute("aria-pressed", String(up === "cascade"));
}

$("tg-up-direct").onclick = () => setUpstreamPills("direct");
$("tg-up-cascade").onclick = () => setUpstreamPills("cascade");

async function saveTelegram(patch) {
  const current = tgData || {};
  const cfg = {
    enabled: patch.enabled !== undefined ? patch.enabled : current.enabled,
    port: parseInt($("tg-port").value, 10) || current.port || 8443,
    tls_domain: $("tg-tls-domain").value.trim() || current.tls_domain || "ya.ru",
    secret: $("tg-secret").value.trim().toLowerCase() || current.secret || "",
    upstream: tgUpstream,
    web_enabled: patch.web_enabled !== undefined ? patch.web_enabled : current.web_enabled,
    web_domain: $("tg-web-domain").value.trim(),
    web_port: parseInt($("tg-web-port").value, 10) || current.web_port || 8085
  };
  const res = await api("telegram/apply", {
    method: "POST",
    body: cfg
  });
  renderTelegram(res);
  return res;
}

$("tg-toggle-btn").onclick = async () => {
  if (!tgData) return;
  const newEnabled = !tgData.enabled;
  try {
    await saveTelegram({ enabled: newEnabled });
    toast(newEnabled ? "MTProto Proxy включен" : "MTProto Proxy отключен");
  } catch (err) {
    toast("Ошибка: " + err.message);
  }
};

$("tg-web-toggle-btn").onclick = async () => {
  if (!tgData) return;
  const newWeb = !tgData.web_enabled;
  try {
    await saveTelegram({ web_enabled: newWeb });
    toast(newWeb ? "Web-мост включен" : "Web-мост отключен");
  } catch (err) {
    toast("Ошибка: " + err.message);
  }
};

$("tg-new-secret").onclick = async () => {
  try {
    const st = await api("telegram/secret", { method: "POST" });
    if (st && st.secret) {
      renderTelegram(st);
      toast("Сгенерирован новый секрет");
    }
  } catch (err) {
    toast("Ошибка генерации: " + err.message);
  }
};

$("tg-form").onsubmit = async (ev) => {
  ev.preventDefault();
  try {
    await saveTelegram({});
    toast("Настройки MTProto сохранены");
  } catch (err) {
    toast("Ошибка сохранения: " + err.message);
  }
};

$("tg-web-form").onsubmit = async (ev) => {
  ev.preventDefault();
  try {
    await saveTelegram({});
    toast("Настройки Web-моста сохранены");
  } catch (err) {
    toast("Ошибка сохранения: " + err.message);
  }
};

$("tg-copy-link").onclick = () => {
  if (tgData && tgData.mtproto_link) {
    navigator.clipboard.writeText(tgData.mtproto_link);
    toast("Ссылка скопирована");
  }
};

$("tg-web-copy").onclick = () => {
  if (tgData && tgData.web_link) {
    navigator.clipboard.writeText(tgData.web_link);
    toast("Веб-ссылка скопирована");
  }
};

function openTelegramQR(title, type) {
  const tabs = document.querySelector(".qr-tabs");
  if (tabs) tabs.hidden = true;
  $("qr-title").textContent = title;
  $("qr-img").hidden = false;
  $("qr-img").src = "api/telegram/qr.svg?type=" + type;
  $("qr-empty-card").hidden = true;
  $("qr-file").hidden = true;
  const link = type === "web" ? (tgData && tgData.web_link) : (tgData && tgData.mtproto_link);
  if (link) {
    $("qr-link-box").hidden = false;
    $("qr-link-input").value = link;
    $("qr-tg-connect").hidden = false;
    $("qr-tg-connect").href = link;
    $("qr-tg-copy").hidden = false;
    $("qr-tg-copy").onclick = () => copyText(link, "Ссылка скопирована");
  } else {
    $("qr-link-box").hidden = true;
    $("qr-tg-connect").hidden = true;
    $("qr-tg-copy").hidden = true;
  }
  $("qr-hint").hidden = false;
  $("qr-hint").style.color = "";
  $("qr-hint").textContent = "Отсканируй QR-код камерой телефона или в Telegram для подключения к прокси.";
  $("qr-dialog").showModal();
}

$("tg-qr-link").onclick = () => openTelegramQR("MTProto Proxy", "mtproto");
$("tg-web-qr").onclick = () => openTelegramQR("Telegram Web Proxy", "web");
