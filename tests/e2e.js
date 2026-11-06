// Сценарии панели в браузере. Запускается из tests/panel-stand.inc.
const { chromium } = require("playwright");
const { execSync } = require("child_process");
const assert = require("assert");
const ADMIN = "admin1", TOKEN = process.env.PANEL_TOKEN;
const URL_ = process.env.PANEL_URL, PASS = process.env.PANEL_PASS, CTL = process.env.CTL, SHOTS = process.env.SHOTS;
let passed = 0, failed = 0;
async function t(name, fn) {
  try { await fn(); console.log("PASS  " + name); passed++; }
  catch (e) { console.log("FAIL  " + name + ": " + String(e.message).split("\n").slice(0,3).join(" | ")); failed++; }
}
const ctl = c => execSync(`${CTL} ${c}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2, colorScheme: "light", acceptDownloads: true });
  const pg = await ctx.newPage();
  const problems = [];
  pg.on("pageerror", e => problems.push("JS: " + e.message));
  pg.on("console", m => { if (m.type() === "error" && !/401|429|403|409|400|502|ERR_CONNECTION|Failed to load resource/.test(m.text())) problems.push(m.text()); });
  await pg.goto(URL_);

  await t("без ссылки администратора не создать", async () => {
    await pg.waitForSelector("#setup-wait:not([hidden])");
    assert.ok(await pg.isHidden("#admin-form"));
  });
  await t("чужая ссылка отклонена", async () => {
    await pg.goto(URL_ + "?setup=" + "0".repeat(64));
    await pg.fill("#admin-user", ADMIN);
    await pg.fill("#admin-pass", PASS);
    await pg.fill("#admin-pass2", PASS);
    await pg.click("#admin-form button");
    await pg.waitForSelector("#admin-error:not([hidden])");
    assert.match(await pg.textContent("#admin-error"), /Ссылка не подошла/);
  });
  await t("по ссылке создаётся администратор и сразу входит", async () => {
    await pg.goto(URL_ + "?setup=" + TOKEN);
    assert.ok(!pg.url().includes("setup="), "ключ остался в адресе");
    await pg.fill("#admin-user", ADMIN);
    await pg.fill("#admin-pass", PASS);
    await pg.fill("#admin-pass2", PASS + "x");
    await pg.click("#admin-form button");
    await pg.waitForSelector("#admin-error:not([hidden])");
    assert.match(await pg.textContent("#admin-error"), /не совпадают/);
    await pg.fill("#admin-pass2", PASS);
    await pg.click("#admin-form button");
    await pg.waitForSelector(".tiles .tile");
  });
  await t("повторно ссылка не работает", async () => {
    await pg.goto(URL_ + "?setup=" + TOKEN);
    await pg.waitForSelector(".tiles .tile");
    await pg.click("#logout");
    await pg.waitForSelector("#login-form");
    assert.ok(await pg.isVisible("#login-user"));
  });

  await t("неверный пароль показывает ошибку", async () => {
    await pg.fill("#login-user", ADMIN);
    await pg.fill("#login-pass", "wrong-password");
    await pg.click("#login-form button");
    await pg.waitForSelector("#login-error:not([hidden])");
    assert.match(await pg.textContent("#login-error"), /Неверное имя или пароль/);
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/login.png" });
  await t("верный пароль открывает панель", async () => {
    await pg.fill("#login-user", ADMIN);
    await pg.fill("#login-pass", PASS);
    await pg.click("#login-form button");
    await pg.waitForSelector(".tiles .tile");
    await pg.click('.tab[data-page="users"]');
    await pg.waitForSelector(".user");
    assert.ok((await pg.textContent("#users-list")).includes("andrey"));
  });
  await t("перезагрузка сохраняет вход и раздел", async () => {
    await pg.click('.tab[data-page="traffic"]');
    await pg.reload();
    await pg.waitForSelector("#page-traffic:not([hidden])");
    await pg.click('.tab[data-page="users"]');
    await pg.waitForSelector(".user");
  });
  await t("новый пользователь сразу показывает QR-код", async () => {
    await pg.fill("#add-name", "vasya");
    await pg.click("#add-form button");
    await pg.waitForSelector("#qr-dialog[open]");
    await pg.waitForFunction(() => document.getElementById("qr-img").naturalWidth > 0);
  });
  await t("щелчок мимо не закрывает окно", async () => {
    await pg.mouse.click(5, 5);
    assert.ok(await pg.isVisible("#qr-dialog"));
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/qr.png" });
  await t("файл настроек скачивается", async () => {
    const [d] = await Promise.all([pg.waitForEvent("download"), pg.click("#qr-file")]);
    assert.strictEqual(d.suggestedFilename(), "vasya.conf");
    await pg.click("#qr-close");
  });
  await t("имя с пробелом отклонено с подсказкой", async () => {
    await pg.fill("#add-name", "имя с пробелом");
    await pg.click("#add-form button");
    await pg.waitForSelector("#add-error:not([hidden])");
    assert.match(await pg.textContent("#add-error"), /латиница/);
  });
  await t("повтор имени отклонён, набранное не пропало", async () => {
    await pg.fill("#add-name", "vasya");
    await pg.click("#add-form button");
    await pg.waitForFunction(() => /уже есть/.test(document.getElementById("add-error").textContent));
    assert.strictEqual(await pg.inputValue("#add-name"), "vasya");
    await pg.fill("#add-name", "");
  });
  const row = n => pg.locator(".user", { hasText: n });
  await t("отключение можно отменить", async () => {
    await row("vasya").getByRole("button", { name: "Отключить" }).click();
    await pg.waitForFunction(() => /отключён/.test(document.getElementById("toast").textContent));
    await row("vasya").getByText("Отключён").waitFor();
    await pg.click("#toast button");
    await row("vasya").getByRole("button", { name: "Отключить" }).waitFor();
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/users.png" });
  await t("удаление спрашивает подтверждение", async () => {
    await row("vasya").getByRole("button", { name: "Удалить" }).click();
    await pg.click("#confirm-no");
    assert.ok(await row("vasya").isVisible());
    await row("vasya").getByRole("button", { name: "Удалить" }).click();
    await pg.click("#confirm-yes");
    await row("vasya").waitFor({ state: "detached" });
  });

  await pg.click('.tab[data-page="traffic"]');
  await t("схема показывает скорость и связь", async () => {
    await pg.waitForFunction(() => /бит\/с/.test(document.querySelector('.route-wide [data-v="via"]').textContent));
    await pg.waitForFunction(() => document.querySelector('.route-wide [data-v="s2state"]').textContent === "на связи");
    assert.ok(await pg.locator('.route-wide .flow.on').count() >= 2);
    const box = await pg.locator('.route-wide [data-flow="via"]').boundingBox();
    assert.ok(box && box.width > 20, "горизонтальная дорожка должна быть видна");
  });
  await t("есть три графика", async () => {
    await pg.waitForFunction(() => document.querySelectorAll(".chart svg[role=img]").length === 3);
  });
  await t("подсказка показывает обе линии", async () => {
    const box = await pg.locator("#chart-s2 svg[role=img]").boundingBox();
    await pg.mouse.move(box.x + box.width * .5, box.y + 60);
    await pg.waitForSelector("#tip:not([hidden])");
    const txt = await pg.textContent("#tip");
    assert.match(txt, /Принято/); assert.match(txt, /Отдано/);
    await pg.mouse.move(2, 2);
  });
  await t("итоги показаны графиками", async () => {
    await pg.waitForSelector("#chart-daily svg[role=img] rect.f-via-c");
    assert.ok(await pg.locator("#month-bars .h-fill").count() === 6);
    assert.ok((await pg.textContent("#user-bars")).includes("andrey"));
  });
  await t("подсказка у столбцов по дням", async () => {
    await pg.locator("#chart-daily svg[role=img]").scrollIntoViewIfNeeded();
    const box = await pg.locator("#chart-daily svg[role=img]").boundingBox();
    await pg.mouse.move(box.x + box.width * .9, box.y + 80);
    await pg.waitForSelector("#tip:not([hidden])");
    assert.match(await pg.textContent("#tip"), /Напрямую/);
    await pg.mouse.move(2, 2);
  });
  await t("таблица открывается кнопкой", async () => {
    assert.ok(!(await pg.isVisible("#totals")));
    await pg.click('[data-table="totals-table"]');
    assert.ok(await pg.isVisible("#totals"));
    assert.strictEqual(await pg.locator("#totals tr").count(), 7);
    await pg.click('[data-table="totals-table"]');
    assert.ok((await pg.textContent("#user-totals")).includes("andrey"));
  });
  for (const r of ["24h", "7d", "30d", "10m"]) {
    await t("период " + r, async () => {
      await pg.click(`[data-range="${r}"]`);
      await pg.waitForSelector(`[data-range="${r}"][aria-pressed="true"]`);
      await pg.waitForFunction(() => !document.querySelector(".chart.loading"));
      assert.strictEqual(await pg.locator(".chart svg[role=img]").count(), 3);
      if (SHOTS && r !== "10m") await pg.screenshot({ path: `${SHOTS}/traffic-${r}.png`, fullPage: true });
    });
  }
  await pg.click('[data-range="7d"]');
  await sleep(600);

  await pg.click('.tab[data-page="youtube"]');
  const opt = n => pg.locator(".opt", { hasText: n });
  await t("YouTube: список способов", async () => {
    await pg.waitForSelector("#yt-presets .opt");
    assert.ok(await pg.locator("#yt-presets .opt").count() >= 17);
    const heads = await pg.locator("#yt-presets h3").allTextContents();
    for (const h of ["zapret2", "GoodbyeDPI", "zapret: программа tpws", "ByeDPI", "Cloudflare WARP"]) assert.ok(heads.includes(h), h);
    assert.ok(await opt("Через сервер 2").getByText("Сейчас включено").isVisible());
  });
  await t("YouTube: без обхода включается одной кнопкой", async () => {
    await opt("С сервера 1 без обхода").getByRole("button", { name: "Включить" }).click();
    await opt("С сервера 1 без обхода").getByText("Сейчас включено").waitFor({ timeout: 15000 });
  });
  await t("YouTube: «не помогло» включает следующий способ", async () => {
    await opt("С сервера 1 без обхода").getByRole("button", { name: "Не помогло, следующий" }).click();
    await opt("Разрезание на TLS-записи").getByText("Сейчас включено").waitFor({ timeout: 15000 });
    assert.ok(await opt("С сервера 1 без обхода").getByText("Не помогло").first().isVisible());
  });
  if (SHOTS) { await sleep(500); await pg.mouse.move(2, 2); await pg.screenshot({ path: SHOTS + "/youtube.png", fullPage: true }); }
  await t("YouTube: отметка «помогло» сохраняется", async () => {
    await opt("Разрезание на TLS-записи").getByRole("button", { name: "Помогло", exact: true }).click();
    await opt("Разрезание на TLS-записи").locator(".tag.on").waitFor({ timeout: 10000 });
    await pg.reload();
    await opt("Разрезание на TLS-записи").locator(".tag.on").waitFor({ timeout: 10000 });
  });
  await t("YouTube: возврат через сервер 2", async () => {
    await opt("Через сервер 2").getByRole("button", { name: "Включить" }).click();
    await opt("Через сервер 2").getByText("Сейчас включено").waitFor({ timeout: 15000 });
  });

  await pg.click('.tab[data-page="routes"]');
  const svc = n => pg.locator(".route-row", { hasText: n });
  await t("маршруты: каталог сервисов", async () => {
    await pg.waitForSelector(".route-row");
    assert.strictEqual(await pg.locator(".route-row").count(), 8);
    assert.strictEqual(await svc("Steam").getByRole("button", { name: "Как обычно" }).getAttribute("aria-pressed"), "true");
    assert.match(await svc("Steam").locator(".route-meta").textContent(), /загрузятся/);
  });
  await t("маршруты: Steam через сервер 1, списки загружены", async () => {
    await svc("Steam").getByRole("button", { name: "Сервер 1" }).click();
    await pg.waitForFunction(() => [...document.querySelectorAll(".route-row")].some(r => /Steam/.test(r.textContent) && r.querySelector('[aria-pressed="true"]').textContent === "Сервер 1"), null, { timeout: 30000 });
    assert.match(await svc("Steam").locator(".route-meta").textContent(), /1 сеть · \d+ домен.* · обновлено/);
  });
  await t("маршруты: ошибка источника видна", async () => {
    await svc("Telegram").getByRole("button", { name: "Сервер 2" }).click();
    await pg.waitForFunction(() => /источник не ответил/.test([...document.querySelectorAll(".route-row")].find(r => /Telegram/.test(r.textContent)).textContent), null, { timeout: 30000 });
  });
  await t("маршруты: своё правило добавляется", async () => {
    await pg.fill("#rule-value", "https://Example.org/page");
    await pg.click('[data-rule-target="2"]');
    await pg.click("#rule-form button[type=submit]");
    await pg.locator(".rule", { hasText: "example.org" }).waitFor({ timeout: 20000 });
    assert.strictEqual(await pg.inputValue("#rule-value"), "");
    assert.match(await pg.locator(".rule", { hasText: "example.org" }).textContent(), /Сервер 2/);
  });
  await t("маршруты: неверный адрес — понятная ошибка", async () => {
    await pg.fill("#rule-value", "1.2.3.0/4");
    await pg.click("#rule-form button[type=submit]");
    await pg.waitForSelector("#rule-error:not([hidden])");
    assert.match(await pg.textContent("#rule-error"), /не шире/);
    await pg.fill("#rule-value", "");
  });
  await t("маршруты: проверка адреса объясняет причину", async () => {
    await pg.fill("#route-check-host", "203.0.113.5");
    await pg.click("#route-check-form button");
    await pg.locator("#route-check li").first().waitFor({ timeout: 15000 });
    const txt = await pg.textContent("#route-check");
    assert.ok(/203\.0\.113\.5/.test(txt) && /Сервер 1/.test(txt) && /Steam/.test(txt), txt);
  });
  if (SHOTS) { await pg.mouse.move(2, 2); await pg.screenshot({ path: SHOTS + "/routes.png", fullPage: true }); }
  await t("маршруты: удаление правила с отменой", async () => {
    await pg.locator(".rule", { hasText: "example.org" }).getByRole("button", { name: "Удалить" }).click();
    await pg.locator("#toast").getByRole("button", { name: "Отменить" }).click({ timeout: 20000 });
    await pg.locator(".rule", { hasText: "example.org" }).waitFor({ timeout: 20000 });
    await pg.locator(".rule", { hasText: "example.org" }).getByRole("button", { name: "Удалить" }).click();
    await pg.waitForFunction(() => !/example\.org/.test(document.getElementById("rules").textContent), null, { timeout: 20000 });
  });
  await t("маршруты: возврат «как обычно» сохраняется", async () => {
    await svc("Telegram").getByRole("button", { name: "Как обычно" }).click();
    await pg.waitForFunction(() => [...document.querySelectorAll(".route-row")].find(r => /Telegram/.test(r.textContent)).querySelector('[aria-pressed="true"]').textContent === "Как обычно", null, { timeout: 20000 });
    await pg.reload();
    await svc("Steam").waitFor();
    assert.strictEqual(await svc("Steam").getByRole("button", { name: "Сервер 1" }).getAttribute("aria-pressed"), "true");
    assert.strictEqual(await svc("Telegram").getByRole("button", { name: "Как обычно" }).getAttribute("aria-pressed"), "true");
  });

  await pg.click('.tab[data-page="servers"]');
  await t("видны оба сервера", async () => {
    await pg.waitForFunction(() => /Память/.test(document.getElementById("host-2").textContent));
    assert.match(await pg.textContent("#host-1"), /Память/);
  });
  await t("проверка каскада из панели", async () => {
    await pg.click("#btn-check");
    await pg.waitForSelector("#check-result:not([hidden])");
    assert.deepStrictEqual(await pg.locator("#check-result .no").allTextContents(), []);
    assert.ok(await pg.locator("#check-result .ok").count() >= 10);
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/servers.png", fullPage: true });
  await t("без агента страница объясняет, что делать", async () => {
    ctl("agent-stop");
    await pg.waitForFunction(() => /agent-install/.test(document.getElementById("host-2").textContent), null, { timeout: 15000 });
    ctl("agent-start");
    await pg.waitForFunction(() => /Память/.test(document.getElementById("host-2").textContent), null, { timeout: 15000 });
  });
  await t("обрыв связи виден, кнопка её возвращает", async () => {
    ctl("uplink-down");
    await pg.waitForFunction(() => /Связи нет/.test(document.getElementById("uplink-state").textContent), null, { timeout: 15000 });
    await pg.click("#btn-reconnect");
    await pg.click("#confirm-yes");
    await pg.waitForFunction(() => /Связь есть/.test(document.getElementById("uplink-state").textContent), null, { timeout: 45000 });
  });
  await t("неверный текущий пароль не меняет пароль", async () => {
    await pg.fill("#pass-old", "not-the-password");
    await pg.fill("#pass-new", "new-password-123");
    await pg.click("#pass-form button");
    await pg.waitForSelector("#pass-error:not([hidden])");
  });
  await t("смена пароля и выход", async () => {
    await pg.fill("#pass-old", PASS);
    await pg.click("#pass-form button");
    await pg.waitForFunction(() => /Пароль изменён/.test(document.getElementById("toast").textContent));
    await pg.click("#logout");
    await pg.waitForSelector("#login:not([hidden])");
    await pg.fill("#login-user", ADMIN);
    await pg.fill("#login-pass", "new-password-123");
    await pg.click("#login-form button");
    await pg.waitForSelector(".side");
  });
  await t("после перезапуска панели история на месте, вход сохранён", async () => {
    ctl("panel-restart");
    await sleep(2500);
    await pg.reload();
    await pg.waitForSelector("#app:not([hidden])", { timeout: 15000 });
    assert.ok(await pg.isHidden("#login"));
    await pg.click('.tab[data-page="traffic"]');
    await pg.waitForFunction(() => document.querySelectorAll(".chart svg[role=img]").length === 3, null, { timeout: 15000 });
  });

  const fits = async p => {
    const r = await p.evaluate(() => [document.documentElement.scrollWidth, innerWidth]);
    assert.ok(r[0] <= r[1], `ширина ${r[0]} при окне ${r[1]}`);
  };
  const state = await ctx.storageState();
  const phone = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: "dark", storageState: state, hasTouch: true });
  const ph = await phone.newPage();
  ph.on("pageerror", e => problems.push("JS: " + e.message));
  await ph.goto(URL_);
  await t("телефон: пользователи без горизонтальной прокрутки", async () => {
    await ph.click('.tab[data-page="users"]');
    await ph.waitForSelector(".user");
    await fits(ph);
    if (SHOTS) await ph.screenshot({ path: SHOTS + "/phone-users.png", fullPage: true });
  });
  await t("телефон: трафик без горизонтальной прокрутки", async () => {
    await ph.click('.tab[data-page="traffic"]');
    await ph.click('[data-range="24h"]');
    await ph.waitForFunction(() => document.querySelectorAll(".chart svg[role=img]").length === 3);
    await sleep(500);
    await fits(ph);
    assert.ok(await ph.isVisible(".route-tall"));
    if (SHOTS) await ph.screenshot({ path: SHOTS + "/phone-traffic.png", fullPage: true });
  });
  await t("телефон: YouTube без горизонтальной прокрутки", async () => {
    await ph.click('.tab[data-page="youtube"]');
    await ph.waitForSelector("#yt-presets .opt");
    await fits(ph);
    if (SHOTS) await ph.screenshot({ path: SHOTS + "/phone-youtube.png", fullPage: true });
  });
  await t("телефон: маршруты без горизонтальной прокрутки", async () => {
    await ph.click('.tab[data-page="routes"]');
    await ph.waitForSelector(".route-row");
    await fits(ph);
    const rows = await ph.$$eval(".side nav .tab", ts => new Set(ts.filter(x => x.offsetParent).map(x => Math.round(x.getBoundingClientRect().top))).size);
    assert.strictEqual(rows, 1, "вкладки в несколько рядов");
    const tall = await ph.$$eval(".route-row .pills button", bs => bs.filter(b => b.getBoundingClientRect().height > 44).length);
    assert.strictEqual(tall, 0, "подписи кнопок переносятся");
    if (SHOTS) await ph.screenshot({ path: SHOTS + "/phone-routes.png" });
  });
  await t("телефон: «Ещё» открывает лист с разделами", async () => {
    assert.ok(await ph.isHidden('.side nav .tab[data-page="servers"]'));
    await ph.click("#more-tab");
    await ph.waitForSelector("#more-sheet:not([hidden])");
    if (SHOTS) await ph.screenshot({ path: SHOTS + "/phone-more.png" });
    await ph.mouse.click(195, 100);
    await ph.waitForSelector("#more-sheet", { state: "hidden" });
    await ph.click("#more-tab");
    await ph.click('[data-go="servers"]');
    await ph.waitForSelector("#page-servers:not([hidden])");
    assert.ok(await ph.isHidden("#more-sheet"));
    assert.strictEqual(await ph.getAttribute("#more-tab", "aria-current"), "page");
  });
  await t("телефон: серверы без горизонтальной прокрутки", async () => {
    await ph.waitForFunction(() => /Сервер 2/.test(document.getElementById("host-2").textContent));
    await sleep(300);
    await fits(ph);
    if (SHOTS) await ph.screenshot({ path: SHOTS + "/phone-servers.png", fullPage: true });
  });
  const dark = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1, colorScheme: "dark", storageState: state });
  const dk = await dark.newPage();
  await dk.goto(URL_ + "#traffic");
  await dk.waitForFunction(() => document.querySelectorAll(".chart svg[role=img]").length === 3).catch(() => {});
  if (SHOTS) await dk.screenshot({ path: SHOTS + "/dark-traffic.png", fullPage: true });

  await t("в браузере нет ошибок и нарушений защиты страницы", async () => assert.deepStrictEqual(problems, []));
  await b.close();
  console.log(`браузер: пройдено ${passed}, не пройдено ${failed}`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
