// Обновление из панели. Запускается из tests/bootstrap-stand.inc.
const { chromium } = require("playwright");
const assert = require("assert");
const { PANEL_URL, SHOTS } = process.env;
let passed = 0, failed = 0;
async function t(name, fn) {
  try { await fn(); console.log("PASS  " + name); passed++; }
  catch (e) { console.log("FAIL  " + name + ": " + String(e.message).split("\n").slice(0, 3).join(" | ")); failed++; }
}

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const pg = await ctx.newPage();
  const problems = [];
  pg.on("pageerror", e => problems.push("JS: " + e.message));
  await pg.goto(PANEL_URL + "#updates");
  await pg.fill("#login-user", "owner");
  await pg.fill("#login-pass", "owner-pass-12345");
  await pg.click("#login-form button");

  await t("раздел открывается с текущей версией", async () => {
    await pg.waitForSelector("#page-updates:not([hidden])");
    assert.strictEqual(await pg.textContent("#upd-current"), "0.7.0");
    assert.ok(await pg.isHidden("#btn-upd-start"));
  });
  await t("проверка находит новую версию и что в ней нового", async () => {
    await pg.click("#btn-upd-check");
    await pg.waitForSelector("#btn-upd-start:not([hidden])");
    assert.match(await pg.textContent("#upd-found"), /Доступна версия 9\.9\.9/);
    assert.match(await pg.textContent("#btn-upd-start"), /Обновить до 9\.9\.9/);
    const notes = await pg.locator("#upd-notes p").allTextContents();
    assert.deepStrictEqual(notes, ["Что нового", "• Первая строка", "• Вторая строка"]);
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/update-found.png" });
  await t("на телефоне без горизонтальной прокрутки", async () => {
    await pg.setViewportSize({ width: 390, height: 844 });
    assert.ok(await pg.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    const rows = await pg.$$eval(".side nav .tab", ts => new Set(ts.map(x => Math.round(x.getBoundingClientRect().top))).size);
    assert.strictEqual(rows, 1, "вкладки в несколько рядов");
    const cut = await pg.$$eval(".side nav .tab span", ss => ss.filter(s => s.scrollWidth > s.clientWidth).map(s => s.textContent));
    assert.strictEqual(cut.join(), "", "подписи обрезаны");
    if (SHOTS) await pg.screenshot({ path: SHOTS + "/update-phone.png", fullPage: true });
    await pg.setViewportSize({ width: 1280, height: 900 });
  });
  await t("обновление идёт и показывает ход", async () => {
    await pg.click("#btn-upd-start");
    await pg.waitForSelector("#upd-run:not([hidden])");
    assert.ok(await pg.isDisabled("#btn-upd-check") || /Обновлено/.test(await pg.textContent("#upd-run-text")));
  });
  await t("обновление завершилось", async () => {
    await pg.waitForFunction(() => /Обновлено до версии 9\.9\.9/.test(document.querySelector("#upd-run-text").textContent), null, { timeout: 120000 });
    assert.ok(await pg.isHidden("#btn-upd-start"));
    assert.match(await pg.textContent("#upd-log"), /ГОТОВО: 9\.9\.9/);
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/update-done.png" });
  await t("после перезагрузки итог виден", async () => {
    await pg.reload();
    await pg.waitForSelector("#upd-run:not([hidden])");
    assert.match(await pg.textContent("#upd-run-text"), /Обновлено до версии 9\.9\.9/);
  });
  await t("ошибок на странице нет", async () => assert.deepStrictEqual(problems, []));
  await b.close();
  console.log(`браузер: пройдено ${passed}, не пройдено ${failed}`);
  process.exit(failed ? 1 : 0);
})();
