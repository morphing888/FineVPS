// Первая настройка в браузере. Запускается из tests/bootstrap-stand.inc.
const { chromium } = require("playwright");
const assert = require("assert");
const { PANEL_LINK, R2_IP, R2_PASS, SHOTS } = process.env;
const ADMIN = "owner", PASS = "owner-pass-12345";
let passed = 0, failed = 0;
async function t(name, fn) {
  try { await fn(); console.log("PASS  " + name); passed++; }
  catch (e) { console.log("FAIL  " + name + ": " + String(e.message).split("\n").slice(0, 3).join(" | ")); failed++; }
}
const noScroll = pg => pg.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const pg = await ctx.newPage();
  const problems = [];
  pg.on("pageerror", e => problems.push("JS: " + e.message));
  await pg.goto(PANEL_LINK);

  await t("ссылка открывает создание администратора", async () => {
    await pg.waitForSelector("#admin-form:not([hidden])");
    assert.ok(!pg.url().includes("setup="));
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/setup-admin.png" });
  await t("администратор создан, открылся мастер", async () => {
    await pg.fill("#admin-user", ADMIN);
    await pg.fill("#admin-pass", PASS);
    await pg.fill("#admin-pass2", PASS);
    await pg.click("#admin-form button");
    await pg.waitForSelector("#exit-form:not([hidden])");
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/setup-exit.png" });
  await t("мастер помещается на телефоне", async () => {
    await pg.setViewportSize({ width: 390, height: 844 });
    assert.ok(await noScroll(pg));
    if (SHOTS) await pg.screenshot({ path: SHOTS + "/setup-exit-phone.png" });
    await pg.setViewportSize({ width: 1280, height: 900 });
  });
  await t("после перезагрузки мастер на месте", async () => {
    await pg.reload();
    await pg.waitForSelector("#exit-form:not([hidden])");
  });
  await t("неверный пароль сервера 2: ошибка и форма", async () => {
    await pg.fill("#exit-ip", R2_IP);
    await pg.fill("#exit-pass", "wrong-root-password");
    await pg.click("#exit-form button");
    await pg.waitForSelector("#exit-error:not([hidden])", { timeout: 60000 });
    assert.match(await pg.textContent("#exit-error"), /не удалось подключиться/);
    assert.strictEqual(await pg.inputValue("#exit-ip"), R2_IP);
    assert.strictEqual(await pg.inputValue("#exit-pass"), "");
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/setup-error.png" });
  await t("верный пароль запускает установку", async () => {
    await pg.fill("#exit-pass", R2_PASS);
    await pg.click("#exit-form button");
    await pg.waitForSelector("#setup-run:not([hidden])");
    assert.strictEqual(await pg.inputValue("#exit-pass"), "");
  });
  await t("перезагрузка не прерывает установку", async () => {
    await pg.reload();
    await pg.waitForSelector("#setup-run:not([hidden])");
    await pg.waitForSelector("#run-steps li.now, #run-steps li.done");
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/setup-run.png" });
  await t("установка завершилась", async () => {
    await pg.waitForSelector("#run-done:not([hidden])", { timeout: 180000 });
    assert.match(await pg.textContent("#run-title"), /Каскад работает/);
    assert.strictEqual(await pg.locator("#run-steps li.done").count(), 5);
  });
  if (SHOTS) await pg.screenshot({ path: SHOTS + "/setup-done.png" });
  await t("из мастера открываются пользователи", async () => {
    await pg.click("#run-done");
    await pg.waitForSelector("#page-users:not([hidden])");
  });
  await t("первый пользователь создаётся в панели", async () => {
    await pg.fill("#add-name", "andrey");
    await pg.click("#add-form button");
    await pg.waitForSelector("#qr-dialog[open]");
    await pg.click("#qr-close");
    await pg.waitForSelector(".user");
  });
  await t("мастер больше не показывается", async () => {
    await pg.reload();
    await pg.waitForSelector(".tiles .tile, .user");
    assert.ok(await pg.isHidden("#setup"));
  });
  await t("вход с именем и паролем", async () => {
    await pg.click("#logout");
    await pg.waitForSelector("#login-form");
    await pg.fill("#login-user", "другой");
    await pg.fill("#login-pass", PASS);
    await pg.click("#login-form button");
    await pg.waitForSelector("#login-error:not([hidden])");
    await pg.fill("#login-user", ADMIN);
    await pg.click("#login-form button");
    await pg.waitForSelector("#app:not([hidden])");
  });
  await t("ошибок на странице нет", async () => assert.deepStrictEqual(problems, []));
  await b.close();
  console.log(`браузер: пройдено ${passed}, не пройдено ${failed}`);
  process.exit(failed ? 1 : 0);
})();
