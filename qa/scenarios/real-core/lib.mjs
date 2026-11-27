// Shared harness for end-to-end scenarios on the real core (qa/real-e2e.sh → qa/shoot.sh --real … --steps E2E/NN.mjs).
// State between scenarios lives in the core (`foca serve`, E2E_DIR/data), so scenarios run in order.
import { execFileSync } from 'child_process';
import fs from 'fs';
import { fileURLToPath } from 'url';

export const ROOT = fileURLToPath(new URL('../../..', import.meta.url)).replace(/\/$/, '');
export const E2E_DIR = process.env.E2E_DIR || '/tmp/foca-e2e';
export const DOMAIN = process.env.E2E_DOMAIN || 'example.test';

// PIN that 05-report-settings sets. The core keeps it (there is no command to remove a PIN), and with a PIN
// every app start opens /lock, so later scenarios unlock after each page load.
export const E2E_PIN = '2580';

export function harness(page, o) {
  const log = []; let fails = 0;
  // Enters the E2E PIN when the app shows the lock screen; resolves true when it is unlocked.
  const unlock = async () => {
    if ((await page.evaluate(() => FOCA.current())) !== '/lock') return true;
    for (const d of E2E_PIN) await page.evaluate(x => FOCA.actions['st-lk'](x), d);
    try { await page.waitForFunction(() => FOCA.current() !== '/lock', null, { timeout: 15000 }); } catch (e) { return false; }
    await page.waitForTimeout(400);
    return true;
  };
  if (!o.rawGo) {
    o.rawGo = o.go;
    o.go = async r => {
      await o.rawGo(r);
      if (r === '/lock' || (await page.evaluate(() => FOCA.current())) !== '/lock') return;
      if (!(await unlock())) return;
      if ((await page.evaluate(() => FOCA.current())) !== r) { await page.evaluate(x => FOCA.go(x), r); await page.waitForTimeout(400); }
    };
  }
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? 'OK' : 'FAIL', name, data === undefined ? '' : data]); console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}${cond || data === undefined ? '' : ' ' + JSON.stringify(data).slice(0, 400)}`); return cond; };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const sfx = `${o.W}_fs${o.fsc}_${o.theme}`;
  const shot = async (n) => { await wait(350); await page.screenshot({ path: `${o.out}/${n}_${sfx}.png` }); };
  const route = () => ev(() => FOCA.current());
  // Tap a data-act element (as a user would); FAIL if it is not on screen.
  const click = async (act, { within = '', nth = 0 } = {}) => {
    const done = await ev(([a, w, n]) => { const els = [...document.querySelectorAll(`${w} [data-act="${a}"]`)].filter(e => e.offsetParent !== null || e.closest('.sheet.show')); const el = els[n]; if (!el) return false; el.click(); return true; }, [act, within, nth]);
    if (!done) ok(`tap [data-act="${act}"]`, false, await route());
    await wait(250); return done;
  };
  const hold = async (act) => { const r = await ev(a => { const b = document.querySelector(`[data-hold="${a}"]`); if (!b || b.disabled) return false; FOCA.actions[a](); return true; }, act); await wait(300); return r; };
  // Wait for a condition (a function evaluated in the page), 60 s by default.
  // An exception in the condition (data still reloading) means "not yet", not an early exit.
  const until = async (f, a, ms = 60000) => { try { await page.waitForFunction(([src, arg]) => { try { return (0, eval)('(' + src + ')')(arg); } catch (e) { return false; } }, [f.toString(), a], { timeout: ms, polling: 200 }); return true; } catch (e) { return false; } };
  // Direct core call (to check that the screen shows what the core reports).
  const api = async (cmd, args = {}) => { const r = await fetch(o.real.replace(/\/$/, '') + '/invoke', { method: 'POST', body: JSON.stringify({ cmd, args }) }); const j = await r.json(); if (!r.ok || j.error) throw Object.assign(new Error(j.error && j.error.message), j.error); return j.result; };
  const serve = (...args) => execFileSync(`${ROOT}/qa/e2e-serve.sh`, args, { env: { ...process.env, E2E_DIR }, encoding: 'utf8' });
  const text = () => ev(() => (document.querySelector('.page') || document.body).innerText);
  const sheetText = () => ev(() => { const s = document.querySelector('.sheet.show'); return s ? s.innerText : ''; });
  const snack = () => ev(() => { const s = document.querySelector('#snack, .snack'); return s ? s.innerText : ''; });
  const overflow = () => ev(() => { const pg = document.querySelector('.page'); return [pg ? pg.scrollWidth - pg.clientWidth : 0, document.documentElement.scrollWidth - innerWidth]; });
  const step = async (name) => { const ov = await overflow(); console.log(`STEP ${name} overflow ${JSON.stringify(ov)}`); await o.checkText(name); await shot(name); };
  const finish = () => { const nOk = log.filter(l => l[0] === 'OK').length; console.log(`${nOk} OK, ${fails} FAIL`); fs.writeFileSync(`${o.out}/log_${sfx}.json`, JSON.stringify(log, null, 1)); };
  const project = () => ev(() => FOCA.db.project && FOCA.db.project.id);
  return { ok, ev, wait, shot, route, click, hold, until, api, serve, text, sheetText, snack, step, finish, project, go: o.go, unlock, log };
}
