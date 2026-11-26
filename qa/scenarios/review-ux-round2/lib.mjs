// Shared helpers for the usability review scenarios (real clicks, tap counter).
export function mk(page, { out, prep }, tag) {
  const log = []; let taps = 0; let shotN = 0;
  const wait = ms => page.waitForTimeout(ms);
  const ev = (f, a) => page.evaluate(f, a);
  const note = (...a) => log.push(a);
  const go = async (r, fresh) => {
    await page.goto('about:blank');
    await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r);
    if (fresh) { await ev(() => { try { localStorage.clear(); } catch (e) {} }); await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); }
    await wait(250); await prep(); await wait(300);
  };
  const shot = async n => { await wait(400); const f = `${out}/${tag}_${String(++shotN).padStart(2, '0')}_${n}.png`; await page.screenshot({ path: f }); return f; };
  // Real tap on a visible element (Playwright scrolls to it); counts the tap.
  const tap = async (sel, label, { n = 0, count = true, timeout = 2500 } = {}) => {
    const loc = typeof sel === 'string' ? page.locator(sel).filter({ visible: true }).nth(n) : sel;
    try { await loc.click({ timeout }); } catch (e) { note('TAP-FAIL', label || String(sel), e.message.split('\n')[0]); return false; }
    if (count) taps++; note('tap', taps, label || String(sel), await cur()); await wait(320); return true;
  };
  const tapText = (text, label, opts) => tap(page.getByText(text, { exact: false }).filter({ visible: true }).first(), label || text, opts);
  const type = async (sel, v, label) => { const loc = page.locator(sel).filter({ visible: true }).first(); try { await loc.fill(v, { timeout: 2500 }); } catch (e) { note('TYPE-FAIL', sel, e.message.split('\n')[0]); return false; } taps++; note('type', taps, label || sel, v); await wait(150); return true; };
  const hold = async (sel, label) => {
    const loc = page.locator(sel).filter({ visible: true }).first();
    try { await loc.scrollIntoViewIfNeeded({ timeout: 2500 }); const b = await loc.boundingBox(); await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2); await page.mouse.down(); await wait(1500); await page.mouse.up(); } catch (e) { note('HOLD-FAIL', label || sel, e.message.split('\n')[0]); return false; }
    taps++; note('hold', taps, label || sel, await cur()); await wait(400); return true;
  };
  const back = async (label = 'Back (system)') => { await ev(() => history.back()); taps++; await wait(400); note('back', taps, label, await cur()); };
  const tbBack = async () => tap('#tb-back', 'Back (arrow)');
  const cur = () => ev(() => ({ r: FOCA.current(), t: document.querySelector('#tb-t')?.textContent || '', sheet: !!document.querySelector('.sheet.show') }));
  const reset = () => { const t = taps; taps = 0; return t; };
  return { log, wait, ev, note, go, shot, tap, tapText, type, hold, back, tbBack, cur, reset, get taps() { return taps; } };
}
