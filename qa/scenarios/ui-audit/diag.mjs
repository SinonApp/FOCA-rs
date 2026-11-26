// Horizontal overflow diagnostics: which element widens .page.
export default async (page, { prep }) => {
  const r = await page.evaluate(() => {
    const pg = document.querySelector('.page');
    const res = { sw: pg.scrollWidth, cw: pg.clientWidth, items: [] };
    for (const e of pg.querySelectorAll('*')) {
      const sw = e.scrollWidth, cw = e.clientWidth;
      const rc = e.getBoundingClientRect();
      if (sw > cw + 1 && getComputedStyle(e).overflowX !== 'auto') res.items.push({ el: e.tagName + '.' + (e.className.baseVal ?? e.className), sw, cw, right: Math.round(rc.right) });
    }
    // Elements extending past the page clientWidth, including transformed ones.
    const pr = pg.getBoundingClientRect();
    res.out = [...pg.querySelectorAll('*')].filter(e => e.getBoundingClientRect().right > pr.left + pg.clientWidth + 0.5).slice(0, 10).map(e => e.tagName + '.' + (e.className.baseVal ?? e.className) + ' r=' + Math.round(e.getBoundingClientRect().right));
    return res;
  });
  console.error(JSON.stringify(r, null, 1));
};
