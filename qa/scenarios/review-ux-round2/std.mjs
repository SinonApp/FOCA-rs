// "Standard" in the new project wizard: project creation before confirmation, Back, checkbox position.
import { mk } from './lib.mjs';
export default async (page, ctx) => {
  const h = mk(page, ctx, 'std'); const { tap, type, back, shot, ev, note, wait } = h;
  try {
    await h.go('/projects'); h.reset();
    await type('#pj-q', 'globex.ua'); await tap('.pj-go', '→');
    await tap('[data-act="la-prof:std"]', 'Standard');
    await shot('std_card');
    note('std-card', await ev(() => document.querySelector('.la-prof.on')?.innerText.replace(/\s+/g, ' ')), await ev(() => document.querySelector('#la-start').innerText));
    await tap('#la-start', 'Next: scope check');
    await wait(400);
    note('confirm', await h.cur(), await ev(() => ({ projects: FOCA.db.projects ? FOCA.db.projects.map(p => p.name) : null, proj: FOCA.project && FOCA.project.name })));
    note('agree-pos', await ev(() => { const a = document.querySelector('.la-agree').getBoundingClientRect(); const f = document.querySelector('.la-foot').getBoundingClientRect(); return { agreeTop: Math.round(a.top), footTop: Math.round(f.top), visible: a.bottom <= f.top, hint: document.querySelector('.la-foot-w')?.innerText }; }));
    await shot('std_confirm');
    await back('Back from confirmation'); note('b1', await h.cur(), await ev(() => document.querySelector('#tb-s')?.innerText));
    await shot('std_back_wizard');
    await back('Back from wizard'); note('b2', await h.cur());
    await shot('std_projects');
    note('projects-list', await ev(() => [...document.querySelectorAll('.pj-card')].map(c => c.innerText.replace(/\s+/g, ' ').slice(0, 70))));
  } catch (e) { note('ERR', e.message.split('\n')[0]); }
  console.log('STD', JSON.stringify({ log: h.log }));
};
