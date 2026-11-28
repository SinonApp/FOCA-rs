// E2E-14: update checks on the real core stay inside the harness. The releases list comes from the
// testnet (`/gh/...`: empty, then one newer release after `e2e-serve.sh releases 1`), the
// start-up dialog shows that release once and "Later" stores it; the signature feeds answer 404
// (`no_update`), manual and automatic. Nothing reaches api.github.com or github.com (the final
// "harness is offline" check of qa/real-e2e.sh).
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, api, serve, step, sheetText } = t;
  try {
    await o.go('/projects');
    await api('settings_set', { patch: { update: { auto: true, prompt: true, prompted: '' } } });
    // Empty releases list: up to date.
    serve('releases', '0');
    let v = await api('update_check', { flavor: 'foss' });
    ok('releases from the harness: up to date', v.outcome === 'up_to_date', v.outcome + ' ' + JSON.stringify(v.error));
    ok('no prompt without an update', v.prompt === false);
    // One newer release: available, the start-up dialog shows it once.
    serve('releases', '1');
    v = await api('update_check', { flavor: 'foss' });
    ok('newer release found', v.outcome === 'available' && v.update && v.update.version === '99.0.0', JSON.stringify(v.update));
    ok('prompt flag for the new version', v.prompt === true);
    await ev(() => FOCA.updateAutoCheck(true)); await wait(800);
    const s = await sheetText();
    ok('start-up dialog names the release', /99\.0\.0/.test(s), s);
    await step('e14_prompt');
    await click('upd-later'); await wait(400);
    v = await api('update_status', { flavor: 'foss' });
    ok('Later stores the version', v.settings.prompted === '99.0.0' && v.prompt === false, v.settings);
    await ev(() => FOCA.updateAutoCheck(true)); await wait(600);
    ok('not asked again for this version', !(await ev(() => !!document.querySelector('#upd-prompt'))));
    // Signature feeds: 404 at the harness, never the public release.
    const m = await api('signatures_update', {});
    ok('manual signature check: no_update from the harness', m.last_check.outcome === 'no_update' && /127\.0\.0\.1/.test(m.last_check.feed_url), m.last_check);
    const a = await api('signatures_update', { auto: true });
    ok('automatic signature check waits after the manual one', a.outcome === 'skipped' && a.skipped === 'not_due', a.outcome + ' ' + a.skipped);
  } catch (e) { ok('exception', false, String(e && e.stack || e)); }
  // Back to an empty list so later runs see no update.
  try { serve('releases', '0'); await api('update_check', { flavor: 'foss' }); } catch (e) { /* best effort */ }
  t.finish();
};
