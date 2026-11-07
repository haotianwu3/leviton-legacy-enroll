// Claim v4 (multi-switch) - run in the console on the LOGGED-IN Devices page
// (myapp.leviton.com/landing-tabs/devices).
// Same as v3 (which claimed the author's first switch successfully), except:
//   - Serial is NOT hardcoded. It prompts for one or more serials,
//     comma-separated, e.g. 1000_000F_XXXX, 1000_000F_YYYY
//   - It loops over each serial: identify -> register (prompting for
//     THAT switch's 12-char key from its leviton_regkey_<serial>.txt
//     file) -> verify, and continues to the next switch on failure
//     instead of aborting the whole run.
//   - Residence is found once and reused for all switches.
//   - v3 is left untouched as the proven single-switch version.
//
// Breakthrough from the v2 diagnostic: the web app does NOT use the
// old APK $LoopBack$ keys. Its session lives in localStorage under:
//   $LevDB$id       -> session token id
//   $LevDB$userId   -> user id
//   $LevDB$ttl / $LevDB$created / $LevDB$rememberMe
// And the residence id appears in key names like:
//   locationData$iotSwitches$<residence-id>
//   sorting$residence:<residence-id>$rooms
// This snippet reads those values ONLY inside the browser to build
// fetch headers. It NEVER logs token, userId value, or registration
// key values - only yes/no, ids found in key names, and statuses.
//
// API base is https://my.leviton.com/api ONLY. The myapp /api path
// 404s (confirmed in v2), and cookie-only calls 401, so the
// Authorization header from $LevDB$id is required.

(async () => {
  const API = 'https://my.leviton.com/api';
  const log = (...a) => console.log('[leviton-claim-v4]', ...a);

  const serialInput = prompt('Enter switch serial(s), comma-separated (e.g. 1000_000F_XXXX, 1000_000F_YYYY):');
  const SERIALS = (serialInput || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!SERIALS.length) { log('STOP: no serial entered.'); return; }
  log('Switches to claim:', SERIALS);

  const token = localStorage.getItem('$LevDB$id');
  const userId = localStorage.getItem('$LevDB$userId');
  log('token found:', token ? 'yes' : 'no');
  log('userId found:', userId ? 'yes' : 'no');
  if (!token) { log('STOP: no $LevDB$id in localStorage. Are you on the logged-in Devices page?'); return; }

  // Residence id from key names (no values needed for this part)
  const resIds = new Set();
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    const m1 = k.match(/residence:(\d+)/);
    const m2 = k.match(/locationData\$[^$]+\$(\d+)$/);
    if (m1) resIds.add(m1[1]);
    if (m2) resIds.add(m2[1]);
  }
  log('residence id(s) from key names:', [...resIds]);

  const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': token };
  async function call(method, path, body) {
    const r = await fetch(API + path, {
      method, headers, credentials: 'include',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const t = await r.text();
    let d = null; try { d = JSON.parse(t); } catch (e) { d = t; }
    return { status: r.status, data: d };
  }

  // Step 1: residence - prefer API lookup, fall back to key-name id
  let residenceId = null;
  if (userId) {
    const acc = await call('GET', '/Person/' + encodeURIComponent(userId) + '/residentialAccounts');
    log('Step 1: residentialAccounts status:', acc.status);
    if (acc.status === 200 && Array.isArray(acc.data)) {
      for (const a of acc.data) {
        const res = await call('GET', '/ResidentialAccounts/' + encodeURIComponent(a.id) + '/residences');
        if (res.status === 200 && Array.isArray(res.data) && res.data.length) {
          log('  residences from API:', res.data.map(r => ({ id: r.id, name: r.name || r.title })));
          residenceId = res.data[0].id;
          break;
        }
      }
    }
  }
  if (!residenceId && resIds.size === 1) {
    residenceId = [...resIds][0];
    log('Step 1: using residence id from key names:', residenceId);
  }
  if (!residenceId) { log('STOP: could not determine residence id.'); return; }

  // Steps 2-4, looped per switch. One switch failing does NOT abort the rest.
  // IMPORTANT workflow order: run secure_connect for a switch, then claim
  // THAT switch (this loop), before running secure_connect for the next
  // switch - otherwise its key file / prompt value gets confused.
  for (const SERIAL of SERIALS) {
    log('=== Switch ' + SERIAL + ' ===');
    // Step 2: identify device
    log('Step 2: identifying device ' + SERIAL + '...');
    let device = null;
    for (let attempt = 1; attempt <= 10; attempt++) {
      const ident = await call('POST', '/IotSwitches/' + encodeURIComponent(SERIAL) + '/identify?seconds=1', {});
      log('  attempt ' + attempt + ': status ' + ident.status);
      if (ident.status === 200 && ident.data) {
        const cand = (ident.data.device && typeof ident.data.device === 'object') ? ident.data.device : ident.data;
        if (cand && cand.id != null) { device = cand; break; }
        log('  no device id:', JSON.stringify(ident.data).slice(0, 300));
      } else {
        log('  ' + JSON.stringify(ident.data).slice(0, 300));
      }
      if (attempt < 10) await new Promise(r => setTimeout(r, 5000));
    }
    if (!device) { log('FAILED for ' + SERIAL + ': device not found in cloud after 10 attempts. Continuing to next switch.'); continue; }
    log('  device found: cloud id=' + device.id + ' residenceId=' + device.residenceId);

    // Step 3: register
    if (device.residenceId == residenceId) {
      log('Step 3: device already belongs to this residence. Nothing to register.');
    } else {
      const regKey = prompt('Paste the 12-character registration key for ' + SERIAL + ' (from its leviton_regkey_' + SERIAL + '.txt file, browser only, not sent to Muse):');
      if (!regKey || regKey.trim().length !== 12) { log('FAILED for ' + SERIAL + ': registration key must be 12 characters. Continuing to next switch.'); continue; }
      log('Step 3: registering device (key length 12, not logged)...');
      const reg = await call('POST', '/Residences/' + encodeURIComponent(residenceId) +
        '/registerDevice?deviceId=' + encodeURIComponent(device.id) +
        '&regKey=' + encodeURIComponent(regKey.trim()), {});
      log('  register status:', reg.status);
      if (![200, 201, 204].includes(reg.status)) {
        log('  FAILED:', JSON.stringify(reg.data).slice(0, 300));
        continue;
      }
      log('  Register OK.');
    }

    // Step 4: verify
    log('Step 4: verifying...');
    const check = await call('GET', '/IotSwitches/' + encodeURIComponent(device.id));
    log('  verify status:', check.status, 'residenceId:', check.data && check.data.residenceId);
  }
  log('Done. Refresh the Devices page - the claimed switches should now appear.');
})();
