// End-to-end test of passwordless LuCI login with Chrome's virtual authenticator.
// usage: node passkey-e2e.js <base-url> <root-password>
//
// Runs against a LuCI instance with this app and passwordless login enabled
// (the plugin's enabled=1 and primary=1),
// served over HTTPS at <base-url>, with no passkeys registered yet. Needs
// Playwright's Chromium. Set RESOLVE=<ip> to map the URL's host to an address.
const { chromium } = require(process.env.PW_CORE || 'playwright');

const BASE = process.argv[2];
const PASSWORD = process.argv[3];
const HOST = new URL(BASE).hostname;

let failures = 0;
function check(name, ok, detail) {
	console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
	if (!ok) failures++;
}

async function anonUbus(page, object, method, args) {
	return page.evaluate(async ([object, method, args]) => {
		const r = await fetch('/ubus', { method: 'POST', headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'call',
				params: ['00000000000000000000000000000000', object, method, args] }) });
		return r.json();
	}, [object, method, args]);
}

// After login, master redirects to /cgi-bin/luci/admin/... while 25.12
// renders the admin pages at /cgi-bin/luci/, so wait for the login form to go.
const loggedIn = (page) => page.waitForFunction(() =>
	document.readyState === 'complete' && !document.querySelector('input[name="luci_password"]'),
	null, { timeout: 15000 });

(async () => {
	const browser = await chromium.launch({
		args: process.env.RESOLVE ? [`--host-resolver-rules=MAP ${HOST} ${process.env.RESOLVE}`] : []
	});
	const context = await browser.newContext();
	// Record every WebAuthn get() so the test can see autofill requests.
	await context.addInitScript(() => {
		window.__webauthnGets = [];
		// Steps that test the button switch autofill off: Chrome's virtual
		// authenticator answers autofill requests immediately.
		if (localStorage.getItem('noAutofill') && window.PublicKeyCredential)
			PublicKeyCredential.isConditionalMediationAvailable = async () => false;
		// Safari only allows create() and a button's get() inside the click
		// that asked for them. Record whether each call happens in the same
		// task as a click, before any server round trip could finish.
		window.__inClick = false;
		document.addEventListener('click', () => {
			window.__inClick = true;
			setTimeout(() => { window.__inClick = false; }, 0);
		}, true);
		const logCall = (kind) => {
			const seen = JSON.parse(sessionStorage.getItem('webauthnCalls') || '[]');
			sessionStorage.setItem('webauthnCalls', JSON.stringify(seen.concat({ kind, inClick: window.__inClick })));
		};
		const origCreate = navigator.credentials.create.bind(navigator.credentials);
		navigator.credentials.create = (opts) => { logCall('create'); return origCreate(opts); };
		const orig = navigator.credentials.get.bind(navigator.credentials);
		navigator.credentials.get = (opts) => {
			if (!(opts && opts.mediation))
				logCall('get');
			window.__webauthnGets.push(opts && opts.mediation || 'required');
			const seen = JSON.parse(sessionStorage.getItem('webauthnGets') || '[]');
			sessionStorage.setItem('webauthnGets', JSON.stringify(seen.concat(opts && opts.mediation || 'required')));
			return orig(opts);
		};
	});
	const page = await context.newPage();
	page.on('console', m => { if (m.type() === 'error') console.log('CONSOLE:', m.text()); });

	const cdp = await context.newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
		protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
		hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

	// 1. Before any passkey exists, the login page has no passkey button.
	await page.goto(`${BASE}/cgi-bin/luci/`);
	check('no passkey button before registration', await page.locator('#webauthn-primary-btn').count() === 0);

	// 2. Anonymous callers cannot reach session.setup over /ubus.
	const setup = await anonUbus(page, 'session', 'setup', { username: 'root' });
	check('anonymous session.setup is denied', !(setup.result && setup.result[0] === 0), JSON.stringify(setup.result ?? setup.error));

	// 3. Password login still works.
	await page.fill('input[name="luci_password"]', PASSWORD);
	await page.click('button.cbi-button-positive');
	await loggedIn(page);
	check('password login works', true);

	// 4. Register a passkey through System > Administration > Passkeys.
	await page.goto(`${BASE}/cgi-bin/luci/admin/system/admin/webauthn`);
	await page.getByRole('button', { name: /Register New Passkey/ }).click();
	const modal = page.locator('.modal');
	await modal.locator('input[type="text"]').fill('Virtual key');
	const regBtn = modal.getByRole('button', { name: 'Register', exact: true });
	await regBtn.waitFor();
	await page.waitForFunction(b => !b.disabled, await regBtn.elementHandle(), { timeout: 15000 });
	await regBtn.click();
	try {
		await page.getByText('Passkey registered successfully!').waitFor({ timeout: 15000 });
	} catch (e) {
		console.log('ALERTS:', await page.locator('.alert-message').allInnerTexts());
		throw e;
	}
	const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
	check('passkey registered', credentials.length === 1 && credentials[0].isResidentCredential,
		`${credentials.length} credential(s), rpId ${credentials[0]?.rpId}`);
	const lastCall = async (kind) => (await page.evaluate(() =>
		JSON.parse(sessionStorage.getItem('webauthnCalls') || '[]'))).filter(c => c.kind === kind).pop();
	check('create() runs inside the Register click (Safari needs this)',
		(await lastCall('create'))?.inClick === true, JSON.stringify(await lastCall('create')));
	const named = await page.waitForFunction(() =>
		[...document.querySelectorAll('#webauthn-table-container input')].some(i => i.value === 'Virtual key'),
		null, { timeout: 5000 }).then(() => true, () => false);
	check('passkey saved under the typed name', named);

	// 5. Autofill: the username field offers the passkey, and choosing it
	// (the virtual authenticator does so at once) logs in.
	await context.clearCookies();
	await page.goto(`${BASE}/cgi-bin/luci/`);
	await loggedIn(page).catch(() => {});
	const gets = await page.evaluate(() => JSON.parse(sessionStorage.getItem('webauthnGets') || '[]'));
	check('autofill (conditional) request made on page load', gets[0] === 'conditional', JSON.stringify(gets));
	check('autofill sign-in creates a session',
		(await context.cookies()).filter(c => c.name.startsWith('sysauth')).length === 1);

	// 5b. With autofill unavailable, the button is the way in.
	await page.evaluate(() => localStorage.setItem('noAutofill', '1'));
	await context.clearCookies();
	await page.goto(`${BASE}/cgi-bin/luci/`);
	check('passkey button shown', await page.locator('#webauthn-primary-btn').count() === 1);

	// 6. Passwordless login (button; aborts the autofill request first).
	await page.waitForLoadState('networkidle');
	await page.click('#webauthn-primary-btn');
	await loggedIn(page);
	check('button get() runs inside the click (Safari needs this)',
		(await lastCall('get'))?.inClick === true, JSON.stringify(await lastCall('get')));
	const cookies = (await context.cookies()).filter(c => c.name.startsWith('sysauth'));
	check('passkey login creates a session', cookies.length === 1, cookies.map(c => c.name).join(','));
	await page.goto(`${BASE}/cgi-bin/luci/admin/system/system`);
	const sysOk = await page.locator('h2', { hasText: 'System' }).first().waitFor({ timeout: 15000 }).then(() => true, () => false);
	check('session has admin rights (System page renders)', sysOk);

	// 7. A replayed assertion is rejected (challenge is single use).
	await context.clearCookies();
	await page.goto(`${BASE}/cgi-bin/luci/`);
	let captured = null;
	await page.route('**/cgi-bin/luci/**', async (route) => {
		if (route.request().method() === 'POST') captured = route.request().postData();
		await route.continue();
	});
	await page.click('#webauthn-primary-btn');
	await loggedIn(page);
	await page.unroute('**/cgi-bin/luci/**');
	await context.clearCookies();
	const replay = await page.request.post(`${BASE}/cgi-bin/luci/`, {
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, data: captured, maxRedirects: 0 });
	check('replayed passkey response is rejected', replay.status() === 403, `status ${replay.status()}`);

	// 8. Without user verification the passkey is refused.
	await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
	await page.goto(`${BASE}/cgi-bin/luci/`);
	await page.click('#webauthn-primary-btn');
	await page.waitForLoadState('load');
	await page.waitForTimeout(2000);
	const noUv = (await context.cookies()).filter(c => c.name.startsWith('sysauth'));
	check('login without user verification is refused', noUv.length === 0);
	await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: true });

	// 9. A wrong password still fails.
	await context.clearCookies();
	await page.goto(`${BASE}/cgi-bin/luci/`);
	await page.fill('input[name="luci_password"]', 'wrong-password');
	await page.click('button.cbi-button-positive');
	await page.waitForLoadState('load');
	check('wrong password is refused', (await context.cookies()).filter(c => c.name.startsWith('sysauth')).length === 0);

	await browser.close();
	console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
	process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
