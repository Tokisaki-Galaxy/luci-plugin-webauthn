// Needs a container target (reads and sets uci through 'podman exec') with
// /tmp/self.crt holding a self-signed certificate, and no passkeys registered.
// Set PW_CORE to playwright-core and RESOLVE=<ip> to map the URL's host.
// Checks the Passkeys tab's setup warnings and the origin saved by the
// first registration. usage: node setup-warnings.js <base-url> <ip-url> <root-password> <container> <shot-dir>
const { chromium } = require(process.env.PW_CORE || 'playwright');
const { execSync } = require('child_process');
const [BASE, IPBASE, PASSWORD, CONTAINER, SHOTS] = process.argv.slice(2);
const P = 'luci_plugins.25e715cf23e44e35bc6763e804d85b85';
const sh = (cmd) => execSync(`podman exec ${CONTAINER} sh -c "${cmd}"`).toString().trim();
let failures = 0;
const check = (name, ok, detail) => { console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`); if (!ok) failures++; };

(async () => {
	const host = new URL(BASE).hostname;
	const browser = await chromium.launch({ args: process.env.RESOLVE ? [`--host-resolver-rules=MAP ${host} ${process.env.RESOLVE}`] : [] });
	const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1100, height: 760 } });
	const page = await context.newPage();
	const login = async (base) => {
		await context.clearCookies();
		await page.goto(`${base}/cgi-bin/luci/`);
		await page.fill('input[name="luci_password"]', PASSWORD);
		await page.click('button.cbi-button-positive');
		await page.waitForFunction(() => !document.querySelector('input[name="luci_password"]'));
	};
	const tab = async (base, shot) => {
		await page.goto(`${base}/cgi-bin/luci/admin/system/admin/webauthn`);
		await page.locator('#webauthn-table-container').waitFor({ timeout: 15000 });
		await page.waitForTimeout(500);
		if (shot) await page.screenshot({ path: `${SHOTS}/${shot}.png`, fullPage: true });
		return {
			warnings: (await page.locator('.cbi-map .alert-message.warning').allInnerTexts()).map(t => t.replace(/\s+/g, ' ')),
			registerDisabled: await page.locator('button:has-text("Register New Passkey")').isDisabled()
		};
	};
	const origin = sh(`uci -q get ${P}.origin || true`);

	await login(BASE);
	let r = await tab(BASE, 'warn-none');
	check('opened at the origin: no warnings, can register', r.warnings.length == 0 && !r.registerDisabled, JSON.stringify(r));

	sh(`uci set ${P}.origin=https://router.example.com && uci commit luci_plugins`);
	r = await tab(BASE, 'warn-elsewhere');
	check('opened elsewhere: warning, register disabled', r.warnings.some(w => /work at https:\/\/router.example.com/.test(w)) && r.registerDisabled, JSON.stringify(r.warnings));
	sh(`uci set ${P}.origin=${origin} && uci commit luci_plugins`);

	sh('uci set uhttpd.main.cert=/tmp/self.crt');
	r = await tab(BASE, 'warn-selfsigned');
	check('self-signed certificate: warning', r.warnings.some(w => /self-signed/.test(w)), JSON.stringify(r.warnings));
	sh('uci revert uhttpd');

	const logged = [];
	page.on('console', m => { if (m.type() === 'info') logged.push(m.text()); });
	await context.clearCookies();
	await page.goto(`${IPBASE}/cgi-bin/luci/`);
	await page.waitForTimeout(500);
	check('login page by IP says why there is no passkey button',
		logged.some(t => /hidden because .*(IP address|no passkey is registered)/.test(t)), JSON.stringify(logged));

	await login(IPBASE);
	r = await tab(IPBASE, 'warn-ip');
	check('opened by IP: warning, register disabled', r.warnings.some(w => /by IP address/.test(w)) && r.registerDisabled, JSON.stringify(r.warnings));

	// First registration saves the origin; deleting the last passkey clears it.
	sh(`uci delete ${P}.origin; uci commit luci_plugins`);
	await login(BASE);
	const cdp = await context.newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
		hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
	await tab(BASE);
	await page.click('button:has-text("Register New Passkey")');
	const regBtn = page.locator('.modal').getByRole('button', { name: 'Register', exact: true });
	await page.waitForFunction(b => !b.disabled, await regBtn.elementHandle(), { timeout: 15000 });
	await regBtn.click();
	await page.getByText('Passkey registered successfully!').waitFor({ timeout: 15000 });
	const saved = sh(`uci -q get ${P}.origin || true`), auto = sh(`uci -q get ${P}.origin_auto || true`);
	check('first registration saves the origin', saved == BASE && auto == '1', `${saved} auto=${auto}`);

	page.once('dialog', d => d.accept());
	await page.click('#webauthn-table-container button:has-text("Delete")');
	await page.waitForTimeout(2000);
	const after = sh(`uci -q get ${P}.origin || echo none`);
	check('deleting the last passkey clears a saved origin', after == 'none', after);

	sh(`uci set ${P}.origin=${origin} && uci commit luci_plugins`);
	await browser.close();
	console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
	process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
