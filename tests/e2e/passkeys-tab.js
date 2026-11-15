// Checks the "Use passkeys" choice on System > Administration > Passkeys:
// each choice saves the right luci_plugins options, an old config with both
// primary and second_factor on shows as "As a second factor", and a disabled
// plugin with a leftover primary '1' stays off when saved untouched.
// usage: node passkeys-tab.js <base-url> <root-password> <podman-container> [screenshot.png]
// Reads and sets uci through 'podman exec', so it needs a container target.
// Set PW_CORE to playwright-core and RESOLVE=<ip> to map the URL's host.
const { chromium } = require(process.env.PW_CORE || 'playwright');
const { execSync } = require('child_process');
const [BASE, PASSWORD, CONTAINER, SHOT] = process.argv.slice(2);
const U = 'luci_plugins.25e715cf23e44e35bc6763e804d85b85';
const state = () => ['enabled', 'primary', 'second_factor'].map(o =>
	`${o}=${execSync(`podman exec ${CONTAINER} uci -q get ${U}.${o} || true`).toString().trim()}`).join(' ');
const uciSet = (...kv) => execSync(`podman exec ${CONTAINER} sh -c "${kv.map(x => `uci set ${U}.${x}`).join(' && ')} && uci commit luci_plugins"`);

let failures = 0;
const check = (name, ok, detail) => {
	console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
	if (!ok) failures++;
};

(async () => {
	const host = new URL(BASE).hostname;
	const browser = await chromium.launch({
		args: process.env.RESOLVE ? [`--host-resolver-rules=MAP ${host} ${process.env.RESOLVE}`] : []
	});
	const page = await browser.newPage({ viewport: { width: 1100, height: 760 } });
	await page.goto(`${BASE}/cgi-bin/luci/`);
	await page.fill('input[name="luci_password"]', PASSWORD);
	await page.click('button.cbi-button-positive');
	await page.waitForFunction(() => !document.querySelector('input[name="luci_password"]'));

	const mode = page.locator('.cbi-value[data-name="_mode"] select');
	const open = async () => {
		await page.goto(`${BASE}/cgi-bin/luci/admin/system/admin/webauthn`);
		await mode.waitFor({ timeout: 15000 });
	};
	const saveApply = async () => {
		await page.locator('.cbi-page-actions .cbi-button-apply').first().click();
		await page.waitForTimeout(4000);
	};
	const choose = async (value) => { await open(); await mode.selectOption(value); await saveApply(); return state(); };

	const before = state();
	await open();
	if (SHOT) await page.screenshot({ path: SHOT, fullPage: true });

	let st = await choose('off');
	check('Off', st == 'enabled=0 primary=0 second_factor=0', st);
	st = await choose('second_factor');
	check('As a second factor', st == 'enabled=1 primary=0 second_factor=1', st);
	st = await choose('passwordless');
	check('Instead of the password', st == 'enabled=1 primary=1 second_factor=0', st);

	uciSet('primary=1', 'second_factor=1');
	await open();
	check('both on shows as "As a second factor"', await mode.inputValue() == 'second_factor', await mode.inputValue());

	uciSet('enabled=0', 'primary=1', 'second_factor=0');
	await open();
	check('disabled plugin shows as Off', await mode.inputValue() == 'off', await mode.inputValue());
	await saveApply();
	st = state();
	await open();
	check('saving it untouched keeps it off', st.startsWith('enabled=0') && await mode.inputValue() == 'off', st);

	execSync(`podman exec ${CONTAINER} sh -c "${before.split(' ').map(kv => `uci set ${U}.${kv}`).join(' && ')} && uci commit luci_plugins"`);
	await browser.close();
	console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
	process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
