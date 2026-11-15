/* Passwordless passkey login for the LuCI login page */
(function() {
	'use strict';

	var NULL_SESSION = '00000000000000000000000000000000';

	function b64urlToBuf(str) {
		var bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
		var arr = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++)
			arr[i] = bin.charCodeAt(i);
		return arr.buffer;
	}

	function bufToB64url(buf) {
		var bytes = new Uint8Array(buf), bin = '';
		for (var i = 0; i < bytes.length; i++)
			bin += String.fromCharCode(bytes[i]);
		return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	function requestOptions(json) {
		if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON)
			return PublicKeyCredential.parseRequestOptionsFromJSON(json);

		var opts = Object.assign({}, json);
		opts.challenge = b64urlToBuf(json.challenge);
		if (json.allowCredentials)
			opts.allowCredentials = json.allowCredentials.map(function(c) {
				return Object.assign({}, c, { id: b64urlToBuf(c.id) });
			});
		return opts;
	}

	function credentialJSON(cred) {
		if (typeof cred.toJSON === 'function')
			return cred.toJSON();

		var r = cred.response;
		return {
			id: cred.id,
			rawId: bufToB64url(cred.rawId),
			type: cred.type,
			authenticatorAttachment: cred.authenticatorAttachment || null,
			clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
			response: {
				clientDataJSON: bufToB64url(r.clientDataJSON),
				authenticatorData: bufToB64url(r.authenticatorData),
				signature: bufToB64url(r.signature),
				userHandle: r.userHandle ? bufToB64url(r.userHandle) : null
			}
		};
	}

	function status(msg, isError) {
		var el = document.getElementById('webauthn-primary-status');
		if (!el)
			return;
		el.style.display = '';
		el.className = 'alert-message' + (isError ? ' error' : '');
		el.textContent = msg;
	}

	function ubusCall(method, args) {
		return fetch(window.location.pathname.replace(/\/cgi-bin\/luci.*$/, '') + '/ubus', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				jsonrpc: '2.0', id: 1, method: 'call',
				params: [ NULL_SESSION, 'luci.webauthn', method, args ]
			})
		}).then(function(r) { return r.json(); }).then(function(reply) {
			var res = reply && reply.result;
			if (!res || res[0] !== 0 || !res[1] || res[1].error)
				throw new Error((res && res[1] && res[1].message) || 'Passkey login is unavailable');
			return res[1];
		});
	}

	// The server drops login challenges after five minutes, so options are
	// fetched again every four.
	var REFRESH_MS = 4 * 60 * 1000;

	// Safari only lets credentials.get() run inside the click that asked for
	// it, and a server round trip in between uses that up. So the options
	// are fetched ahead of time and the button calls get() straight away.
	var current = null;	// { begin, fetchedAt } from the last login_begin
	var refreshTimer = null;
	var useAutofill = false;
	var autofill = null;	// AbortController of the pending autofill request
	var submitted = false;

	function submitAssertion(challengeId, cred) {
		var field = document.querySelector('input[name="webauthn_login_response"]');

		if (submitted || !field)
			return;

		submitted = true;
		field.value = JSON.stringify({ challengeId: challengeId, credential: credentialJSON(cred) });
		status('Signing in…', false);
		field.form.submit();
	}

	function stopAutofill() {
		if (!autofill)
			return;

		autofill.abort();
		autofill = null;
	}

	// Offer passkeys in the browser's autofill list for the username field.
	function startAutofill(begin) {
		var controller = new AbortController();

		stopAutofill();
		autofill = controller;

		navigator.credentials.get({
			mediation: 'conditional',
			publicKey: requestOptions(begin.publicKey),
			signal: controller.signal
		}).then(function(cred) {
			if (cred)
				submitAssertion(begin.challengeId, cred);
		}).catch(function() {
			// Aborts are ours (refresh or button press); anything else just
			// means no autofill, and the button still works.
			if (autofill === controller)
				autofill = null;
		});
	}

	function refresh() {
		clearTimeout(refreshTimer);
		refreshTimer = setTimeout(refresh, REFRESH_MS);

		return ubusCall('login_begin', { rpId: window.location.hostname }).then(function(begin) {
			current = { begin: begin, fetchedAt: Date.now() };
			if (useAutofill && !submitted)
				startAutofill(begin);
			return begin;
		});
	}

	function signIn() {
		var btn = document.getElementById('webauthn-primary-btn');

		if (!btn)
			return;

		if (!window.isSecureContext || !window.PublicKeyCredential) {
			status('Passkeys need HTTPS and a browser that supports them.', true);
			return;
		}

		// Only one WebAuthn request may be pending at a time.
		stopAutofill();

		btn.disabled = true;
		status('Waiting for passkey…', false);

		// With fresh options get() is called before this function returns,
		// still inside the click.
		var fresh = current && (Date.now() - current.fetchedAt) < REFRESH_MS;
		var getCred = function(begin) {
			return navigator.credentials.get({ publicKey: requestOptions(begin.publicKey) }).then(function(cred) {
				submitAssertion(begin.challengeId, cred);
			});
		};

		(fresh ? getCred(current.begin) : refresh().then(getCred)).catch(function(err) {
			btn.disabled = false;
			status(err && err.name === 'NotAllowedError'
				? 'Passkey sign-in was cancelled or no passkey matched.'
				: ((err && err.message) || 'Passkey sign-in failed.'), true);
			// The challenge may be spent now; fetch a new one, which also
			// restarts autofill.
			refresh().catch(function() {});
		});
	}

	function maybeStartAutofill() {
		var username = document.querySelector('input[name="luci_username"]');

		if (!username || !window.isSecureContext || !window.PublicKeyCredential ||
		    typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function')
			return;

		PublicKeyCredential.isConditionalMediationAvailable().then(function(available) {
			if (!available || submitted)
				return;

			// Browsers only offer passkeys on fields marked "webauthn".
			var tokens = (username.getAttribute('autocomplete') || 'username').split(/\s+/);
			if (tokens.indexOf('webauthn') < 0)
				username.setAttribute('autocomplete', tokens.concat('webauthn').join(' '));

			useAutofill = true;
			if (current && !submitted)
				startAutofill(current.begin);
		});
	}

	function init() {
		var btn = document.getElementById('webauthn-primary-btn');
		if (btn)
			btn.addEventListener('click', signIn);

		refresh().catch(function() {});
		maybeStartAutofill();
	}

	if (document.readyState === 'loading')
		document.addEventListener('DOMContentLoaded', init);
	else
		init();
})();
