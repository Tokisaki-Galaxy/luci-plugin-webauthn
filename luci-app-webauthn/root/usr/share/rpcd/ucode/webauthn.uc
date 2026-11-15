#!/usr/bin/env ucode

// LuCI WebAuthn RPC middleware
// Proxies requests to the webauthn-helper Rust CLI (v1.0)
//
// The CLI uses subcommand flags (not stdin JSON) for most commands,
// and only register-finish / login-finish read client JSON from stdin.
// All CLI responses use the envelope { success, data } or { success, error }.

'use strict';

import { popen, access, open } from 'fs';
import { cursor } from 'uci';

const HELPER_BIN = '/usr/libexec/webauthn-helper';

const PLUGIN_UUID = '25e715cf23e44e35bc6763e804d85b85';
const CHALLENGE_PATH_PREFIX = '/tmp/webauthn-auth-';
const CHALLENGE_MAX_AGE = 120;

function configured_origin() {
	return cursor().get('luci_plugins', PLUGIN_UUID, 'origin');
}

function plugin_origin() {
	const uci = cursor();
	let origin = uci.get('luci_plugins', PLUGIN_UUID, 'origin');

	if (!origin) {
		let fd = popen('uci get system.@system[0].hostname 2>/dev/null');
		let hostname = fd ? trim(fd.read('all')) : 'openwrt';
		if (fd) fd.close();
		origin = 'https://' + hostname;
	}

	return origin;
}

// Extract hostname (rp-id) from an origin URL, stripping scheme and port.
function get_rp_id(origin) {
	let rest = replace(origin, /^https?:\/\//, '');
	let host = split(rest, '/')[0];
	let parts = split(host, ':');
	return parts[0];
}

// Shell-escape a value using POSIX single-quote wrapping.
// Inside single quotes all characters are literal; only ' itself needs
// the break-escape-reopen sequence: ' → '\''
function esc(s) {
	return "'" + replace(s ?? '', "'", "'\\''") + "'";
}

// Execute the helper binary and return parsed JSON.
// `cmd` is the full command string; `stdin_data` is optional JSON piped to stdin.
function exec_helper(cmd, stdin_data) {
	if (!access(HELPER_BIN)) {
		return { error: 'HELPER_NOT_FOUND', message: 'webauthn-helper binary not found' };
	}

	let full_cmd;
	if (stdin_data) {
		full_cmd = sprintf("printf '%%s' %s | %s", esc(stdin_data), cmd);
	} else {
		full_cmd = cmd;
	}

	let fd = popen(full_cmd, 'r');
	if (!fd) {
		return { error: 'EXEC_FAILED', message: 'Failed to execute webauthn-helper' };
	}

	let output = fd.read('all');
	fd.close();

	let result;
	try {
		result = json(output);
	} catch (e) {
		return { error: 'PARSE_ERROR', message: 'Invalid JSON from helper' };
	}

	return result;
}

// Unwrap the { success, data } / { success, error } envelope from the CLI.
// Returns the inner `data` on success, or { error, message } on failure.
function unwrap(result) {
	if (result == null)
		return result;

	// Already a middleware-level error (no envelope)
	if (type(result.error) == 'string')
		return result;

	// CLI error: { success: false, error: { code, message } }
	if (result.success == false && result.error)
		return { error: result.error.code, message: result.error.message };

	// CLI success: { success: true, data: <payload> }
	if (result.success == true)
		return result.data;

	return result;
}

// Reads one DER item (tag, length, contents) at off.
function der_item(der, off) {
	let tag = ord(der, off), len = ord(der, off + 1), hdr = 2;

	if (tag == null || len == null)
		return null;

	if (len & 0x80) {
		let n = len & 0x7f;

		if (n < 1 || n > 3)
			return null;

		len = 0;
		for (let i = 0; i < n; i++)
			len = len * 256 + ord(der, off + 2 + i);
		hdr += n;
	}

	return { tag: tag, start: off, body: off + hdr, end: off + hdr + len };
}

// Whether the certificate uhttpd serves is self-signed (its issuer is its
// subject), as the one a stock install generates is. Browsers refuse
// passkeys on a page whose certificate they don't trust. null when the
// certificate can't be read.
function cert_self_signed() {
	let path = cursor().get('uhttpd', 'main', 'cert');
	let fd = path ? open(path, 'r') : null;

	if (!fd)
		return null;

	let pem = fd.read('all');
	fd.close();

	// The first certificate in the file is the server's own.
	const BEGIN = '-----BEGIN CERTIFICATE-----';
	let from = index(pem ?? '', BEGIN);
	let to = (from >= 0) ? index(substr(pem, from), '-----END CERTIFICATE-----') : -1;
	let der = (to > 0) ? b64dec(replace(substr(pem, from + length(BEGIN), to - length(BEGIN)), /[ \t\r\n]+/g, '')) : null;
	let cert = der ? der_item(der, 0) : null;
	let tbs = cert ? der_item(der, cert.body) : null;

	if (!tbs)
		return null;

	// TBSCertificate: [0] version (optional), serial, signature algorithm,
	// issuer, validity, subject, ...
	let fields = [];
	for (let off = tbs.body; off < tbs.end && length(fields) < 6; ) {
		let item = der_item(der, off);

		if (!item)
			return null;

		if (!length(fields) && item.tag != 0xa0)
			push(fields, null);

		push(fields, item);
		off = item.end;
	}

	let issuer = fields[3], subject = fields[5];

	if (!issuer || !subject)
		return null;

	return substr(der, issuer.start, issuer.end - issuer.start) ==
		substr(der, subject.start, subject.end - subject.start);
}

function read_challenge_state(token) {
	if (!match(token, /^[0-9a-f]{32}$/))
		return null;

	let path = CHALLENGE_PATH_PREFIX + token;
	let fd = open(path, 'r');
	if (!fd)
		return null;

	let data = null;
	try { data = json(fd); } catch (e) {}
	fd.close();

	if (!data?.username || !data?.publicKey || !data?.challengeId || !data?.timestamp || !data?.origin)
		return null;

	if (time() - data.timestamp > CHALLENGE_MAX_AGE)
		return null;

	return data;
}

const methods = {
	health: {
		call: function() {
			let cmd = sprintf('%s health-check', HELPER_BIN);
			let result = unwrap(exec_helper(cmd));

			if (type(result) == 'object')
				result.certSelfSigned = cert_self_signed();

			return result;
		}
	},

	// Called before login (granted to the unauthenticated group): start a
	// passwordless login. The RP ID is the configured origin's host, or
	// else the hostname the browser is on; the browser only lets a page use
	// an RP ID its own origin is under, and login-finish checks the
	// request's origin against it.
	login_begin: {
		args: { rpId: 'rpId' },
		call: function(request) {
			const uci = cursor();

			if (uci.get('luci_plugins', PLUGIN_UUID, 'enabled') != '1')
				return { error: 'DISABLED', message: 'Passkey login is disabled' };

			let configured = uci.get('luci_plugins', PLUGIN_UUID, 'origin');
			let rp_id = configured ? get_rp_id(configured) : request.args.rpId;

			if (type(rp_id) != 'string' || !match(rp_id, /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/))
				return { error: 'INVALID_INPUT', message: 'Invalid RP ID' };

			let cmd = sprintf('%s login-begin --rp-id %s', HELPER_BIN, esc(rp_id));
			let data = unwrap(exec_helper(cmd));

			if (data?.error)
				return { error: data.error, message: 'Passkey login unavailable' };

			return { challengeId: data.challengeId, publicKey: data.publicKey };
		}
	},

	register_begin: {
		args: { username: 'username', userVerification: 'userVerification', origin: 'origin' },
		call: function(request) {
			let origin = configured_origin() || request.args.origin || plugin_origin();
			let rp_id = get_rp_id(origin);
			let username = request.args.username || 'root';
			let uv = request.args.userVerification || 'required';

			let cmd = sprintf('%s register-begin --username %s --rp-id %s --user-verification %s',
				HELPER_BIN, esc(username), esc(rp_id), esc(uv));

			return unwrap(exec_helper(cmd));
		}
	},

	register_finish: {
		args: {
			challengeId: 'challengeId',
			deviceName: 'deviceName',
			id: 'id',
			type: 'type',
			response: {},
			origin: 'origin'
		},
		call: function(request) {
			let origin = configured_origin() || request.args.origin || plugin_origin();
			let a = request.args;

			let cmd = sprintf('%s register-finish --challenge-id %s --origin %s --device-name %s',
				HELPER_BIN, esc(a.challengeId), esc(origin), esc(a.deviceName));

			// WebAuthn spec: rawId is the binary form, id is base64url.
			// In JSON both carry the same base64url value; the CLI expects both.
			let stdin_data = sprintf('%J', {
				id: a.id, rawId: a.id, type: a.type, response: a.response
			});

			let result = unwrap(exec_helper(cmd, stdin_data));

			// Passkeys only ever work at the address they were registered
			// at. Without a configured origin, keep that one, so the login
			// page and the Passkeys tab know where passkeys work.
			if (type(result) == 'object' && !result.error && !configured_origin()) {
				const uci = cursor();
				uci.set('luci_plugins', PLUGIN_UUID, 'origin', origin);
				uci.set('luci_plugins', PLUGIN_UUID, 'origin_auto', '1');
				uci.commit('luci_plugins');
			}

			return result;
		}
	},

	auth_challenge: {
		args: { token: 'token' },
		call: function(request) {
			let state = read_challenge_state(request.args.token);
			if (!state)
				return { error: 'CHALLENGE_INVALID', message: 'Challenge not found or expired' };

			return {
				challengeId: state.challengeId,
				publicKey: state.publicKey,
				origin: state.origin
			};
		}
	},

	manage_list: {
		call: function() {
			let cmd = sprintf('%s credential-manage list --username %s',
				HELPER_BIN, esc('root'));

			let data = unwrap(exec_helper(cmd));

			// Backend returns an array; frontend expects { credentials: [...] }.
			// Also map credentialId -> id for each item.
			if (type(data) == 'array') {
				for (let i = 0; i < length(data); i++) {
					if (data[i].credentialId)
						data[i].id = data[i].credentialId;
				}
				return { credentials: data };
			}

			return data;
		}
	},

	manage_delete: {
		args: { id: 'id' },
		call: function(request) {
			let cmd = sprintf('%s credential-manage delete --id %s',
				HELPER_BIN, esc(request.args.id));
			let result = unwrap(exec_helper(cmd));

			// With the last passkey gone, forget an origin that the first
			// registration set, so the next one can be made elsewhere.
			const uci = cursor();
			if (type(result) == 'object' && !result.error &&
			    uci.get('luci_plugins', PLUGIN_UUID, 'origin_auto') == '1') {
				let left = unwrap(exec_helper(sprintf('%s credential-manage list --username %s', HELPER_BIN, esc('root'))));

				if (type(left) == 'array' && !length(left)) {
					uci.delete('luci_plugins', PLUGIN_UUID, 'origin');
					uci.delete('luci_plugins', PLUGIN_UUID, 'origin_auto');
					uci.commit('luci_plugins');
				}
			}

			return result;
		}
	},

	manage_update: {
		args: { id: 'id', name: 'name' },
		call: function(request) {
			let cmd = sprintf('%s credential-manage update --id %s --name %s',
				HELPER_BIN, esc(request.args.id), esc(request.args.name));

			return unwrap(exec_helper(cmd));
		}
	}
};

return { 'luci.webauthn': methods };
