'use strict';
'require baseclass';
'require form';
'require webauthn.settings as settings';

// This plugin's entry on System > Plugins. System > Administration > Passkeys
// edits the same settings and is where passkeys are registered.

return baseclass.extend({
	class: 'auth',
	class_i18n: _('Authentication'),

	type: 'login',
	type_i18n: _('Login'),

	name: 'WebAuthn Passkey',
	id: '25e715cf23e44e35bc6763e804d85b85',
	title: _('Passkeys'),
	description: _('Sign in with a passkey instead of the password, or ask for one as a second factor. ' +
	               'Register passkeys under System > Administration > Passkeys.'),

	addFormOptions: function(s) {
		var o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;

		o = settings.addModeOption(s, false);
		o.depends('enabled', '1');

		settings.addAdvancedOptions(s);
	},

	configSummary: function(section) {
		return settings.summary(section);
	}
});
