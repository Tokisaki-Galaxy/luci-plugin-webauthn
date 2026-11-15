'use strict';
'require baseclass';
'require form';

return baseclass.extend({
	class: 'auth',
	class_i18n: _('Authentication'),

	type: 'login',
	type_i18n: _('Login'),

	name: 'WebAuthn Passkey',
	id: '25e715cf23e44e35bc6763e804d85b85',
	title: _('WebAuthn Passkey Authentication'),
	description: _('Sign in to LuCI with a passkey instead of a password, or require one after the password. ' +
	               'Register passkeys under System > Administration > Passkeys.'),

	addFormOptions: function(s) {
		var o;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Flag, 'primary', _('Passwordless login'),
			_('Offer "Sign in with passkey" on the login page. The password login stays available.'));
		o.depends('enabled', '1');
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Flag, 'second_factor', _('Require after password'),
			_('Ask for a passkey after a correct password.'));
		o.depends('enabled', '1');
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Value, 'priority', _('Priority'),
			_('Execution order for this plugin. Lower values run earlier.'));
		o.depends('enabled', '1');
		o.datatype = 'integer';
		o.placeholder = '20';
		o.rmempty = true;

		o = s.option(form.Value, 'origin', _('Origin (optional override)'),
			_('Optional origin override for WebAuthn verification, e.g. https://router.example.com'));
		o.depends('enabled', '1');
		o.placeholder = 'https://openwrt.local';
		o.rmempty = true;
	},

	configSummary: function(section) {
		if (section.enabled != '1')
			return null;

		var modes = [];
		if (section.primary != '0')
			modes.push(_('passwordless'));
		if (section.second_factor == '1')
			modes.push(_('second factor'));

		return (section.origin
			? _('enabled (%s), custom origin: %s').format(modes.join(', '), section.origin)
			: _('enabled (%s)').format(modes.join(', ')));
	}
});
