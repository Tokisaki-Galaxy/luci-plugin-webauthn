'use strict';
'require baseclass';
'require form';
'require uci';

// Settings shared by System > Administration > Passkeys and the plugin's
// entry on System > Plugins. Both edit the plugin's luci_plugins section.

var PLUGIN_UUID = '25e715cf23e44e35bc6763e804d85b85';

function get(section_id, option) {
	return uci.get('luci_plugins', section_id, option);
}

function set(section_id, option, value) {
	uci.set('luci_plugins', section_id, option, value);
}

return baseclass.extend({
	uuid: PLUGIN_UUID,

	// 'off', 'passwordless' or 'second_factor'. A section with both
	// primary and second_factor on shows as 'second_factor', which still
	// always needs the passkey.
	modeOf: function(section_id) {
		if (get(section_id, 'enabled') != '1')
			return 'off';
		if (get(section_id, 'second_factor') == '1')
			return 'second_factor';
		if (get(section_id, 'primary') == '1')
			return 'passwordless';
		return 'off';
	},

	// The "Use passkeys" choice. With withOff it also switches the plugin
	// on and off; without it, an Enabled flag next to it does that (the
	// Plugins page has one per plugin).
	addModeOption: function(s, withOff) {
		var self = this;
		var o = s.option(form.ListValue, '_mode', _('Use passkeys'),
			_('<em>Instead of the password</em> adds "Sign in with passkey" to the login page; the password keeps working. ' +
			  '<em>As a second factor</em> asks for a passkey once the password is correct, as soon as one is registered.'));

		if (withOff)
			o.value('off', _('Off'));
		o.value('passwordless', _('Instead of the password'));
		o.value('second_factor', _('As a second factor'));
		o.rmempty = false;

		o.cfgvalue = function(section_id) {
			var mode = self.modeOf(section_id);

			if (!withOff && mode == 'off')
				return get(section_id, 'second_factor') == '1' ? 'second_factor' : 'passwordless';

			return mode;
		};

		o.write = function(section_id, mode) {
			if (withOff)
				set(section_id, 'enabled', mode != 'off' ? '1' : '0');
			set(section_id, 'primary', mode == 'passwordless' ? '1' : '0');
			set(section_id, 'second_factor', mode == 'second_factor' ? '1' : '0');
		};

		o.remove = function() {};

		return o;
	},

	addAdvancedOptions: function(s) {
		var o = s.option(form.Value, 'origin', _('Origin'),
			_('The address passkeys are registered for, such as https://router.example.com. ' +
			  'Leave empty to use the address the page was opened with.'));
		o.placeholder = 'https://openwrt.lan';
		o.rmempty = true;

		o = s.option(form.Value, 'priority', _('Priority'),
			_('Order among login plugins. Lower values run earlier.'));
		o.datatype = 'integer';
		o.placeholder = '20';
		o.rmempty = true;
	},

	summary: function(section) {
		var mode = (section.enabled == '1')
			? (section.second_factor == '1' ? 'second_factor' : (section.primary == '1' ? 'passwordless' : 'off'))
			: 'off';
		var text = {
			off: _('off'),
			passwordless: _('instead of the password'),
			second_factor: _('as a second factor')
		}[mode];

		return section.origin ? _('%s, origin %s').format(text, section.origin) : text;
	}
});
