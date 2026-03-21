package glitch

import data.glitch_lib

privilege_key_pattern := "(?i).*(role|policy|permission|permissions|actions|resources|effect|access|acl|privilege|authorization).*"
user_key_pattern := "(?i).*(runasuser|runasgroup|uid|gid|user|group|owner|become_user).*"
priv_flag_key_pattern := "(?i).*(privileged|allowprivilegeescalation|become|sudo|elevate).*"
capability_key_pattern := "(?i).*(capabilities|capability).*"
host_key_pattern := "(?i).*(hostnetwork|hostpid|hostipc|host|namespace).*"
credential_key_pattern := "(?i).*(username|login|account|credential).*"
device_key_pattern := "(?i).*device.*"
inherit_key_pattern := "(?i).*(inherit|setuid|setgid).*"
exec_key_pattern := "(?i).*(command|cmd|shell|exec|run|script|action).*"

privileged_value_pattern := "(?i).*(\\*|\\ball\\b|\\bany\\b|\\bfull\\b|\\bmanage\\b|\\bwrite\\b|\\breadwrite\\b|admin|administrator|owner|root|superuser|fullaccess).*"
root_value_pattern := "(?i).*(\\b0\\b|root|system|admin|superuser).*"
admin_value_pattern := "(?i).*(admin|root|superuser|master|dbowner).*"
capability_value_pattern := "(?i).*(\\ball\\b|sys_admin).*"
exec_priv_pattern := "(?i).*(sudo|su\\s+|root@|\\broot\\b|\\badmin\\b|superuser).*"
true_string_pattern := "(?i)^(true|1|yes|on)$"

key_matches(name, pattern) {
	regex.match(pattern, name)
}

value_has_pattern(val, pattern) {
	glitch_lib.traverse(val, pattern)
}

value_contains_int(val, n) {
	walk(val, [_, v])
	v.ir_type == "Integer"
	v.value == n
}

value_is_true(val) {
	glitch_lib.traverse(val, true)
} else {
	value_has_pattern(val, true_string_pattern)
} else {
	value_contains_int(val, 1)
}

value_is_root(val) {
	value_has_pattern(val, root_value_pattern)
} else {
	value_contains_int(val, 0)
}

suspicious_kv(kv) {
	key_matches(kv.name, privilege_key_pattern)
	value_has_pattern(kv.value, privileged_value_pattern)
}
suspicious_kv(kv) {
	key_matches(kv.name, user_key_pattern)
	value_is_root(kv.value)
}
suspicious_kv(kv) {
	key_matches(kv.name, priv_flag_key_pattern)
	value_is_true(kv.value)
}
suspicious_kv(kv) {
	key_matches(kv.name, capability_key_pattern)
	value_has_pattern(kv.value, capability_value_pattern)
}
suspicious_kv(kv) {
	key_matches(kv.name, host_key_pattern)
	value_is_true(kv.value)
}
suspicious_kv(kv) {
	key_matches(kv.name, device_key_pattern)
	value_has_pattern(kv.value, privileged_value_pattern)
}
suspicious_kv(kv) {
	key_matches(kv.name, credential_key_pattern)
	value_has_pattern(kv.value, admin_value_pattern)
}
suspicious_kv(kv) {
	key_matches(kv.name, inherit_key_pattern)
	value_is_true(kv.value)
}
suspicious_kv(kv) {
	key_matches(kv.name, exec_key_pattern)
	value_has_pattern(kv.value, exec_priv_pattern)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	attrs := glitch_lib.all_attributes(parent)
	kv := attrs[_]
	suspicious_kv(kv)
	result := {
		"type": "sec_def_admin",
		"element": kv,
		"path": parent.path,
		"description": "Execution with unnecessary privileges - Avoid assigning admin/root/wildcard privileges or enabling privileged execution. (CWE-250)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	vars := glitch_lib.all_variables(parent)
	kv := vars[_]
	suspicious_kv(kv)
	result := {
		"type": "sec_def_admin",
		"element": kv,
		"path": parent.path,
		"description": "Execution with unnecessary privileges - Avoid assigning admin/root/wildcard privileges or enabling privileged execution. (CWE-250)"
	}
}