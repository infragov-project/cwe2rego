package glitch

import data.glitch_lib

plaintext_protocols := {"http", "ftp", "telnet", "smtp", "pop3", "imap", "ldap", "snmp", "ws"}
secure_protocols := {"https", "wss", "ftps", "ldaps", "imaps", "pop3s", "smtps", "ssl", "tls"}
plaintext_ports := {80, 21, 23, 25, 110, 143, 389, 161, 445}

endpoint_keys := {"protocol", "scheme", "listener", "endpoint", "url", "uri", "address", "addr", "host", "hostname", "server", "proxy", "listen", "bind", "connection", "connection_string", "conn", "dsn", "broker", "service", "api", "webhook", "remote", "target"}
tls_disable_keys := {"tls_enabled", "ssl_enabled", "require_ssl", "require_tls", "enforce_ssl", "https_only", "secure_transfer", "encryption_in_transit", "transport_encryption", "require_https", "enforce_https", "ssl_required", "tls_required", "enable_ssl", "enable_tls", "use_ssl", "use_tls", "verify_ssl", "verify_tls", "ssl_verify", "tls_verify", "validate_certs", "verify_cert", "verify_certificate", "check_hostname", "verify_host", "verify_peer", "sslmode", "ssl_mode", "tls_mode", "start_tls", "starttls", "https_required", "secure_transport", "force_https", "force_ssl", "ssl_enforced", "tls_enforced", "ssl_only", "tls_only"}
allow_insecure_keys := {"allow_insecure", "allow_plaintext", "insecure", "skip_tls_verify", "skip_ssl_verify", "tls_skip_verify", "ssl_skip_verify", "disable_ssl", "disable_tls", "accept_unencrypted", "allow_http", "allow_unencrypted", "skipverify", "skip_verify", "insecure_skip_verify", "unsafe_skip_verify", "no_verify", "no_check_certificate", "skipcert", "skip_cert", "skip_cert_verify", "skip_cert_validation", "skip_certificate_validation", "allow_insecure_connections", "plaintext"}
cert_keys := {"certificate", "cert", "cert_file", "cert_key", "key_file", "tls_config", "ssl_policy", "tls_version", "min_tls_version", "cipher", "ca_cert", "client_cert", "root_ca", "ca_file", "tls_cert", "ssl_cert", "ssl_certificate", "ssl_cert_file", "ssl_key_file"}

name_contains(name, keys) {
	key := keys[_]
	regex.match(sprintf("(?i).*%s.*", [key]), name)
}

key_name(k) = name {
	k.ir_type == "String"
	name := k.value
}
key_name(k) = name {
	k.ir_type == "VariableReference"
	name := k.value
}

is_container(val) {
	val.ir_type == "Hash"
}
is_container(val) {
	val.ir_type == "Array"
}
is_container(val) {
	val.ir_type == "BlockExpr"
}

value_is_url_like(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i)^(http|ftp|telnet|smtp|pop3|imap|ldap|snmp|ws)://", n.value)
}

value_has_plaintext_protocol(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	proto := plaintext_protocols[_]
	lower(n.value) == proto
}
value_has_plaintext_protocol(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i).*(http|ftp|telnet|smtp|pop3|imap|ldap|snmp|ws)://.*", n.value)
}

value_has_secure_protocol(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	proto := secure_protocols[_]
	lower(n.value) == proto
}
value_has_secure_protocol(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i).*(https|wss|ftps|ldaps|imaps|pop3s|smtps|ssl|tls)://.*", n.value)
}

value_has_insecure_conn_params(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i).*(ssl\\s*=\\s*false|encrypt\\s*=\\s*false|use\\s*ssl\\s*=\\s*0|usessl\\s*=\\s*0|tls\\s*=\\s*off|sslmode\\s*=\\s*disable|ssl_mode\\s*=\\s*disable|verify\\s*=\\s*false|trustservercertificate\\s*=\\s*true).*", n.value)
}

value_is_disabled(val) {
	walk(val, [_, n])
	n.ir_type == "Boolean"
	n.value == false
}
value_is_disabled(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i)^(false|no|off|disabled|disable|none|0)$", n.value)
}
value_is_disabled(val) {
	walk(val, [_, n])
	n.ir_type == "Integer"
	n.value == 0
}

value_is_true(val) {
	walk(val, [_, n])
	n.ir_type == "Boolean"
	n.value == true
}
value_is_true(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i)^(true|yes|on|1)$", n.value)
}
value_is_true(val) {
	walk(val, [_, n])
	n.ir_type == "Integer"
	n.value == 1
}

value_is_enabled(val) {
	value_is_true(val)
}
value_is_enabled(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	regex.match("(?i)^(true|yes|on|1|enabled|enable|require|required|enforce|enforced|strict|mandatory)$", n.value)
}

value_is_empty_or_null(val) {
	val.ir_type == "Null"
}
value_is_empty_or_null(val) {
	val.ir_type == "Undef"
}
value_is_empty_or_null(val) {
	val.ir_type == "String"
	val.value == ""
}
value_is_empty_or_null(val) {
	val.ir_type == "Array"
	count(val.value) == 0
}
value_is_empty_or_null(val) {
	val.ir_type == "Hash"
	count(val.value) == 0
}

value_has_plaintext_port(val) {
	walk(val, [_, n])
	n.ir_type == "Integer"
	p := plaintext_ports[_]
	n.value == p
}
value_has_plaintext_port(val) {
	walk(val, [_, n])
	n.ir_type == "String"
	p := plaintext_ports[_]
	regex.match(sprintf("(?i).*\\b%d\\b.*", [p]), n.value)
}

name_has_port_related(name) {
	regex.match("(?i).*port.*", name)
}
name_has_port_related(name) {
	name_contains(name, {"ingress", "egress"})
}

tls_context(h) {
	p := h.value[_]
	n := key_name(p.key)
	name_contains(n, {"protocol", "scheme"})
	value_has_secure_protocol(p.value)
}
tls_context(h) {
	p := h.value[_]
	n := key_name(p.key)
	name_contains(n, {"url", "uri", "endpoint", "listener", "host", "server", "address", "addr", "bind", "listen"})
	value_has_secure_protocol(p.value)
}
tls_context(h) {
	p := h.value[_]
	n := key_name(p.key)
	name_contains(n, {"tls", "ssl", "https", "start_tls", "starttls"})
	value_is_enabled(p.value)
}

insecure_kv_value(name, val) {
	value_is_url_like(val)
}
insecure_kv_value(name, val) {
	name_contains(name, endpoint_keys)
	value_has_plaintext_protocol(val)
}
insecure_kv_value(name, val) {
	value_has_insecure_conn_params(val)
}
insecure_kv_value(name, val) {
	name_contains(name, tls_disable_keys)
	value_is_disabled(val)
}
insecure_kv_value(name, val) {
	name_contains(name, allow_insecure_keys)
	value_is_true(val)
}
insecure_kv_value(name, val) {
	name_has_port_related(name)
	value_has_plaintext_port(val)
}

insecure_pair(pair, h) {
	name := key_name(pair.key)
	name_contains(name, endpoint_keys)
	not is_container(pair.value)
	value_has_plaintext_protocol(pair.value)
}
insecure_pair(pair, h) {
	name := key_name(pair.key)
	name_contains(name, endpoint_keys)
	not is_container(pair.value)
	value_has_insecure_conn_params(pair.value)
}
insecure_pair(pair, h) {
	name := key_name(pair.key)
	name_contains(name, tls_disable_keys)
	not is_container(pair.value)
	value_is_disabled(pair.value)
}
insecure_pair(pair, h) {
	name := key_name(pair.key)
	name_contains(name, allow_insecure_keys)
	not is_container(pair.value)
	value_is_true(pair.value)
}
insecure_pair(pair, h) {
	name := key_name(pair.key)
	name_has_port_related(name)
	not is_container(pair.value)
	value_has_plaintext_port(pair.value)
}
insecure_pair(pair, h) {
	name := key_name(pair.key)
	name_contains(name, cert_keys)
	value_is_empty_or_null(pair.value)
	tls_context(h)
}
insecure_pair(pair, h) {
	not is_container(pair.value)
	value_has_insecure_conn_params(pair.value)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	attr := glitch_lib.all_attributes(parent)[_]
	not is_container(attr.value)
	insecure_kv_value(attr.name, attr.value)

	result := {
		"type": "sec_https",
		"element": attr,
		"path": parent.path,
		"description": "Cleartext transmission of sensitive information - Ensure encrypted transport (TLS/SSL) is enforced. (CWE-319)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	v := glitch_lib.all_variables(parent)[_]
	not is_container(v.value)
	insecure_kv_value(v.name, v.value)

	result := {
		"type": "sec_https",
		"element": v,
		"path": parent.path,
		"description": "Cleartext transmission of sensitive information - Ensure encrypted transport (TLS/SSL) is enforced. (CWE-319)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [_, h])
	h.ir_type == "Hash"
	pair := h.value[_]
	insecure_pair(pair, h)

	result := {
		"type": "sec_https",
		"element": pair.value,
		"path": parent.path,
		"description": "Cleartext transmission of sensitive information - Ensure encrypted transport (TLS/SSL) is enforced. (CWE-319)"
	}
}