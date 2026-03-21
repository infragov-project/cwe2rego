package glitch

import data.glitch_lib

algo_name_tokens := {
	"encryption",
	"encrypt",
	"decrypt",
	"crypto",
	"cipher",
	"hash",
	"digest",
	"hmac",
	"mac",
	"signature",
	"jwt",
	"auth_method",
	"authentication",
	"auth",
	"password",
	"passwd",
	"passphrase",
	"password_hash",
	"password-hash",
	"signature_algorithm",
	"algorithm",
	"key_spec",
	"key-spec",
	"kms_key_spec"
}

cipher_suite_name_tokens := {
	"cipher_suites",
	"cipher_suite",
	"ciphersuites",
	"cipherlist",
	"cipher_list",
	"allowed_ciphers",
	"ssl_ciphers",
	"tls_ciphers",
	"ssl_cipher",
	"tls_cipher",
	"ciphers"
}

protocol_name_tokens := {
	"ssl_protocol",
	"tls_version",
	"min_tls_version",
	"max_tls_version",
	"min_tls",
	"max_tls",
	"ssl_version",
	"tls_versions",
	"protocols",
	"protocol",
	"ssl_policy",
	"tls_policy",
	"ssl",
	"tls"
}

key_size_tokens := {
	"key_size",
	"key_length",
	"keylen",
	"key_len",
	"keysize",
	"keylength",
	"rsa_bits",
	"rsa_size",
	"rsa_key",
	"rsa_length",
	"dh_group",
	"dh_bits",
	"dh_size",
	"dsa_bits",
	"dsa_size",
	"ec_curve",
	"elliptic_curve",
	"ec_bits",
	"ec_size"
}

toggle_name_tokens := {
	"allow_weak_ciphers",
	"allow_weak",
	"weak_cipher",
	"weak_ciphers",
	"legacy_crypto",
	"legacy_cipher",
	"legacy_ssl",
	"legacy_tls",
	"compatibility_mode",
	"compatibility_crypto",
	"compatibility_cipher",
	"compatibility_ssl",
	"compatibility_tls"
}

crypto_function_tokens := {
	"hash",
	"digest",
	"hmac",
	"encrypt",
	"decrypt",
	"cipher",
	"jwt",
	"sign",
	"signature",
	"openssl",
	"md5",
	"sha1",
	"sha-1"
}

weak_algo_patterns := {
	"(?i)(^|[^a-z0-9])md2([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])md4([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])md5([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])sha-?1([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])sha-?0([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])des([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])3des([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])rc2([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])rc4([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])blowfish([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])idea([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])tea([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])xor([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])rot([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])custom([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])ecb([^a-z0-9]|$)"
}

weak_cipher_patterns := {
	"(?i)(^|[^a-z0-9])null([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])export([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])anon([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])anull([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])enull([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])low([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])rc4([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])3des([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])des([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])md5([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])sha1([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])sha([^0-9]|$)",
	"(?i)(^|[^a-z0-9])cbc([^a-z0-9]|$)"
}

weak_protocol_patterns := {
	"(?i)(^|[^a-z0-9])sslv?2([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])sslv?3([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])tlsv?1\\.0([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])tlsv?1\\.1([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])tls1\\.0([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])tls1\\.1([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])ssh1([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])ikev1([^a-z0-9]|$)",
	"(?i)(^|[^a-z0-9])legacy([^a-z0-9]|$)"
}

path_has_unit_blocks(path) {
	path[_] == "unit_blocks"
}

name_has_token(name, tokens) {
	t := tokens[_]
	glitch_lib.contains(name, t)
}

is_algorithm_name(name) {
	name_has_token(name, algo_name_tokens)
}

is_cipher_suite_name(name) {
	name_has_token(name, cipher_suite_name_tokens)
}

is_protocol_name(name) {
	name_has_token(name, protocol_name_tokens)
}

is_key_size_name(name) {
	name_has_token(name, key_size_tokens)
}

is_toggle_name(name) {
	name_has_token(name, toggle_name_tokens)
}

is_crypto_function_name(name) {
	name_has_token(name, crypto_function_tokens)
}

is_keyvalue(node) {
	node.ir_type == "Attribute"
}

is_keyvalue(node) {
	node.ir_type == "Variable"
}

is_string_like(n) {
	n.ir_type == "String"
}

is_string_like(n) {
	n.ir_type == "VariableReference"
}

match_any(str, patterns) {
	p := patterns[_]
	regex.match(p, str)
}

value_has_pattern(val, patterns) {
	some n
	walk(val, [_, n])
	is_string_like(n)
	match_any(n.value, patterns)
}

weak_algo_in_value(val) {
	value_has_pattern(val, weak_algo_patterns)
}

weak_cipher_in_value(val) {
	value_has_pattern(val, weak_cipher_patterns)
}

weak_protocol_in_value(val) {
	value_has_pattern(val, weak_protocol_patterns)
}

weak_protocol_in_value(val) {
	some n
	walk(val, [_, n])
	v := numeric_value(n)
	v <= 1.1
}

weak_algo_str(s) {
	match_any(s, weak_algo_patterns)
}

numeric_value(node) = n {
	node.ir_type == "Integer"
	n := node.value
}

numeric_value(node) = n {
	node.ir_type == "Float"
	n := node.value
}

numeric_value(node) = n {
	node.ir_type == "String"
	regex.match("^[0-9]+(\\.[0-9]+)?$", node.value)
	n := to_number(node.value)
}

numeric_value(node) = n {
	node.ir_type == "VariableReference"
	regex.match("^[0-9]+(\\.[0-9]+)?$", node.value)
	n := to_number(node.value)
}

key_size_is_weak(name, size) {
	regex.match("(?i).*(rsa|dsa|dh).*", name)
	size < 2048
}

key_size_is_weak(name, size) {
	regex.match("(?i).*(ec|curve).*", name)
	size < 224
}

key_size_is_weak(name, size) {
	not regex.match("(?i).*(rsa|dsa|dh|ec|curve).*", name)
	size < 128
}

weak_key_size_value(name, value) {
	some n
	walk(value, [_, n])
	size := numeric_value(n)
	key_size_is_weak(name, size)
}

is_true_value(n) {
	n.ir_type == "Boolean"
	n.value == true
}

is_true_value(n) {
	n.ir_type == "String"
	regex.match("(?i)^(true|yes|on|1)$", n.value)
}

is_true_value(n) {
	n.ir_type == "Integer"
	n.value == 1
}

is_true_value(n) {
	n.ir_type == "VariableReference"
	regex.match("(?i)^(true|yes|on|1)$", n.value)
}

weak_toggle_value(value) {
	some n
	walk(value, [_, n])
	is_true_value(n)
}

weak_crypto_keyvalue(name, value) {
	is_algorithm_name(name)
	weak_algo_in_value(value)
}

weak_crypto_keyvalue(name, value) {
	is_algorithm_name(name)
	weak_algo_str(name)
}

weak_crypto_keyvalue(name, value) {
	is_cipher_suite_name(name)
	weak_cipher_in_value(value)
}

weak_crypto_keyvalue(name, value) {
	is_protocol_name(name)
	weak_protocol_in_value(value)
}

weak_crypto_keyvalue(name, value) {
	is_key_size_name(name)
	weak_key_size_value(name, value)
}

weak_crypto_keyvalue(name, value) {
	is_toggle_name(name)
	weak_toggle_value(value)
}

weak_any_in_args(args) {
	arg := args[_]
	weak_algo_in_value(arg)
}

weak_any_in_args(args) {
	arg := args[_]
	weak_cipher_in_value(arg)
}

weak_any_in_args(args) {
	arg := args[_]
	weak_protocol_in_value(arg)
}

weak_crypto_function(fc) {
	is_crypto_function_name(fc.name)
	weak_any_in_args(fc.args)
}

weak_crypto_function(fc) {
	weak_algo_str(fc.name)
}

weak_crypto_method(mc) {
	is_crypto_function_name(mc.method)
	weak_any_in_args(mc.args)
}

weak_crypto_method(mc) {
	weak_algo_str(mc.method)
}

weak_crypto_method(mc) {
	weak_algo_in_value(mc.receiver)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, kv])
	not path_has_unit_blocks(path)
	is_keyvalue(kv)
	weak_crypto_keyvalue(kv.name, kv.value)

	result := {
		"type": "sec_weak_crypt",
		"element": kv,
		"path": parent.path,
		"description": "Use of broken or risky cryptographic algorithm, protocol, or weak key size. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, h])
	not path_has_unit_blocks(path)
	h.ir_type == "Hash"
	entry := h.value[_]
	key := entry.key
	val := entry.value
	is_string_like(key)
	weak_crypto_keyvalue(key.value, val)

	result := {
		"type": "sec_weak_crypt",
		"element": val,
		"path": parent.path,
		"description": "Use of broken or risky cryptographic algorithm, protocol, or weak key size. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, fc])
	not path_has_unit_blocks(path)
	fc.ir_type == "FunctionCall"
	weak_crypto_function(fc)

	result := {
		"type": "sec_weak_crypt",
		"element": fc,
		"path": parent.path,
		"description": "Use of broken or risky cryptographic algorithm, protocol, or weak key size. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, mc])
	not path_has_unit_blocks(path)
	mc.ir_type == "MethodCall"
	weak_crypto_method(mc)

	result := {
		"type": "sec_weak_crypt",
		"element": mc,
		"path": parent.path,
		"description": "Use of broken or risky cryptographic algorithm, protocol, or weak key size. (CWE-327)"
	}
}