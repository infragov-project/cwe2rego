package glitch

import data.glitch_lib

weak_algo_fields := [
	"encryption_algorithm",
	"cipher",
	"cipher_algorithm",
	"encryption_type",
	"encryption_method",
	"encryption_mode",
	"crypto_algorithm",
	"cipher_mode"
]

weak_algo_patterns := [
	"(?i).*\\bdes\\b.*",
	"(?i).*3des.*",
	"(?i).*\\brc2\\b.*",
	"(?i).*\\brc4\\b.*",
	"(?i).*blowfish.*",
	"(?i).*\\bidea\\b.*",
	"(?i).*\\btea\\b.*",
	"(?i).*\\bxor\\b.*",
	"(?i).*\\becb\\b.*",
	"(?i).*legacy.*",
	"(?i).*custom.*",
	"(?i).*simple.*"
]

key_size_fields := [
	"key_size",
	"key_length",
	"key_bits",
	"keysize",
	"keylength",
	"key_spec",
	"rsa_bits",
	"dh_bits",
	"minimum_key_size",
	"minimum_key_length",
	"minimum_key_bits",
	"min_key_size",
	"min_key_length",
	"min_key_bits"
]

asym_key_tokens := [
	"rsa",
	"dh",
	"dsa",
	"diffie",
	"asymmetric"
]

ec_curve_fields := [
	"ec_curve",
	"elliptic_curve",
	"ecc_curve",
	"named_curve",
	"curve"
]

weak_ec_curve_patterns := [
	"(?i).*secp160.*",
	"(?i).*secp192.*",
	"(?i).*secp224.*",
	"(?i).*prime160.*",
	"(?i).*prime192.*",
	"(?i).*prime224.*",
	"(?i).*p-160.*",
	"(?i).*p-192.*",
	"(?i).*p-224.*",
	"(?i).*secp128.*",
	"(?i).*prime128.*"
]

tls_version_fields := [
	"tls_version",
	"min_tls_version",
	"ssl_protocols",
	"enabled_protocols",
	"security_protocol",
	"protocols",
	"ssl_protocol",
	"tls_protocol",
	"min_protocol_version",
	"protocol_version"
]

weak_tls_patterns := [
	"(?i).*sslv2.*",
	"(?i).*sslv3.*",
	"(?i).*tls1\\.0.*",
	"(?i).*tls1\\.1.*",
	"(?i).*tlsv1\\.0.*",
	"(?i).*tlsv1\\.1.*"
]

cipher_fields := [
	"cipher_suites",
	"cipher_suite",
	"ciphers",
	"ssl_ciphers",
	"tls_ciphers",
	"allowed_ciphers",
	"ssl_cipher",
	"tls_cipher",
	"security_policy",
	"ssl_policy"
]

weak_cipher_patterns := [
	"(?i).*rc4.*",
	"(?i).*rc2.*",
	"(?i).*3des.*",
	"(?i).*\\bdes\\b.*",
	"(?i).*export.*",
	"(?i).*\\bnull\\b.*",
	"(?i).*anull.*",
	"(?i).*enull.*",
	"(?i).*md5.*",
	"(?i).*\\blow\\b.*"
]

policy_fields := [
	"encryption_strength",
	"security_level",
	"security_policy",
	"ssl_policy",
	"encryption_policy",
	"crypto_policy",
	"encryption_level"
]

low_policy_patterns := [
	"(?i).*compat.*",
	"(?i).*legacy.*",
	"(?i).*\\blow\\b.*",
	"(?i).*\\bweak\\b.*",
	"(?i).*\\bstandard\\b.*"
]

field_match(name, fields) {
	some i
	f := fields[i]
	regex.match(sprintf("(?i).*%s.*", [f]), name)
}

value_match(expr, patterns) {
	some i
	p := patterns[i]
	glitch_lib.traverse(expr, p)
}

numbers_in_expr(expr)[num] {
	walk(expr, [_, v])
	v.ir_type == "Integer"
	num = v.value
}

numbers_in_expr(expr)[num] {
	walk(expr, [_, v])
	v.ir_type == "Float"
	num = v.value
}

numbers_in_expr(expr)[num] {
	walk(expr, [_, v])
	v.ir_type == "String"
	regex.match("^[0-9]+$", v.value)
	num = to_number(v.value)
}

weak_algorithm_kv(kv) {
	field_match(kv.name, weak_algo_fields)
	value_match(kv.value, weak_algo_patterns)
}

weak_tls_kv(kv) {
	field_match(kv.name, tls_version_fields)
	value_match(kv.value, weak_tls_patterns)
}

weak_cipher_kv(kv) {
	field_match(kv.name, cipher_fields)
	value_match(kv.value, weak_cipher_patterns)
}

weak_policy_kv(kv) {
	field_match(kv.name, policy_fields)
	value_match(kv.value, low_policy_patterns)
}

weak_key_size_kv(kv) {
	field_match(kv.name, key_size_fields)
	field_match(kv.name, asym_key_tokens)
	num := numbers_in_expr(kv.value)[_]
	num > 0
	num < 2048
}

weak_key_size_kv(kv) {
	field_match(kv.name, key_size_fields)
	not field_match(kv.name, asym_key_tokens)
	num := numbers_in_expr(kv.value)[_]
	num > 0
	num < 128
}

weak_ec_curve_kv(kv) {
	field_match(kv.name, ec_curve_fields)
	value_match(kv.value, weak_ec_curve_patterns)
}

weak_ec_curve_kv(kv) {
	field_match(kv.name, ec_curve_fields)
	num := numbers_in_expr(kv.value)[_]
	num > 0
	num < 256
}

weak_crypto_kv(kv) { weak_algorithm_kv(kv) }
weak_crypto_kv(kv) { weak_tls_kv(kv) }
weak_crypto_kv(kv) { weak_cipher_kv(kv) }
weak_crypto_kv(kv) { weak_policy_kv(kv) }
weak_crypto_kv(kv) { weak_key_size_kv(kv) }
weak_crypto_kv(kv) { weak_ec_curve_kv(kv) }

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	attrs := glitch_lib.all_attributes(parent)
	attr := attrs[_]
	weak_crypto_kv(attr)
	result := {
		"type": "sec_weak_crypt",
		"element": attr,
		"path": parent.path,
		"description": "Inadequate encryption strength - Avoid weak or legacy algorithms, protocols, cipher suites or insufficient key sizes. (CWE-326)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	vars := glitch_lib.all_variables(parent)
	variable := vars[_]
	weak_crypto_kv(variable)
	result := {
		"type": "sec_weak_crypt",
		"element": variable,
		"path": parent.path,
		"description": "Inadequate encryption strength - Avoid weak or legacy algorithms, protocols, cipher suites or insufficient key sizes. (CWE-326)"
	}
}