package glitch

import data.glitch_lib

weak_algorithms := {
	"des", "3des", "tripledes", "desede", "blowfish", "rc2", "rc4", "skipjack",
	"tea", "xtea", "md4", "md5", "sha0", "sha1", "ripedmd", "whirlpool",
	"ssl", "sslv2", "sslv3", "tls1.0", "tls1.1", "tlsv1.0", "tlsv1.1", "ssh1",
	"ecb", "md5_crypt", "sha1_crypt", "sha0_crypt", "sha1_hash", "md5_hash",
	"sha_1", "sha-1", "md_5", "md-5", "ssh-rsa", "rsa-sha", "dsa"
}

weak_crypto_fields := {"encrypt", "encryption", "cipher", "hash", "digest", "hmac", "signature", "sign", "algorithm", "method", "mode", "protocol", "version", "tls", "ssl", "kdf", "pbkdf", "scrypt", "bcrypt", "crypt", "checksum"}

is_weak_algorithm(val) {
	lower_val := lower(val)
	alg := weak_algorithms[_]
	lower_val == alg
}

is_weak_algorithm(val) {
	lower_val := lower(val)
	alg := weak_algorithms[_]
	contains(lower_val, alg)
}

is_crypto_field(name) {
	lower_name := lower(name)
	field := weak_crypto_fields[_]
	contains(lower_name, field)
}

has_weak_value(node) {
	walk(node, [_, n])
	n.ir_type == "String"
	is_weak_algorithm(n.value)
}

has_weak_value(node) {
	walk(node, [_, n])
	n.ir_type == "VariableReference"
	is_weak_algorithm(n.value)
}

is_weak_function_call(node) {
	node.ir_type == "FunctionCall"
	name := lower(node.name)
	func := weak_algorithms[_]
	contains(name, func)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	node.ir_type == "FunctionCall"
	is_weak_function_call(node)
	result := {
		"type": "sec_weak_crypt",
		"element": node,
		"path": parent.path,
		"description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	node.ir_type == "KeyValue"
	is_crypto_field(node.name)
	has_weak_value(node.value)
	result := {
		"type": "sec_weak_crypt",
		"element": node,
		"path": parent.path,
		"description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	node.ir_type == "Attribute"
	is_crypto_field(node.name)
	has_weak_value(node.value)
	result := {
		"type": "sec_weak_crypt",
		"element": node,
		"path": parent.path,
		"description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	node.ir_type == "Variable"
	is_crypto_field(node.name)
	has_weak_value(node.value)
	result := {
		"type": "sec_weak_crypt",
		"element": node,
		"path": parent.path,
		"description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [path, node])
	node.ir_type == "MethodCall"
	is_weak_function_call(node)
	result := {
		"type": "sec_weak_crypt",
		"element": node,
		"path": parent.path,
		"description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
	}
}