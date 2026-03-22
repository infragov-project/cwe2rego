package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

weak_hash_filter(value) {
	is_string(value)
	weak_hashes := {"sha1", "md5", "md4", "md2"}
	hash_name := weak_hashes[_]
	contains(lower(value), sprintf("hash('%s')", [hash_name]))
}

weak_hash_filter(value) {
	is_string(value)
	weak_hashes := {"sha1", "md5", "md4", "md2"}
	hash_name := weak_hashes[_]
	contains(lower(value), sprintf("hash(\"%s\")", [hash_name]))
}

weak_encrypt_algo(algo) {
	weak := {"md5_crypt", "des_crypt", "sha1_crypt", "bsdi_crypt"}
	lower(algo) == weak[_]
}

weak_cipher_value(value) {
	is_string(value)
	weak := {"des", "3des", "triple_des", "tripledes", "rc2", "rc4", "rc5", "idea", "blowfish"}
	lower(value) == weak[_]
}

weak_hash_value(value) {
	is_string(value)
	weak := {"md5", "md4", "md2", "sha1", "sha-1", "sha_1", "hmac-md5", "hmac-sha1"}
	lower(value) == weak[_]
}

weak_tls_value(value) {
	is_string(value)
	weak := {"sslv2", "sslv3", "ssl2", "ssl3", "tlsv1", "tlsv1.0", "tlsv1.1", "tls_1_0", "tls_1_1"}
	lower(value) == weak[_]
}

weak_tls_value(value) {
	is_string(value)
	patterns := {"tls-1-0", "tls-1-1"}
	contains(lower(value), patterns[_])
}

is_enc_field(field) {
	fields := {"algorithm", "cipher", "cipher_suite", "encryption_algorithm", "server_side_encryption", "sse_algorithm", "encryption_type", "encryption_method"}
	fields[field]
}

is_hash_field(field) {
	fields := {"hash_algorithm", "signing_algorithm", "digest_algorithm", "key_algorithm", "signature_algorithm", "checksum_algorithm"}
	fields[field]
}

is_tls_field(field) {
	fields := {"minimum_tls_version", "min_tls_version", "tls_version", "ssl_policy", "security_policy", "ssl_protocol", "protocol_version", "tls_policy"}
	fields[field]
}

# Detect weak Jinja2 hash filter in any task string value (any depth)
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	walk(task, [path, value])
	is_string(value)
	count(path) > 0
	is_string(path[0])
	path[0] != "name"
	weak_hash_filter(value)

	path_parts := [p | p := path[_]; is_string(p)]
	path_key := concat(".", path_parts)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, path_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Jinja2 hash filter should use a strong algorithm such as sha256 or sha512",
		"keyActualValue": sprintf("Weak hash algorithm detected in Jinja2 template filter: '%s'", [value]),
	}
}

# Detect weak encrypt algorithm in vars_prompt (playbook level)
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	prompt := playbook.vars_prompt[_]
	commonLib.valid_key(prompt, "encrypt")
	weak_encrypt_algo(prompt.encrypt)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": prompt.name,
		"searchKey": sprintf("vars_prompt.name={{%s}}.encrypt", [prompt.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "vars_prompt 'encrypt' should use a strong algorithm (e.g., sha256_crypt, sha512_crypt)",
		"keyActualValue": sprintf("vars_prompt 'encrypt' is set to weak algorithm '%s'", [prompt.encrypt]),
	}
}

# Detect weak cipher in encryption-related module fields (depth 2)
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	walk(task, [path, value])
	is_string(value)
	count(path) == 2
	is_string(path[1])
	is_enc_field(path[1])
	weak_cipher_value(value)

	result := {
		"documentId": id,
		"resourceType": path[0],
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, path[0], path[1]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use a strong encryption algorithm (e.g., AES-256)", [path[1]]),
		"keyActualValue": sprintf("'%s' is set to weak algorithm '%s'", [path[1], value]),
	}
}

# Detect weak hash algorithm in hash-related module fields (depth 2)
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	walk(task, [path, value])
	is_string(value)
	count(path) == 2
	is_string(path[1])
	is_hash_field(path[1])
	weak_hash_value(value)

	result := {
		"documentId": id,
		"resourceType": path[0],
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, path[0], path[1]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use a strong hash algorithm (e.g., SHA-256 or higher)", [path[1]]),
		"keyActualValue": sprintf("'%s' is set to weak hash algorithm '%s'", [path[1], value]),
	}
}

# Detect deprecated TLS/SSL protocol in TLS-related module fields (depth 2)
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	walk(task, [path, value])
	is_string(value)
	count(path) == 2
	is_string(path[1])
	is_tls_field(path[1])
	weak_tls_value(value)

	result := {
		"documentId": id,
		"resourceType": path[0],
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, path[0], path[1]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use TLS 1.2 or higher", [path[1]]),
		"keyActualValue": sprintf("'%s' is set to deprecated protocol '%s'", [path[1], value]),
	}
}