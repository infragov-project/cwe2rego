package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

has_weak_jinja2_hash(val) {
	is_string(val)
	weak_algos := {"md2", "md4", "md5", "sha1", "sha-1", "sha_1", "ripemd"}
	algo := weak_algos[_]
	contains(lower(val), sprintf("hash('%s')", [algo]))
}

has_weak_jinja2_hash(val) {
	is_string(val)
	weak_algos := {"md2", "md4", "md5", "sha1", "sha-1", "sha_1", "ripemd"}
	algo := weak_algos[_]
	contains(lower(val), sprintf("hash(\"%s\")", [algo]))
}

is_weak_crypt(val) {
	weak := {"md5_crypt", "des_crypt", "sha1_crypt", "md5", "sha1", "sha-1", "des", "3des", "rc4", "rc2", "md4", "md2"}
	lower(val) == weak[_]
}

is_weak_protocol(val) {
	weak := {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1", "tls1_0", "tls1_1", "tls10", "tls11"}
	lower(val) == weak[_]
}

is_weak_cipher(val) {
	weak := {"des", "3des", "triple_des", "rc2", "rc4", "arc4", "arcfour", "blowfish", "tea", "null", "none"}
	lower(val) == weak[_]
}

is_weak_hash(val) {
	weak := {"md2", "md4", "md5", "sha1", "sha-1", "sha_1", "ripemd"}
	lower(val) == weak[_]
}

is_weak_dh(val) {
	weak := {"group1", "group2", "dh1", "dh2", "modp768", "modp1024"}
	lower(val) == weak[_]
}

is_task_meta(key) {
	meta := {
		"name", "become", "become_user", "when", "register", "notify",
		"tags", "with_items", "with_fileglob", "loop", "vars", "environment",
		"no_log", "run_once", "delegate_to", "ignore_errors", "changed_when",
		"failed_when", "any_errors_fatal", "check_mode", "diff",
		"block", "rescue", "always", "listen", "args", "with_dict",
		"with_sequence", "until", "retries", "delay",
	}
	meta[key]
}

# Detect weak Jinja2 hash() filter in any string value within a task
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	walk(task, [path, val])
	is_string(val)
	has_weak_jinja2_hash(val)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, commonLib.concat_path(path)]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Jinja2 hash() filter should use a strong algorithm such as sha256 or sha512",
		"keyActualValue": sprintf("Value uses a weak hash algorithm in Jinja2 hash() filter: '%s'", [val]),
	}
}

# Detect weak encryption algorithm in vars_prompt
CxPolicy[result] {
	doc := input.document[i]
	playbook := doc.playbooks[_]
	prompt := playbook.vars_prompt[_]
	is_object(prompt)
	commonLib.valid_key(prompt, "encrypt")
	is_weak_crypt(prompt.encrypt)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": prompt.name,
		"searchKey": sprintf("vars_prompt.name={{%s}}.encrypt", [prompt.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "vars_prompt.encrypt should use sha256_crypt or sha512_crypt",
		"keyActualValue": sprintf("vars_prompt.encrypt is set to '%s', a weak or broken cryptographic algorithm", [prompt.encrypt]),
	}
}

# Detect weak TLS/SSL protocol version
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	proto_field := {"ssl_policy", "tls_policy", "security_policy", "protocol_version", "minimum_tls_version", "ssl_protocol", "minimum_protocol_version"}[_]
	commonLib.valid_key(module, proto_field)
	is_weak_protocol(module[proto_field])

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, proto_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use TLSv1.2 or higher", [proto_field]),
		"keyActualValue": sprintf("'%s' is set to '%s', a weak or deprecated protocol", [proto_field, module[proto_field]]),
	}
}

# Detect weak symmetric cipher
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	enc_field := {"encryption_algorithm", "algorithm", "cipher", "cipher_suite", "sse_algorithm", "encryption_type", "server_side_encryption"}[_]
	commonLib.valid_key(module, enc_field)
	is_weak_cipher(module[enc_field])

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, enc_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should specify a strong cipher such as AES-256-GCM", [enc_field]),
		"keyActualValue": sprintf("'%s' is set to '%s', a weak or broken cipher", [enc_field, module[enc_field]]),
	}
}

# Detect weak hash algorithm in crypto-specific module fields
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	hash_field := {"hash_algorithm", "digest_algorithm", "signature_algorithm", "signing_algorithm", "integrity_algorithm", "authentication_algorithm", "prf_algorithm", "hmac_algorithm"}[_]
	commonLib.valid_key(module, hash_field)
	is_weak_hash(module[hash_field])

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, hash_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use SHA-256 or a stronger hash algorithm", [hash_field]),
		"keyActualValue": sprintf("'%s' is set to '%s', a weak hash algorithm", [hash_field, module[hash_field]]),
	}
}

# Detect ECB block cipher mode
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	mode_field := {"mode", "cipher_mode", "block_mode"}[_]
	commonLib.valid_key(module, mode_field)
	lower(module[mode_field]) == "ecb"

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, mode_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not use ECB; prefer GCM or another authenticated mode", [mode_field]),
		"keyActualValue": sprintf("'%s' is set to 'ECB', which exposes plaintext patterns", [mode_field]),
	}
}

# Detect insufficient RSA/DSA key size
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	key_field := {"key_size", "key_length", "rsa_bits", "bit_size", "key_bits", "modulus_size"}[_]
	commonLib.valid_key(module, key_field)
	to_number(module[key_field]) < 2048

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, key_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be at least 2048 bits for RSA/DSA", [key_field]),
		"keyActualValue": sprintf("'%s' is set to %v, below the minimum 2048 bits", [key_field, module[key_field]]),
	}
}

# Detect weak Diffie-Hellman group
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	dh_field := {"dh_group", "pfs_group"}[_]
	commonLib.valid_key(module, dh_field)
	is_weak_dh(module[dh_field])

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, dh_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use group14 (2048-bit) or stronger", [dh_field]),
		"keyActualValue": sprintf("'%s' is set to '%s', a weak DH group", [dh_field, module[dh_field]]),
	}
}

# Detect encryption explicitly disabled
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := task[mod_key]
	is_object(module)
	is_string(mod_key)
	not is_task_meta(mod_key)
	enc_field := {"encrypted", "encryption_enabled", "enable_encryption", "storage_encrypted", "at_rest_encryption", "in_transit_encryption"}[_]
	commonLib.valid_key(module, enc_field)
	ansLib.isAnsibleFalse(module[enc_field])

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, mod_key, enc_field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be set to true to enforce encryption", [enc_field]),
		"keyActualValue": sprintf("'%s' is set to false, leaving data unencrypted", [enc_field]),
	}
}