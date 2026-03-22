package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

# Detect broken hash algorithms used in Jinja2 hash filter (single-quoted)
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	commonLib.valid_key(task, "name")
	[path, value] := walk(task)
	is_string(value)
	count(path) > 0
	last_key := path[count(path) - 1]
	is_string(last_key)

	broken_hashes := {"sha1", "sha-1", "md5", "md4", "md2", "ripemd", "ripemd160"}
	bh := broken_hashes[_]
	contains(lower(value), sprintf("hash('%s')", [bh]))

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, last_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Hash filter should use a strong algorithm such as sha256 or sha512",
		"keyActualValue": sprintf("Hash filter uses broken cryptographic algorithm '%s' (CWE-327)", [bh]),
	}
}

# Detect broken hash algorithms used in Jinja2 hash filter (double-quoted)
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	commonLib.valid_key(task, "name")
	[path, value] := walk(task)
	is_string(value)
	count(path) > 0
	last_key := path[count(path) - 1]
	is_string(last_key)

	broken_hashes := {"sha1", "sha-1", "md5", "md4", "md2", "ripemd", "ripemd160"}
	bh := broken_hashes[_]
	contains(lower(value), sprintf("hash(\"%s\")", [bh]))

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, last_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Hash filter should use a strong algorithm such as sha256 or sha512",
		"keyActualValue": sprintf("Hash filter uses broken cryptographic algorithm '%s' (CWE-327)", [bh]),
	}
}

# Detect broken encrypt algorithms in vars_prompt at playbook level
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	prompt := playbook.vars_prompt[_]
	commonLib.valid_key(prompt, "encrypt")

	broken_encrypts := {"md5_crypt", "des_crypt", "sha1_crypt", "bsdi_crypt"}
	broken_encrypts[_] == lower(prompt.encrypt)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars_prompt.name={{%s}}.encrypt", [prompt.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'encrypt' should use a strong algorithm such as 'sha512_crypt'",
		"keyActualValue": sprintf("'encrypt' is set to '%s', which is a broken or risky cryptographic algorithm (CWE-327)", [prompt.encrypt]),
	}
}

# Detect broken algorithms referenced in explicit cryptographic attribute keys in tasks
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	commonLib.valid_key(task, "name")
	[path, value] := walk(task)
	count(path) >= 1
	last_key := path[count(path) - 1]
	is_string(last_key)
	is_string(value)

	crypto_attr_keys := {
		"encryption_algorithm", "cipher", "cipher_suite", "algorithm", "encryption_type",
		"encryption_mode", "hash_algorithm", "hashing_algorithm", "digest_algorithm",
		"signing_algorithm", "integrity_algorithm", "checksum_algorithm",
		"fingerprint_algorithm", "certificate_algorithm", "key_signing_algorithm",
		"signature_algorithm", "cert_algorithm", "ssl_policy", "tls_policy",
		"minimum_tls_version", "min_tls_version", "tls_version", "ssl_version",
	}
	crypto_attr_keys[_] == lower(last_key)

	broken_algos := {
		"des", "3des", "triple_des", "rc2", "rc4", "arc4", "rc5", "blowfish", "tea", "ecb",
		"md5", "md4", "md2", "sha1", "sha-1", "ripemd",
		"sslv2", "sslv3", "tls1.0", "tls1.1", "tlsv1", "tlsv1.1",
		"md5withrsa", "md5withrsaencryption", "sha1withrsa", "sha1withrsaencryption", "dsawithsha1",
	}
	broken_algos[_] == lower(value)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, last_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use a strong and modern cryptographic algorithm", [last_key]),
		"keyActualValue": sprintf("'%s' is set to '%s', which is a broken or risky cryptographic algorithm (CWE-327)", [last_key, value]),
	}
}

# Detect weak key sizes in tasks
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	commonLib.valid_key(task, "name")
	[path, value] := walk(task)
	count(path) >= 1
	last_key := path[count(path) - 1]
	is_string(last_key)
	is_number(value)

	key_size_keys := {"key_size", "key_length", "rsa_bits", "key_bits", "bit_length"}
	key_size_keys[_] == lower(last_key)

	value < 2048

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, last_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be at least 2048 bits", [last_key]),
		"keyActualValue": sprintf("'%s' is set to %v, which is below the recommended minimum key size (CWE-327)", [last_key, value]),
	}
}