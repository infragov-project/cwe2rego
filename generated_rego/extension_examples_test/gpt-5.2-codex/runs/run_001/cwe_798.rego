package glitch

import data.glitch_lib

desc := "Use of hard-coded credentials - Credentials should not be embedded in IaC definitions. (CWE-798)"

non_secret_values := {
	"",
	"true",
	"false",
	"yes",
	"no",
	"on",
	"off",
	"null",
	"nil",
	"none",
	"n/a",
	"na",
	"undef",
	"undefined"
}

normalize(name) = n {
	l := lower(name)
	s := regex.replace("[^a-z0-9]+", l, "_")
	s1 := regex.replace("^_+", s, "")
	n := regex.replace("_+$", s1, "")
}

is_non_secret_value(s) {
	lower(s) == non_secret_values[_]
}

is_interpolated(s) {
	regex.match(".*(\\$\\{|\\{\\{).*", s)
}

is_literal_value(v) {
	v.ir_type == "String"
	not is_non_secret_value(v.value)
	not is_interpolated(v.value)
}
is_literal_value(v) { v.ir_type == "Integer" }
is_literal_value(v) { v.ir_type == "Float" }
is_literal_value(v) { v.ir_type == "Complex" }

secret_keywords := {
	"password",
	"passwd",
	"pwd",
	"passphrase",
	"secret",
	"shared_secret",
	"sharedsecret",
	"community",
	"enable_password",
	"enablepassword",
	"token",
	"auth_token",
	"authtoken",
	"api_key",
	"apikey",
	"access_key",
	"accesskey",
	"secret_key",
	"secretkey",
	"client_secret",
	"clientsecret",
	"bearer",
	"private_key",
	"privatekey",
	"ssh_key",
	"sshkey",
	"key_data",
	"keydata",
	"certificate",
	"keystore",
	"ca_key",
	"cakey",
	"credential",
	"credentials"
}

contains_kw(n, kw) {
	regex.match(sprintf(".*%s.*", [kw]), n)
}

is_secret_name(n) {
	kw := secret_keywords[_]
	contains_kw(n, kw)
}
is_secret_name(n) {
	regex.match("(^|_)key($|_)", n)
}

is_user_name(n) { n == "user" }
is_user_name(n) { endswith(n, "_user") }
is_user_name(n) { endswith(n, "username") }
is_user_name(n) { endswith(n, "user_name") }
is_user_name(n) { endswith(n, "login") }
is_user_name(n) { endswith(n, "_login") }
is_user_name(n) { endswith(n, "admin") }
is_user_name(n) { endswith(n, "_admin") }
is_user_name(n) { endswith(n, "root") }
is_user_name(n) { endswith(n, "_root") }
is_user_name(n) { endswith(n, "service_account") }
is_user_name(n) { endswith(n, "serviceaccount") }

is_credential_name(name) {
	n := normalize(name)
	is_secret_name(n)
}
is_credential_name(name) {
	n := normalize(name)
	is_user_name(n)
}

kv(node, name, value, element) {
	node.ir_type == "Variable"
	name = node.name
	value = node.value
	element = node
}
kv(node, name, value, element) {
	node.ir_type == "Attribute"
	name = node.name
	value = node.value
	element = node
}
kv(node, name, value, element) {
	key := object.get(node, "key", null)
	key != null
	key.ir_type == "String"
	name = key.value
	value = node.value
	element = value
}

inline_secret(s) {
	regex.match("(?i).*BEGIN [A-Z ]*PRIVATE KEY.*", s)
}
inline_secret(s) {
	regex.match("(?i).*://[^/\\s]+:[^@\\s]+@.*", s)
}
inline_secret(s) {
	regex.match("(?i).*(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret)\\s*=", s)
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [_, node])
	kv(node, name, value, element)
	is_credential_name(name)
	is_literal_value(value)
	result := {
		"type": "sec_hard_secr",
		"element": element,
		"path": parent.path,
		"description": desc
	}
}

Glitch_Analysis[result] {
	parent := glitch_lib._gather_parent_unit_blocks[_]
	parent.path != ""
	walk(parent, [_, n])
	n.ir_type == "String"
	not is_interpolated(n.value)
	inline_secret(n.value)
	result := {
		"type": "sec_hard_secr",
		"element": n,
		"path": parent.path,
		"description": desc
	}
}