package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

sensitive_keys := {
	"password", "passwd", "pass", "pwd",
	"secret", "secret_key", "shared_secret", "master_secret",
	"api_key", "apikey", "api_token", "access_token", "auth_token",
	"private_key", "private_key_pem", "signing_key", "encryption_key",
	"community_string", "client_secret", "consumer_secret", "webhook_secret",
	"ssh_key", "ssh_private_key", "rsa_key",
	"admin_password", "root_password", "db_password", "database_password",
	"login_password", "hmac_key", "jwt_secret", "token_secret",
	"oauth_secret", "master_key",
}

is_sensitive(fname) {
	lower(fname) == sensitive_keys[_]
}

is_sensitive(fname) {
	contains(lower(fname), "password")
}

is_sensitive(fname) {
	contains(lower(fname), "secret")
}

is_hardcoded(val) {
	is_string(val)
	val != ""
	not contains(val, "{{")
	not contains(val, "${")
	not startswith(lower(val), "vault://")
}

# Detect hardcoded credentials in named credential fields anywhere in the document
CxPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, val])
	count(path) > 0
	fname := path[minus(count(path), 1)]
	is_string(fname)
	is_sensitive(fname)
	is_hardcoded(val)
	sk := commonLib.concat_path(path)
	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use a vault or secret manager reference instead of a hardcoded value", [fname]),
		"keyActualValue": sprintf("'%s' contains a hardcoded credential", [fname]),
	}
}

# Detect hardcoded key in authentication blocks that declare key-based method
CxPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, auth_obj])
	is_object(auth_obj)
	method := auth_obj.method
	is_string(method)
	lower(method) == "key"
	key_val := auth_obj["key"]
	is_hardcoded(key_val)
	parent_path_str := commonLib.concat_path(path)
	sk := sprintf("%s.key={{%s}}", [parent_path_str, key_val])
	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'key' in a key-based authentication block should reference a vault or secret manager, not be hardcoded",
		"keyActualValue": sprintf("'key' contains a hardcoded authentication credential '%s'", [key_val]),
	}
}