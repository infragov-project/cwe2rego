package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

sensitive_key(key) {
	contains(lower(key), "password")
}

sensitive_key(key) {
	contains(lower(key), "passwd")
}

sensitive_key(key) {
	contains(lower(key), "secret")
}

sensitive_key(key) {
	exact_keys := {
		"api_key", "apikey", "api_password",
		"auth_token", "access_token",
		"private_key", "certificate_password", "keystore_password",
		"truststore_password", "registry_password", "docker_password",
		"ssh_password", "ftp_password", "smtp_password", "mail_password",
		"service_account_password", "bind_password", "ldap_password",
		"sha512_password",
	}
	lower(key) == exact_keys[_]
}

is_plaintext(value) {
	is_string(value)
	value != ""
	not contains(value, "{{")
	not contains(value, "lookup(")
	not startswith(upper(value), "$ANSIBLE_VAULT")
}

auth_context_parent(parent) {
	auth_indicators := {"auth", "credential", "cred", "login", "token"}
	contains(lower(parent), auth_indicators[_])
}

# Document-level: sensitive field name (group_vars/host_vars without playbooks)
CxPolicy[result] {
	doc := input.document[i]
	not doc.playbooks
	[path, value] := walk(doc)
	count(path) >= 1
	key := path[minus(count(path), 1)]
	is_string(key)
	key != "id"
	key != "file"
	sensitive_key(key)
	is_plaintext(value)
	searchPath := commonLib.build_search_line(path, [])
	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("%s={{%s}}", [commonLib.concat_path(searchPath), value]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a variable or vault instead of a hardcoded credential", [key]),
		"keyActualValue": sprintf("'%s' contains a hardcoded value", [key]),
	}
}

# Document-level: field named 'key' directly under an auth-context parent
CxPolicy[result] {
	doc := input.document[i]
	not doc.playbooks
	[path, value] := walk(doc)
	count(path) >= 2
	fieldName := path[minus(count(path), 1)]
	is_string(fieldName)
	lower(fieldName) == "key"
	parent := path[minus(count(path), 2)]
	is_string(parent)
	auth_context_parent(parent)
	is_plaintext(value)
	searchPath := commonLib.build_search_line(path, [])
	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("%s={{%s}}", [commonLib.concat_path(searchPath), value]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'key' in authentication context should reference a variable or vault",
		"keyActualValue": "'key' contains a hardcoded value in an authentication context",
	}
}

# Task-level: sensitive field name
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 1
	key := path[minus(count(path), 1)]
	is_string(key)
	sensitive_key(key)
	is_plaintext(value)
	taskName := object.get(task, "name", "unknown")
	searchPath := commonLib.build_search_line(path, [])
	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.%s={{%s}}", [taskName, commonLib.concat_path(searchPath), value]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a variable or vault instead of a hardcoded credential", [key]),
		"keyActualValue": sprintf("'%s' contains a hardcoded value", [key]),
	}
}

# Task-level: field named 'key' directly under an auth-context parent
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 2
	fieldName := path[minus(count(path), 1)]
	is_string(fieldName)
	lower(fieldName) == "key"
	parent := path[minus(count(path), 2)]
	is_string(parent)
	auth_context_parent(parent)
	is_plaintext(value)
	taskName := object.get(task, "name", "unknown")
	searchPath := commonLib.build_search_line(path, [])
	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.%s={{%s}}", [taskName, commonLib.concat_path(searchPath), value]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'key' in authentication context should reference a variable or vault",
		"keyActualValue": "'key' contains a hardcoded value in an authentication context",
	}
}

# Playbook-level: sensitive field name
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	[path, value] := walk(playbook)
	count(path) >= 1
	key := path[minus(count(path), 1)]
	is_string(key)
	sensitive_key(key)
	is_plaintext(value)
	searchPath := commonLib.build_search_line(path, [])
	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("%s={{%s}}", [commonLib.concat_path(searchPath), value]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a variable or vault instead of a hardcoded credential", [key]),
		"keyActualValue": sprintf("'%s' contains a hardcoded value", [key]),
	}
}

# Playbook-level: field named 'key' directly under an auth-context parent
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	[path, value] := walk(playbook)
	count(path) >= 2
	fieldName := path[minus(count(path), 1)]
	is_string(fieldName)
	lower(fieldName) == "key"
	parent := path[minus(count(path), 2)]
	is_string(parent)
	auth_context_parent(parent)
	is_plaintext(value)
	searchPath := commonLib.build_search_line(path, [])
	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("%s={{%s}}", [commonLib.concat_path(searchPath), value]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'key' in authentication context should reference a variable or vault",
		"keyActualValue": "'key' contains a hardcoded value in an authentication context",
	}
}