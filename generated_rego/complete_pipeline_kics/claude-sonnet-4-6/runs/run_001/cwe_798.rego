package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

credential_field_names := {
	"password", "passwd", "pass",
	"secret", "secret_key", "secret_value",
	"api_key", "api_secret", "api_token",
	"access_key", "access_secret",
	"token", "auth_token", "bearer_token",
	"private_key", "encryption_key", "crypto_key",
	"credential", "credentials",
	"database_password", "db_password", "db_pass",
	"master_password", "admin_password",
	"smtp_password", "mail_password",
	"vpn_psk", "pre_shared_key", "shared_secret",
	"bind_password", "ldap_password",
	"rsa_key", "dsa_key", "ecdsa_key",
	"signing_key", "hmac_key",
	"key",
	"sha512_password",
}

credential_field_suffixes := {
	"_password", "_passwd", "_secret", "_token",
	"_credential", "_credentials", "_pass", "_key",
}

is_credential_field(field) {
	credential_field_names[lower(field)]
}

is_credential_field(field) {
	suffix := credential_field_suffixes[_]
	endswith(lower(field), suffix)
}

is_hardcoded_value(value) {
	is_string(value)
	value != ""
	not regex.match(`\{\{[^}]+\}\}`, value)
	not startswith(value, "$(")
	not contains(value, "lookup(")
	not contains(value, "| vault")
	not contains(value, "|vault")
}

# Rule 1: Task-level credential fields
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 1
	field := path[minus(count(path), 1)]
	is_string(field)
	is_credential_field(field)
	is_hardcoded_value(value)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": object.get(task, "name", "unknown"),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [object.get(task, "name", "unknown"), field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a secrets manager instead of a hardcoded value", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded credential value", [field]),
	}
}

# Rule 2: PEM material in task fields
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	is_string(value)
	contains(value, "-----BEGIN")
	count(path) >= 1
	field := path[minus(count(path), 1)]
	is_string(field)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": object.get(task, "name", "unknown"),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [object.get(task, "name", "unknown"), field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not contain embedded PEM/cryptographic key material", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded PEM key or certificate", [field]),
	}
}

# Rule 3: URLs with embedded credentials in tasks
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	is_string(value)
	regex.match(`://[^:{\s]+:[^@{\s]+@`, value)
	count(path) >= 1
	field := path[minus(count(path), 1)]
	is_string(field)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": object.get(task, "name", "unknown"),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [object.get(task, "name", "unknown"), field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not embed credentials directly in the URL", [field]),
		"keyActualValue": sprintf("'%s' contains a URL with hardcoded credentials", [field]),
	}
}

# Rule 4: Flat document structures (group_vars, host_vars, etc.)
CxPolicy[result] {
	document := input.document[i]
	[path, obj] := walk(document)
	is_object(obj)
	field := object.keys(obj)[_]
	is_credential_field(field)
	value := obj[field]
	is_hardcoded_value(value)
	path[0] != "id"
	path[0] != "file"
	path[0] != "playbooks"

	parentPath := commonLib.concat_path(path)
	searchKey := sprintf("%s.%s={{%s}}", [parentPath, field, value])

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a secrets manager instead of a hardcoded value", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded credential value", [field]),
	}
}

# Rule 4b: Top-level credential fields in flat documents
CxPolicy[result] {
	document := input.document[i]
	field := object.keys(document)[_]
	field != "id"
	field != "file"
	field != "playbooks"
	is_credential_field(field)
	value := document[field]
	is_hardcoded_value(value)

	searchKey := sprintf("%s={{%s}}", [field, value])

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a secrets manager instead of a hardcoded value", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded credential value", [field]),
	}
}

# Rule 5: PEM material in flat documents
CxPolicy[result] {
	document := input.document[i]
	[path, obj] := walk(document)
	is_object(obj)
	field := object.keys(obj)[_]
	value := obj[field]
	is_string(value)
	contains(value, "-----BEGIN")
	path[0] != "id"
	path[0] != "file"
	path[0] != "playbooks"

	parentPath := commonLib.concat_path(path)
	searchKey := sprintf("%s.%s", [parentPath, field])

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not contain embedded PEM/cryptographic key material", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded PEM key or certificate", [field]),
	}
}

# Rule 6: URLs with embedded credentials in flat documents
CxPolicy[result] {
	document := input.document[i]
	[path, obj] := walk(document)
	is_object(obj)
	field := object.keys(obj)[_]
	value := obj[field]
	is_string(value)
	regex.match(`://[^:{\s]+:[^@{\s]+@`, value)
	path[0] != "id"
	path[0] != "file"
	path[0] != "playbooks"

	parentPath := commonLib.concat_path(path)
	searchKey := sprintf("%s.%s", [parentPath, field])

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not embed credentials directly in the URL", [field]),
		"keyActualValue": sprintf("'%s' contains a URL with hardcoded credentials", [field]),
	}
}

# Rule 7: Playbook-level vars
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	commonLib.valid_key(playbook, "vars")
	[path, obj] := walk(playbook.vars)
	is_object(obj)
	field := object.keys(obj)[_]
	is_credential_field(field)
	value := obj[field]
	is_hardcoded_value(value)

	parentPath := commonLib.concat_path(path)
	searchKey := sprintf("vars.%s.%s={{%s}}", [parentPath, field, value])

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": object.get(playbook, "name", "unknown"),
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' in playbook vars should reference a secrets manager", [field]),
		"keyActualValue": sprintf("'%s' in playbook vars contains a hardcoded credential", [field]),
	}
}