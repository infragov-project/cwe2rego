package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

sensitive_keys := {
	"password", "passwd", "pass", "pwd", "passphrase",
	"user_password", "admin_password", "root_password", "default_password", "master_password",
	"secret", "secret_key", "client_secret", "shared_secret", "jwt_secret", "app_secret",
	"token", "access_token", "auth_token", "api_token", "bearer_token", "refresh_token", "session_token",
	"api_key", "apikey", "api_secret", "access_key", "secret_access_key",
	"private_key", "encryption_key", "signing_key", "hmac_key", "aes_key", "rsa_key", "key_data",
	"ssh_key", "ssh_private_key", "ssh_authorized_keys", "identity_key",
	"db_password", "database_password", "db_secret",
	"community_string", "snmp_community",
}

task_meta_keys := {
	"name", "become", "become_user", "when", "register", "tags", "notify",
	"loop", "loop_control", "with_items", "vars", "no_log", "ignore_errors",
	"changed_when", "failed_when", "check_mode", "environment", "delegate_to",
	"run_once", "block", "rescue", "always", "listen", "args", "any_errors_fatal",
	"with_dict", "with_list", "with_sequence", "with_nested", "with_indexed_items",
	"collections", "connection", "debugger", "diff", "timeout", "module_defaults",
}

is_hardcoded_credential(value) {
	is_string(value)
	count(value) > 0
	not contains(value, "{{")
}

is_sensitive_key(key) {
	lower(key) == sensitive_keys[_]
}

# Task-level: detect hardcoded credentials in module parameters
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	task_name := object.get(task, "name", "n/a")

	[path, value] := walk(task)
	count(path) >= 2

	module_name := path[0]
	is_string(module_name)
	not task_meta_keys[module_name]

	cred_key := path[count(path) - 1]
	is_string(cred_key)
	is_sensitive_key(cred_key)
	is_hardcoded_credential(value)

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task_name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task_name, module_name, cred_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a variable or secret manager, not contain a hardcoded value", [cred_key]),
		"keyActualValue": sprintf("'%s' contains a hardcoded credential value", [cred_key]),
	}
}

# Task-level: detect hardcoded credentials defined in task vars
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	task_name := object.get(task, "name", "n/a")

	vars := task.vars
	is_object(vars)

	value := vars[key]
	is_string(key)
	is_sensitive_key(key)
	is_hardcoded_credential(value)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task_name,
		"searchKey": sprintf("name={{%s}}.vars.%s", [task_name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'vars.%s' should not contain a hardcoded credential; use a variable or vault reference", [key]),
		"keyActualValue": sprintf("'vars.%s' contains a hardcoded credential value", [key]),
	}
}

# Playbook-level: detect hardcoded credentials defined in playbook vars
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]

	vars := playbook.vars
	is_object(vars)

	value := vars[key]
	is_string(key)
	is_sensitive_key(key)
	is_hardcoded_credential(value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars.%s", [key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'vars.%s' should not contain a hardcoded credential; use a variable or vault reference", [key]),
		"keyActualValue": sprintf("'vars.%s' contains a hardcoded credential value", [key]),
	}
}