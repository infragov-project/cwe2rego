package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_credential_field(key) {
	names := {
		"password", "passwd", "passphrase", "pwd", "pass",
		"secret", "secret_key", "secret_value", "client_secret", "app_secret", "shared_secret",
		"api_key", "access_key", "private_key", "encryption_key", "signing_key", "auth_key",
		"auth_token", "access_token", "api_token", "bearer_token",
		"login_password", "bind_pw", "db_password", "database_password",
		"connection_password", "master_password", "admin_password", "root_password", "user_password",
	}
	lower(key) == names[_]
}

is_credential_field(key) {
	endswith(lower(key), "_password")
}

is_credential_field(key) {
	endswith(lower(key), "_passwd")
}

is_credential_field(key) {
	endswith(lower(key), "_secret")
}

is_credential_field(key) {
	endswith(lower(key), "_token")
}

is_hardcoded(val) {
	is_string(val)
	val != ""
	not contains(val, "{{")
	not startswith(val, "$(")
	not startswith(val, "${")
	not startswith(val, "$ANSIBLE_VAULT")
}

to_path_str(path) = s {
	parts := [p | e := path[_]; is_string(e); p := e]
	s := concat(".", parts)
}

task_meta_keys := {
	"name", "become", "become_user", "when", "register",
	"notify", "tags", "loop", "with_items", "environment",
	"vars", "no_log", "ignore_errors", "failed_when",
	"changed_when", "delegate_to", "run_once", "listen",
	"block", "rescue", "always",
}

kics_meta_keys := {"id", "file", "playbooks"}

auth_parent_terms := {"auth", "cred", "passw", "login", "secret", "token"}

is_auth_context_parent(path) {
	count(path) >= 2
	parent := path[count(path) - 2]
	is_string(parent)
	contains(lower(parent), auth_parent_terms[_])
}

CxPolicy[result] {
	document := input.document[i]
	playbook := document.playbooks[_]
	is_object(playbook.vars)
	walk(playbook.vars, [path, value])
	count(path) >= 1
	field := path[count(path) - 1]
	is_string(field)
	is_credential_field(field)
	is_hardcoded(value)
	sk := sprintf("name={{%s}}.vars.%s", [playbook.name, to_path_str(path)])
	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": playbook.name,
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a vault secret or variable, not a hardcoded value", [field]),
		"keyActualValue": sprintf("'%s' is set to a hardcoded credential value", [field]),
	}
}

CxPolicy[result] {
	document := input.document[i]
	playbook := document.playbooks[_]
	is_object(playbook.vars)
	walk(playbook.vars, [path, value])
	count(path) >= 2
	field := path[count(path) - 1]
	is_string(field)
	lower(field) == "key"
	is_auth_context_parent(path)
	is_hardcoded(value)
	sk := sprintf("name={{%s}}.vars.%s={{%s}}", [playbook.name, to_path_str(path), value])
	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": playbook.name,
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' in auth context should not be hardcoded; use Ansible Vault", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded authentication key", [field]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	some module_name
	module := task[module_name]
	not task_meta_keys[module_name]
	is_object(module)
	walk(module, [path, value])
	count(path) >= 1
	field := path[count(path) - 1]
	is_string(field)
	is_credential_field(field)
	is_hardcoded(value)
	sk := sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_name, to_path_str(path)])
	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a vault secret or variable, not a hardcoded value", [field]),
		"keyActualValue": sprintf("'%s' is set to a hardcoded credential value", [field]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	is_object(task.environment)
	some env_key
	env_val := task.environment[env_key]
	is_credential_field(env_key)
	is_hardcoded(env_val)
	sk := sprintf("name={{%s}}.environment.%s", [task.name, env_key])
	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Environment variable '%s' should not contain a hardcoded credential", [env_key]),
		"keyActualValue": sprintf("Environment variable '%s' is set to a hardcoded value", [env_key]),
	}
}

CxPolicy[result] {
	document := input.document[i]
	not commonLib.valid_key(document, "playbooks")
	some top_key
	not kics_meta_keys[top_key]
	top_section := document[top_key]
	is_object(top_section)
	walk(top_section, [path, value])
	count(path) >= 1
	field := path[count(path) - 1]
	is_string(field)
	is_credential_field(field)
	is_hardcoded(value)
	sk := sprintf("%s.%s", [top_key, to_path_str(path)])
	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a vault secret or variable, not a hardcoded value", [field]),
		"keyActualValue": sprintf("'%s' is set to a hardcoded credential value", [field]),
	}
}

CxPolicy[result] {
	document := input.document[i]
	not commonLib.valid_key(document, "playbooks")
	some top_key
	not kics_meta_keys[top_key]
	top_section := document[top_key]
	is_object(top_section)
	walk(top_section, [path, value])
	count(path) >= 2
	field := path[count(path) - 1]
	is_string(field)
	lower(field) == "key"
	is_auth_context_parent(path)
	is_hardcoded(value)
	sk := sprintf("%s.%s={{%s}}", [top_key, to_path_str(path), value])
	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sk,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' in auth context should not be hardcoded; use Ansible Vault", [field]),
		"keyActualValue": sprintf("'%s' contains a hardcoded authentication key", [field]),
	}
}