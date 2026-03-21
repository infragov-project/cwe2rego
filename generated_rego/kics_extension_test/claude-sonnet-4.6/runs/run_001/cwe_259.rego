package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

password_field_names := {
	"password", "passwd", "pass", "pwd",
	"secret", "secret_key", "secret_string", "secret_value",
	"admin_password", "root_password", "master_password", "db_password",
	"database_password", "user_password", "service_password", "auth_password",
	"login_password",
}

task_meta_keys := {
	"name", "become", "become_user", "when", "register", "tags",
	"notify", "with_items", "loop", "vars", "environment", "delegate_to",
	"ignore_errors", "changed_when", "failed_when", "no_log", "run_once",
	"any_errors_fatal", "check_mode", "diff", "timeout", "block", "rescue",
	"always", "listen", "until", "retries", "delay",
}

is_password_field(name) {
	password_field_names[lower(name)]
}

is_hardcoded_password(val) {
	is_string(val)
	val != ""
	not regex.match(`\{\{.*\}\}`, val)
}

# Playbook-level vars: detect hardcoded passwords including in nested structures
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	commonLib.valid_key(playbook, "vars")
	vars := playbook.vars

	walk(vars, [path, val])
	count(path) > 0

	field_name := path[minus(count(path), 1)]
	is_string(field_name)
	is_password_field(field_name)
	is_hardcoded_password(val)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars.%s", [field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a secrets manager instead of containing a hardcoded value", [field_name]),
		"keyActualValue": sprintf("'%s' contains a hardcoded password", [field_name]),
	}
}

# Task-level module parameters: detect hardcoded passwords including nested structures
CxPolicy[result] {
	task := ansLib.tasks[id][t]

	some module_key
	module_params := task[module_key]
	not task_meta_keys[module_key]
	is_object(module_params)

	walk(module_params, [path, val])
	count(path) > 0

	field_name := path[minus(count(path), 1)]
	is_string(field_name)
	is_password_field(field_name)
	is_hardcoded_password(val)

	result := {
		"documentId": id,
		"resourceType": module_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_key, field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should reference a secrets manager instead of containing a hardcoded value", [field_name]),
		"keyActualValue": sprintf("'%s' contains a hardcoded password", [field_name]),
	}
}

# Task-level environment blocks: detect hardcoded passwords in sensitive env vars
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	commonLib.valid_key(task, "environment")
	env := task.environment
	is_object(env)

	some env_key
	env_val := env[env_key]

	sensitive_env_patterns := {"password", "passwd", "pwd", "secret", "credential", "auth_token", "api_key"}
	contains(lower(env_key), sensitive_env_patterns[_])
	is_hardcoded_password(env_val)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.environment.%s", [task.name, env_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Environment variable '%s' should not contain a hardcoded password", [env_key]),
		"keyActualValue": sprintf("Environment variable '%s' contains a hardcoded literal value", [env_key]),
	}
}