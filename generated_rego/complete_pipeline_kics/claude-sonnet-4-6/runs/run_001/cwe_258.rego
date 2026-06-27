package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

non_doc_keys := {"file", "id", "playbooks"}

non_module_keys := {
	"name", "become", "become_user", "register", "when", "notify",
	"tags", "loop", "with_items", "with_dict", "with_list", "vars",
	"ignore_errors", "failed_when", "changed_when", "no_log",
	"delegate_to", "run_once", "environment", "block", "rescue",
	"always", "listen", "any_errors_fatal", "check_mode",
}

is_password_field(key) {
	exact_keys := {
		"password", "passwd", "pwd", "pass", "secret", "credentials",
		"token", "access_key", "bind_password", "login_password",
		"console_password", "api_password", "initial_password",
		"auth_pass", "user_pass", "auth_password", "db_password",
		"admin_password", "user_password", "root_password", "activationkey",
	}
	lower(key) == exact_keys[_]
}

is_password_field(key) {
	endswith(lower(key), "_password")
}

is_password_field(key) {
	endswith(lower(key), "_passwd")
}

is_password_field(key) {
	endswith(lower(key), "_secret")
}

is_password_field(key) {
	endswith(lower(key), "_pwd")
}

is_password_field(key) {
	endswith(lower(key), "_pass")
}

is_password_field(key) {
	contains(lower(key), "activationkey")
}

is_password_field(key) {
	endswith(lower(key), "_key")
	contains(lower(key), "activation")
}

CxPolicy[result] {
	doc := input.document[i]
	some field_key
	field_val := doc[field_key]
	not non_doc_keys[field_key]
	is_string(field_key)
	is_password_field(field_key)
	commonLib.emptyOrNull(field_val)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": field_key,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should contain a non-empty credential value", [field_key]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value, providing no authentication barrier", [field_key]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	some mod_key
	module_config := task[mod_key]
	not non_module_keys[mod_key]
	is_object(module_config)
	some field_key
	field_val := module_config[field_key]
	is_string(field_key)
	is_password_field(field_key)
	commonLib.emptyOrNull(field_val)

	task_name := object.get(task, "name", "undefined")

	result := {
		"documentId": id,
		"resourceType": mod_key,
		"resourceName": task_name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task_name, mod_key, field_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should contain a non-empty credential value", [field_key]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value, providing no authentication barrier", [field_key]),
	}
}