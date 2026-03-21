package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

non_module_keys := {
	"name", "become", "become_user", "when", "register",
	"notify", "tags", "vars", "loop", "with_items", "with_list",
	"with_dict", "block", "rescue", "always", "ignore_errors",
	"no_log", "environment", "delegate_to", "run_once",
	"changed_when", "failed_when", "listen", "async", "poll",
	"check_mode", "diff", "connection", "port", "remote_user",
	"timeout", "any_errors_fatal",
}

is_password_field(key) {
	password_subs := {"password", "passwd", "secret", "credential"}
	contains(lower(key), password_subs[_])
}

is_password_field(key) {
	lower(key) == "pwd"
}

is_empty_value(value) {
	value == null
}

is_empty_value(value) {
	is_string(value)
	trim(value, " \t\n\r") == ""
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	some module_key
	module_value := task[module_key]
	not non_module_keys[module_key]
	is_object(module_value)
	some field_name
	field_value := module_value[field_name]
	is_string(field_name)
	is_password_field(field_name)
	is_empty_value(field_value)

	result := {
		"documentId": id,
		"resourceType": module_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_key, field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty or null", [field_name]),
		"keyActualValue": sprintf("'%s' is empty or null", [field_name]),
	}
}

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	some var_key
	var_value := playbook.vars[var_key]
	is_string(var_key)
	is_password_field(var_key)
	is_empty_value(var_value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars.%s", [var_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty or null", [var_key]),
		"keyActualValue": sprintf("'%s' is empty or null", [var_key]),
	}
}