package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_binding_key(key) {
	contains(lower(key), "bind")
}

is_binding_key(key) {
	contains(lower(key), "listen")
}

is_unrestricted_ip(val) {
	unrestricted := {"0.0.0.0", "::", "::0", "0.0.0.0/0", "::/0", "*", ""}
	lower(val) == unrestricted[_]
}

task_meta_keys := {
	"name", "become", "become_user", "when", "register", "vars", "tags",
	"notify", "with_items", "loop", "ignore_errors", "no_log", "failed_when",
	"changed_when", "environment", "block", "always", "rescue",
	"any_errors_fatal", "run_once", "delegate_to", "check_mode",
}

# Document root-level binding keys (e.g., group_vars flat YAML files)
CxPolicy[result] {
	doc := input.document[i]
	some key
	value := doc[key]
	is_string(value)
	is_binding_key(key)
	is_unrestricted_ip(value)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": key,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be set to a specific restricted IP address", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', binding to all network interfaces", [key, value]),
	}
}

# Playbook vars with binding keys
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	vars := playbook.vars
	some key
	value := vars[key]
	is_string(value)
	is_binding_key(key)
	is_unrestricted_ip(value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": playbook.name,
		"searchKey": sprintf("name={{%s}}.vars.%s", [playbook.name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be set to a specific restricted IP address", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', binding to all network interfaces", [key, value]),
	}
}

# Task module attributes with binding keys
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	some module_name
	module_obj := task[module_name]
	not task_meta_keys[module_name]
	is_object(module_obj)
	some key
	value := module_obj[key]
	is_string(value)
	is_binding_key(key)
	is_unrestricted_ip(value)
	ansLib.checkState(module_obj)

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be set to a specific restricted IP address", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', binding to all network interfaces", [key, value]),
	}
}