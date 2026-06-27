package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

unrestricted_bind_values := {"0.0.0.0", "::", "::0", "*"}

task_control_keys := {
	"name", "become", "become_user", "when", "register",
	"loop", "with_items", "with_list", "notify", "tags", "vars",
	"environment", "ignore_errors", "failed_when", "changed_when",
	"delegate_to", "no_log", "run_once", "any_errors_fatal",
	"block", "rescue", "always", "listen",
}

is_bind_related(field_name) {
	contains(lower(field_name), "bind")
}

is_bind_related(field_name) {
	contains(lower(field_name), "listen_addr")
}

is_bind_related(field_name) {
	contains(lower(field_name), "listen_on")
}

is_bind_related(field_name) {
	lower(field_name) == "listen_host"
}

is_bind_related(field_name) {
	lower(field_name) == "listenaddr"
}

# Detect in flat document-level key-value pairs (e.g., group_vars files)
CxPolicy[result] {
	document := input.document[i]
	some field_name
	value := document[field_name]
	is_string(value)
	is_bind_related(field_name)
	unrestricted_bind_values[lower(value)]

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": field_name,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be bound to a specific IP address, not an unrestricted wildcard", [field_name]),
		"keyActualValue": sprintf("'%s' is set to '%s', which binds to all available network interfaces", [field_name, value]),
	}
}

# Detect in playbook-level vars
CxPolicy[result] {
	document := input.document[i]
	playbook := document.playbooks[_]
	some field_name
	value := playbook.vars[field_name]
	is_string(value)
	is_bind_related(field_name)
	unrestricted_bind_values[lower(value)]

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars.%s", [field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be bound to a specific IP address, not an unrestricted wildcard", [field_name]),
		"keyActualValue": sprintf("'%s' is set to '%s', which binds to all available network interfaces", [field_name, value]),
	}
}

# Detect in task module parameters
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	some module_name
	module_params := task[module_name]
	is_object(module_params)
	not task_control_keys[module_name]

	some field_name
	value := module_params[field_name]
	is_string(value)
	is_bind_related(field_name)
	unrestricted_bind_values[lower(value)]

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_name, field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be bound to a specific IP address, not an unrestricted wildcard", [field_name]),
		"keyActualValue": sprintf("'%s' is set to '%s', which binds to all available network interfaces", [field_name, value]),
	}
}