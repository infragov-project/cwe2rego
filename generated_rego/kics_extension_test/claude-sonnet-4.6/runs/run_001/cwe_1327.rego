package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_bind_field(key) {
	contains(lower(key), "bind")
}

is_bind_field(key) {
	contains(lower(key), "listen")
}

is_bind_field(key) {
	endswith(lower(key), "_address")
}

is_bind_field(key) {
	endswith(lower(key), "_addr")
}

is_bind_field(key) {
	endswith(lower(key), "_ip")
}

is_bind_field(key) {
	lower(key) == "address"
}

is_bind_field(key) {
	lower(key) == "host"
}

is_bind_field(key) {
	lower(key) == "ip"
}

is_unrestricted_address(value) {
	wildcards := {"0.0.0.0", "::", "0:0:0:0:0:0:0:0", "*", "any"}
	lower(value) == wildcards[_]
}

is_task_meta(key) {
	meta := {"name", "become", "become_user", "when", "register", "tags", "notify", "with_items", "loop", "vars", "environment", "delegate_to", "ignore_errors", "failed_when", "changed_when", "no_log", "block", "always", "rescue"}
	meta[key]
}

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	vars := playbook.vars
	is_object(vars)
	value := vars[key]
	is_string(key)
	is_bind_field(key)
	is_string(value)
	is_unrestricted_address(value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": playbook.name,
		"searchKey": sprintf("name={{%s}}.vars.%s", [playbook.name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be set to a specific IP address, not a wildcard", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', binding the service to all network interfaces", [key, value]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := task[moduleName]
	is_object(module)
	not is_task_meta(moduleName)
	value := module[key]
	is_string(key)
	is_bind_field(key)
	is_string(value)
	is_unrestricted_address(value)

	result := {
		"documentId": id,
		"resourceType": moduleName,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, moduleName, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be set to a specific IP address, not a wildcard", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', binding the service to all network interfaces", [key, value]),
	}
}