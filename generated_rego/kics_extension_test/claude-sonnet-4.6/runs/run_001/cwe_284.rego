package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

bind_ip_keywords := {"bindip", "bind_ip", "bind_addr", "bindaddr", "listen_addr", "listen_ip"}

unrestricted_binds := {"0.0.0.0", "::"}

is_unrestricted_bind_var(key, value) {
	contains(lower(key), bind_ip_keywords[_])
	unrestricted_binds[value]
}

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	some key
	value := playbook.vars[key]
	is_unrestricted_bind_var(key, value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": playbook.name,
		"searchKey": sprintf("vars.%s", [key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'vars.%s' should not bind to all interfaces; use a specific IP address", [key]),
		"keyActualValue": sprintf("'vars.%s' is set to '%s' which binds the service to all network interfaces", [key, value]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	some key
	value := task.vars[key]
	is_unrestricted_bind_var(key, value)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.vars.%s", [task.name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'vars.%s' should not bind to all interfaces; use a specific IP address", [key]),
		"keyActualValue": sprintf("'vars.%s' is set to '%s' which binds the service to all network interfaces", [key, value]),
	}
}