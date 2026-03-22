package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_credential_key(key) {
	contains(lower(key), "password")
}

is_credential_key(key) {
	contains(lower(key), "passwd")
}

is_credential_key(key) {
	contains(lower(key), "secret")
}

is_credential_key(key) {
	contains(lower(key), "token")
}

is_credential_key(key) {
	contains(lower(key), "access_key")
}

is_credential_key(key) {
	contains(lower(key), "auth_pass")
}

CxPolicy[result] {
	doc := input.document[i]
	some field_name
	value := doc[field_name]
	is_string(field_name)
	field_name != "id"
	field_name != "file"
	is_credential_key(field_name)
	commonLib.emptyOrNull(value)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": field_name,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty or null (CWE-258: Empty Password in Configuration File)", [field_name]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value", [field_name]),
	}
}

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	is_object(playbook.vars)
	some field_name
	value := playbook.vars[field_name]
	is_string(field_name)
	is_credential_key(field_name)
	commonLib.emptyOrNull(value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars.%s", [field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty or null (CWE-258: Empty Password in Configuration File)", [field_name]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value", [field_name]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	some module_name
	module := task[module_name]
	is_object(module)
	some field_name
	value := module[field_name]
	is_string(field_name)
	is_credential_key(field_name)
	commonLib.emptyOrNull(value)
	task_name := object.get(task, "name", module_name)

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task_name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task_name, module_name, field_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty or null (CWE-258: Empty Password in Configuration File)", [field_name]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value", [field_name]),
	}
}