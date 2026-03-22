package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_sensitive_field(name) {
	lower_name := lower(name)
	sensitive_terms := {"password", "passwd", "pwd", "secret", "credential", "token"}
	term := sensitive_terms[_]
	contains(lower_name, term)
}

is_sensitive_field(name) {
	lower_name := lower(name)
	endswith(lower_name, "key")
}

is_empty_value(value) {
	is_string(value)
	count(trim(value, " \t\n\r")) == 0
}

is_empty_value(value) {
	is_null(value)
}

CxPolicy[result] {
	doc := input.document[i]
	value := doc[field]
	is_string(field)
	is_sensitive_field(field)
	is_empty_value(value)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": field,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%v' should not be set to an empty or null value", [field]),
		"keyActualValue": sprintf("'%v' is set to an empty or null value", [field]),
	}
}

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	value := playbook[field]
	is_string(field)
	is_sensitive_field(field)
	is_empty_value(value)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": field,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%v' should not be set to an empty or null value", [field]),
		"keyActualValue": sprintf("'%v' is set to an empty or null value", [field]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module_params := task[module]
	is_string(module)
	is_object(module_params)
	value := module_params[field]
	is_string(field)
	is_sensitive_field(field)
	is_empty_value(value)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.{{%s}}", [task.name, module, field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%v' should not be set to an empty or null value", [field]),
		"keyActualValue": sprintf("'%v' is set to an empty or null value", [field]),
	}
}