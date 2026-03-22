package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_password_key(key) {
	contains(lower(key), "password")
}

is_password_key(key) {
	contains(lower(key), "passwd")
}

is_password_key(key) {
	contains(lower(key), "passphrase")
}

is_password_key(key) {
	lower(key) == "pass"
}

is_password_key(key) {
	lower(key) == "pwd"
}

is_password_key(key) {
	endswith(lower(key), "_pass")
}

is_password_key(key) {
	endswith(lower(key), "_pwd")
}

is_password_key(key) {
	contains(lower(key), "secret")
}

is_password_key(key) {
	endswith(lower(key), "key")
}

is_password_key(key) {
	endswith(lower(key), "_token")
}

is_password_key(key) {
	contains(lower(key), "credential")
}

CxPolicy[result] {
	document := input.document[i]
	value := document[key]
	is_string(key)
	is_password_key(key)
	commonLib.emptyOrNull(value)

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": key,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty", [key]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value", [key]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 1
	key := path[count(path) - 1]
	is_string(key)
	is_password_key(key)
	commonLib.emptyOrNull(value)
	task_name := object.get(task, "name", "n/a")

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task_name,
		"searchKey": sprintf("name={{%s}}.%s", [task_name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty", [key]),
		"keyActualValue": sprintf("'%s' is set to an empty or null value", [key]),
	}
}