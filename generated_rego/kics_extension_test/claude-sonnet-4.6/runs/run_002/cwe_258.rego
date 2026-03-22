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
	contains(lower(key), "secret")
}

is_password_key(key) {
	lower(key) == "pwd"
}

is_password_key(key) {
	lower(key) == "pass"
}

is_password_key(key) {
	endswith(lower(key), "key")
}

is_meta_key(key) {
	key == "id"
}

is_meta_key(key) {
	key == "file"
}

CxPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, val])
	count(path) >= 1
	last := path[count(path) - 1]
	is_string(last)
	not is_meta_key(last)
	is_password_key(last)
	val == ""

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": commonLib.concat_path(path),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty", [last]),
		"keyActualValue": sprintf("'%s' is set to an empty string", [last]),
	}
}

CxPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, val])
	count(path) >= 1
	last := path[count(path) - 1]
	is_string(last)
	not is_meta_key(last)
	is_password_key(last)
	val == null

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": commonLib.concat_path(path),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be null", [last]),
		"keyActualValue": sprintf("'%s' is null", [last]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	name := object.get(task, "name", "n/a")
	walk(task, [path, val])
	count(path) >= 1
	last := path[count(path) - 1]
	is_string(last)
	not is_meta_key(last)
	is_password_key(last)
	val == ""

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": name,
		"searchKey": sprintf("name={{%s}}.%s", [name, commonLib.concat_path(path)]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be empty", [last]),
		"keyActualValue": sprintf("'%s' is set to an empty string", [last]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	name := object.get(task, "name", "n/a")
	walk(task, [path, val])
	count(path) >= 1
	last := path[count(path) - 1]
	is_string(last)
	not is_meta_key(last)
	is_password_key(last)
	val == null

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": name,
		"searchKey": sprintf("name={{%s}}.%s", [name, commonLib.concat_path(path)]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be null", [last]),
		"keyActualValue": sprintf("'%s' is null", [last]),
	}
}