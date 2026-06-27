package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

unrestricted_bind_values := {"0.0.0.0", "::", "::0", "*"}

is_bind_key(key) {
	contains(lower(key), "bind")
}

# Rule 1: bind address in playbook-level vars
CxPolicy[result] {
	document := input.document[i]
	playbook := document.playbooks[_]
	vars := playbook.vars
	[path, value] := walk(vars)
	count(path) >= 1
	key := path[count(path) - 1]
	is_string(key)
	is_string(value)
	is_bind_key(key)
	unrestricted_bind_values[value]

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars.%s", [key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be set to an unrestricted bind address", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', allowing connections from all interfaces", [key, value]),
	}
}

# Rule 2: bind address as top-level document key (flat group_vars / host_vars files)
CxPolicy[result] {
	document := input.document[i]
	[path, value] := walk(document)
	count(path) == 1
	key := path[0]
	is_string(key)
	is_string(value)
	key != "id"
	key != "file"
	is_bind_key(key)
	unrestricted_bind_values[value]

	result := {
		"documentId": document.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": key,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be set to an unrestricted bind address", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', allowing connections from all interfaces", [key, value]),
	}
}

# Rule 3: bind address inside task modules
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 1
	key := path[count(path) - 1]
	is_string(key)
	is_string(value)
	is_bind_key(key)
	unrestricted_bind_values[value]

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.%s", [task.name, key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be set to an unrestricted bind address", [key]),
		"keyActualValue": sprintf("'%s' is set to '%s', allowing connections from all interfaces", [key, value]),
	}
}

# Rule 4: publicly_accessible = true in tasks
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 2
	path[count(path) - 1] == "publicly_accessible"
	ansLib.isAnsibleTrue(value)
	module_name := path[0]

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.publicly_accessible", [task.name, module_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'publicly_accessible' should be set to 'false'",
		"keyActualValue": "'publicly_accessible' is set to 'true'",
	}
}

# Rule 5: public ACL values in tasks
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, value] := walk(task)
	count(path) >= 2
	path[count(path) - 1] == "acl"
	is_string(value)
	public_acl_values := {"public-read", "public-read-write", "authenticated-read"}
	public_acl_values[lower(value)]
	module_name := path[0]

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.acl", [task.name, module_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'acl' should not be set to a public value",
		"keyActualValue": sprintf("'acl' is set to '%s'", [value]),
	}
}