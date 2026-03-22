package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	lower(playbook.remote_user) == "root"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": "remote_user",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'remote_user' should not be set to 'root' to avoid running with unnecessary privileges",
		"keyActualValue": "'remote_user' is set to 'root'",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	lower(task.remote_user) == "root"

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("name={{%s}}.remote_user", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'remote_user' should not be set to 'root' to avoid running with unnecessary privileges",
		"keyActualValue": "'remote_user' is set to 'root'",
	}
}