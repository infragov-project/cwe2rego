package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

# Playbook-level: remote_user set to root
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	lower(playbook.remote_user) == "root"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": "remote_user",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'remote_user' should not be 'root' to follow the principle of least privilege",
		"keyActualValue": "'remote_user' is set to 'root'",
	}
}

# Playbook-level: become_user set to root with become enabled
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	ansLib.isAnsibleTrue(playbook.become)
	lower(playbook.become_user) == "root"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": "become_user",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'become_user' should not be 'root' to follow the principle of least privilege",
		"keyActualValue": "'become_user' is set to 'root'",
	}
}

# Task-level: remote_user set to root
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	lower(task.remote_user) == "root"

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.remote_user", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'remote_user' should not be 'root'",
		"keyActualValue": "'remote_user' is set to 'root'",
	}
}

# Task-level: become_user set to root with become enabled
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	ansLib.isAnsibleTrue(task.become)
	lower(task.become_user) == "root"

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.become_user", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'become_user' should not be 'root'",
		"keyActualValue": "'become_user' is set to 'root'",
	}
}

# Docker container running in privileged mode
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	docker_mods := {"community.docker.docker_container", "docker_container"}
	module := docker_mods[_]
	container := task[module]
	ansLib.isAnsibleTrue(container.privileged)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.privileged", [task.name, module]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'privileged' should not be 'true'",
		"keyActualValue": "'privileged' is set to 'true'",
	}
}

# Docker container with dangerous Linux capabilities
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	docker_mods := {"community.docker.docker_container", "docker_container"}
	module := docker_mods[_]
	container := task[module]
	dangerous_caps := {"ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE"}
	cap := container.cap_add[_]
	upper(cap) == dangerous_caps[_]

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.cap_add", [task.name, module]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'cap_add' should not contain dangerous capabilities",
		"keyActualValue": sprintf("'cap_add' contains dangerous capability '%s'", [cap]),
	}
}