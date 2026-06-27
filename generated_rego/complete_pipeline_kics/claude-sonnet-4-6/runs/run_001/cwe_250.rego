package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_root_user(user) {
	lower(user) == "root"
}

is_root_user(user) {
	user == "0"
}

is_root_user(user) {
	user == 0
}

docker_container_modules := {"community.docker.docker_container", "docker_container"}

dangerous_capabilities := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE", "DAC_OVERRIDE", "SETUID", "SETGID"}

# Playbook-level: remote_user set to root
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	commonLib.valid_key(playbook, "remote_user")
	is_root_user(playbook.remote_user)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("remote_user={{%s}}", [playbook.remote_user]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'remote_user' should not be 'root' or '0' to avoid execution with unnecessary privileges (CWE-250)",
		"keyActualValue": sprintf("'remote_user' is set to '%s'", [playbook.remote_user]),
	}
}

# Playbook-level: become true running as root (explicit or default)
CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	ansLib.isAnsibleTrue(playbook.become)
	become_user := object.get(playbook, "become_user", "root")
	is_root_user(become_user)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": "become",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Playbook should not execute with root/superuser privileges (CWE-250)",
		"keyActualValue": sprintf("'become' is true and effective user is '%s'", [become_user]),
	}
}

# Task-level: remote_user set to root
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	commonLib.valid_key(task, "remote_user")
	is_root_user(task.remote_user)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.remote_user={{%s}}", [task.name, task.remote_user]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'remote_user' should not be 'root' or '0' to avoid execution with unnecessary privileges (CWE-250)",
		"keyActualValue": sprintf("'remote_user' is set to '%s'", [task.remote_user]),
	}
}

# Task-level: become true running as root (explicit or default)
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	ansLib.isAnsibleTrue(task.become)
	become_user := object.get(task, "become_user", "root")
	is_root_user(become_user)

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.become", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Task should not execute with root/superuser privileges (CWE-250)",
		"keyActualValue": sprintf("'become' is true and effective user is '%s'", [become_user]),
	}
}

# Docker container: privileged mode enabled
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := docker_container_modules[_]
	container := task[module]
	ansLib.isAnsibleTrue(container.privileged)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.privileged", [task.name, module]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'privileged' should not be 'true' to avoid execution with unnecessary privileges (CWE-250)",
		"keyActualValue": "'privileged' is set to 'true'",
	}
}

# Docker container: running as root user
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := docker_container_modules[_]
	container := task[module]
	commonLib.valid_key(container, "user")
	is_root_user(container.user)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.user", [task.name, module]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'user' should not be 'root' or '0' to avoid execution with unnecessary privileges (CWE-250)",
		"keyActualValue": sprintf("'user' is set to '%s'", [container.user]),
	}
}

# Docker container: dangerous Linux capabilities granted
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	module := docker_container_modules[_]
	container := task[module]
	cap := container.capabilities[_]
	upper(cap) == dangerous_capabilities[_]

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.capabilities", [task.name, module]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Container should not be granted the '%s' capability (CWE-250)", [upper(cap)]),
		"keyActualValue": sprintf("Container has the '%s' capability granted", [cap]),
	}
}