package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	get_url_mods := {"get_url", "ansible.builtin.get_url"}
	module_name := get_url_mods[_]
	get_url_task := task[module_name]

	commonLib.valid_key(get_url_task, "url")
	not commonLib.valid_key(get_url_task, "checksum")

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s' task should define 'checksum' to verify the integrity of the downloaded file", [module_name]),
		"keyActualValue": sprintf("'%s' task does not define 'checksum'", [module_name]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	yum_repo_mods := {"yum_repository", "ansible.builtin.yum_repository"}
	module_name := yum_repo_mods[_]
	yum_repo := task[module_name]

	ansLib.isAnsibleFalse(yum_repo.gpgcheck)

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.gpgcheck", [task.name, module_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.gpgcheck' should be 'yes' to enforce GPG signature verification", [module_name]),
		"keyActualValue": sprintf("'%s.gpgcheck' is set to 'no'", [module_name]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	pkg_mods := {"yum", "ansible.builtin.yum", "dnf", "ansible.builtin.dnf"}
	module_name := pkg_mods[_]
	pkg_task := task[module_name]

	ansLib.isAnsibleTrue(pkg_task.disable_gpg_check)

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.disable_gpg_check", [task.name, module_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.disable_gpg_check' should be 'no' to enforce package signature verification", [module_name]),
		"keyActualValue": sprintf("'%s.disable_gpg_check' is set to 'yes'", [module_name]),
	}
}