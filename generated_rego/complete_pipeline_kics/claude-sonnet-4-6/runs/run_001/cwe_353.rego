package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

get_url_modules := {"get_url", "ansible.builtin.get_url"}

uri_modules := {"uri", "ansible.builtin.uri"}

shell_modules := {"shell", "command", "ansible.builtin.shell", "ansible.builtin.command"}

apt_modules := {"apt", "ansible.builtin.apt"}

pip_modules := {"pip", "ansible.builtin.pip"}

yum_repo_modules := {"yum_repository", "ansible.builtin.yum_repository", "rhsm_repository"}

gpgcheck_disabled(v) {
	v == 0
}

gpgcheck_disabled(v) {
	v == "0"
}

gpgcheck_disabled(v) {
	ansLib.isAnsibleFalse(v)
}

# Rule 1: get_url without checksum - missing integrity check
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := get_url_modules[_]
	get_url_task := task[module]
	is_object(get_url_task)
	not commonLib.valid_key(get_url_task, "checksum")

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s' task should define 'checksum' to verify integrity of the downloaded file", [module]),
		"keyActualValue": sprintf("'%s' task does not define 'checksum'", [module]),
	}
}

# Rule 2: get_url with validate_certs disabled
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := get_url_modules[_]
	get_url_task := task[module]
	is_object(get_url_task)
	ansLib.isAnsibleFalse(get_url_task.validate_certs)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task should have 'validate_certs' set to 'true'", [module]),
		"keyActualValue": sprintf("'%s' task has 'validate_certs' disabled, bypassing TLS integrity checks", [module]),
	}
}

# Rule 3: uri module with validate_certs disabled
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := uri_modules[_]
	uri_task := task[module]
	is_object(uri_task)
	ansLib.isAnsibleFalse(uri_task.validate_certs)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task should have 'validate_certs' set to 'true'", [module]),
		"keyActualValue": sprintf("'%s' task has 'validate_certs' disabled, bypassing TLS integrity checks", [module]),
	}
}

# Rule 4: get_url using insecure protocol (http:// or ftp://)
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := get_url_modules[_]
	get_url_task := task[module]
	is_object(get_url_task)
	url := get_url_task.url
	is_string(url)
	insecure_schemes := {"http://", "ftp://"}
	startswith(url, insecure_schemes[_])

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task should use a secure protocol (https://) when fetching remote files", [module]),
		"keyActualValue": sprintf("'%s' task uses an insecure protocol in 'url': %s", [module, url]),
	}
}

# Rule 5: apt module with allow_unauthenticated enabled
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := apt_modules[_]
	apt_task := task[module]
	is_object(apt_task)
	ansLib.isAnsibleTrue(apt_task.allow_unauthenticated)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task should have 'allow_unauthenticated' set to 'false'", [module]),
		"keyActualValue": sprintf("'%s' task has 'allow_unauthenticated' enabled, bypassing package integrity checks", [module]),
	}
}

# Rule 6: pip module with insecure flags in extra_args
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := pip_modules[_]
	pip_task := task[module]
	is_object(pip_task)
	commonLib.valid_key(pip_task, "extra_args")
	extra_args := pip_task.extra_args
	is_string(extra_args)
	insecure_flags := {"--trusted-host", "--allow-unauthenticated", "--insecure", "--no-verify"}
	contains(extra_args, insecure_flags[_])

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task 'extra_args' should not include flags that bypass integrity verification", [module]),
		"keyActualValue": sprintf("'%s' task uses insecure flags in 'extra_args': %s", [module, extra_args]),
	}
}

# Rule 7: shell/command task downloading via curl/wget without checksum (string form)
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := shell_modules[_]
	shell_val := task[module]
	is_string(shell_val)
	download_tools := {"curl ", "wget "}
	contains(shell_val, download_tools[_])
	not contains(shell_val, "sha256")
	not contains(shell_val, "sha512")
	not contains(shell_val, "md5sum")
	not contains(shell_val, "checksum")

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s' task using curl/wget should include a checksum verification step", [module]),
		"keyActualValue": sprintf("'%s' task downloads content without any integrity verification", [module]),
	}
}

# Rule 8: shell/command task downloading via curl/wget without checksum (object cmd form)
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := shell_modules[_]
	shell_val := task[module]
	is_object(shell_val)
	cmd := shell_val.cmd
	is_string(cmd)
	download_tools := {"curl ", "wget "}
	contains(cmd, download_tools[_])
	not contains(cmd, "sha256")
	not contains(cmd, "sha512")
	not contains(cmd, "md5sum")
	not contains(cmd, "checksum")

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s' task using curl/wget should include a checksum verification step", [module]),
		"keyActualValue": sprintf("'%s' task downloads content without any integrity verification", [module]),
	}
}

# Rule 9: shell/command task using insecure TLS bypass flags
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := shell_modules[_]
	shell_val := task[module]
	is_string(shell_val)
	bypass_flags := {"--no-check-certificate", "--insecure", "-k "}
	contains(shell_val, bypass_flags[_])

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task should not use flags that disable certificate or integrity verification", [module]),
		"keyActualValue": sprintf("'%s' task uses a flag that bypasses TLS/integrity verification", [module]),
	}
}

# Rule 10: yum_repository task with gpgcheck disabled
CxPolicy[result] {
	task := ansLib.tasks[id][_]
	module := yum_repo_modules[_]
	repo_task := task[module]
	is_object(repo_task)
	commonLib.valid_key(repo_task, "gpgcheck")
	gpgcheck_disabled(repo_task.gpgcheck)

	result := {
		"documentId": id,
		"resourceType": module,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' task should have 'gpgcheck' enabled to verify package signatures", [module]),
		"keyActualValue": sprintf("'%s' task has 'gpgcheck' disabled, skipping GPG signature verification", [module]),
	}
}

# Rule 11: gpgcheck disabled in vars/defaults files (walk document for repo dicts)
CxPolicy[result] {
	doc := input.document[i]
	[path, value] := walk(doc)
	is_object(value)
	commonLib.valid_key(value, "gpgcheck")
	gpgcheck_disabled(value.gpgcheck)
	count(path) > 0
	repo_name := path[count(path) - 1]
	is_string(repo_name)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": sprintf("%s", [repo_name]),
		"searchKey": sprintf("%s.gpgcheck", [repo_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Repository 'gpgcheck' should be set to 1 to verify package integrity",
		"keyActualValue": "Repository 'gpgcheck' is disabled, skipping GPG signature verification",
	}
}