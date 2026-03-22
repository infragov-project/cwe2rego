package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	get_url_modules := {"get_url", "ansible.builtin.get_url"}
	module_name := get_url_modules[_]
	get_url_task := task[module_name]
	not commonLib.valid_key(get_url_task, "checksum")

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}", [task.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'%s' should define 'checksum' to verify the integrity of the downloaded file", [module_name]),
		"keyActualValue": sprintf("'%s' does not define 'checksum'", [module_name]),
	}
}

CxPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	path[count(path)-1] == "gpgcheck"
	gpgcheck_disabled(value)
	searchKey := commonLib.concat_path(path)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'gpgcheck' should be enabled (1/yes/true) to verify package signatures",
		"keyActualValue": sprintf("'gpgcheck' is set to '%v', disabling package signature verification", [value]),
	}
}

gpgcheck_disabled(value) { value == 0 }
gpgcheck_disabled(value) { value == "0" }
gpgcheck_disabled(value) { value == false }
gpgcheck_disabled(value) { is_string(value); lower(value) == "false" }
gpgcheck_disabled(value) { is_string(value); lower(value) == "no" }