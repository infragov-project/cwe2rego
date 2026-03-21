package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

weak_hash_filters := {"md5", "sha1", "sha-1", "md4", "md2", "ripemd128", "ripemd160"}

contains_weak_jinja_hash_filter(val) {
	filter := weak_hash_filters[_]
	contains(lower(val), sprintf("| hash('%s')", [filter]))
}

contains_weak_jinja_hash_filter(val) {
	filter := weak_hash_filters[_]
	contains(lower(val), sprintf("| hash(\"%s\")", [filter]))
}

contains_weak_jinja_hash_filter(val) {
	filter := weak_hash_filters[_]
	contains(lower(val), sprintf("|hash('%s')", [filter]))
}

contains_weak_jinja_hash_filter(val) {
	filter := weak_hash_filters[_]
	contains(lower(val), sprintf("|hash(\"%s\")", [filter]))
}

task_meta_keys := {
	"name", "become", "become_user", "become_method", "become_flags",
	"register", "when", "tags", "vars", "notify", "with_items", "loop",
	"loop_control", "ignore_errors", "failed_when", "changed_when",
	"delegate_to", "delegate_facts", "environment", "no_log", "run_once",
	"listen", "block", "rescue", "always", "collections", "module_defaults",
	"any_errors_fatal", "check_mode", "diff", "async", "poll", "timeout",
	"debugger", "ignore_unreachable", "retries", "delay", "until",
	"args", "with_fileglob", "with_dict", "with_nested", "with_sequence",
}

CxPolicy[result] {
	task := ansLib.tasks[id][_]
	[path, val] := walk(task)
	count(path) == 2
	module_key := path[0]
	field_key := path[1]
	is_string(module_key)
	is_string(field_key)
	not task_meta_keys[module_key]
	is_string(val)
	contains_weak_jinja_hash_filter(val)

	result := {
		"documentId": id,
		"resourceType": module_key,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_key, field_key]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not use weak hash algorithms (md5, sha1) in Jinja2 expressions", [field_key]),
		"keyActualValue": sprintf("'%s' uses a weak hash function in a Jinja2 template expression", [field_key]),
	}
}

is_weak_prompt_encrypt(val) {
	weak := {"md5_crypt", "sha1_crypt", "des_crypt", "bsdi_crypt"}
	lower(val) == weak[_]
}

CxPolicy[result] {
	playbook := input.document[i].playbooks[_]
	vp := playbook.vars_prompt[_]
	commonLib.valid_key(vp, "encrypt")
	is_weak_prompt_encrypt(vp.encrypt)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("vars_prompt.name={{%s}}.encrypt", [vp.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "vars_prompt 'encrypt' should use a strong hashing algorithm such as 'sha256_crypt' or 'sha512_crypt'",
		"keyActualValue": sprintf("vars_prompt 'encrypt' is set to weak algorithm '%s'", [vp.encrypt]),
	}
}