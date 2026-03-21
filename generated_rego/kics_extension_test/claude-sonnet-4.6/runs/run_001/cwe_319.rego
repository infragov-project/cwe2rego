package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

insecure_when_false := {
	"validate_certs",
	"ssl_enabled",
	"tls_enabled",
	"enable_ssl",
	"use_ssl",
	"use_tls",
	"https_only",
	"enforce_https",
	"require_secure_transport",
	"secure_transfer_required",
	"encryption_in_transit",
	"transit_encryption_enabled",
}

ssl_mode_fields := {"ssl_mode", "sslmode"}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	count(path) == 2
	field := path[1]
	insecure_when_false[field]
	ansLib.isAnsibleFalse(value)
	module_name := path[0]

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_name, field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.%s' should be enabled to ensure encrypted and verified connections", [module_name, field]),
		"keyActualValue": sprintf("'%s.%s' is disabled, allowing cleartext or unverified transmission of sensitive information", [module_name, field]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	count(path) == 2
	field := path[1]
	ssl_mode_fields[field]
	is_string(value)
	lower(value) == "disable"
	module_name := path[0]

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, module_name, field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.%s' should not be set to 'disable' to ensure encrypted connections", [module_name, field]),
		"keyActualValue": sprintf("'%s.%s' is set to 'disable', allowing cleartext database connections", [module_name, field]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	count(path) == 2
	path[1] == "url"
	is_string(value)
	insecure_prefixes := {"http://", "ftp://", "telnet://", "ldap://"}
	startswith(lower(value), insecure_prefixes[_])
	module_name := path[0]

	result := {
		"documentId": id,
		"resourceType": module_name,
		"resourceName": task.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}.url", [task.name, module_name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s.url' should use a secure protocol such as https://", [module_name]),
		"keyActualValue": sprintf("'%s.url' uses an insecure cleartext protocol", [module_name]),
	}
}