package Cx

import future.keywords.in
import data.generic.ansible as ansLib
import data.generic.common as commonLib

# Task-level: validate_certs disabled
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	path[count(path)-1] == "validate_certs"
	ansLib.isAnsibleFalse(value)

	taskName := object.get(task, "name", "n/a")

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.validate_certs", [taskName]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'validate_certs' should be 'yes' to enforce SSL certificate validation",
		"keyActualValue": "'validate_certs' is disabled, allowing unverified or cleartext connections",
	}
}

# Task-level: HTTPS/TLS enforcement boolean flags set to false
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	https_flags := {"https_only", "force_ssl", "require_ssl", "enforce_https", "secure_transfer_enabled", "require_tls", "enforce_ssl", "tls_enabled", "ssl_enabled", "transit_encryption_enabled"}
	flag := https_flags[_]
	path[count(path)-1] == flag
	ansLib.isAnsibleFalse(value)

	taskName := object.get(task, "name", "n/a")

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.%s", [taskName, flag]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be true to enforce encrypted transmission", [flag]),
		"keyActualValue": sprintf("'%s' is false, allowing cleartext data transmission", [flag]),
	}
}

# Task-level: insecure protocol values
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	proto_fields := {"protocol", "listener_protocol", "endpoint_protocol", "transport_protocol"}
	field := proto_fields[_]
	path[count(path)-1] == field
	is_string(value)
	insecure_protocols := {"http", "ftp", "telnet", "smtp", "ldap", "imap", "pop3"}
	lower(value) == insecure_protocols[_]

	taskName := object.get(task, "name", "n/a")

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.%s", [taskName, field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use a secure protocol such as HTTPS or SFTP", [field]),
		"keyActualValue": sprintf("'%s' is set to insecure protocol '%s'", [field, value]),
	}
}

# Task-level: URL/endpoint fields using http://
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	url_fields := {"url", "endpoint", "base_url", "connection_string", "proxy_pass", "upstream"}
	field := url_fields[_]
	path[count(path)-1] == field
	is_string(value)
	startswith(lower(value), "http://")

	taskName := object.get(task, "name", "n/a")

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.%s", [taskName, field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use HTTPS instead of HTTP", [field]),
		"keyActualValue": sprintf("'%s' uses cleartext HTTP: %s", [field, value]),
	}
}

# Task-level: encryption in transit disabled via string
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	[path, value] := walk(task)
	transit_fields := {"encryption_in_transit", "in_transit_encryption", "transit_encryption"}
	field := transit_fields[_]
	path[count(path)-1] == field
	is_string(value)
	lower(value) == "disabled"

	taskName := object.get(task, "name", "n/a")

	result := {
		"documentId": id,
		"resourceType": "n/a",
		"resourceName": taskName,
		"searchKey": sprintf("name={{%s}}.%s", [taskName, field]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be enabled to protect data in transit", [field]),
		"keyActualValue": sprintf("'%s' is explicitly disabled", [field]),
	}
}

# Document-level: URL variables containing http:// (flat var/defaults files)
CxPolicy[result] {
	doc := input.document[i]
	[path, value] := walk(doc)
	count(path) > 0
	last := path[count(path)-1]
	is_string(last)
	is_string(value)
	not last == "file"
	not "playbooks" in path
	contains(lower(last), "url")
	startswith(lower(value), "http://")

	searchKey := commonLib.concat_path(path)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use HTTPS instead of HTTP", [last]),
		"keyActualValue": sprintf("'%s' uses cleartext HTTP: %s", [last, value]),
	}
}

# Document-level: protocol fields with insecure values (flat var/defaults files)
CxPolicy[result] {
	doc := input.document[i]
	[path, value] := walk(doc)
	count(path) > 0
	last := path[count(path)-1]
	is_string(last)
	is_string(value)
	not "playbooks" in path
	lower(last) == "protocol"
	insecure_protocols := {"http", "ftp", "telnet", "smtp", "ldap", "imap", "pop3"}
	lower(value) == insecure_protocols[_]

	searchKey := commonLib.concat_path(path)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should use a secure protocol such as HTTPS", [last]),
		"keyActualValue": sprintf("'%s' is set to insecure protocol '%s'", [last, value]),
	}
}

# Document-level: security boolean flags false in flat var files
CxPolicy[result] {
	doc := input.document[i]
	[path, value] := walk(doc)
	count(path) > 0
	last := path[count(path)-1]
	is_string(last)
	not "playbooks" in path
	not last == "id"
	security_flags := {"https_only", "force_ssl", "require_ssl", "enforce_https", "secure_transfer_enabled", "require_tls", "enforce_ssl", "tls_enabled", "ssl_enabled", "transit_encryption_enabled", "validate_certs"}
	last == security_flags[_]
	ansLib.isAnsibleFalse(value)

	searchKey := commonLib.concat_path(path)

	result := {
		"documentId": doc.id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": searchKey,
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should be true to enforce encrypted transmission", [last]),
		"keyActualValue": sprintf("'%s' is false, allowing cleartext data transmission", [last]),
	}
}