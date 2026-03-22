package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

# Detect cleartext HTTP scheme in URL-type fields anywhere in the document
CxPolicy[result] {
    document := input.document[i]
    [path, value] := walk(document)
    is_string(value)
    startswith(lower(value), "http://")

    count(path) > 0
    key := path[count(path)-1]
    is_string(key)

    url_hints := {"url", "uri", "endpoint", "backend", "target", "connection", "link", "addr", "href"}
    contains(lower(key), url_hints[_])

    searchKey := commonLib.concat_path(commonLib.build_search_line(path, []))

    result := {
        "documentId": document.id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": searchKey,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' should use HTTPS to prevent cleartext transmission of sensitive information", [key]),
        "keyActualValue": sprintf("'%s' uses HTTP, transmitting sensitive information in cleartext", [key]),
    }
}

# Detect insecure cleartext protocol declared in any 'protocol' field
CxPolicy[result] {
    document := input.document[i]
    [path, value] := walk(document)
    is_string(value)

    insecure_protocols := {"http", "ftp", "telnet", "ldap", "smtp", "pop3", "imap"}
    insecure_protocols[lower(value)]

    count(path) > 0
    key := path[count(path)-1]
    key == "protocol"

    searchKey := commonLib.concat_path(commonLib.build_search_line(path, []))

    result := {
        "documentId": document.id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": searchKey,
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'protocol' should be set to a secure encrypted protocol to prevent cleartext transmission",
        "keyActualValue": sprintf("'protocol' is set to '%s', an insecure cleartext protocol", [value]),
    }
}

# Task-level: Detect cleartext HTTP URL in Ansible request modules
CxPolicy[result] {
    task := ansLib.tasks[id][_]
    req_modules := {"uri", "ansible.builtin.uri", "get_url", "ansible.builtin.get_url"}
    module_name := req_modules[_]
    module := task[module_name]
    is_object(module)

    url := module.url
    is_string(url)
    startswith(lower(url), "http://")

    result := {
        "documentId": id,
        "resourceType": module_name,
        "resourceName": task.name,
        "searchKey": sprintf("name={{%s}}.{{%s}}.url", [task.name, module_name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s.url' should use HTTPS to protect data in transit", [module_name]),
        "keyActualValue": sprintf("'%s.url' uses HTTP, transmitting data in cleartext", [module_name]),
    }
}

# Task-level: Detect disabled SSL/TLS certificate validation
CxPolicy[result] {
    task := ansLib.tasks[id][_]
    some module_name
    module := task[module_name]
    is_object(module)
    commonLib.valid_key(module, "validate_certs")
    ansLib.isAnsibleFalse(module.validate_certs)

    result := {
        "documentId": id,
        "resourceType": module_name,
        "resourceName": task.name,
        "searchKey": sprintf("name={{%s}}.{{%s}}.validate_certs", [task.name, module_name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'validate_certs' should be 'true' to verify SSL/TLS certificates",
        "keyActualValue": "'validate_certs' is 'false', bypassing SSL/TLS certificate verification",
    }
}