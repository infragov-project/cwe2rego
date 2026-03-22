package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

is_credential_key(key) {
    lower_key := lower(key)
    credential_terms := {"password", "passwd", "passphrase", "secret", "token", "pwd"}
    ct := credential_terms[_]
    contains(lower_key, ct)
}

is_credential_key(key) {
    lower_key := lower(key)
    endswith(lower_key, "key")
}

# Detect empty/null credentials in flat Ansible variable files (group_vars, host_vars, defaults)
CxPolicy[result] {
    doc := input.document[i]
    [path, val] := walk(doc)
    count(path) == 1
    key := path[0]
    is_string(key)
    key != "id"
    key != "file"
    commonLib.emptyOrNull(val)
    is_credential_key(key)

    result := {
        "documentId": doc.id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' should not be empty or null", [key]),
        "keyActualValue": sprintf("'%s' is set to an empty or null value", [key]),
    }
}

# Detect empty/null credentials in playbook-level vars
CxPolicy[result] {
    doc := input.document[i]
    playbook := doc.playbooks[_]
    vars := playbook.vars
    [path, val] := walk(vars)
    count(path) >= 1
    key := path[count(path) - 1]
    is_string(key)
    commonLib.emptyOrNull(val)
    is_credential_key(key)

    result := {
        "documentId": doc.id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": sprintf("vars.{{%s}}", [key]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' in vars should not be empty or null", [key]),
        "keyActualValue": sprintf("'%s' in vars is set to an empty or null value", [key]),
    }
}

# Detect empty/null credentials in task module parameters
CxPolicy[result] {
    task := ansLib.tasks[id][_]
    task_name := object.get(task, "name", "n/a")
    [path, val] := walk(task)
    count(path) >= 1
    key := path[count(path) - 1]
    is_string(key)
    commonLib.emptyOrNull(val)
    is_credential_key(key)

    result := {
        "documentId": id,
        "resourceType": "n/a",
        "resourceName": task_name,
        "searchKey": sprintf("name={{%s}}.{{%s}}", [task_name, key]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' should not be empty or null", [key]),
        "keyActualValue": sprintf("'%s' is set to an empty or null value", [key]),
    }
}