package Cx

import data.generic.ansible as ansLib
import data.generic.common as commonLib

# CWE-284: Detect bind to all interfaces (0.0.0.0) in playbook-level vars
CxPolicy[result] {
    doc := input.document[i]
    playbook := doc.playbooks[_]
    vars := playbook.vars
    [path, value] := walk(vars)
    count(path) == 1
    key := path[0]
    is_string(key)
    is_string(value)
    contains(lower(key), "bind")
    value == "0.0.0.0"

    result := {
        "documentId": doc.id,
        "resourceType": "n/a",
        "resourceName": playbook.name,
        "searchKey": sprintf("name={{%s}}.vars.{{%s}}", [playbook.name, key]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' should not bind to all interfaces (0.0.0.0)", [key]),
        "keyActualValue": sprintf("'%s' is set to '0.0.0.0'", [key]),
    }
}

# CWE-284: Detect bind to all interfaces (0.0.0.0) in flat variable files (group_vars, host_vars)
CxPolicy[result] {
    doc := input.document[i]
    not commonLib.valid_key(doc, "playbooks")
    [path, value] := walk(doc)
    count(path) == 1
    key := path[0]
    is_string(key)
    is_string(value)
    contains(lower(key), "bind")
    value == "0.0.0.0"

    result := {
        "documentId": doc.id,
        "resourceType": "n/a",
        "resourceName": "n/a",
        "searchKey": key,
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' should not bind to all interfaces (0.0.0.0)", [key]),
        "keyActualValue": sprintf("'%s' is set to '0.0.0.0'", [key]),
    }
}

# CWE-284: Detect bind to all interfaces (0.0.0.0) in task-level module parameters
CxPolicy[result] {
    task := ansLib.tasks[id][t]
    [modPath, module] := walk(task)
    count(modPath) == 1
    is_object(module)
    [path, value] := walk(module)
    count(path) == 1
    key := path[0]
    is_string(key)
    is_string(value)
    contains(lower(key), "bind")
    value == "0.0.0.0"

    result := {
        "documentId": id,
        "resourceType": modPath[0],
        "resourceName": task.name,
        "searchKey": sprintf("name={{%s}}.{{%s}}.{{%s}}", [task.name, modPath[0], key]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("'%s' should not bind to all interfaces (0.0.0.0)", [key]),
        "keyActualValue": sprintf("'%s' is set to '0.0.0.0'", [key]),
    }
}