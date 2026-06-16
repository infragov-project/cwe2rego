package glitch

import data.glitch_lib

patterns := {"password", "secret", "token", "credential", "auth", "apikey", "secretkey", "accesstoken", "passphrase", "privatekey", "sha512_password", "keystore_password", "truststore_password", "secret_uuid", "user"}

check_credential_key(key) {
    lower_key := lower(key)
    pattern := patterns[_]
    regex.match(sprintf("(?i)\\b%s\\b", [pattern]), lower_key)
}

is_path(value) {
    regex.match("^(?:/|[a-zA-Z]:\\\\|\\./|\\.\\\\)", value)
}

is_class_name(value) {
    regex.match("^[a-zA-Z][a-zA-Z0-9]*(\\.[a-zA-Z][a-zA-Z0-9]*)+$", value)
}

find_credential_assignments(node) = elements {
    elements1 := {n |
        walk(node, [path, n])
        n.ir_type == "Variable"
        check_credential_key(n.name)
        n.value.ir_type == "String"
        not is_path(n.value.value)
        not is_class_name(n.value.value)
    }
    elements2 := {n |
        walk(node, [path, n])
        n.ir_type == "Attribute"
        check_credential_key(n.name)
        n.value.ir_type == "String"
        not is_path(n.value.value)
        not is_class_name(n.value.value)
    }
    elements3 := {key_node |
        walk(node, [path, n])
        n.key.ir_type == "String"
        n.value.ir_type == "String"
        check_credential_key(n.key.value)
        not is_path(n.value.value)
        not is_class_name(n.value.value)
        key_node := n.key
    }
    elements := elements1 | elements2 | elements3
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    elements := find_credential_assignments(parent)
    element := elements[_]
    
    result := {
        "type": "sec_hard_secr",
        "element": element,
        "path": parent.path,
        "description": "Hard-coded credential detected in IaC script. (CWE-798)"
    }
}