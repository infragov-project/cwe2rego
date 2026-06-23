package glitch

import data.glitch_lib

password_keywords := {
    "password", "passwd", "pwd", "pass",
    "secret", "secret_key", "secretkey",
    "credentials", "creds", "auth_token",
    "api_key", "apikey", "api_secret",
    "private_key", "privatekey",
    "access_key", "accesskey",
    "admin_password", "root_password",
    "master_password", "master_pwd",
    "connection_string", "conn_string",
    "sha512_password"
}

is_password_field(name) {
    lower_field := lower(name)
    keyword := password_keywords[_]
    lower_field == keyword
} else {
    lower_field := lower(name)
    keyword := password_keywords[_]
    startswith(lower_field, sprintf("%s_", [keyword]))
} else {
    lower_field := lower(name)
    keyword := password_keywords[_]
    endswith(lower_field, sprintf("_%s", [keyword]))
} else {
    lower_field := lower(name)
    contains(lower_field, "_password")
} else {
    lower_field := lower(name)
    contains(lower_field, ".password")
}

is_hardcoded_credential(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_external_reference(value.value)
    not is_file_path(value.value)
}

is_external_reference(str) {
    contains(str, "data.")
} else {
    contains(str, "var.")
} else {
    contains(str, "vault_")
} else {
    contains(str, "random_")
} else {
    contains(str, "${")
} else {
    contains(str, "module.")
} else {
    contains(str, "lookup(")
} else {
    contains(str, "hiera(")
}

is_file_path(str) {
    startswith(str, "/")
} else {
    startswith(str, "./")
} else {
    startswith(str, "../")
} else {
    regex.match("^[a-zA-Z]+:", str)
}

get_key_name(key) = name {
    key.ir_type == "String"
    name := key.value
} else = name {
    key.ir_type == "VariableReference"
    name := key.value
} else = name {
    name := ""
}

find_path(node) = path {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, n])
    n == node
    path := ub.path
} else = path {
    path := ""
}

scan_all_hashes(root) = results {
    results := {r |
        walk(root, [_, node])
        node.ir_type == "Hash"
        [key, val] := node.value[_]
        key_name := get_key_name(key)
        is_password_field(key_name)
        is_hardcoded_credential(val)
        r := {
            "key_name": key_name,
            "value": val,
            "element": val
        }
    }
}

scan_env_in_arrays(root) = results {
    results := {r |
        walk(root, [_, node])
        node.ir_type == "Array"
        elem := node.value[_]
        elem.ir_type == "String"
        str := elem.value
        contains(str, "=")
        parts := split(str, "=")
        count(parts) >= 2
        key_part := parts[0]
        val_part := concat("=", array.slice(parts, 1, count(parts)))
        is_password_field(key_part)
        count(val_part) > 0
        not is_external_reference(val_part)
        not is_file_path(val_part)
        r := {
            "key_name": key_part,
            "value": elem,
            "element": elem
        }
    }
}

scan_direct_password(root) = results {
    results := {r |
        walk(root, [_, node])
        node.ir_type == "Attribute"
        is_password_field(node.name)
        is_hardcoded_credential(node.value)
        r := {
            "key_name": node.name,
            "value": node.value,
            "element": node.value
        }
    }
}

scan_direct_variable_password(root) = results {
    results := {r |
        walk(root, [_, node])
        node.ir_type == "Variable"
        is_password_field(node.name)
        is_hardcoded_credential(node.value)
        r := {
            "key_name": node.name,
            "value": node.value,
            "element": node.value
        }
    }
}

Glitch_Analysis[result] {
    found := scan_all_hashes(input)
    count(found) > 0
    item := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": item.element,
        "path": find_path(item.element),
        "description": "Use of Hard-coded Password - Passwords should not be embedded directly in resource definitions. Use external secret stores instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    found := scan_env_in_arrays(input)
    count(found) > 0
    item := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": item.element,
        "path": find_path(item.element),
        "description": "Use of Hard-coded Password - Passwords should not be embedded directly in resource definitions. Use external secret stores instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    found := scan_direct_password(input)
    count(found) > 0
    item := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": item.element,
        "path": find_path(item.element),
        "description": "Use of Hard-coded Password - Passwords should not be embedded directly in resource definitions. Use external secret stores instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    found := scan_direct_variable_password(input)
    count(found) > 0
    item := found[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": item.element,
        "path": find_path(item.element),
        "description": "Use of Hard-coded Password - Passwords should not be embedded directly in resource definitions. Use external secret stores instead. (CWE-259)"
    }
}