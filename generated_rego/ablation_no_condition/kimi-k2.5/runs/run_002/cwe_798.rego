package glitch

import data.glitch_lib

import future.keywords.if
import future.keywords.in

credential_patterns := {"password", "passwd", "pwd", "secret", "key", "api_key", "apikey", "api_secret", "apisecret", "token", "auth_token", "access_token", "refresh_token", "credential", "creds", "private_key", "privatekey", "secret_key", "secretkey", "access_key", "accesskey"}

strict_credential_patterns := {"password", "passwd", "pwd", "secret", "api_key", "apikey", "api_secret", "apisecret", "token", "auth_token", "access_token", "refresh_token", "credential", "creds", "private_key", "privatekey", "secret_key", "secretkey", "access_key", "accesskey"}

matches_credential_pattern(name) if {
    lower_name := lower(name)
    some pattern in credential_patterns
    contains(lower_name, pattern)
}

matches_strict_credential_pattern(name) if {
    lower_name := lower(name)
    some pattern in strict_credential_patterns
    contains(lower_name, pattern)
}

is_hardcoded_credential_value(value) if {
    value.ir_type == "String"
    count(value.value) > 0
    not value.value == ""
    not glitch_lib.has_variable_reference(value)
}

is_hardcoded_credential_value(value) if {
    value.ir_type == "Integer"
    not glitch_lib.has_variable_reference(value)
}

is_path_value(value) if {
    value.ir_type == "String"
    regex.match(`^(/[^/ ]*)+/?$`, value.value)
}

build_element_from_parts(name, val, info) = elem if {
    elem := {
        "ir_type": "KeyValue",
        "line": info.line,
        "column": info.column,
        "end_line": info.end_line,
        "end_column": info.end_column,
        "code": info.code,
        "name": name,
        "value": val
    }
}

build_var_element(var) = elem if {
    elem := {
        "ir_type": "Variable",
        "line": var.line,
        "column": var.column,
        "end_line": var.end_line,
        "end_column": var.end_column,
        "code": var.code,
        "name": var.name,
        "value": var.value
    }
}

depth_limited_walk(node, max_depth) = [{[], node}] if {
    max_depth >= 0
}

depth_limited_walk(node, max_depth) = results if {
    max_depth > 0
    node.ir_type == "Hash"
    results := {r |
        some entry in node.value
        entry.key.ir_type == "String"
        key := entry.key.value
        val := entry.value
        sub_results := depth_limited_walk(val, max_depth - 1)
        some sub in sub_results
        sub_path := sub.path
        new_path := [key]
        concat([key], sub_path) == new_path_concat
        r := {"path": concat(".", new_path_concat), "node": sub.node}
    } | {r |
        some entry in node.value
        entry.key.ir_type == "String"
        key := entry.key.value
        val := entry.value
        sub_results := depth_limited_walk(val, max_depth - 1)
        some sub in sub_results
        sub.path == []
        r := {"path": key, "node": sub.node}
    }
}

depth_limited_walk(node, max_depth) = results if {
    max_depth > 0
    node.ir_type == "Array"
    results := {r |
        some i, elem in node.value
        sub_results := depth_limited_walk(elem, max_depth - 1)
        some sub in sub_results
        idx := format_int(i, 10)
        new_path := [idx]
        concat([idx], sub.path) == new_path_concat
        r := {"path": concat(".", new_path_concat), "node": sub.node}
    } | {r |
        some i, elem in node.value
        sub_results := depth_limited_walk(elem, max_depth - 1)
        some sub in sub_results
        sub.path == []
        r := {"path": format_int(i, 10), "node": sub.node}
    }
}

depth_limited_walk_flat(node, max_depth) = flats if {
    results := depth_limited_walk(node, max_depth)
    flats := {flat |
        some r in results
        flat := {
            "path": r.path,
            "node": r.node
        }
    }
}

collect_nested_credentials(root, max_depth) = all_creds if {
    flats := depth_limited_walk_flat(root, max_depth)
    all_creds := {cred |
        some flat in flats
        flat.node.ir_type == "Hash"
        some entry in flat.node.value
        entry.key.ir_type == "String"
        key := entry.key.value
        val := entry.value
        
        matches_credential_pattern(key)
        is_hardcoded_credential_value(val)
        not is_path_value(val)
        
        path_prefix := flat.path
        full_path := concat(".", array.concat([path_prefix], [key]))
        clean_path := regex.replace(full_path, `^\.*`, "")
        
        cred := {
            "type": "sec_hard_secr",
            "element": build_element_from_parts(key, val, entry.key),
            "path": clean_path,
            "description": "Use of Hard-coded Credentials - Avoid hardcoding passwords, API keys, tokens, or other sensitive credentials. Use secure configuration management or secret management systems instead. (CWE-798)"
        }
    }
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    some var in parent.variables
    matches_strict_credential_pattern(var.name)
    is_hardcoded_credential_value(var.value)
    not is_path_value(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": build_var_element(var),
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding passwords, API keys, tokens, or other sensitive credentials. Use secure configuration management or secret management systems instead. (CWE-798)"
    }
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    some var in parent.variables
    creds := collect_nested_credentials(var.value, 10)
    some cred in creds
    
    result := cred
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    some var in parent.variables
    var.name == "default"
    var.value.ir_type == "Hash"
    some entry in var.value.value
    entry.key.ir_type == "String"
    key_name := entry.key.value
    matches_strict_credential_pattern(key_name)
    is_hardcoded_credential_value(entry.value)
    not is_path_value(entry.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": build_element_from_parts(key_name, entry.value, entry.key),
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding passwords, API keys, tokens, or other sensitive credentials. Use secure configuration management or secret management systems instead. (CWE-798)"
    }
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    some cond in parent.statements
    cond.ir_type == "ConditionalStatement"
    some stmt in cond.statements
    stmt.ir_type == "Variable"
    matches_strict_credential_pattern(stmt.name)
    is_hardcoded_credential_value(stmt.value)
    not is_path_value(stmt.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": build_var_element(stmt),
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding passwords, API keys, tokens, or other sensitive credentials. Use secure configuration management or secret management systems instead. (CWE-798)"
    }
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    some child in parent.unit_blocks
    some attr in child.attributes
    matches_credential_pattern(attr.name)
    is_hardcoded_credential_value(attr.value)
    not is_path_value(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": {
            "ir_type": "Attribute",
            "line": attr.line,
            "column": attr.column,
            "end_line": attr.end_line,
            "end_column": attr.end_column,
            "code": attr.code,
            "name": attr.name,
            "value": attr.value
        },
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hardcoding passwords, API keys, tokens, or other sensitive credentials. Use secure configuration management or secret management systems instead. (CWE-798)"
    }
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    creds := collect_nested_credentials(parent, 15)
    some cred in creds
    
    result := cred
}

Glitch_Analysis[result] if {
    some parent in input
    parent.ir_type == "UnitBlock"
    parent.path != ""
    
    some child in parent.unit_blocks
    creds := collect_nested_credentials(child, 15)
    some cred in creds
    
    result := cred
}