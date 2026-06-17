package glitch

import data.glitch_lib
import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(".*(bind|ip|address|addr).*", node.name)
    node.value.ir_type == "String"
    node.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Unrestricted network access detected - Open firewall rules may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(".*(bind|ip|address|addr).*", node.name)
    node.value.ir_type == "String"
    node.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Unrestricted network access detected - Open firewall rules may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some pair in node.value
    key_string := pair.key.value
    regex.match(".*(bind|ip|address|addr).*", key_string)
    element := pair.value
    element.ir_type == "String"
    element.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": element,
        "path": parent.path,
        "description": "Unrestricted network access detected - Open firewall rules may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(".*\\*.*", node.value)
    some pattern in {"permission", "action", "policy", "role", "principal"}
    path_contains_pattern(path, pattern)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Overly permissive access detected - Wildcards in permissions may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Boolean"
    node.value == true
    path_contains_pattern(path, "public")
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Default insecure settings detected - Public access or hardcoded credentials may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(".*admin:admin.*", node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Default insecure settings detected - Public access or hardcoded credentials may lead to improper access control. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Boolean"
    node.value == false
    path_contains_pattern(path, "logging")
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Lack of accountability detected - Disabled logging may lead to improper access control. (CWE-284)"
    }
}

path_contains_pattern(path, pattern) {
    some i
    is_string(path[i])
    regex.match(pattern, path[i])
}