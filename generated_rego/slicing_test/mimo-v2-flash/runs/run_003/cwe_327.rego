package glitch

import data.glitch_lib

weak_crypto_pattern := "(?i).*(des|3des|rc4|md5|sha1|rsa-1024|ecb|cbc|tls_v1|ssl_v3|proprietary|custom|obfuscation).*"

check_weak_crypto(str) {
    regex.match(weak_crypto_pattern, str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    check_weak_crypto(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic algorithm found in attribute value. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    check_weak_crypto(var.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak cryptographic algorithm found in variable value. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    check_weak_crypto(node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm found in access key. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    check_weak_crypto(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": arg,
        "path": parent.path,
        "description": "Weak cryptographic algorithm found in function argument. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.value.ir_type == "String"
    check_weak_crypto(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent.path,
        "description": "Weak cryptographic algorithm found in hash value. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "String"
    check_weak_crypto(elem.value)
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Weak cryptographic algorithm found in array element. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    check_weak_crypto(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm function called. (CWE-327)"
    }
}