package glitch

import data.glitch_lib

password_keyword_pattern := "(?i)(password|secret|credential|token|passphrase|auth_key|admin_password|default_password|initial_password|root_password|encryption_key|ssl_key|private_key|sha512_password|keystore_password|truststore_password|mysql_password|key)"
base64_pattern := "^[A-Za-z0-9+/]+={0,2}$"
password_hash_pattern := "^\\$(1|2a|5|6)\\$"

is_plain_text_password(value) {
    lower_value := lower(value)
    lower_value != "true"
    lower_value != "false"
    lower_value != "method"
    lower_value != "network-admin"
    lower_value != "privilege"
    lower_value != "15"
    not regex.match("^[a-zA-Z]:[\\\\/]", lower_value)
    not regex.match("^/", lower_value)
    not regex.match("^\\.", lower_value)
    not regex.match("^\\$6\\$", lower_value)
    not regex.match("^\\$1\\$", lower_value)
    not regex.match("^\\$2a\\$", lower_value)
    not regex.match(".*\\.(keystore|jks|p12|pem|crt|key)$", lower_value)
    value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    key.ir_type == "String"
    value.ir_type == "String"
    regex.match(password_keyword_pattern, key.value)
    is_plain_text_password(value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding sensitive credentials in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    key.ir_type == "String"
    value.ir_type == "String"
    regex.match(password_keyword_pattern, key.value)
    regex.match(base64_pattern, value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": value,
        "path": parent.path,
        "description": "Use of base64-encoded secret - Obfuscating passwords with base64 does not provide security. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    key.ir_type == "String"
    value.ir_type == "String"
    regex.match(password_keyword_pattern, key.value)
    regex.match(password_hash_pattern, value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": value,
        "path": parent.path,
        "description": "Use of hard-coded password hash - Avoid embedding password hashes in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "String"
    regex.match(password_keyword_pattern, item.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": item,
        "path": parent.path,
        "description": "Use of hard-coded password in array - Avoid embedding sensitive credentials in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)base64_encode", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    arg.value != ""
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of base64-encoded secret - Obfuscating passwords with base64 does not provide security. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(password_keyword_pattern, node.name)
    node.value.ir_type == "String"
    is_plain_text_password(node.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding sensitive credentials in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(password_keyword_pattern, node.name)
    node.value.ir_type == "String"
    is_plain_text_password(node.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid embedding sensitive credentials in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(password_keyword_pattern, node.name)
    node.value.ir_type == "String"
    regex.match(base64_pattern, node.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of base64-encoded secret - Obfuscating passwords with base64 does not provide security. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(password_keyword_pattern, node.name)
    node.value.ir_type == "String"
    regex.match(base64_pattern, node.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of base64-encoded secret - Obfuscating passwords with base64 does not provide security. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(password_keyword_pattern, node.name)
    node.value.ir_type == "String"
    regex.match(password_hash_pattern, node.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password hash - Avoid embedding password hashes in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(password_keyword_pattern, node.name)
    node.value.ir_type == "String"
    regex.match(password_hash_pattern, node.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password hash - Avoid embedding password hashes in code. (CWE-259)"
    }
}