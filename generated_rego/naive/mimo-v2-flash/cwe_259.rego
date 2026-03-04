package glitch

import data.glitch_lib

sensitive_keywords := {"password", "pass", "pwd", "passwd", "admin_password", "db_password", "db_username", "root_password", "api_key", "secret_key", "access_key", "shared_secret", "token", "admin_user", "username", "user", "secret", "key"}

sensitive_content_keywords := {"password", "secret", "token", "key", "credential", "passwd", "pwd"}

script_keywords := {"user_data", "custom_data", "startup_script", "init_config", "cloud_config"}

config_keywords := {"config_map", "config_file", "file_content", "source"}

env_keywords := {"environment", "env", "environment_variables"}

policy_keywords := {"policy", "principal", "authentication"}

image_keywords := {"image", "image_url"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = sensitive_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in attribute - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = script_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in embedded script - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = config_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in configuration file - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = env_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in environment variable - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = policy_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded secret in policy - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = image_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    regex.match(".*:[^@]*@.*", attr.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials in image URL - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = env_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    lower_value := lower(n.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in environment variables hash - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = env_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "Array"
    walk(attr.value, [path, n])
    n.ir_type == "Attribute"
    lower_attr_name := lower(n.name)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_attr_name, m)
    n.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": "Hard-coded password in environment array - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    lower_value := lower(n.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": "Hard-coded password in hash attribute - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "Array"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    lower_value := lower(n.value)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_value, m)
    
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": "Hard-coded password in array attribute - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = env_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, n])
    n.ir_type == "Attribute"
    lower_attr_name := lower(n.name)
    some m
    m = sensitive_content_keywords[_]
    contains(lower_attr_name, m)
    n.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": "Hard-coded password in environment hash entry - Avoid using hard-coded credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    lower_name := lower(attr.name)
    some k
    k = sensitive_content_keywords[_]
    contains(lower_name, k)
    
    attr.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in attribute - Avoid using hard-coded credentials. (CWE-259)"
    }
}