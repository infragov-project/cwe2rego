package glitch

import data.glitch_lib

insecure_protocols = {"http", "ftp", "telnet", "smtp", "tcp"}

insecure_encryption_flags = {"enable_https_traffic_only", "ssl_enforcement_enabled", "require_tls", "force_https", "use_ssl", "secure_transfer_required", "encryption_in_transit"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    kv := var.value.value[_]
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    lower_key := lower(kv.key.value)
    contains(lower_key, "protocol")
    insecure_protocols[kv.value.value]
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [path, n])
    n.ir_type == "String"
    regex.match("(?i)http://|ftp://|telnet://|smtp://", n.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URI configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    insecure_protocols[attr.value.value]
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    kv := var.value.value[_]
    kv.key.ir_type == "String"
    kv.value.ir_type == "Boolean"
    kv.value.value == false
    lower_key := lower(kv.key.value)
    insecure_encryption_flags[lower_key]
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption flag disabled. (CWE-319)"
    }
}