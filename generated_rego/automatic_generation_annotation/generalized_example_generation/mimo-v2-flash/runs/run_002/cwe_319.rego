package glitch

import data.glitch_lib

# Helper function to check if a string contains insecure HTTP patterns
contains_insecure_string(s) {
    regex.match("(?i)\\bprotocol\\s+http\\b", s)
} else {
    regex.match("(?i)\\bssl_enforcement\\s+disabled\\b", s)
} else {
    regex.match("(?i)\\benable_https\\s+false\\b", s)
} else {
    regex.match("(?i)\\brequire_tls\\s+false\\b", s)
} else {
    regex.match("(?i)\\bencryption\\s+none\\b", s)
} else {
    regex.match("(?i)\\bssl_mode\\s+disabled\\b", s)
} else {
    regex.match("(?i)\\benable_https_traffic_only\\s+false\\b", s)
} else {
    regex.match("(?i)\\bsecure_transfer_required\\s+false\\b", s)
} else {
    regex.match("(?i)\\bpublic_access\\s+enabled\\b", s)
} else {
    regex.match("(?i)\\blistener_protocol\\s+HTTP\\b", s)
} else {
    regex.match("(?i)\\bcertificate_arn\\s+null\\b", s)
} else {
    regex.match("(?i)\\bssl_policy\\s+disabled\\b", s)
} else {
    regex.match("(?i)\\bendpoint_type\\s+HTTP\\b", s)
} else {
    regex.match("(?i)\\btls_version\\s+null\\b", s)
} else {
    regex.match("(?i)\\bconnection_string\\s+http://", s)
} else {
    regex.match("(?i)\\ballow_plain_text_auth\\s+true\\b", s)
} else {
    regex.match("(?i)\\bencryption\\s+disabled\\b", s)
}

# Pattern 1: Check for insecure URLs in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    url_value := attr.value.value
    regex.match("^(http|ftp)://", url_value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Insecure URL detected (CWE-319)"
    }
}

# Pattern 2: Check for insecure configuration in content attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    content_value := attr.value.value
    contains_insecure_string(content_value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Insecure configuration detected (CWE-319)"
    }
}

# Pattern 3: Check for insecure HTTPS settings - boolean version
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Boolean"
    attr.name == "enable_https_traffic_only"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - HTTPS traffic not enforced (CWE-319)"
    }
}

# Pattern 3: Check for insecure HTTPS settings - string version (enable_https_traffic_only)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "enable_https_traffic_only"
    attr.value.value == "false"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - HTTPS traffic not enforced (CWE-319)"
    }
}

# Pattern 3: Check for insecure HTTPS settings - string version (secure_transfer_required)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "secure_transfer_required"
    attr.value.value == "false"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - HTTPS traffic not enforced (CWE-319)"
    }
}

# Pattern 4: Check for insecure protocol settings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "protocol"
    attr.value.value == "http"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - HTTP protocol detected (CWE-319)"
    }
}

# Pattern 5: Check for SSL enforcement disabled - boolean version
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Boolean"
    attr.name == "ssl_enforcement"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - SSL enforcement disabled (CWE-319)"
    }
}

# Pattern 5: Check for SSL enforcement disabled - string version
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "ssl_enforcement"
    attr.value.value == "disabled"
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - SSL enforcement disabled (CWE-319)"
    }
}