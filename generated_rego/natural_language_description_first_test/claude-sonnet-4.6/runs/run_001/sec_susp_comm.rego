```
package glitch

import data.glitch_lib

suspicious_pattern := "(?i)\\b(TODO|FIXME|HACK|BUG|INSECURE|WORKAROUND|TEMPORARY|TEMP|XXX|VULNERABILITY|VULN|UNSAFE|BROKEN|NOTSECURE|NOT-SECURE)\\b"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Comment"
    regex.match(suspicious_pattern, node.content)
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious security comment detected - Comments containing keywords indicating unresolved security concerns, known vulnerabilities, or temporary workarounds left in production. (CWE-1078)"
    }
}