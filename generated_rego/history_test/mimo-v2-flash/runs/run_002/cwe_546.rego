package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "TEMPORARY", "WORKAROUND", "INSECURE", "VULNERABLE", "BYPASS", "TRUST", "DANGER", "CHECK", "LEAK", "HARD-CODED", "DEFAULT", "IGNORE", "FAILSAFE", "OVERRIDE"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := parent.comments[_]
    content := comment.content
    
    some keyword in suspicious_keywords
    contains(content, keyword)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comment indicates unresolved security risks or deferred vulnerabilities. (CWE-546)"
    }
}