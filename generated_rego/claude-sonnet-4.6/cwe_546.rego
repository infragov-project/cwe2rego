package glitch

import data.glitch_lib

suspicious_comment_pattern := "(?i)(?s).*(\\bTODO\\b|\\bFIXME\\b|\\bFIX\\b|\\bHACK\\b|\\bXXX\\b|\\bBUG\\b|\\bKLUDGE\\b|\\bTEMP\\b|\\bTEMPORARY\\b|\\bLATER\\b|\\bWORKAROUND\\b|\\bBANDAID\\b|\\bSHORTCUT\\b|NOT SECURE|INSECURE|UNSAFE|DO NOT USE IN PRODUCTION|NOT FOR PROD|hardcoded|hard-coded|placeholder|change this|replace this|update before deploy|default password|test password|dummy key|fake secret|example token|sample credential|disabled for now|commented out|skip for now|encryption disabled|auth disabled|tls disabled|open to all|allow all|bypass|no validation|too permissive|overly broad|tighten later|wide open|open temporarily|restrict later|not implemented|\\bstub\\b|placeholder block|\\bmissing\\b|\\bincomplete\\b|\\bskeleton\\b|fill in|\\bTBD\\b|known issue|known bug|known vulnerability|CVE-|security issue|\\bvulnerability\\b|this is bad|bad practice|avoid this|technical debt|legacy issue|nosec|nocheck|suppress|checkov:skip|tfsec:ignore|trivy:ignore|compliance exception|audit exception|waived|exempted|approved exception).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_comment_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments indicating unresolved security issues, deferred controls, hardcoded credentials, or acknowledged vulnerabilities in infrastructure code. (CWE-546)"
    }
}