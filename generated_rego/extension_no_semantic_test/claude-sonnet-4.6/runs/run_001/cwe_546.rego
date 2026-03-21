package glitch

import data.glitch_lib

suspicious_comment_pattern := `(?si).*(TODO|TO-DO|TO\s+DO|FIXME|FIX\s+ME|LATER2?|PENDING|BUG|BUGFIX|BROKEN|DEFECT|ISSUE|HACK|KLUDGE|WORKAROUND|BAND-AID|BANDAID|SHORTCUT|TEMP|TEMPORARY|TMP|INTERIM|SHORT-TERM|INSECURE|UNSAFE|VULNERABLE|SECURITY|RISK|DANGER|WARNING|NOSONAR|NOSEC|NOLINT|DISABLE|SUPPRESS|IGNORE|REVIEW|REVISIT|RECHECK|VERIFY|VALIDATE|CONFIRM|XXX|!!!|\?\?\?|PLACEHOLDER|HARDCODED|DEPRECATED).*`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_comment_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments containing keywords like TODO, FIXME, HACK, BUG, etc. may indicate incomplete, insecure, or deferred security configurations. (CWE-546)"
    }
}