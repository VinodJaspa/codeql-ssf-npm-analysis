/**
 * @name Evasive Computed  Property Access on Sensitive Objects
 * @description Identifies when 'process' or 'child_process' is accessed via dynamic keys,
 * a common technique in obfuscated malware.
 * @kind table
 * @id js/computed-property-access
 * @tags security, obfuscation
 */
// Let G_{proc}$ be the global reference to the process object. 
// We define a violation V as an index expression where the index $i$ 
// is a non-literal member of the set of expressions 
// $E$ :$$V = \{ idx(G_{proc}, i) \mid i \in E \land i \notin \text{StringLiteral} \}$$
// Computed Access: $V = \{ \text{Access}(o, i) \mid i \in C_{evade} \}$ (The Sneaky Syntax)The Dropper: $V_{drop} = (W_p \prec M_p \prec E_p)$ (The Criminal Timeline)

import javascript

from IndexExpr idx, GlobalVariable gv
where
  gv.getName() = "process" and
  idx.getBase() = gv.getAnAccess() and
  // This catches cases like process[variable] or process[functionCall()]
  not idx.getIndex() instanceof StringLiteral
select idx, idx.getLocation().getFile().getRelativePath() as filePath,
  idx.getLocation().getStartLine().toString() as startLine, idx.getLocation().getEndLine().toString() as endLine,
  "Potential obfuscated access to sensitive 'process' object.." as message
