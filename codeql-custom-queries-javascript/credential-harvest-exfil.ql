/**
 * @name Credential Harvesting and Exfiltration
 * @description Detects credential theft via obfuscation +
 *              account manipulation + token exfiltration
 * @kind problem
 * @id js/credential-harvest-exfil
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-522
 */

import javascript

// Obfuscated String Array ──────────────────────────────────
//  check INNER function returns array, not outer
predicate isObfuscatedStringArray(Function f) {
  exists(ArrayExpr arr, ReturnStmt ret |
    ret.getContainer() = f and
    ret.getExpr() = arr and
    arr.getSize() > 20 and
    forall(Expr e | e = arr.getAnElement() |
      e instanceof StringLiteral
    )
  ) and
  exists(AssignExpr reassign |
    // ← Fix: use getContainer() on Stmt, not chained getEnclosingFunction()
    reassign.getContainer() = f
    or
    // OR reassignment is in a nested function inside f
    reassign.getEnclosingFunction() = f
  )
}

// Token Exfiltration Pattern ───────────────────────────────
// look for structural co-occurrence

predicate isTokenExfiltrationFile(File file) {
  // File has POST fetch call
  exists(CallExpr fetch |
    fetch.getCalleeName() = "fetch" and
    fetch.getFile() = file and
    exists(StringLiteral method |
      method.getValue() = "POST" and
      method.getParent*() = fetch.getArgument(1)
    )
  ) and
  // AND file has Authorization header pattern
  exists(StringLiteral auth |
    auth.getFile() = file and
    auth.getValue().regexpMatch("(?i).*(authorization|Authorization).*")
  ) and
  // AND file has credential modification
  exists(StringLiteral patch |
    patch.getFile() = file and
    patch.getValue() = "PATCH"
  )
}

//Account Takeover Sequence ────────────────────────────────
// Fix: look for co-occurrence of manipulation patterns
// in same file rather than same function
predicate isAccountTakeoverFile(File file) {
  // Has password change pattern
  exists(StringLiteral s |
    s.getFile() = file and
    s.getValue().regexpMatch("(?i).*password.*")
  ) and
  // Has email change pattern  
  exists(StringLiteral s |
    s.getFile() = file and
    s.getValue().regexpMatch("(?i).*email.*")
  ) and
  // Has PATCH method
  exists(StringLiteral s |
    s.getFile() = file and
    s.getValue() = "PATCH"
  ) and
  // Has DELETE method (remove friends/connections)
  exists(StringLiteral s |
    s.getFile() = file and
    s.getValue() = "DELETE"
  )
}

// ── Obfuscated Decoder Invocation ───────────────────────────
//detect the decoder call pattern
// _0x4bfe(0x97) called repeatedly = obfuscated string lookup
predicate hasObfuscatedDecoderCalls(TopLevel tl) {
  // Many calls to same short-named function with hex literals
  count(CallExpr c |
    c.getFile().getATopLevel() = tl and
    c.getNumArgument() = 1 and
    c.getArgument(0) instanceof NumberLiteral and
    c.getCallee().(Identifier).getName().regexpMatch("_0x[0-9a-f]+")
  ) > 10
}

// ── Main Detection ────────────────────────────────────────────────────────────
from Locatable node, string reason
where
  // Branch 1: Obfuscated string array
  exists(Function f |
    isObfuscatedStringArray(f) and
    node = f and
    reason = "Obfuscated string array decoder: " +
             "rotating array with " +
             count(Expr e | 
               exists(ArrayExpr arr, ReturnStmt ret |
                 ret.getContainer() = f and
                 ret.getExpr() = arr and
                 e = arr.getAnElement()
               )
             ).toString() + " encoded strings"
  )
  or
  // Branch 2: Token exfiltration file
  exists(File file |
    isTokenExfiltrationFile(file) and
    // Report at file level
    exists(CallExpr fetch |
      fetch.getCalleeName() = "fetch" and
      fetch.getFile() = file and
      node = fetch
    ) and
    reason = "Token exfiltration pattern: POST with " +
             "Authorization headers in same file as " +
             "credential modification (PATCH)"
  )
  or
  //  Account takeover
  exists(File file |
    isAccountTakeoverFile(file) and
    exists(TopLevel tl |
      tl.getFile() = file and
      node = tl
    ) and
    reason = "Account takeover pattern: password + " +
             "email modification + DELETE sequence " +
             "detected in same file"
  )
  or
  //  Obfuscated decoder calls
  exists(TopLevel tl |
    hasObfuscatedDecoderCalls(tl) and
    node = tl and
    reason = "Obfuscated string decoder invocations: " +
             "repeated hex-argument function calls " +
             "characteristic of runtime string decoding"
  )
select node, reason,
       node.getLocation().getFile().getRelativePath() as filePath,
       node.getLocation().getStartLine() as startLine,
       node.getLocation().getEndLine() as endLine,
       "Credential harvesting and exfiltration pattern detected: " + reason as message


