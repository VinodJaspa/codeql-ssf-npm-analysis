// * @name Obfuscated Payload Detonation
//  * @description Detects malicious execution where obfuscated or remotely sourced data
//  * is decoded and passed into a dynamic execution sink. Attack payloads are commonly
//  * hidden as long Base64 strings, numeric byte arrays, or fetched from remote sources
//  * to evade keyword-based detection. This query tracks taint flow from these encoded
//  * sources to execution sinks including child_process methods, eval, vm.runInContext,
//  * and the Function constructor. Unlike reverse shell queries (which require a network
//  * pipe back-channel), this query targets local payload detonation — the moment an
//  * obfuscated command is decoded and handed to a system execution API.
//  * @kind table
//  * @id js/obfuscated-payload-detonation
//  * @tags security malware obfuscation
//  * external/cwe/cwe-94
//  * external/mitre/attack/T1059
// Observed pattern: malicious npm packages embed compressed shell scripts as
// Base64 strings or byte arrays, decode them at runtime, and execute via
// child_process or eval. This behavior is rare in benign packages and strongly
// correlates with supply chain attack payloads.
import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.RemoteFlowSources

module ReverseShellConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    // 1. Remote Data (Sockets, HTTP)
    source instanceof RemoteFlowSource
    or
    // 2. Hardcoded long Base64 strings (Common in malicious packages)
    exists(string s | 
      s = source.asExpr().(StringLiteral).getValue() and
      s.regexpMatch("(?i)[a-z0-9+/]{80,}=*")
    )
    or
    // 3. Byte Arrays (The "[101, 99, ...]" sample)
    exists(ArrayExpr arr |
      arr = source.asExpr() and
      arr.getSize() > 20 and 
      // Ensure the array contains mostly numbers (typical of character codes)
      forall(Expr e | e = arr.getElement(_) | e instanceof Literal)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::Node callNode |
      (
        // Catches child_process calls like spawn, exec, etc.
        exists(DataFlow::SourceNode cp |
          cp = DataFlow::moduleImport("child_process") and
          callNode = cp.getAMemberCall(["spawn", "exec", "execSync", "execFile"])
        )
        or
        // Catches eval and vm.runIn... calls
        exists(CallExpr ce |
          ce.getCalleeName() in ["eval", "runInContext", "runInNewContext", "runInThisContext"] and
          callNode.asExpr() = ce
        )
        or
        // Catches new Function(...) constructors
        exists(NewExpr ne |
          ne.getCalleeName() = "Function" and
          callNode.asExpr() = ne
        )
      ) and
      // Map the sink to the first argument of the execution call
      sink.asExpr() = callNode.asExpr().(InvokeExpr).getArgument(0)
    )
  }
}

module ReverseShellFlow = TaintTracking::Global<ReverseShellConfig>;
import ReverseShellFlow::PathGraph

from ReverseShellFlow::PathNode source, ReverseShellFlow::PathNode sink
where ReverseShellFlow::flowPath(source, sink)
select 
 
  sink.getNode().getLocation().getFile().getRelativePath() as filePath,
  source.getNode().getLocation().getStartLine() as startLine, 
  sink.getNode().getLocation().getEndLine() as endLine,
  "Malicious execution of data from $@." +source.getNode() + "this source" as message 