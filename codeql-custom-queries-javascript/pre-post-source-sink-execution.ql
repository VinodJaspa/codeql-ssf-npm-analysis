/**
 * @name Pre-install and post-install script sources to malicious sinks
 * @description Detects flows where pre-install and post-install scripts defined
 * in package.json lead to potentially malicious operations like command execution
 * or data exfiltration.
 * @id js/pre-post-source-sink-execution
 * @tags security external/cwe/cwe-20 external/mitre/attack/T1195
 * @kind table
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking

/**
 * Checks if code contains suspicious network patterns
 */
predicate hasSuspiciousNetworkPattern(Expr e) {
  exists(StringLiteral host |
    host = e.getAChild*() and
    (
      host.getValue().matches("%.pipedream.%") or
      host.getValue().matches("%.burpcollaborator.%") or
      host.getValue().matches("%.ngrok.%") or
      host.getValue().matches("%.requestbin.%") or
      // Hex/obfuscated looking domains
      host.getValue().regexpMatch("[a-f0-9]{20,}.*") or
      // IP addresses in requests
      host.getValue().regexpMatch("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
    )
  )
}

/**
 * Checks if an expression involves encoding operations
 */
predicate involvesEncoding(Expr e) {
  exists(CallExpr call | call = e or call = e.getAChild*() |
    call.getCalleeName() in ["stringify", "from", "encode", "btoa"]
  )
  or
  exists(MethodCallExpr mce | mce = e or mce = e.getAChild*() |
    mce.getMethodName() in ["toString", "toJSON", "serialize"]
  )
}

module LifecycleToMaliciousSinkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    //from preinstall/postinstall scripts script is stated in package.json
    exists(PackageJson pj, string scriptStr, string fileName |
      (
        pj.getScripts().getPropValue("preinstall").(JsonPrimitiveValue).getStringValue() = scriptStr or
        pj.getScripts().getPropValue("postinstall").(JsonPrimitiveValue).getStringValue() =
          scriptStr
      ) and
      fileName = scriptStr.regexpCapture("node\\s+([^\\s]+\\.js).*", 1) and
      source.getFile().getRelativePath().matches("%" + fileName)
    )
    or
    // Detect access to process.env (sensitive data)
    exists(PropAccess pa |
      pa.getBase().(GlobalVarAccess).getName() = "process" and
      pa.getPropertyName() = "env" and
      source = DataFlow::valueNode(pa)
    )
    or
    // Handle obfuscated access: process[someCall(...)] where call returns "env"
    exists(IndexExpr ie, DataFlow::CallNode ce |
      ie.getBase().(GlobalVarAccess).getName() = "process" and
      ie.getIndex() = ce.asExpr() and
      // Heuristic: The function is called with a number/hex literal (obfuscation pattern)
      ce.getAnArgument().asExpr() instanceof Literal and
      // Heuristic: The function is defined in the same file (local obfuscation)
      exists(Function f |
        f = ce.getACallee() and
        f.getFile() = ce.asExpr().getFile()
      ) and
      source = DataFlow::valueNode(ie)
    )
    or
    // Also catch just process[call()] even without checking the function
    exists(IndexExpr ie |
      ie.getBase().(GlobalVarAccess).getName() = "process" and
      ie.getIndex() instanceof CallExpr and
      source = DataFlow::valueNode(ie)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Command execution sinks
    exists(CallExpr call |
      (
        call.getCalleeName() = "exec" or
        call.getCalleeName() = "execSync" or
        call.getCalleeName() = "spawn" or
        call.getCalleeName() = "spawnSync" or
        call.getCalleeName() = "runInThisContext"
      ) and
      sink = DataFlow::valueNode(call.getArgument(0))
    )
    or
    exists(MethodCallExpr mce |
      (
        mce.getMethodName() = "exec" or
        mce.getMethodName() = "execSync" or
        mce.getMethodName() = "spawn" or
        mce.getMethodName() = "spawnSync" or
        mce.getMethodName() = "runInThisContext"
      ) and
      sink = DataFlow::valueNode(mce.getArgument(0))
    )
    or
    // Network writes with encoding (likely exfiltration)
    // Standard .write() calls
    exists(MethodCallExpr mce |
      mce.getMethodName() = "write" and
      sink = DataFlow::valueNode(mce.getArgument(0)) and
      (
        involvesEncoding(mce.getArgument(0)) or
        hasSuspiciousNetworkPattern(mce)
      )
    )
    or
    // Obfuscated .write() calls: obj[obfuscatedCall()](...)
    exists(CallExpr call |
      call.getNumArgument() > 0 and
      // The callee is an index expression (like req[a0_0x7e16ee(0x1d2)])
      call.getCallee() instanceof IndexExpr and
      sink = DataFlow::valueNode(call.getArgument(0)) and
      (
        involvesEncoding(call.getArgument(0)) or
        hasSuspiciousNetworkPattern(call)
      )
    )
    or
    // Network end() with encoded data
    exists(MethodCallExpr mce |
      mce.getMethodName() = "end" and
      mce.getNumArgument() > 0 and
      sink = DataFlow::valueNode(mce.getArgument(0)) and
      (
        involvesEncoding(mce.getArgument(0)) or
        hasSuspiciousNetworkPattern(mce)
      )
    )
    or
    // Obfuscated .end() calls
    exists(CallExpr call |
      call.getNumArgument() > 0 and
      call.getCallee() instanceof IndexExpr and
      // If it takes no arguments or only one, likely end()
      call.getNumArgument() <= 1 and
      sink = DataFlow::valueNode(call.getArgument(0)) and
      involvesEncoding(call.getArgument(0))
    )
    or
    // HTTP request arguments in suspicious contexts
    exists(MethodCallExpr mce |
      (
        mce.getMethodName() = "request" or
        mce.getMethodName() = "get" or
        mce.getMethodName() = "post"
      ) and
      hasSuspiciousNetworkPattern(mce) and
      (
        sink = DataFlow::valueNode(mce.getArgument(0)) or
        sink = DataFlow::valueNode(mce.getArgument(1))
      )
    )
    or
    // File writes of encoded sensitive data
    exists(MethodCallExpr mce |
      (
        mce.getMethodName() = "writeFile" or
        mce.getMethodName() = "writeFileSync" or
        mce.getMethodName() = "appendFile" or
        mce.getMethodName() = "appendFileSync"
      ) and
      sink = DataFlow::valueNode(mce.getArgument(1)) and
      involvesEncoding(mce.getArgument(1))
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // Logging operations (benign use of process.env)
    exists(MethodCallExpr mce |
      (
        mce.getMethodName() = "log" or
        mce.getMethodName() = "info" or
        mce.getMethodName() = "debug" or
        mce.getMethodName() = "warn" or
        mce.getMethodName() = "error"
      ) and
      node.asExpr() = mce.getAnArgument()
    )
    or
    // Environment variable checks in conditions
    exists(IfStmt ifStmt | node.asExpr() = ifStmt.getCondition().getAChild*())
    or
    // Comparison operations (checking env values)
    exists(BinaryExpr be |
      be.getOperator() in ["==", "===", "!=", "!=="] and
      node.asExpr() = be.getAnOperand()
    )
    or
    // Logical OR for default values (process.env.PORT || 3000)
    exists(LogicalBinaryExpr lbe |
      lbe.getOperator() = "||" and
      node.asExpr() = lbe.getLeftOperand()
    )
    or
    // String replacement/substitution (config variable interpolation)
    exists(MethodCallExpr mce |
      (
        mce.getMethodName() = "replace" or
        mce.getMethodName() = "replaceAll" or
        mce.getMethodName() = "match" or
        mce.getMethodName() = "exec"
      ) and
      node.asExpr() = mce.getReceiver()
    )
    or
    // Assignment to configuration objects (not exfiltration)
    exists(AssignExpr assign, VarAccess va |
      assign.getLhs() = va and
      (
        va.getVariable().getName().toLowerCase().matches("%config%") or
        va.getVariable().getName().toLowerCase().matches("%options%") or
        va.getVariable().getName().toLowerCase().matches("%settings%")
      ) and
      node.asExpr() = assign.getRhs()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Property/index access - critical for process.env tracking
    exists(PropAccess pa |
      node1 = DataFlow::valueNode(pa.getBase()) and
      node2 = DataFlow::valueNode(pa)
    )
    or
    exists(IndexExpr ie |
      node1 = DataFlow::valueNode(ie.getBase()) and
      node2 = DataFlow::valueNode(ie)
    )
    or
    // String concatenation
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      (
        node1 = DataFlow::valueNode(be.getLeftOperand()) or
        node1 = DataFlow::valueNode(be.getRightOperand())
      ) and
      node2 = DataFlow::valueNode(be)
    )
    or
    // Template literals
    exists(TemplateLiteral tl |
      node1 = DataFlow::valueNode(tl.getAnElement()) and
      node2 = DataFlow::valueNode(tl)
    )
    or
    // Array join
    exists(MethodCallExpr mce |
      mce.getMethodName() = "join" and
      node1 = DataFlow::valueNode(mce.getReceiver()) and
      node2 = DataFlow::valueNode(mce)
    )
    or
    // JSON.stringify - crucial for exfiltration detection
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "stringify" and
      node1 = call.getAnArgument() and
      node2 = call
    )
    or
    // Buffer.from
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "from" and
      node1 = call.getAnArgument() and
      node2 = call
    )
    or
    // .toString() method
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "toString" and
      node1 = call.getReceiver() and
      node2 = call
    )
    or
    // Track through local obfuscation functions
    exists(DataFlow::CallNode call, Function func |
      func = call.getACallee() and
      func.getFile() = call.asExpr().getFile() and
      func.getNumParameter() <= 2 and
      node1 = call.getAnArgument() and
      node2 = call
    )
  }
}

module LifecycleToMaliciousSinkFlow = TaintTracking::Global<LifecycleToMaliciousSinkConfig>;

from DataFlow::Node src, DataFlow::Node sink
where LifecycleToMaliciousSinkFlow::flow(src, sink)
select sink.asExpr().getLocation().getFile().getRelativePath() as filePath,
  src.asExpr().getLocation().getStartLine() as startLine,
  sink.asExpr().getLocation().getEndLine() as endLine,
  "Source path " + src.asExpr().toString() + " flows into sensitive operation" as message
