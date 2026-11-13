/**
 * @name OS fingerprinting data exfiltration (scoped baseline)
 * @description Flows from OS, environment, or file data to modeled network requests
 * @kind table
 * @id js/os-fingerprinting-exfiltration
 * @tags security
 *       external/cwe/cwe-506
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking

/** `process.env` (the whole object). */
predicate isProcessEnv(Expr e) {
  e.(PropAccess).getPropertyName() = "env" and
  e.(PropAccess).getBase().(GlobalVarAccess).getName() = "process"
}

/** Env variables that are sources on their own. */
string sensitiveEnvName() { result in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP"] }

module OSFingerprintingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // os.* fingerprint calls, however the module was imported (require, import, destructuring)
    exists(string m |
      m in [
          "userInfo", "cpus", "homedir", "hostname", "networkInterfaces", "platform", "release",
          "type", "arch"
        ] and
      source = DataFlow::moduleMember("os", m).getACall()
    )
    or
    // the whole environment object (e.g. JSON.stringify(process.env), {...process.env})
    exists(Expr e | isProcessEnv(e) and source = DataFlow::valueNode(e))
    or
    // selected environment variables
    exists(PropAccess variable |
      isProcessEnv(variable.getBase()) and
      variable.getPropertyName() = sensitiveEnvName() and
      source = DataFlow::valueNode(variable)
    )
    or
    // file reads (sync, callback, promise) as modeled by the standard library
    source = any(FileSystemReadAccess r).getADataNode()
  }

  predicate isSink(DataFlow::Node sink) {
    // data or URL handed to a modeled HTTP client (http, https, axios, got, fetch, XHR, ...)
    exists(ClientRequest r | sink = r.getADataNode() or sink = r.getUrl())
  }

  predicate isBarrier(DataFlow::Node n) {
    // reading ONE ordinary env variable must not carry the whole-object taint onwards;
    // the sensitive ones above stay sources
    exists(PropAccess pa |
      pa = n.asExpr() and
      isProcessEnv(pa.getBase()) and
      not pa.getPropertyName() = sensitiveEnvName()
    )
    or
    // do not propagate through vendored or minified code
    n.getTopLevel().isMinified()
    or
    n.getTopLevel().getFile().getRelativePath().regexpMatch(".*(node_modules|/vendor/).*")
  }
}

module OSFingerprintingFlow = TaintTracking::Global<OSFingerprintingConfig>;
from OSFingerprintingFlow::PathNode src, OSFingerprintingFlow::PathNode sink
where OSFingerprintingFlow::flowPath(src, sink)
select sink.getNode().getLocation().getFile().getRelativePath() as filePath,
  src.getNode().getLocation().getStartLine() as startLine,
  sink.getNode().getLocation().getEndLine() as endLine,
  "Potential OS/environment/file data exfiltration. Source: " + src.toString() + " (" +
    src.getNode().getLocation().getFile().getRelativePath() + ":" + src.getNode().getLocation().getStartLine().toString() +
    ") -> Sink: " + sink.toString() as message
