
/**
 * @name Remote response reaches dynamic code execution
 * @description Detects possible taint flow from a request callback
 *              response body to a dynamic Function or eval sink.
 * @kind path-problem
 * @problem.severity error
 * @id js/network-response-dynamic-execution
 * @tags security
 *       external/cwe/cwe-094
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking

class NetworkResponseSource extends DataFlow::Node {
  NetworkResponseSource() {
    exists(DataFlow::CallNode call |
      call.getCalleeName() in ["req", "request"] and
      this = call.getABoundCallbackParameter(1, 2) or
      exists(ClientRequest req | this = req.getAResponseDataNode())
    )
  }
}

class DynamicExecutionSink extends DataFlow::Node {
  DynamicExecutionSink() {
    exists(DataFlow::NewNode n |
      n.getCalleeNode().toString().matches("%Function%") and
      this = n.getArgument(1)
    )
    or
    exists(DataFlow::CallNode c |
      c.getCalleeName() = "eval" and
      this = c.getArgument(0)
    )
  }
}

module NetworkRCEConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof NetworkResponseSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof DynamicExecutionSink
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, DataFlow::Node node2
  ) {
    none()
  }
}

module NetworkRCEFlow = TaintTracking::Global<NetworkRCEConfig>;

import NetworkRCEFlow::PathGraph

from NetworkRCEFlow::PathNode source,
     NetworkRCEFlow::PathNode sink
where NetworkRCEFlow::flowPath(source, sink)
select
  sink.getNode().getLocation().getFile().getRelativePath() as filePath,
  source.getNode().getLocation().getStartLine() as startLine,
  sink.getNode().getLocation().getEndLine() as endLine,
  "Malicious execution of data from $@." +
    source.getNode() + "this source" as message
