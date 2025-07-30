/**
 * @name introduction workshop
 * @description Sample SQL Injection problem
 * @id test
 * @kind path-problem
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class ReadLineSource extends Source {
  ReadLineSource() { this.getMethod().hasQualifiedName("java.io", "Console", "readLine") }
}

abstract class Source extends MethodCall { }

class Sink extends MethodCall {
  Sink() { this.getMethod().hasQualifiedName("java.sql", "Statement", "executeUpdate") }
}

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    //exists(Source s | source.asExpr() = s)
    source.asExpr() instanceof Source
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Sink sink2 | sink.asExpr() = sink2.getArgument(_))
    //any()
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(MethodCall s |
      s.getMethod().getName() = "hypotheticalSanitizer" and
      s.getAnArgument() = node.asExpr()
    )
  }
  //   predicate isAdditionalFlowStep(DataFlow::Node inNode, DataFlow::Node outNode) {
  //     exists(MethodCall mc |
  //       outNode.asExpr() = mc and
  //       mc.getMethod().hasQualifiedName("java.lang", "String", "format") and
  //       inNode.asExpr() = mc.getAnArgument()
  //     )
  //     // exists(MethodCall mc |
  //     //   mc.getAnArgument() = inNode.asExpr() and
  //     //   outNode.asExpr() = mc
  //     // )
  //   }
}

//purposely does not find the result
module MyFlow = DataFlow::Global<MyFlowConfiguration>;

import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink, source, sink, "Potential sql injection here "
