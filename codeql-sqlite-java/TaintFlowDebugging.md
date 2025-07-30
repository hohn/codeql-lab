# Debugging with partial flow

When there is a missing node on a path that you are trying to define there are 2 ways to figure out what the missing node is:

1) Using the predicate `any()` in place of a sink. [QL documentation](https://codeql.github.com/docs/writing-codeql-queries/debugging-data-flow-queries-using-partial-flow/#partial-flow) explains the details of why this is not too performat, but it works fine when an application is small or you have a confident idea of what the missing piece is and really only need a small quick check to help out.

2) [Partial flow](https://codeql.github.com/docs/writing-codeql-queries/debugging-data-flow-queries-using-partial-flow/#debugging-data-flow-queries-using-partial-flow) dataflow configuration is the preferred, more thorough solution for debugging dataflow. This configuration can allow you to see the partial pathes either forward or backward through the application and answer a question of "how far does the current path get?". This is extremely useful for cases where a node is missing in the dataflow graph, and an additional taint step is required to model the full problem.


The QL below demonstrates what partial debugging would look like, on [this Java SqlInjection sample](https://github.com/advanced-security/codeql-workshops-staging/tree/master/java/codeql-dataflow-sql-injection).

```
/**
 * @name introduction workshop
 * @description Sample SQL Injection problem
 * @id test
 * @kind path-problem
 * @problem.severity warning
 */

import java

class ReadLineSource extends Source {
  ReadLineSource() { this.getMethod().hasQualifiedName("java.io", "Console", "readLine") }
}

abstract class Source extends MethodCall { }

class Sink extends MethodCall {
  Sink() { this.getMethod().hasQualifiedName("java.sql", "Statement", "executeUpdate") }
}

import semmle.code.java.dataflow.TaintTracking

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof Source }

  predicate isSink(DataFlow::Node sink) {
    exists(Sink sink2 | sink.asExpr() = sink2.getArgument(_))
    //previous debug technique shown , not ideal though
    //any()
  }

  //this is the necessary flow step to close the gap
  //   predicate isAdditionalFlowStep(DataFlow::Node inNode, DataFlow::Node outNode) {
  //     exists(MethodCall mc |
  //       outNode.asExpr() = mc and
  //       mc.getMethod().hasQualifiedName("java.lang", "String", "format") and
  //       inNode.asExpr() = mc.getAnArgument()
  //     )
  //   }
}

int explorationLimit() { result = 100 }

module MyFlow = DataFlow::Global<MyFlowConfiguration>;

module MyPartialFlow = MyFlow::FlowExplorationFwd<explorationLimit/0>;

import MyPartialFlow::PartialPathGraph

from MyPartialFlow::PartialPathNode start, MyPartialFlow::PartialPathNode end
where MyPartialFlow::partialFlow(start, end, _)
select end, start, end, "Sql injection from $@", start, "here"
```