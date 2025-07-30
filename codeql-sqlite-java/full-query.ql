/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id cpp/SQLIVulnerable
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow 

/**
 * A global data-flow configuration using modules
 */
// Note result differences between 
module InputToSQL = TaintTracking::Global<SqliFlowConfig>;
// and 
// module InputToSQL = DataFlow::Global<SqliFlowConfig>;

module SqliFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // System.console().readLine();
    exists(Call read |
      read.getCallee().getName() = "readLine" and
      read = source.asExpr()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // conn.createStatement().executeUpdate(query);
    exists(Call exec |
      exec.getCallee().getName() = "executeUpdate" and
      exec.getArgument(0) = sink.asExpr()
    )
  }

  // predicate isSanitizer(DataFlow::Node sanitizer) { none() }

  // predicate isAdditionalTaintStep(DataFlow::Node into, DataFlow::Node out) {
  //   // Extra taint step
  //   //     String.format("INSERT INTO users VALUES (%d, '%s')", id, info);
  //   // Not needed here, but may be needed for larger libraries.
  //   none()
  // }
}

// To construct the paths between sources and sinks.
import InputToSQL::PathGraph

from InputToSQL::PathNode source, InputToSQL::PathNode sink
where InputToSQL::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"
