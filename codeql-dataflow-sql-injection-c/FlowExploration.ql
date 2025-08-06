/**
* @name SQLI Vulnerability
* @description Using untrusted strings in a sql query allows sql injection attacks.
* @kind path-problem
* @id cpp/sqlivulnerable
* @problem.severity warning
*/

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module SqliFlowConfig implements DataFlow::ConfigSig {

    predicate isSource(DataFlow::Node source) {
        // count = read(STDIN_FILENO, buf, BUFSIZE);
        exists(FunctionCall read |
            read.getTarget().getName() = "read" and
            (
            read.getArgument(1) = source.asDefiningArgument()
                or
            read.getArgument(1) = source.asExpr()
            )
        )
    }

    predicate isBarrier(DataFlow::Node sanitizer) { none() }

    predicate isSink(DataFlow::Node sink) {
        // rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
        exists(FunctionCall exec |
            exec.getTarget().getName() = "sqlite3_exec" and
            exec.getArgument(1) = sink.asIndirectArgument()
        )
    }
}

int explorationLimit() { result = 100 }

// We break the flow chain by switching from TaintFlow to DataFlow
module MyFlow = DataFlow::Global<SqliFlowConfig>;

module MyPartialFlow = MyFlow::FlowExplorationFwd<explorationLimit/0>;

import MyPartialFlow::PartialPathGraph

from MyPartialFlow::PartialPathNode start, MyPartialFlow::PartialPathNode end
where MyPartialFlow::partialFlow(start, end, _)
select end, start, end, "Sql injection from $@", start, "here"

// note: using the pathgraph gives a more readable output, in the form
// 'from here' 'to there' 

// This query goes up to add-user.c:80:73.  
// This indicates that the flow is not crossing the snprintf, so this is where 
// further exploration is needed.  See Explore.ql