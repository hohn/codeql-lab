/**
 * @name Illustrations
 * @description Illustrations of some codeql classes.
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import QueryInjectionFlow::PathGraph

// Find starting points -- UserInput etc. -- from
// ql/cpp/ql/src/Security/CWE/CWE-089/SqlTainted.ql 

from UserInput ui, QueryInjectionSink qsi
select ui, qsi
