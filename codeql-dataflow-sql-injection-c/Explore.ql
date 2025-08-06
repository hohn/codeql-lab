/**
* @name SQLI Vulnerability
* @description Using untrusted strings in a sql query allows sql injection attacks.
* @ kind path-problem
* @id cpp/sqlivulnerable
* @problem.severity warning
*/

import cpp
// import semmle.code.cpp.dataflow.new.TaintTracking


from FunctionCall exec
where exec.getTarget().getName().matches("%snprintf%")
select exec, exec.getTarget().getName(), exec.getAnArgument()
