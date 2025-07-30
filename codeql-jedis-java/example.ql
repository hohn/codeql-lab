import java
private import semmle.code.java.dataflow.ExternalFlow
private import semmle.code.java.dataflow.DataFlow

from DataFlow::Node n, string type
where sinkNode(n, type) 
and type = "code-injection"
select n, type

// // See if we have calls to eval() in the library 
// from Call c 
// where c.getCallee().hasQualifiedName("redis.clients.jedis","Jedis", "eval")
// select c
