import java

// // Find the source
// class ReadLine extends MethodCall {
//     ReadLine() { 
//         exists(MethodCall g | 
//             g.getMethod().hasQualifiedName("java.io", "Console", "readLine") and
//             this = g
//         )
//     }
// }
// from ReadLine rl
// select rl

private import semmle.code.java.dataflow.FlowSources

// Find the source
class ReadLine extends RemoteFlowSource {
    ReadLine() { 
        exists(MethodCall g | 
            g.getMethod().hasQualifiedName("java.io", "Console", "readLine") and
            this.asExpr() = g
        )
    }
      override string getSourceType() { result = "readline input parameter" }     

}
from ReadLine rl
select rl

