# gorados

The lightweight client to interact with the RADOS cluster purely implemented with golang.

## Motivation

When your application interacts with ceph, there will be needs to connect to the RADOS cluster in addition to S3(radosgw), file system(cephfs) and raw device(rbd).
Thanks for the librados, which provides the common API to fullfil the demand mentioned before, and if you develop your application with Golang, there is also a project called [go-ceph](https://github.com/ceph/go-ceph) providing a librados binding with cgo.
It is the first solution for applications to connect RADOS cluster directly. It's easy to use and works OK and I used it in one project, but there are some problems annoying me:

- The librados heavily depends on the low-level messenger implementation and it will create 14 new threads if you just creating a connection to the RADOS cluster(use pstack on centos7). It causes the problem [here](https://stackoverflow.com/questions/47466139/there-are-many-threads-reserved-while-golang-application-running?answertab=votes#tab-top) when the golang runtime and librados work together.
- It must close explicitly if you create a connection to the RADOS cluster because golang runtime does not manage it. So there needs to create a connection pool for management to avoid the waste of resource of the RADOS cluster. However, it increases complexity and needs a strong testing.
- The application must depend on the librados when compiling and running which decreases the portability and maintainability compared with common static-built golang program.

There are also some other problems if you want to build a elegant solution for you golang application interacting with the RADOS cluster. So the idea for gorados comes out. There is every reason to implement the gorados - pure go client to connect the RADOS cluster - to make ceph as a backend storage in production-level golang project directly.

## Implementation

The implementation key points are:

- Create and manage the TCP/IP socket to the RADOS cluster.
- Implement the cephx protocol to connect to the monitor.
- Create and send the specific message to the RADOS cluster and parse the result.
- Just process the client-side matters concerned.

It implements the framework to connect to the ceph-mon and can send monitor commands to make some control to the cluster. Further functions sush as interaction to the ceph-osd need more development.

## Quick Start

The following code snippet shows how to get the status of the RADOS cluster:

```golang
import (
	"context"
	"encoding/json"
	"log"

	"github.com/oshynsong/gorados"
)

func main() {
	ctx := context.Backgroud()

	// 1. prepare to create a connection to ceph-mon
	c := gorados.NewRadosConn(ctx, gorados.MON)

	// 2. dial the TCP socket
	if err := c.Dial("tcp", "10.10.10.12:6789"); err != nil {
		log.Fatal(err)
	}

	// 3. connect to the ceph-mon with the cephx protocol
	if err := c.Connect("AQAXzGxdPT7BIBAAVz8zMAw+70YdylosZcijng=="); err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// 4. send a monitor command
	cmd, _ := json.Marshal(map[string]interface{}{
		"prefix": "status",
		"format": "text",
	})
	res, err := c.MonCommand(cmd)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(res))
}
```

## Documentation

Reference locates on the golang.org [here](https://godoc.org/github.com/oshynsong/gorados).

## Contribution

It needs more development and improvement to make gorados strong and stable. Just fork this [repository](https://github.com/oshynsong/gorados) and make pull request.
