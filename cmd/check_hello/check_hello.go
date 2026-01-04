package main

import (
	"fmt"
	tls "github.com/sardanioss/utls"
)

func main() {
	// Check available Chrome HelloIDs
	fmt.Println("Chrome HelloIDs available in uTLS:")
	fmt.Printf("HelloChrome_120: %+v\n", tls.HelloChrome_120)
	fmt.Printf("HelloChrome_120_PQ: %+v\n", tls.HelloChrome_120_PQ)
	fmt.Printf("HelloChrome_131: %+v\n", tls.HelloChrome_131)
	fmt.Printf("HelloChrome_133: %+v\n", tls.HelloChrome_133)
}
