package main

import (
  "fmt"
  "flag"
  "github.com/google/certificate-transparency-go/trillian/revocation"
)

var (
  logConfig = flag.String("log_config", "../integration/demo-script.cfg","")
  httpServers = flag.String("ct_http_servers", "localhost:6965","")
  testDir = flag.String("testdata_dir", "../testdata","")
)

func main() {
  flag.Parse()
  fmt.Println(logConfig)
}
