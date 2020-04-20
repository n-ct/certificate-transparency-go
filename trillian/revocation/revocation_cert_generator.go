package revocation

import (
  "context"
  "flag"

  "github.com/golang/glog"
  "github.com/google/certificate-transparency-go/trillian/integration"
  "github.com/google/certificate-transparency-go/trillian/ctfe"
  "github.com/google/certificate-transparency-go/client"
)


// syntheticly generates certs using testdir and adds to log specified in config
// Uses multiple functions used in ct_hammer
// Only intended for a single log to be specified in logConfig
func GenerateAndAdd(numCerts int,logConfig string,httpServers string, testDir string) error {

  cfg, err := ctfe.LogConfigFromFile(*logConfig)
  if err != nil {
    glog.Exitf("Failed to read log config: %v", err)
  }

  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  generatorFactory,err := integration.SyntheticGeneratorFactory(*testDir, "")
  if err != nil {
    glog.Exitf("Failed to make cert generator: %v",err)
  }

  c := cfg[0] // Using first log only
  pool, err := integration.NewRandomPool(*httpServers, c.PublicKey, c.Prefix)
  if err != nil {
    glog.Exitf("Failed to create client pool: %v", err)
  }

  generator, err := generatorFactory(c)
  if err != nil {
    glog.Exitf("Failed to build chain generator: %v", err)
  }
  
  // Possible TODO: Parallel chain add
  for i := 0; i < numCerts; i++ {
    chain,err := generator.CertChain()
    if err != nil {
      glog.Exitf("failed to make fresh cert: %v", err)
    }
    glog.Infof("i: %d, generated new cert: %v",i,chain)

    sct, err := pool.Next().AddChain(ctx,chain)
    glog.Infof("Logged with sct = %v",sct)
    if err != nil {
      if err, ok := err.(client.RspError); ok {
        glog.Errorf("add-chain: error %v HTTP status %d body %s", err.Error(), err.StatusCode, err.Body)
      }
    }
  }

  return nil
}


