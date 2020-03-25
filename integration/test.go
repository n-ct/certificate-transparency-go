package main

import (
	"context"
	"flag"
	"net/http"
	_ "os"
	_ "os/signal"
	_ "sync"
	_ "syscall"
	"time"

	_ "github.com/coreos/etcd/clientv3"
	_ "github.com/coreos/etcd/clientv3/naming"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	_ "github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/trillian"
	_ "github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/monitoring/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/tomasen/realip"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/balancer/roundrobin"
	_ "google.golang.org/grpc/naming"

	// Register PEMKeyFile, PrivateKey and PKCS11Config ProtoHandlers
	_ "github.com/google/trillian/crypto/keys/der/proto"
	_ "github.com/google/trillian/crypto/keys/pem/proto"
	_ "github.com/google/trillian/crypto/keys/pkcs11/proto"
)

var (
	logConfig    = flag.String("log_config", "./integration/demo-script.cfg", "File holding log config in text proto format")
	rpcBackend   = flag.String("log_rpc_server", "13.90.199.163:8090", "Backend specification; comma-separated list or etcd service name (if --etcd_servers specified). If unset backends are specified in config (as a LogMultiConfig proto)")
	rpcDeadline        = flag.Duration("rpc_deadline", time.Second*10, "Deadline for backend RPC requests")
	getSTHInterval     = flag.Duration("get_sth_interval", time.Second*180, "Interval between internal get-sth operations (0 to disable)")
	httpEndpoint = flag.String("http_endpoint", "0.0.0.0:6965", "Endpoint for HTTP (host:port)")
	maskInternalErrors = flag.Bool("mask_internal_errors", false, "Don't return error strings with Internal Server Error HTTP responses")
	quotaRemote        = flag.Bool("quota_remote", true, "Enable requesting of quota for IP address sending incoming requests")
	quotaIntermediate  = flag.Bool("quota_intermediate", true, "Enable requesting of quota for intermediate certificates in sumbmitted chains")
	handlerPrefix      = flag.String("handler_prefix", "", "If set e.g. to '/logs' will prefix all handlers that don't define a custom prefix")
)

const unknownRemoteUser = "UNKNOWN_REMOTE"

func main() {
	flag.Parse()
	ctx := context.Background()

	var cfg *configpb.LogMultiConfig
	var err error
	if len(*rpcBackend) > 0 {
		var cfgs []*configpb.LogConfig
		if cfgs, err = ctfe.LogConfigFromFile(*logConfig); err == nil {
			cfg = ctfe.ToMultiLogConfig(cfgs, *rpcBackend)
		} else {
			glog.Fatal("Could not parse config: ", err)
		}
	} else {
		glog.Fatal("no rpc server address specified.")
	}

	backendMap, err := ctfe.ValidateLogMultiConfig(cfg)
	if err != nil {
		glog.Exitf("Invalid config: %v", err)
	}

	glog.CopyStandardLogTo("WARNING")
	glog.Info("**** Mock CT HTTP Server Starting ****")

	dialOpts := []grpc.DialOption{grpc.WithInsecure()}
	clientMap := make(map[string]trillian.TrillianLogClient)
	for _, backend := range backendMap {
		glog.Infof("Dialling backend: %v", backend)
		if len(backendMap) == 1 {
			// If there's only one of them we use the blocking option as we can't
			// serve anything until connected.
			dialOpts = append(dialOpts, grpc.WithBlock())
		}
		glog.Infof("Dial Options: %v", dialOpts)
		conn, err := grpc.Dial(backend.BackendSpec, dialOpts...)
		if err != nil {
			glog.Exitf("Could not dial RPC server: %v: %v", backend, err)
		} else {
			glog.Warningf("Successfully dialed Trillian RPC server: %+v", backend)
		}
		defer conn.Close()
		clientMap[backend.Name] = trillian.NewTrillianLogClient(conn)
	}

	gossiperMux := http.NewServeMux()
	corsHandler := cors.AllowAll().Handler(gossiperMux)
	http.Handle("/", corsHandler)

	// setupAndRegister
	for _, c := range cfg.LogConfigs.Config {
		inst, err := setupAndRegister(ctx, clientMap[c.LogBackendName],
			*rpcDeadline, c, gossiperMux, *handlerPrefix, *maskInternalErrors)
		if err != nil {
			glog.Exitf("Failed to set up log instance for %+v: %v", cfg, err)
		} else {
			glog.Infof("Set up and Registered:\n----- %+v\n------", cfg)
		}
		if *getSTHInterval > 0 {
			go inst.RunUpdateSTH(ctx, *getSTHInterval)
		}
	}

	for name, client := range clientMap {
		glog.Infof("Connected to Client \"%v\": %T", name, client)
	}
}

/// adapted from from ./trillian/integration/ct_server/main.go
func setupAndRegister(
	ctx context.Context, client trillian.TrillianLogClient, deadline time.Duration,
	cfg *configpb.LogConfig, mux *http.ServeMux, globalHandlerPrefix string, maskInternalErrors bool,
	) (*ctfe.Instance, error) {
	vCfg, err := ctfe.ValidateLogConfig(cfg)
	if err != nil {
		return nil, err
	}

	opts := ctfe.InstanceOptions{
		Validated:          vCfg,
		Client:             client,
		Deadline:           deadline,
		MetricFactory:      prometheus.MetricFactory{},
		RequestLog:         new(ctfe.DefaultRequestLog),
		MaskInternalErrors: maskInternalErrors,
	}
	if *quotaRemote {
		glog.Info("Enabling quota for requesting IP")
		opts.RemoteQuotaUser = func(r *http.Request) string {
			var remoteUser = realip.FromRequest(r)
			if len(remoteUser) == 0 {
				return unknownRemoteUser
			}
			return remoteUser
		}
	}
	if *quotaIntermediate {
		glog.Info("Enabling quota for intermediate certificates")
		opts.CertificateQuotaUser = ctfe.QuotaUserForCert
	}
	/// disable custom prefix
	// Full handler pattern will be of the form "/logs/yyz/ct/v1/add-chain", where "/logs" is the
	// HandlerPrefix and "yyz" is the c.Prefix for this particular log. Use the default
	// HandlerPrefix unless the log config overrides it. The custom prefix in
	// the log configuration intended for use in migration scenarios where logs
	// have an existing URL path that differs from the global one. For example
	// if all new logs are served on "/logs/log/..." and a previously existing
	// log is at "/log/..." this is now supported.
	// lhp := globalHandlerPrefix
	// if ohPrefix := cfg.OverrideHandlerPrefix; len(ohPrefix) > 0 {
	// 	glog.Infof("Log with prefix: %s is using a custom HandlerPrefix: %s", cfg.Prefix, ohPrefix)
	// 	lhp = "/" + strings.Trim(ohPrefix, "/")
	// }
	inst, err := ctfe.SetUpInstance(ctx, opts)
	if err != nil {
		return nil, err
	}
	for path, handler := range inst.Handlers {
		// mux.Handle(lhp+path, handler)
		mux.Handle(path, handler)
	}
	return inst, nil
}
