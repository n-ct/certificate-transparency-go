package feeder

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "os"
	_ "os/signal"
	_ "sync"
	_ "syscall"
	"time"

	_ "github.com/coreos/etcd/clientv3"
	_ "github.com/coreos/etcd/clientv3/naming"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	_ "github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	_ "github.com/google/trillian/monitoring/opencensus"
	"github.com/google/trillian/monitoring/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tomasen/realip"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/balancer/roundrobin"
	_ "google.golang.org/grpc/naming"

	// Register PEMKeyFile, PrivateKey and PKCS11Config ProtoHandlers
	_ "github.com/google/trillian/crypto/keys/der/proto"
	_ "github.com/google/trillian/crypto/keys/pem/proto"
	_ "github.com/google/trillian/crypto/keys/pkcs11/proto"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
)

var (
	logID      = flag.Int64("log_id", 4963881968625083525, "Trillian LogID to populate.")
	logConfig  = flag.String("log_config", "./trillian/multilog/demo-script.cfg", "File holding log config in text proto format")
	rpcBackend = flag.String("log_rpc_server", "13.90.199.163:8090", "Backend specification; comma-separated list or etcd service name (if --etcd_servers specified). If unset backends are specified in config (as a LogMultiConfig proto)")
	// rpcDeadline        = flag.Duration("rpc_deadline", time.Second*10, "Deadline for backend RPC requests")
	rpcDeadline    = time.Second * 10
	getSTHInterval = flag.Duration("get_sth_interval", time.Second*180, "Interval between internal get-sth operations (0 to disable)")
	httpEndpoint   = flag.String("http_endpoint", "0.0.0.0:6965", "Endpoint for HTTP (host:port)")
	// maskInternalErrors = flag.Bool("mask_internal_errors", false, "Don't return error strings with Internal Server Error HTTP responses")
	maskInternalErrors = false
	quotaRemote        = flag.Bool("quota_remote", true, "Enable requesting of quota for IP address sending incoming requests")
	quotaIntermediate  = flag.Bool("quota_intermediate", true, "Enable requesting of quota for intermediate certificates in sumbmitted chains")
	// handlerPrefix      = flag.String("handler_prefix", "", "If set e.g. to '/logs' will prefix all handlers that don't define a custom prefix")
	handlerPrefix = ""
)

const unknownRemoteUser = "UNKNOWN_REMOTE"

type Mouth struct {
	keepConnAlive *grpc.ClientConn
	tladmin       trillian.TrillianAdminClient
	tlclient      trillian.TrillianLogClient
	ClientToTree  map[string]*trillian.Tree
}

/// Dial Backend
func InitializeFeeder(ctx context.Context, rpcEndpoint string, logUrls []string) *Mouth {
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock()}
	glog.Infof("Dialling backend: /%v/ with opts /%v/", rpcBackend, dialOpts)
	conn, err := grpc.Dial(rpcEndpoint, dialOpts...)
	if err != nil {
		glog.Exitf("Could not dial RPC server: %v: %v", rpcBackend, err)
	} else {
		glog.Infof("Successfully dialed Trillian RPC server: %v", rpcBackend)
	}
	defer conn.Close()

	mouth := &Mouth{
		keepConnAlive: conn,
		tladmin:       trillian.NewTrillianAdminClient(conn),
		tlclient:      trillian.NewTrillianLogClient(conn),
		ClientToTree:  make(map[string]*trillian.Tree),
	}
	var tree *trillian.Tree
	for i, v := range logUrls {
		tree, err = CreateAndInitTree(ctx, mouth)
		if err != nil {
			glog.Fatalf("could not create tree(%v|%v): %+v", i, v, err)
		}
		mouth.ClientToTree[v] = tree
		glog.Infof("Created %v of %v trees", i+1, len(logUrls))
	}
	return mouth
}

func CreateAndInitTree(ctx context.Context, mouth *Mouth) (*trillian.Tree, error) {
	req := newCreateDefaultTreeRequest()
	if req == nil {
		glog.Warningf("CANNOT CREATE NEW TREE REQUEST")
		return nil, fmt.Errorf("Could not create new tree request")
	}

	tree, err := client.CreateAndInitTree(ctx, req, mouth.tladmin, nil, mouth.tlclient)
	if err != nil {
		glog.Warningf("CANNOT CREATE AND INIT TREE: %+v", err)
		return nil, fmt.Errorf("Could not create and init tree: %+v", err)
	}

	return tree, nil
}

func Feed(ctx context.Context, gossipReq ct.GossipExchangeRequest, mouth *Mouth) error {
	flag.Parse()

	tl := &trillian.LogLeaf{LeafValue: []byte("somecustomdata1212121")}
	q := &trillian.QueueLeafRequest{LogId: mouth.ClientToTree[gossipReq.LogURL].TreeId, Leaf: tl}
	r, err := mouth.tlclient.QueueLeaf(ctx, q)
	if err != nil{
		glog.Fatalf("Could not queue leaf:\n----- %+v\n------", err)
	}
	glog.Infof("Data \\Was/ QUEUED!: \n%+s\n---------\n%+q\n", q, r)

	return nil
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

func newCreateDefaultTreeRequest() *trillian.CreateTreeRequest {
	sa := sigpb.DigitallySigned_ECDSA
	ctr := &trillian.CreateTreeRequest{Tree: &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_LOG,
		HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
		HashAlgorithm:      sigpb.DigitallySigned_SHA256,
		SignatureAlgorithm: sigpb.DigitallySigned_SignatureAlgorithm(sa),
		DisplayName:        "Gossiper",
		Description:        "TestCreated@" + time.Now().String(),
		MaxRootDuration:    ptypes.DurationProto(0),
	}}
	glog.Infof("Creating tree %+v", ctr.Tree)

	ctr.KeySpec = &keyspb.Specification{}
	switch sigpb.DigitallySigned_SignatureAlgorithm(sa) {
	case sigpb.DigitallySigned_ECDSA:
		ctr.KeySpec.Params = &keyspb.Specification_EcdsaParams{
			EcdsaParams: &keyspb.Specification_ECDSA{},
		}
	case sigpb.DigitallySigned_RSA:
		ctr.KeySpec.Params = &keyspb.Specification_RsaParams{
			RsaParams: &keyspb.Specification_RSA{},
		}
	default:
		return nil
	}
	return ctr
}
