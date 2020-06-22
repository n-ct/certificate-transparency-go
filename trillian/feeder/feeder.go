// Copyright 2020. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package feeder allows monitors to save gossiped data for multiple CT SourceLogs to trillian
package feeder

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"google.golang.org/grpc"

	// Register PEMKeyFile, PrivateKey and PKCS11Config ProtoHandlers
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
)

const millisPerNano int64 = 1000 * 1000
const leafIndex = 0

// A Portal allows the feeder to connect to trillian and feed data for a log to its tree
type Portal struct {
	ClientToTreeMap map[string]*trillian.Tree
	RPCEndpoint     string
}

// DialTrillian connects to a trillian server and keeps the connection open
func DialTrillian(ctx context.Context, rpcEndpoint string) (*grpc.ClientConn, error) {
	go func() {
		<-ctx.Done()
		glog.Exitf("DialTrillian: Abandoning gRPC call to Trillian backend")
	}()

	glog.Infof("Dialing Trillian RPC server: %v", rpcEndpoint)
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock()}
	conn, err := grpc.Dial(rpcEndpoint, dialOpts...)
	if err != nil {
		glog.Warningf("Could not dial RPC server: %v: %v", rpcEndpoint, err)
		return nil, fmt.Errorf("Could not dial RPC server")
	}
	glog.Infof("Successfully dialed Trillian RPC server: %v", rpcEndpoint)
	return conn, nil
}

// InitializeFeeder creates a tree for every source log
func InitializeFeeder(ctx context.Context, rpcEndpoint string, logUrls []string) *Portal {
	if len(rpcEndpoint) == 0 {
		glog.Exitf("no RPC endpoint specified")
	}
	conn, err := DialTrillian(ctx, rpcEndpoint)
	if err != nil {
		glog.Exitf("Could not initilize feeder because trillian is unreachable: %v", err)
	}
	defer conn.Close()

	clientToTreeMap, err := createAndInitTrees(ctx, conn, logUrls)
	if err != nil {
		glog.Fatalf("could not create tree %+v", err)
	}
	return &Portal{
		RPCEndpoint:     rpcEndpoint,
		ClientToTreeMap: clientToTreeMap,
	}
}

func createAndInitTrees(ctx context.Context, conn *grpc.ClientConn, logUrls []string) (map[string]*trillian.Tree, error) {
	tladmin, tlclient := trillian.NewTrillianAdminClient(conn), trillian.NewTrillianLogClient(conn)
	clientToTreeMap := make(map[string]*trillian.Tree)
	req := newCreateDefaultTreeRequest()
	if req == nil {
		glog.Warningf("CANNOT CREATE NEW TREE REQUEST")
		return nil, fmt.Errorf("Could not create new tree request")
	}

	for i, v := range logUrls {
		tree, err := client.CreateAndInitTree(ctx, req, tladmin, nil, tlclient)
		if err != nil {
			glog.Warningf("CANNOT CREATE AND INIT TREE: (%v|%v): %+v", i, v, err)
		}
		clientToTreeMap[v] = tree
	}
	return clientToTreeMap, nil
}

// Feed data from a gossip reqest to the trillian server referenced in the Portal
func Feed(ctx context.Context, gossipReq ct.GossipExchangeRequest, portal *Portal) error {
	conn, err := DialTrillian(ctx, portal.RPCEndpoint)
	if err != nil {
		return err
	}
	tlclient := trillian.NewTrillianLogClient(conn)

	leaf, err := buildLogLeafForGossiper(gossipReq, portal)
	if err != nil {
		return fmt.Errorf("[Feed] failed to build LogLeaf: %s", err)
	}

	req := &trillian.QueueLeafRequest{
		LogId: portal.ClientToTreeMap[gossipReq.LogURL].TreeId,
		Leaf:  &leaf,
	}
	resp, err := tlclient.QueueLeaf(ctx, req)
	if err != nil {
		return fmt.Errorf("Could not queue leaf:\n----- %+v\n------", err)
	}
	glog.Infof("Data was queued for %v:\n---Resp---\n%+v", gossipReq.LogURL, resp)

	return nil
}

func buildLogLeafForGossiper(gossipReq ct.GossipExchangeRequest, portal *Portal) (trillian.LogLeaf, error) {
	// Get the current time in the form used throughout RFC6962, namely milliseconds since Unix
	// epoch, and use this throughout.
	timeMillis := uint64(time.Now().UnixNano() / millisPerNano)
	gossipEntryData := []byte(fmt.Sprintf("%v", gossipReq))

	leafData, err := tls.Marshal(ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			EntryType: ct.GossipLogEntryType,
			Timestamp: timeMillis,
			GossipEntry: &ct.GossipEntry{
				Data: gossipEntryData,
			},
		},
	})
	if err != nil {
		glog.Warningf("buildLogLeafForGossiper: Failed to serialize Merkle leaf: %v", err)
		return trillian.LogLeaf{}, err
	}

	leafIDHash := sha256.Sum256(gossipEntryData)
	return trillian.LogLeaf{
		LeafValue:        leafData,
		ExtraData:        nil,
		LeafIndex:        leafIndex,
		LeafIdentityHash: leafIDHash[:],
	}, nil
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
