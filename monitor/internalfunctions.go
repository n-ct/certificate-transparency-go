//DAS: these are the internal functions




package monitor

import (
	"github.com/google/trillian/merkle"
	// DAS:this is for any functions within logclient.go that
	// the verify consistency and inclusion proofs need

	"bytes"
	"errors"
	"fmt"
	"math/bits"

	"github.com/google/trillian/merkle/hashers"
	//check out the gossip folder

	"github.com/google/certificate-transparency-go/client"          //for the functions of logclient.go
	"github.com/google/certificate-transparency-go/client/ctclient" //for the functions
)


//TODO: create types for log_id_list, mirroring_list, treestate_list, monitors_list
	//log_id is int64
	//treestate is inf32


type misbehaviorProof struct {
	log_id int64 // does this need to be a different variable? Since log_id is used elsewhere
	consistency_proof int64 //does this have to be two snapshots
	sth_original, sth_expected, sth_recieved  []ct.SignedTreeHead // certificate-transparency-go/types.go:292



}
/*
func ObtainCurrentView(log_id_list TYPEHERE, mirroring_list TYPEhere, treestate_list TYPEHERE ){

}
*/


func UpdateView(log_id int, treestate int, mirroring is false){
	//this is the get-sth.... the function is in logclient.go line 154


}


func GossipMisbehaviorProof






//DAS: This code is from trillian/merkle/log_verifier.go:48
// VerifyInclusionProof verifies the correctness of the proof given the passed
// in information about the tree and leaf.
func (v LogVerifier) VerifyInclusionProof(leafIndex, treeSize int64, proof [][]byte, root []byte, leafHash []byte) error {
	calcRoot, err := v.RootFromInclusionProof(leafIndex, treeSize, proof, leafHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(calcRoot, root) {
		return RootMismatchError{
			CalculatedRoot: calcRoot,
			ExpectedRoot:   root,
		}
	}
	return nil
}

func (v LogVerifier) VerifyConsistencyProof(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error {
	switch {
	case snapshot1 < 0:
		return fmt.Errorf("snapshot1 (%d) < 0 ", snapshot1)
	case snapshot2 < snapshot1:
		return fmt.Errorf("snapshot2 (%d) < snapshot1 (%d)", snapshot1, snapshot2)
	case snapshot1 == snapshot2:
		if !bytes.Equal(root1, root2) {
			return RootMismatchError{
				CalculatedRoot: root1,
				ExpectedRoot:   root2,
			}
		} else if len(proof) > 0 {
			return errors.New("root1 and root2 match, but proof is non-empty")
		}
		return nil // Proof OK.
	case snapshot1 == 0:
		// Any snapshot greater than 0 is consistent with snapshot 0.
		if len(proof) > 0 {
			return fmt.Errorf("expected empty proof, but got %d components", len(proof))
		}
		return nil // Proof OK.
	case len(proof) == 0:
		return errors.New("empty proof")
	}

	inner, border := decompInclProof(snapshot1-1, snapshot2)
	shift := bits.TrailingZeros64(uint64(snapshot1))
	inner -= shift // Note: shift < inner if snapshot1 < snapshot2.

	// The proof includes the root hash for the sub-tree of size 2^shift.
	seed, start := proof[0], 1
	if snapshot1 == 1<<uint(shift) { // Unless snapshot1 is that very 2^shift.
		seed, start = root1, 0
	}
	if got, want := len(proof), start+inner+border; got != want {
		return fmt.Errorf("wrong proof size %d, want %d", got, want)
	}
	proof = proof[start:]
	// Now len(proof) == inner+border, and proof is effectively a suffix of
	// inclusion proof for entry |snapshot1-1| in a tree of size |snapshot2|.

	// Verify the first root.
	ch := hashChainer(v)
	mask := (snapshot1 - 1) >> uint(shift) // Start chaining from level |shift|.
	hash1 := ch.chainInnerRight(seed, proof[:inner], mask)
	hash1 = ch.chainBorderRight(hash1, proof[inner:])
	if !bytes.Equal(hash1, root1) {
		return RootMismatchError{
			CalculatedRoot: hash1,
			ExpectedRoot:   root1,
		}
	}

	// Verify the second root.
	hash2 := ch.chainInner(seed, proof[:inner], mask)
	hash2 = ch.chainBorderRight(hash2, proof[inner:])
	if !bytes.Equal(hash2, root2) {
		return RootMismatchError{
			CalculatedRoot: hash2,
			ExpectedRoot:   root2,
		}
	}

	return nil // Proof OK.
}

// this is where the sth check isand also where the ct.signedtreehead is referenced
//certificate-transparency-go/client/logclient.go

//logid
//  certificate-transparency-go/logid/logid.go

//for the inclusion proof it is also called the merkle audit proof