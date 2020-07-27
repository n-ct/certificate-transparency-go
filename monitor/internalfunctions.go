
package monitor

import (
	"bytes"
	"errors"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"math/bits"
)



//These are just test values
var log_id_list = []int64{12334, 234456, 34567}
var mirroring_list = []byte{0, 1, 0 }
var treestate_list = []int32{11,22,33}


type MisbehaviorProof struct {
	log_id int64 // QUESTION: does this need to be a different variable? Since log_id is used elsewhere
	consistency_proof int64 //QUESTION: does this have to be two snapshots like the function does. //todo: look at the what is returned from the consistency_proof
	SignedTreeheadOriginal ct.SignedTreeHead //QUESTION: does this need to be a pointer?
	SignedTreeheadExpected ct.SignedTreeHead
	SignedTreeheadRecieved ct.SignedTreeHead //ct.SignedTreeHead is from  certificate-transparency-go/types.go:292
}


//I was looking for an example on how to make a struct and return it. I haven't found one so far. This is my best attempt and I know it does't work. I'm gonna keep looking at it.
//QUESTION: Does the ct.SignedTreeHead need to be a pointer in the parameters being passed in?
func GenerateMisbebehaviorProof (logid int64, consistencyproof int64, STHoriginal *ct.SignedTreehead, STHreceived *ct.SignedTreehead, STHexpected *ct.SignedTreehead) {
	misbehaviorproof := MisbehaviorProof{logid, consistencyproof, STHoriginal, STHexpected, STHreceived}
	return misbehaviorproof //On this line I get the error of too many arguments to return.
}

func ObtainCurrentView(log_id_list []int64, treestate_list []int32, mirroring_list []byte   )  {

	/*
	I do not know how to pass a false boolean value into the UpdateView() as outlined in the task breakdown.

	This chunk of code is something that I am stuck on and working on. I am trying to compare the log_id_list and the mirroring_list slices.
	I want to loop through each slice at the same time and at each index value, compare the slices. If the mirroring list contains a 0 (false), then I will create a new slice
	of just the values that are mirrored from the log_id_list. That new slice will be passed into the UpdateView() function.
	*/

	if len(mirroring_list) == len(log_id_list) {
		for i, x := range log_id_list {
			if (bytes.Contains(mirroring_list[i]byte, []byte"1" ) ) //one idea I had to try to get it to work. It isn't quite working out. 
		}
	}



}

/*
func UpdateView(log_id int, treestate int) {
	//this is the get-sth.... the function is in logclient.go line 154
	//GetSTH(ctx context.Context) (*ct.SignedTreeHead, error)

}

*/

/*
func GossipMisbehaviorProof

*/


//DAS: I feel that the next two functions are not going to work. I feel like calling them from the package might work better. But I do not know how to just yet.

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

//DAS: found in trillian/merkle/log_verifier.go:92
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

