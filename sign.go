package sign

import (
	"encoding/hex"
	"fmt"

	"github.com/ChyKusuma/hashtree"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/syndtr/goleveldb/leveldb"
)

// KeyManager interface defines methods for key management and cryptographic operations
type KeyManager interface {
	GenerateKeys(params *parameters.Parameters) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK)
	SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error)
	VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool
	SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error)
	DeserializeSK(params *parameters.Parameters, skBytes []byte) (*sphincs.SPHINCS_SK, error)
	SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error)
	DeserializePK(params *parameters.Parameters, pkBytes []byte) (*sphincs.SPHINCS_PK, error)
	SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error)
	DeserializeSignature(params *parameters.Parameters, sigBytes []byte) (*sphincs.SPHINCS_SIG, error)
}

// SphincsManager implements the KeyManager interface for SPHINCS+ operations
type SphincsManager struct {
	db *leveldb.DB // LevelDB instance for storing leaves
}

// NewSphincsManager creates a new instance of SphincsManager with a LevelDB instance
func NewSphincsManager(db *leveldb.DB) *SphincsManager {
	return &SphincsManager{db: db}
}

// GenerateKeys generates a new pair of secret and public keys
func (sm *SphincsManager) GenerateKeys(params *parameters.Parameters) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK) {
	return sphincs.Spx_keygen(params)
}

// SignMessage signs a given message using the secret key
func (sm *SphincsManager) SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error) {
	sig := sphincs.Spx_sign(params, message, sk)
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return nil, nil, err
	}

	// Split the serialized signature into parts for building a Merkle tree
	chunkSize := len(sigBytes) / 4
	sigParts := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 3 {
			end = len(sigBytes)
		}
		sigParts[i] = sigBytes[start:end]
	}

	// Build a Merkle Tree from the signature parts and get the root node
	merkleRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return nil, nil, err
	}

	// Save leaf nodes to LevelDB
	if err := hashtree.SaveLeavesBatchToDB(sm.db, sigParts); err != nil {
		return nil, nil, err
	}

	// Optionally prune old leaves based on your criteria (e.g., number of leaves)
	if err := hashtree.PruneOldLeaves(sm.db, 10); err != nil { // Adjust the number as needed
		return nil, nil, err
	}

	return sig, merkleRoot, nil
}

// VerifySignature verifies if a signature is valid for a given message and public key
func (sm *SphincsManager) VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	isValid := sphincs.Spx_verify(params, message, sig, pk)
	if !isValid {
		return false
	}

	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return false
	}

	// Split the serialized signature into parts to rebuild the Merkle tree
	chunkSize := len(sigBytes) / 4
	sigParts := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 3 {
			end = len(sigBytes)
		}
		sigParts[i] = sigBytes[start:end]
	}

	// Rebuild the Merkle Tree from the signature parts and compare with provided root node
	rebuiltRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return false
	}

	return hex.EncodeToString(rebuiltRoot.Hash) == hex.EncodeToString(merkleRoot.Hash)
}

// Helper functions for key serialization and deserialization
func (sm *SphincsManager) SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error) {
	return sk.SerializeSK()
}

func (sm *SphincsManager) DeserializeSK(params *parameters.Parameters, skBytes []byte) (*sphincs.SPHINCS_SK, error) {
	return sphincs.DeserializeSK(params, skBytes)
}

func (sm *SphincsManager) SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error) {
	return pk.SerializePK()
}

func (sm *SphincsManager) DeserializePK(params *parameters.Parameters, pkBytes []byte) (*sphincs.SPHINCS_PK, error) {
	return sphincs.DeserializePK(params, pkBytes)
}

func (sm *SphincsManager) SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature()
}

func (sm *SphincsManager) DeserializeSignature(params *parameters.Parameters, sigBytes []byte) (*sphincs.SPHINCS_SIG, error) {
	return sphincs.DeserializeSignature(params, sigBytes)
}

// buildMerkleTreeFromSignature constructs a Merkle tree from signature parts and returns the root node
func buildMerkleTreeFromSignature(sigParts [][]byte) (*hashtree.HashTreeNode, error) {
	if len(sigParts) == 0 {
		return nil, fmt.Errorf("no signature parts provided")
	}
	return hashtree.BuildHashTree(sigParts), nil
}
