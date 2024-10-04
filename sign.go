package sign

import (
	"encoding/hex"
	"fmt"

	"github.com/ChyKusuma/hashtree"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// KeyManager interface defines methods for key management and cryptographic operations
type KeyManager interface {
	// GenerateKeys generates a new pair of secret and public keys based on the provided parameters
	GenerateKeys(params *parameters.Parameters) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK)

	// SignMessage signs a given message using the secret key, returns the signature and the Merkle tree root node
	SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error)

	// VerifySignature checks if a signature is valid for a given message and public key, using the Merkle tree root node
	VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool

	// SerializeSK converts a secret key to a byte slice
	SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error)

	// DeserializeSK converts a byte slice back into a secret key
	DeserializeSK(params *parameters.Parameters, skBytes []byte) (*sphincs.SPHINCS_SK, error)

	// SerializePK converts a public key to a byte slice
	SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error)

	// DeserializePK converts a byte slice back into a public key
	DeserializePK(params *parameters.Parameters, pkBytes []byte) (*sphincs.SPHINCS_PK, error)

	// SerializeSignature converts a signature to a byte slice
	SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error)

	// DeserializeSignature converts a byte slice back into a signature
	DeserializeSignature(params *parameters.Parameters, sigBytes []byte) (*sphincs.SPHINCS_SIG, error)
}

// SphincsManager implements the KeyManager interface for SPHINCS+ operations
type SphincsManager struct{}

// GenerateKeys generates a new pair of secret and public keys
func (sm *SphincsManager) GenerateKeys(params *parameters.Parameters) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK) {
	// Call SPHINCS+ key generation function with the provided parameters
	return sphincs.Spx_keygen(params)
}

// SignMessage signs a given message using the secret key
func (sm *SphincsManager) SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error) {
	// Generate SPHINCS+ signature for the message using the secret key
	sig := sphincs.Spx_sign(params, message, sk)

	// Serialize the generated signature into bytes
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

	// Return the signature and the Merkle root node
	return sig, merkleRoot, nil
}

// VerifySignature verifies if a signature is valid for a given message and public key
func (sm *SphincsManager) VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	// Verify the signature with the given message and public key
	isValid := sphincs.Spx_verify(params, message, sig, pk)
	if !isValid {
		return false
	}

	// Serialize the signature to bytes for Merkle tree rebuilding
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

	// Compare the rebuilt Merkle root hash with the provided Merkle root hash
	return hex.EncodeToString(rebuiltRoot.Hash) == hex.EncodeToString(merkleRoot.Hash)
}

// Helper functions for key serialization and deserialization
// SerializeSK converts a secret key to a byte slice
func (sm *SphincsManager) SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error) {
	return sk.SerializeSK()
}

// DeserializeSK converts a byte slice back into a secret key
func (sm *SphincsManager) DeserializeSK(params *parameters.Parameters, skBytes []byte) (*sphincs.SPHINCS_SK, error) {
	return sphincs.DeserializeSK(params, skBytes)
}

// SerializePK converts a public key to a byte slice
func (sm *SphincsManager) SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error) {
	return pk.SerializePK()
}

// DeserializePK converts a byte slice back into a public key
func (sm *SphincsManager) DeserializePK(params *parameters.Parameters, pkBytes []byte) (*sphincs.SPHINCS_PK, error) {
	return sphincs.DeserializePK(params, pkBytes)
}

// SerializeSignature converts a signature to a byte slice
func (sm *SphincsManager) SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature()
}

// DeserializeSignature converts a byte slice back into a signature
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
