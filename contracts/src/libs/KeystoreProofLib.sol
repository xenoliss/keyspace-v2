// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";
import {MerkleTrie} from "optimism/libraries/trie/MerkleTrie.sol";

import {BlockHeader, BlockLib} from "./BlockLib.sol";
import {L1ProofLib, L1BlockHashProof} from "./L1ProofLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

struct KeystoreRecordProof {
    bytes[] slotProof;
    bytes rootProof;
}

struct KeystoreRootProof {
    bytes l1BlockHeader;
    L1BlockHashProof l1BlockHashProof;
    bytes[] anchorStateRegistryAccountProof;
    bytes[] anchorStateRegistrySlotProof;
    bytes[] keystoreAccountProof;
    bytes32 l2StateRoot;
    bytes32 l2MessagePasserStorageRoot;
    bytes32 l2BlockHash;
}

library KeystoreProofLib {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;
    
    /// @notice The slot where the reference L2 OutputRoot is stored on the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    bytes32 constant KEYSTORE_RECORDS_SLOT = 0;

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         block header does not match the L1 block hash returned by the `l1BlockHashOracle` contract.
    error InvalidBlockHeader();

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         parameters do not match the recovered reference L2 OutputRoot.
    error InvalidL2OutputRootPreimages();

    function hasRootProof(KeystoreRecordProof memory proof) internal pure returns (bool) {
        return proof.rootProof.length > 0;
    }

    function getRootProof(KeystoreRecordProof memory proof) internal pure returns (KeystoreRootProof memory) {
        if (!hasRootProof(proof)) {
            revert("KeystoreProofLib: INVALID_PROOF");
        }
        return abi.decode(proof.rootProof, (KeystoreRootProof));
    }

    /// @dev Verifies the keystore record proof against the provided id and storage root.
    ///
    /// @param proof The proof object containing the slot proof.
    /// @param id The identifier for the keystore record.
    /// @param root The storage root to verify against.
    /// @return The keystore record's value hash.
    function verify(KeystoreRecordProof memory proof, bytes32 id, bytes32 root) internal pure returns (bytes32) {
        bytes memory idSlot = abi.encode(id, KEYSTORE_RECORDS_SLOT);
        return StorageProofLib.verifySlotProof({
            slot: keccak256(abi.encodePacked(idSlot)),
            slotProof: proof.slotProof,
            storageRoot: root
        });
    }

    /// @dev The following proving steps are performed to validate the Keystore root:
    ///      1. Prove the validity of the provided `blockHeaderRlp` against the L1 block hash returned by the
    ///         `l1BlockHashOracle`.
    ///      2. From the L1 state root hash (within the `blockHeaderRlp`), recover the storage root of the
    ///         `AnchorStateRegistry` contract on L1.
    ///      3. From the storage root of the `AnchorStateRegistry`, recover the reference L2 OutputRoot stored at slot
    ///         `ANCHOR_STATE_REGISTRY_SLOT`. This slot corresponds to calling `anchors(0)` on the `AnchorStateRegistry`
    ///         contract.
    ///      4. From the recovered reference L2 OutputRoot, verify the provided `l2StateRoot`. This is done by
    ///         recomputing the L2 OutputRoot using the `l2StateRoot`, `l2MessagePasserStorageRoot`, and `l2BlockHash`
    ///         parameters. For more details, see the link:
    ///         https://github.com/ethereum-optimism/optimism/blob/d141b53e4f52a8eb96a552d46c2e1c6c068b032e/op-service/eth/output.go#L49-L63
    ///      5. From the `l2StateRoot`, recover the Keystore storage root on the reference L2.
    ///
    /// @dev The current implementation is compatible only with OpStack chains due to the specifics of the
    ///      `AnchorStateRegistry` contract and how the `l2StateRoot` is recovered from the reference L2 OutputRoot.
    ///
    function verify(KeystoreRootProof memory proof, address keystore, address anchorStateRegistry) internal view returns (bytes32, uint256) {
        BlockHeader memory header = BlockLib.parseBlockHeader(proof.l1BlockHeader);

        // Ensure the provided block header is valid.
        if (!L1ProofLib.verifyBlockHash(proof.l1BlockHashProof, header.hash)) {
            revert InvalidBlockHeader();
        }

        bytes32 outputRoot = getOutputRoot(proof, anchorStateRegistry, header.stateRootHash);

        // Ensure the provided preimages of the `outputRoot` are valid.
        validateOutputRootPreimages(proof, outputRoot);

        // From the L2 state root, recover the Keystore storage root.
        bytes32 keystoreStorageRoot = getKeystoreStorageRoot(proof, keystore);

        return (keystoreStorageRoot, header.number);
    }

    function getOutputRoot(KeystoreRootProof memory proof, address anchorStateRegistry, bytes32 stateRootHash) internal pure returns (bytes32) {
        return StorageProofLib.verifyStorageProof({
            account: anchorStateRegistry,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            accountProof: proof.anchorStateRegistryAccountProof,
            slotProof: proof.anchorStateRegistrySlotProof,
            stateRoot: stateRootHash
        });
    }

    function validateOutputRootPreimages(KeystoreRootProof memory proof, bytes32 outputRoot) internal pure {
        bytes32 version = bytes32(0);
        bytes32 recomputedOutputRoot =
            keccak256(abi.encodePacked(version, proof.l2StateRoot, proof.l2MessagePasserStorageRoot, proof.l2BlockHash));
        if (recomputedOutputRoot != outputRoot) {
            revert InvalidL2OutputRootPreimages();
        }
    }

    function getKeystoreStorageRoot(KeystoreRootProof memory proof, address keystore) internal pure returns (bytes32) {
        bytes32 keystoreHash = keccak256(abi.encodePacked(keystore));
        return bytes32(
            MerkleTrie.get({_key: abi.encodePacked(keystoreHash), _proof: proof.keystoreAccountProof, _root: proof.l2StateRoot})
                .toRlpItem().toList()[2].toUint()
        );
    }

}
