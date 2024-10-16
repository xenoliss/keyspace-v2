// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";

import {BlockHeader, BlockLib} from "./BlockLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./L1ProofLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

struct KeystoreRecordProof {
    bytes[] storageProof;
    bytes rootProof;
}

/// @dev
struct KeystoreRootProof {
    /// @dev The L1 block header, RLP-encoded.
    bytes l1BlockHeaderRlp;
    /// @dev The proof of the L1 block hash.
    L1BlockHashProof l1BlockHashProof;
    /// @dev The account proof of the `AnchorStateRegistry` contract on L1.
    bytes[] anchorStateRegistryAccountProof;
    /// @dev The storage proof of the reference L2 root within the `AnchorStateRegistry` on L1.
    bytes[] anchorStateRegistryStorageProof;
    /// @dev The account proof of the Keystore contract on the reference L2.
    bytes[] keystoreAccountProof;
    /// @dev The state root of the reference L2.
    bytes32 l2StateRoot;
    /// @dev The storage root of the `MessagePasser` contract on the reference L2.
    bytes32 l2MessagePasserStorageRoot;
    /// @dev The block hash of the reference L2.
    bytes32 l2BlockHash;
}

library KeystoreProofLib {
    using RLPReader for RLPReader.RLPItem;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         block header does not match the L1 block hash returned by the `l1BlockHashOracle` contract.
    error InvalidBlockHeader();

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         parameters do not match the recovered reference L2 OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The slot where the reference L2 OutputRoot is stored on the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    /// @notice The slot where the reference L2 OutputRoot is stored on the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant KEYSTORE_RECORDS_SLOT = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the Keystore record ValueHash on the reference L2 from the given `proof`.
    ///
    /// @param keystoreStorageRoot The Keystore contract storage root on the reference L2.
    /// @param id The identifier for the Keystore record.
    /// @param proof The KeystoreRecordProof struct.
    ///
    /// @return The keystore record's ValueHash.
    function extractKeystoreRecordValueHash(bytes32 keystoreStorageRoot, bytes32 id, KeystoreRecordProof memory proof)
        internal
        pure
        returns (bytes32)
    {
        bytes memory idSlot = abi.encode(id, KEYSTORE_RECORDS_SLOT);

        return StorageProofLib.extractSlotValue({
            storageRoot: keystoreStorageRoot,
            slot: keccak256(abi.encodePacked(idSlot)),
            storageProof: proof.storageProof
        });
    }

    /// @notice Extracts the Keystore contract storage root on the reference L2 from the given `proof`.
    ///
    /// @dev The current implementation is compatible only with OpStack chains due to the specifics of the
    ///      `AnchorStateRegistry` contract and how the `l2StateRoot` is recovered from the reference L2 OutputRoot.
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
    /// @param anchorStateRegistry The AnchorStateRegistry contract address on L1.
    /// @param keystore The Keystore contract address on the reference L2.
    /// @param proof The KeystoreRootProof struct.
    ///
    /// @return The Keystore contract storage root on the reference L2.
    /// @return The corresponding L1 block number.
    function extractKeystoreRoot(address anchorStateRegistry, address keystore, KeystoreRootProof memory proof)
        internal
        view
        returns (bytes32, uint256)
    {
        BlockHeader memory header = BlockLib.parseBlockHeader(proof.l1BlockHeaderRlp);

        // Ensure the provided block header is valid.
        if (!L1ProofLib.verifyBlockHash({proof: proof.l1BlockHashProof, expectedBlockHash: header.hash})) {
            revert InvalidBlockHeader();
        }

        // Get the Output root that was submitted to the AnchorStateRegistry contract.
        bytes32 outputRoot = StorageProofLib.extractAccountStorageValue({
            stateRoot: header.stateRootHash,
            account: anchorStateRegistry,
            accountProof: proof.anchorStateRegistryAccountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: proof.anchorStateRegistryStorageProof
        });

        // Ensure the provided preimages of the `outputRoot` are valid.
        _validateOutputRootPreimages({proof: proof, outputRoot: outputRoot});

        // From the L2 state root, recover the Keystore storage root.
        bytes32 keystoreStorageRoot = StorageProofLib.extractAccountStorageRoot({
            stateRoot: proof.l2StateRoot,
            account: keystore,
            accountProof: proof.keystoreAccountProof
        });

        return (keystoreStorageRoot, header.number);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         PRIVATE FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the proof's preimages values correctly hash to the expected `outputRoot`.
    ///
    /// @dev Reverts if the proof's preimages values do not hash to the expected `outputRoot`.
    ///
    /// @param proof The KeystoreRootProof struct.
    /// @param outputRoot The outputRoot to validate.
    function _validateOutputRootPreimages(KeystoreRootProof memory proof, bytes32 outputRoot) private pure {
        bytes32 version = bytes32(0);
        bytes32 recomputedOutputRoot =
            keccak256(abi.encodePacked(version, proof.l2StateRoot, proof.l2MessagePasserStorageRoot, proof.l2BlockHash));

        if (recomputedOutputRoot != outputRoot) {
            revert InvalidL2OutputRootPreimages();
        }
    }
}
