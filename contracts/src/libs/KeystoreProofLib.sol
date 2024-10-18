// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, BlockLib} from "./BlockLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./L1ProofLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

/// @dev A proof from which a Keystore storage root can be extracted.
struct KeystoreStorageRootProof {
    /// @dev The L1 block header, RLP-encoded.
    bytes l1BlockHeaderRlp;
    /// @dev The L1 block hash proof.
    L1BlockHashProof l1BlockHashProof;
    /// @dev The `AnchorStateRegistry` account proof on L1.
    bytes[] anchorStateRegistryAccountProof;
    /// @dev The storage proof of the reference L2 OutputRoot stored in the `AnchorStateRegistry` contract on L1.
    bytes[] anchorStateRegistryStorageProof;
    /// @dev The Keystore account proof on the reference L2.
    bytes[] keystoreAccountProof;
    /// @dev The state root of the reference L2.
    bytes32 l2StateRoot;
    /// @dev The storage root of the `MessagePasser` contract on the reference L2.
    bytes32 l2MessagePasserStorageRoot;
    /// @dev The block hash of the reference L2.
    bytes32 l2BlockHash;
}

library KeystoreProofLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         parameters do not match the recovered reference L2 OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The slot where the OutputRoot is stored in the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    /// @notice The  Keystore records mapping slot in the Keystore contract on the reference L2.
    bytes32 constant KEYSTORE_RECORDS_SLOT = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the Keystore record ValueHash on the reference L2 from the given `storageProof`.
    ///
    /// @param keystoreStorageRoot The Keystore storage root on the reference L2.
    /// @param id The identifier for the Keystore record.
    /// @param storageProof The record's ValueHash storage proof.
    ///
    /// @return The keystore record's ValueHash.
    function extractKeystoreRecordValueHash(bytes32 keystoreStorageRoot, bytes32 id, bytes[] calldata storageProof)
        internal
        pure
        returns (bytes32)
    {
        bytes memory recordSlot = abi.encode(id, KEYSTORE_RECORDS_SLOT);

        return StorageProofLib.extractSlotValue({
            storageRoot: keystoreStorageRoot,
            slot: keccak256(abi.encodePacked(recordSlot)),
            storageProof: storageProof
        });
    }

    /// @notice Extracts the Keystore storage root on the reference L2 from the given `proof`.
    ///
    /// @dev The current implementation is compatible only with OpStack chains due to the specifics of the
    ///      `AnchorStateRegistry` contract and how the `l2StateRoot` is recovered from the reference L2 OutputRoot.
    /// @dev The following proving steps are performed to validate the Keystore storage root:
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
    /// @param anchorStateRegistry The AnchorStateRegistry address on L1.
    /// @param keystore The Keystore address on the reference L2.
    /// @param keystoreStorageRootProof The KeystoreStorageRootProof struct.
    ///
    /// @return The Keystore storage root on the reference L2.
    /// @return The corresponding L1 block number.
    function extractKeystoreStorageRoot(
        address anchorStateRegistry,
        address keystore,
        KeystoreStorageRootProof memory keystoreStorageRootProof
    ) internal view returns (bytes32, uint256) {
        BlockHeader memory header = BlockLib.parseBlockHeader(keystoreStorageRootProof.l1BlockHeaderRlp);

        // Ensure the provided L1 block header can be used (i.e the block hash is valid).
        L1ProofLib.verifyL1BlockHash({
            proof: keystoreStorageRootProof.l1BlockHashProof,
            expectedL1BlockHash: header.hash
        });

        // Get the OutputRoot that was submitted to the AnchorStateRegistry contract on L1.
        bytes32 outputRoot = StorageProofLib.extractAccountStorageValue({
            stateRoot: header.stateRootHash,
            account: anchorStateRegistry,
            accountProof: keystoreStorageRootProof.anchorStateRegistryAccountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: keystoreStorageRootProof.anchorStateRegistryStorageProof
        });

        // Ensure the provided preimages of the `outputRoot` are valid.
        _validateOutputRootPreimages({
            l2StateRoot: keystoreStorageRootProof.l2StateRoot,
            l2MessagePasserStorageRoot: keystoreStorageRootProof.l2MessagePasserStorageRoot,
            l2BlockHash: keystoreStorageRootProof.l2BlockHash,
            outputRoot: outputRoot
        });

        // From the reference L2 state root, recover the Keystore storage root.
        bytes32 keystoreStorageRoot = StorageProofLib.extractAccountStorageRoot({
            stateRoot: keystoreStorageRootProof.l2StateRoot,
            account: keystore,
            accountProof: keystoreStorageRootProof.keystoreAccountProof
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
    /// @param l2StateRoot The state root of the reference L2.
    /// @param l2MessagePasserStorageRoot The storage root of the `MessagePasser` contract on the reference L2.
    /// @param l2BlockHash The block hash of the reference L2.
    /// @param outputRoot The outputRoot to validate.
    function _validateOutputRootPreimages(
        bytes32 l2StateRoot,
        bytes32 l2MessagePasserStorageRoot,
        bytes32 l2BlockHash,
        bytes32 outputRoot
    ) private pure {
        bytes32 version = bytes32(0);
        bytes32 recomputedOutputRoot =
            keccak256(abi.encodePacked(version, l2StateRoot, l2MessagePasserStorageRoot, l2BlockHash));

        require(recomputedOutputRoot == outputRoot, InvalidL2OutputRootPreimages());
    }
}
