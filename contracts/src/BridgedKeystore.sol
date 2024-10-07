// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";
import {MerkleTrie} from "optimism/libraries/trie/MerkleTrie.sol";

import {IL1BlockOracle} from "./interfaces/IL1BlockOracle.sol";
import {BlockHeader, BlockLib} from "./libs/BlockLib.sol";
import {KeystoreLib, ValueHashPreimages} from "./libs/KeystoreLib.sol";

contract BridgedKeystore {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when the Keystore storage root from the reference L2 is successfully synchronized.
    ///
    /// @param keystoreStorageRoot The new synchronized Keystore storage root.
    event KeystoreRootSynchronized(bytes32 keystoreStorageRoot);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         block header does not match the L1 block hash returned by the `l1BlockHashOracle` contract.
    error InvalidBlockHeader();

    /// @notice Thrown when attempting to synchronize the Keystore storage root from the reference L2, but the provided
    ///         parameters do not match the recovered reference L2 OutputRoot.
    error InvalidL2OutputRootPreimages();

    /// @notice Thrown when attempting to preconfirm a Keyspace record update (non-forking method), but the confirmed
    ///         ValueHash (recovered from the `keystoreStorageRoot`) was not found at the provided lookup index in the
    ///         active fork history of the Keyspace record.
    ///
    /// @param confirmedValueHash The confirmed ValueHash recovered from the `keystoreStorageRoot`.
    /// @param preconfirmedValueHash The preconfirmed ValueHash found at the provided lookup index.
    error InvalidPreconfirmedValueHash(bytes32 confirmedValueHash, bytes32 preconfirmedValueHash);

    /// @notice Thrown when attempting to preconfirm a Keyspace record update (forking method), but the confirmed
    ///         ValueHash (recovered from the `keystoreStorageRoot`) and the ValueHash at the given lookup index in the
    ///         active fork history are the same.
    ///
    /// @param valueHash The common ValueHash.
    error NoValueHashConflict(bytes32 valueHash);

    /// @notice Thrown when attempting to preconfirm a Keyspace record update (non-forking method), but the nonces
    ///         committed in the conflicting ValueHashes are not equal.
    ///
    /// @param confirmedNonce The nonce committed in the confirmed ValueHash recovered from the `keystoreStorageRoot`.
    /// @param preconfirmedNonce The nonce committed in the preconfirmed ValueHash found at the provided lookup index.
    error InvalidConflictingNonce(uint256 confirmedNonce, uint256 preconfirmedNonce);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The slot where the reference L2 OutputRoot is stored on the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    /// @notice The address of the `L1Block` contract on this L2.
    address public immutable l1BlockHashOracle;

    /// @notice The address of the `AnchorStateRegistry` contract on L1.
    address public immutable anchorStateRegistry;

    /// @notice The address of the `Keystore` contract on the reference L2.
    address public immutable keystore;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STORAGE                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The reference L2 Keystore storage root.
    bytes32 public keystoreStorageRoot;

    /// @notice The active fork for each Keyspace ID.
    ///
    /// @dev Preconfirmations are organized into "forks," which are sequences of successive ValueHashes set for a
    ///      given Keyspace record. A new fork is created if a conflict arises between the active fork's history
    ///      and the confirmed ValueHash (recovered from the L2 Keystore storage root). The active fork for any
    ///      Keyspace record is always the most recent one created.
    mapping(bytes32 id => uint256 activeFork) public activeForks;

    /// @notice Preconfirmed Keyspace records for each fork.
    mapping(bytes32 id => mapping(uint256 fork => bytes32[] valueHashes)) public preconfirmedValueHashes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Deploys a `BridgedKeystore` contract.
    ///
    /// @param l1BlockHashOracle_ The address of the `L1Block` oracle contract on this chain.
    /// @param anchorStateRegistry_ The address of the `AnchorStateRegistry` contract on L1.
    /// @param keystore_ The address of the `Keystore` contract on the reference L2.
    constructor(address l1BlockHashOracle_, address anchorStateRegistry_, address keystore_) {
        l1BlockHashOracle = l1BlockHashOracle_;
        anchorStateRegistry = anchorStateRegistry_;
        keystore = keystore_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Synchronizes the Keystore root from the reference L2.
    ///
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
    /// @param blockHeaderRlp The L1 block header, RLP-encoded.
    /// @param anchorStateRegistryAccountProof The account proof of the `AnchorStateRegistry` contract on L1.
    /// @param anchorStateRegistryStorageProof The storage proof of the reference L2 root within the
    ///                                        `AnchorStateRegistry` on L1.
    /// @param keystoreAccountProof The account proof of the Keystore contract on the reference L2.
    /// @param l2StateRoot The state root of the reference L2.
    /// @param l2MessagePasserStorageRoot The storage root of the `MessagePasser` contract on the reference L2.
    /// @param l2BlockHash The block hash of the reference L2.
    function syncRoot(
        bytes memory blockHeaderRlp,
        bytes[] memory anchorStateRegistryAccountProof,
        bytes[] memory anchorStateRegistryStorageProof,
        bytes[] memory keystoreAccountProof,
        bytes32 l2StateRoot,
        bytes32 l2MessagePasserStorageRoot,
        bytes32 l2BlockHash
    ) public {
        // TODO: Using the execution root might make it hard to submit a valid proof.
        //       Consider proving from the Beacon root instead.

        BlockHeader memory header = BlockLib.parseBlockHeader(blockHeaderRlp);

        // Ensure the provided block header is valid.
        if (header.hash != IL1BlockOracle(l1BlockHashOracle).hash()) {
            revert InvalidBlockHeader();
        }

        // NOTE: MerkleTrie.get reverts if the slot does not exist.

        // Add scope to avoid stack too deep error.
        {
            // From the L1 state root hash, recover the storage root of the AnchorStateRegistry.
            bytes32 anchorStateRegistryHash = keccak256(abi.encodePacked(anchorStateRegistry));
            bytes32 anchorStateRegistryStorageRoot = bytes32(
                MerkleTrie.get({
                    _key: abi.encodePacked(anchorStateRegistryHash),
                    _proof: anchorStateRegistryAccountProof,
                    _root: header.stateRootHash
                }).toRlpItem().toList()[2].toUint()
            );

            // From the storage root of the AnchorStateRegistry, recover the l2 output root
            // stored at slot ANCHOR_STATE_REGISTRY_SLOT.
            bytes32 anchorStateRegistryOutputRootSlotHash = keccak256(abi.encodePacked(ANCHOR_STATE_REGISTRY_SLOT));
            bytes32 outputRoot = bytes32(
                MerkleTrie.get({
                    _key: abi.encodePacked(anchorStateRegistryOutputRootSlotHash),
                    _proof: anchorStateRegistryStorageProof,
                    _root: anchorStateRegistryStorageRoot
                }).toRlpItem().toUint()
            );

            // Ensure the provided preimages of the `outputRoot` are valid.
            bytes32 version;
            bytes32 recomputedOutputRoot =
                keccak256(abi.encodePacked(version, l2StateRoot, l2MessagePasserStorageRoot, l2BlockHash));
            if (recomputedOutputRoot != outputRoot) {
                revert InvalidL2OutputRootPreimages();
            }
        }

        // From the L2 state root, recover the Keystore storage root.
        bytes32 keystoreHash = keccak256(abi.encodePacked(keystore));
        bytes32 keystoreStorageRoot_ = bytes32(
            MerkleTrie.get({_key: abi.encodePacked(keystoreHash), _proof: keystoreAccountProof, _root: l2StateRoot})
                .toRlpItem().toList()[2].toUint()
        );

        // Set the reference L2 Keystore storage root.
        keystoreStorageRoot = keystoreStorageRoot_;

        emit KeystoreRootSynchronized({keystoreStorageRoot: keystoreStorageRoot});
    }

    /// @notice Preconfirms a new update to a Keyspace record.
    ///
    /// @dev This function should only be called if the new preconfirmed update can be added on top of the active fork
    ///      history of the targeted Keyspace record.
    ///
    /// @param id The ID of the Keyspace record being updated.
    /// @param confirmedValueHashInclusionProof The inclusion proof for recovering the confirmed ValueHash of the
    ///                                         Keyspace record from the `keystoreStorageRoot`.
    /// @param confirmedIndex The index of the confirmed ValueHash in the active fork history of the Keyspace record.
    /// @param currentValueHashPreimages The preimages of the ValuHash used. For the very first preconfirmation the
    ///                                  ValueHash used will be the confirmed ValueHash recovered from the current
    ///                                  `keystoreStorageRoot`. Otherwise the ValueHash used will be the latest
    ///                                  ValueHash of the current active fork history associted with that Keyspace
    ///                                  record.
    /// @param newValueHash The new ValueHash to be stored in the Keyspace record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param controllerProof A proof provided to the Keyspace record `controller` to authorize the update.
    function preconfirmUpdate(
        bytes32 id,
        bytes[] calldata confirmedValueHashInclusionProof,
        uint256 confirmedIndex,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata controllerProof
    ) public {
        bytes32 confirmedValueHash =
            _recoverConfirmedValueHash({id: id, confirmedValueHashInclusionProof: confirmedValueHashInclusionProof});

        // Get the active fork history for the Keyspace record.
        uint256 activeFork = activeForks[id];
        bytes32[] storage preconfirmedValueHashes_ = preconfirmedValueHashes[id][activeFork];

        // By default assume the `confirmedValueHash` to be the current one.
        bytes32 currentValueHash = confirmedValueHash;

        // If the active fork is not empty, ensure that the `confirmedValueHash` is part of its history.
        // If it is, the successive updates that have been applied on top of it are consiered valid and we peek
        // the latest one as the current ValueHash.
        if (preconfirmedValueHashes_.length > 0) {
            bytes32 valueHash = preconfirmedValueHashes_[confirmedIndex];
            if (valueHash != confirmedValueHash) {
                revert InvalidPreconfirmedValueHash({
                    confirmedValueHash: confirmedValueHash,
                    preconfirmedValueHash: valueHash
                });
            }

            currentValueHash = preconfirmedValueHashes_[preconfirmedValueHashes_.length - 1];
        }

        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: currentValueHash,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            controllerProof: controllerProof
        });

        // Add the `newValueHash` to the latest fork history.
        preconfirmedValueHashes_.push(newValueHash);

        // TODO: Emit event.
    }

    /// @notice Preconfirms a new Keyspace record update in case of a conflict.
    ///
    /// @dev This function should only be called if the new preconfirmed update cannot be added on top of the active
    ///      fork history of the targeted Keyspace record. This situation occurs when the new confirmed ValueHash
    ///      (recovered from the `keystoreStorageRoot`) conflicts with an existing ValueHash in the Keyspace record’s
    ///      fork history.
    ///
    /// @param id The ID of the Keyspace record being updated.
    /// @param confirmedValueHashInclusionProof The inclusion proof to recover the confirmed ValueHash of the Keyspace
    ///                                         record from the `keystoreStorageRoot`.
    /// @param confirmedValueHashPreimages The preimages of the confirmed ValueHash recovered from the
    ///                                    `keystoreStorageRoot`.
    /// @param newValueHash The new ValueHash to be stored in the Keyspace record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param conflictingIndex The index of the conflicting ValueHash in the active fork history of the Keyspace
    ///                         record.
    /// @param conflictingValueHashPreimages The preimages of the ValueHash expected at the `conflictingIndex` in the
    ///                                      active fork history.
    /// @param controllerProof A proof provided to the Keyspace record `controller` to authorize the update.
    function preconfirmUpdateWithFork(
        bytes32 id,
        bytes[] calldata confirmedValueHashInclusionProof,
        ValueHashPreimages calldata confirmedValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        uint256 conflictingIndex,
        ValueHashPreimages calldata conflictingValueHashPreimages,
        bytes calldata controllerProof
    ) public {
        bytes32 confirmedValueHash =
            _recoverConfirmedValueHash({id: id, confirmedValueHashInclusionProof: confirmedValueHashInclusionProof});

        // NOTE: We do not check that the `confirmedValueHashPreimages` effectively hash to `confirmedValueHash`.
        //       This check is performed later in `KeystoreLib.verifyNewValueHash` where we use `confirmedValueHash`
        //       as the current ValueHash.

        // Get the conflicting ValueHash from the latest fork history.
        uint256 activeFork = activeForks[id];
        bytes32[] storage preconfirmedValueHashes_ = preconfirmedValueHashes[id][activeFork];
        bytes32 conflictingValueHash = preconfirmedValueHashes_[conflictingIndex];

        // Ensure the ValueHashes are effectively different (else there is no conflict).
        if (conflictingValueHash == confirmedValueHash) {
            revert NoValueHashConflict({valueHash: confirmedValueHash});
        }

        // Ensure that the `conflictingValueHashPreimages` hash to `conflictingValueHash`.
        KeystoreLib.verifyRecordPreimages({
            valueHash: conflictingValueHash,
            valueHashPreimages: conflictingValueHashPreimages
        });

        // Ensure the nonce of the conflicting ValueHashes are equal.
        if (confirmedValueHashPreimages.nonce != conflictingValueHashPreimages.nonce) {
            revert InvalidConflictingNonce({
                confirmedNonce: confirmedValueHashPreimages.nonce,
                preconfirmedNonce: conflictingValueHashPreimages.nonce
            });
        }

        // Use the `confirmedValueHash` as the `currentValueHash` to authorize the `newValueHash`.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: confirmedValueHash,
            currentValueHashPreimages: confirmedValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            controllerProof: controllerProof
        });

        // Avoid stack too deep error...
        bytes32 id_ = id;

        // Create a new fork history.
        activeFork += 1;
        activeForks[id_] = activeFork;
        preconfirmedValueHashes_ = preconfirmedValueHashes[id_][activeFork];
        preconfirmedValueHashes_.push(confirmedValueHash);
        preconfirmedValueHashes_.push(newValueHash);

        // TODO: Emit event.
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Recovers the confirmed ValueHash of a Keyspace record from the current `keystoreStorageRoot`.
    ///
    /// @param id The ID of the Keyspace record.
    /// @param confirmedValueHashInclusionProof The inclusion proof for the ValueHash of the Keyspace record committed
    ///                                         in the current `keystoreStorageRoot`.
    function _recoverConfirmedValueHash(bytes32 id, bytes[] calldata confirmedValueHashInclusionProof)
        private
        view
        returns (bytes32)
    {
        // From the reference L2 Keystore storage root, recover the user Keyspace record confirmed value hash.
        bytes32 keyspaceRecordSlot = keccak256(abi.encodePacked(id, bytes32(0)));
        bytes32 keyspaceRecordSlotHash = keccak256(abi.encodePacked(keyspaceRecordSlot));
        return bytes32(
            MerkleTrie.get({
                _key: abi.encodePacked(keyspaceRecordSlotHash),
                _proof: confirmedValueHashInclusionProof,
                _root: keystoreStorageRoot
            }).toRlpItem().toUint()
        );
    }
}
