// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";
import {MerkleTrie} from "optimism/libraries/trie/MerkleTrie.sol";

import {IL1BlockOracle} from "./IL1BlockOracle.sol";
import {KeystoreLib} from "./KeystoreLib.sol";

// TODO: Use custom errors.

contract BridgedKeystore {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL STRUCTURES                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Block header structure returned by `_parseBlockHeader()`.
    struct _BlockHeader {
        /// @dev The block hash.
        bytes32 hash;
        /// @dev The state root hash.
        bytes32 stateRootHash;
        /// @dev The block number.
        uint256 number;
        /// @dev The block timestamp.
        uint256 timestamp;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The slot where the reference L2 OutputRoot is stored on the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed from keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot matches with
    ///      calling `anchors(0)` on the AnchorStateRegistry contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    /// @notice The address of the `L1Block` contract on this L2.
    address public immutable l1BlockHashOracle;

    /// @notice The address of the `AnchorStateRegistry` contract on the L1.
    address public immutable anchorStateRegistry;

    /// @notice The address of the `Keystore` contract on the reference L2.
    address public immutable keystore;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STORAGE                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The current epoch.
    uint256 public epoch;

    /// @notice The reference L2 Keystore storage root per epoch.
    mapping(uint256 epoch => bytes32 root) public epochRoots;

    /// @notice The preconfirmed Keyspace record per epoch.
    mapping(uint256 epoch => mapping(bytes32 id => bytes32 value)) public preconfirmedRecords;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

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
    ///         1. Prove the valdiity of the provided `blockHeaderRlp` against the L1 block hash returned by the
    ///            `l1BlockHashOracle`.
    ///         2. From the L1 state root hash (provided within the `blockHeaderRlp`), recover the storage root of the
    ///            AnchorStateRegistry contract on the L1.
    ///         3. From the storage root of the AnchorStateRegistry, recover the reference L2 OutputRoot stored at slot
    ///            `ANCHOR_STATE_REGISTRY_SLOT`. This slot matches with calling `anchors(0)` on the AnchorStateRegistry
    ///            contract.
    ///         4. From the recovered reference L2 OutputRoot, ensure the provided `l2StateRoot` is valid. This is
    ///            performed by recomputing the L2 OutputRoot manually from the given `l2StateRoot`,
    ///            `l2MessagePasserStorageRoot` and `l2BlockHash` parameter. See the link below for more details:
    ///            https://github.com/ethereum-optimism/optimism/blob/d141b53e4f52a8eb96a552d46c2e1c6c068b032e/op-service/eth/output.go#L49-L63
    ///         5. From the `l2StateRoot`, recover the Keystore storage root on the reference L2.
    /// @dev The current implementation is only comptaible with OpStack chains due to the specifiticy of the
    ///      AnchorStateRegistry contract and the way the `l2StateRoot` is recovered from the reference L2 OutputRoot.
    ///
    /// @param blockHeaderRlp The L1 block header RLP encoded.
    /// @param anchorStateRegistryAccountProof The AnchorStateRegistry account proof on L1.
    /// @param anchorStateRegistryStorageProof The AnchorStateRegistry storage proof (of the reference L2 root) on L1.
    /// @param keystoreAccountProof The Keystore account proof on the reference L2.
    /// @param l2StateRoot The reference L2 state root.
    /// @param l2MessagePasserStorageRoot The MessagePasser storage root on the reference L2.
    /// @param l2BlockHash The reference L2 block hash.
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

        _BlockHeader memory header = _parseBlockHeader(blockHeaderRlp);

        // Ensure the provided block header is valid.
        if (header.hash != IL1BlockOracle(l1BlockHashOracle).hash()) {
            revert("Invalid block header");
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

            // Ensure the provided `l2StateRoot` is valid.
            bytes32 version;
            bytes32 recomputedOutputRoot =
                keccak256(abi.encodePacked(version, l2StateRoot, l2MessagePasserStorageRoot, l2BlockHash));
            if (recomputedOutputRoot != outputRoot) {
                revert("Invalid L2 state root");
            }
        }

        // From the L2 state root, recover the Keystore storage root.
        bytes32 keystoreHash = keccak256(abi.encodePacked(keystore));
        bytes32 keystoreStorageRoot = bytes32(
            MerkleTrie.get({_key: abi.encodePacked(keystoreHash), _proof: keystoreAccountProof, _root: l2StateRoot})
                .toRlpItem().toList()[2].toUint()
        );

        // Start a new epoch and set the reference L2 Keystore storage root.
        epoch++;
        epochRoots[epoch] = keystoreStorageRoot;

        // TODO: Emit event.
    }

    /// @notice Update a Keyspace record to a `newValue`.
    ///         This function should only be called if the user did not already performed an update during the current
    ///         epoch. Otherwise `setFromPreconfirmation` should be used.
    ///
    /// @dev This function is taking the current Keyspace value that is recovered from `currentValueProof` against the
    ///      reference L2 Keystore root stored for the current epoch. This function reverts if the user already
    ///      preconfirmed a Keyspace update during the current epoch (the `setFromPreconfirmation` function should be
    ///      used instead).
    ///
    /// @param id The ID of the Keyspace record to update.
    /// @param newValue The new Keyspace value to store.
    /// @param controller The controller address, responsible for authorizing the update.
    /// @param storageHash The current storage hash commited in the Keyspace record.
    /// @param currentValueProof A proof to recover the user Keyspace record current value.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function set(
        bytes32 id,
        bytes32 newValue,
        address controller,
        bytes32 storageHash,
        bytes[] calldata currentValueProof,
        bytes calldata proof
    ) public {
        // Get the user Keyspace record and ensure the user did not already perform an update during the current epoch.
        mapping(bytes32 => bytes32) storage records = preconfirmedRecords[epoch];
        require(records[id] == 0, "The record has already been preconfirmed for the current epoch.");

        // Get the reference L2 Keystore storage root for the current epoch.
        bytes32 currentKeystoreRoot = epochRoots[epoch];

        // From the reference L2 Keystore storage root, recover the user Keyspace record current value.
        bytes32 keyspaceRecordSlot = keccak256(abi.encodePacked(id, bytes32(0)));
        bytes32 keyspaceRecordSlotHash = keccak256(abi.encodePacked(keyspaceRecordSlot));
        bytes32 currentValue = bytes32(
            MerkleTrie.get({
                _key: abi.encodePacked(keyspaceRecordSlotHash),
                _proof: currentValueProof,
                _root: currentKeystoreRoot
            }).toRlpItem().toUint()
        );

        // Perform the authorized update on the preconfirmed records.
        KeystoreLib.set({
            records: records,
            id: id,
            currentValue: currentValue,
            newValue: newValue,
            controller: controller,
            storageHash: storageHash,
            proof: proof
        });
    }

    /// @notice Update a Keyspace record to a `newValue`.
    ///         This function should only be called if the user already performed an update in the current epoch.
    ///         Otherwise `set` should be used.
    ///
    /// @dev This function is taking the current Keyspace value stored in the `preconfirmedRecords` for the current
    ///      epoch as the source of truth. This function reverts if the user did not already preconfirm a Keyspace
    ///      update during the current epoch (the `set` function should be used instead).
    ///
    /// @param id The ID of the Keyspace record to update.
    /// @param newValue The new Keyspace value to store.
    /// @param controller The controller address, responsible for authorizing the update.
    /// @param storageHash The current storage hash commited in the Keyspace record.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function setFromPreconfirmation(
        bytes32 id,
        bytes32 newValue,
        address controller,
        bytes32 storageHash,
        bytes calldata proof
    ) public {
        // Get the user Keyspace record and ensure the user already performed an update during the current epoch.
        mapping(bytes32 id => bytes32 value) storage records = preconfirmedRecords[epoch];
        bytes32 currentValue = records[id];
        require(currentValue != 0, "The record has not been preconfirmed for the current epoch.");

        // Perform the authorized update on the preconfirmed records.
        KeystoreLib.set({
            records: records,
            id: id,
            currentValue: currentValue,
            newValue: newValue,
            controller: controller,
            storageHash: storageHash,
            proof: proof
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Parses RLP-encoded block header.
    ///
    /// @dev Implementation is from
    /// https://github.com/lidofinance/curve-merkle-oracle/blob/fffd375659358af54a6e8bbf8c3aa44188894c81/contracts/StateProofVerifier.sol.
    ///
    /// @param headerRlpBytes The encoded RLP-encoded block header.
    ///
    /// @return The decoded `_BlockHeader`.
    function _parseBlockHeader(bytes memory headerRlpBytes) private pure returns (_BlockHeader memory) {
        _BlockHeader memory result;
        RLPReader.RLPItem[] memory headerFields = headerRlpBytes.toRlpItem().toList();

        result.stateRootHash = bytes32(headerFields[3].toUint());
        result.number = headerFields[8].toUint();
        result.timestamp = headerFields[11].toUint();
        result.hash = keccak256(headerRlpBytes);

        return result;
    }
}
