// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";
import {MerkleTrie} from "optimism/libraries/trie/MerkleTrie.sol";

import {KeystoreLib} from "./KeystoreLib.sol";
import {IL1BlockOracle} from "./IL1BlockOracle.sol";

/// @notice Block header structure returned by `_parseBlockHeader()`.
struct BlockHeader {
    /// @notice The block hash.
    bytes32 hash;
    /// @notice The state root hash.
    bytes32 stateRootHash;
    /// @notice The block number.
    uint256 number;
    /// @notice The block timestamp.
    uint256 timestamp;
}

bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

contract BridgedKeystore {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    address public immutable l1BlockHashOracle;
    address public immutable anchorStateRegistry;
    address public immutable keystore;
    uint256 public epoch;

    mapping(uint256 epoch => bytes32 root) public epochRoots;
    mapping(uint256 epooch => mapping(bytes32 id => bytes32 value)) public preconfirmedRecords;

    constructor(address l1BlockHashOracle_, address anchorStateRegistry_, address keystore_) {
        l1BlockHashOracle = l1BlockHashOracle_;
        anchorStateRegistry = anchorStateRegistry_;
        keystore = keystore_;
    }

    function syncRoot(
        bytes memory blockHeaderRlp,
        bytes[] memory anchorStateRegistryAccountProof,
        bytes[] memory anchorStateRegistryStorageProof,
        bytes[] memory keystoreAccountProof,
        bytes32 l2StateRoot,
        bytes32 l2MessagePasserStorageRoot,
        bytes32 l2BlockHash
    ) public {
        BlockHeader memory header = _parseBlockHeader(blockHeaderRlp);

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

        epoch++;
        epochRoots[epoch] = keystoreStorageRoot;
    }

    function set(
        bytes32 id,
        bytes32 currentValue,
        bytes calldata currentValueProof,
        bytes32 newValue,
        bytes calldata proof,
        address controller,
        bytes32 storageHash
    ) public {
        mapping(bytes32 => bytes32) storage records = preconfirmedRecords[epoch];
        require(records[id] == 0, "The record has already been preconfirmed for the current epoch.");

        // TODO: Verify the currentValueProof storage proof against the current epoch root before using currentValue.

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

    function setFromPreconfirmation(
        bytes32 id,
        bytes32 newValue,
        bytes calldata proof,
        address controller,
        bytes32 storageHash
    ) public {
        mapping(bytes32 => bytes32) storage records = preconfirmedRecords[epoch];
        bytes32 currentValue = records[id];
        require(currentValue != 0, "The record has not been preconfirmed for the current epoch.");

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

    /// @notice Parses RLP-encoded block header.
    ///
    /// @dev Implementation is from https://github.com/lidofinance/curve-merkle-oracle/blob/fffd375659358af54a6e8bbf8c3aa44188894c81/contracts/StateProofVerifier.sol.
    ///
    /// @param headerRlpBytes The encoded RLP-encoded block header.
    ///
    /// @return The decoded `BlockHeader`.
    function _parseBlockHeader(bytes memory headerRlpBytes) private pure returns (BlockHeader memory) {
        BlockHeader memory result;
        RLPReader.RLPItem[] memory headerFields = headerRlpBytes.toRlpItem().toList();

        result.stateRootHash = bytes32(headerFields[3].toUint());
        result.number = headerFields[8].toUint();
        result.timestamp = headerFields[11].toUint();
        result.hash = keccak256(headerRlpBytes);

        return result;
    }
}
