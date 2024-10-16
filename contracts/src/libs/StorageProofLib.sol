// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";

import {MerklePatriciaProofVerifier} from "./MerklePatriciaProofVerifier.sol";

library StorageProofLib {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the storage value from the given account and slot proofs.
    ///
    /// @dev Reverts if any of the proofs is invalid.
    ///
    /// @param stateRoot The root hash of the state trie.
    /// @param account The address of the account whose storage is being read.
    /// @param accountProof The Merkle proof for the account.
    /// @param slot The storage slot being read.
    /// @param storageProof The Merkle proof for the storage slot.
    ///
    /// @return The value stored at the given slot.
    function extractAccountStorageValue(
        bytes32 stateRoot,
        address account,
        bytes[] memory accountProof,
        bytes32 slot,
        bytes[] memory storageProof
    ) internal pure returns (bytes32) {
        bytes32 storageRoot =
            extractAccountStorageRoot({stateRoot: stateRoot, account: account, accountProof: accountProof});

        return extractSlotValue({storageRoot: storageRoot, slot: slot, storageProof: storageProof});
    }

    /// @notice Extracts the account storage root from the given account proof.
    ///
    /// @dev Reverts if the account proof is invalid.
    ///
    /// @param stateRoot The root hash of the state trie.
    /// @param account The address of the account.
    /// @param accountProof The Merkle Patricia proof for the account.
    ///
    /// @return The account storage root.
    function extractAccountStorageRoot(bytes32 stateRoot, address account, bytes[] memory accountProof)
        internal
        pure
        returns (bytes32)
    {
        bytes32 accountHash = keccak256(abi.encodePacked(account));

        return bytes32(
            MerklePatriciaProofVerifier.extractProofValue({
                rootHash: stateRoot,
                path: abi.encodePacked(accountHash),
                stack: _parseRLPItems(accountProof)
            }).toRlpItem().toList()[2].toUint()
        );
    }

    /// @notice Extracts the slot value from the given storage proof.
    ///
    /// @dev Reverts if the account proof is invalid.
    ///
    /// @param storageRoot The root hash of the storage trie.
    /// @param slot The storage slot being read.
    /// @param storageProof The Merkle proof for the storage slot.
    ///
    /// @return The value stored at the specified slot.
    function extractSlotValue(bytes32 storageRoot, bytes32 slot, bytes[] memory storageProof)
        internal
        pure
        returns (bytes32)
    {
        bytes32 slotHash = keccak256(abi.encodePacked(slot));

        RLPReader.RLPItem memory slotRlp = MerklePatriciaProofVerifier.extractProofValue({
            rootHash: storageRoot,
            path: abi.encodePacked(slotHash),
            stack: _parseRLPItems(storageProof)
        }).toRlpItem();

        if (slotRlp.len == 0) {
            return bytes32(0);
        }

        return bytes32(slotRlp.toUint());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Parses RLP items from the given proof bytes.
    ///
    /// @param proof The proof bytes.
    ///
    /// @return The parsed RLP items.
    function _parseRLPItems(bytes[] memory proof) private pure returns (RLPReader.RLPItem[] memory) {
        RLPReader.RLPItem[] memory proofItems = new RLPReader.RLPItem[](proof.length);
        for (uint256 i; i < proof.length; i++) {
            proofItems[i] = proof[i].toRlpItem();
        }

        return proofItems;
    }
}
