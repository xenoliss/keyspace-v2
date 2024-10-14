// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {MerklePatriciaProofVerifier} from "./MerklePatriciaProofVerifier.sol";
import {RLPReader} from "Solidity-RLP/RLPReader.sol";

library StorageProofLib {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    /// @dev Verifies the storage proof for a given account and slot.
    ///
    /// This function takes an account address, a slot hash, account proof, slot proof, and state root,
    /// and verifies the storage proof using Merkle Trie. It returns the value stored at the given slot.
    ///
    /// @param account The address of the account whose storage is being verified.
    /// @param slot The storage slot being verified.
    /// @param accountProof The Merkle proof for the account.
    /// @param slotProof The Merkle proof for the storage slot.
    /// @param stateRoot The root hash of the state trie.
    /// @return The value stored at the given slot.
    ///
    /// @notice The call will revert if any of the proofs fail.
    function verifyStorageProof(address account, bytes32 slot, bytes[] memory accountProof, bytes[] memory slotProof, bytes32 stateRoot) internal pure returns (bytes32) {
        RLPReader.RLPItem[] memory accountRecord = verifyAccountProof(account, accountProof, stateRoot);
        bytes32 storageRoot = bytes32(accountRecord[2].toUint());
        return verifySlotProof(slot, slotProof, storageRoot);
    }

    /// @dev Verifies the Merkle Patricia proof for an Ethereum account.
    ///
    /// @param account The address of the account to verify.
    /// @param accountProof The Merkle Patricia proof for the account.
    /// @param stateRoot The root hash of the state trie.
    /// @return An array of RLP items representing the account data.
    function verifyAccountProof(address account, bytes[] memory accountProof, bytes32 stateRoot) internal pure returns (RLPReader.RLPItem[] memory) {
        bytes32 accountHash = keccak256(abi.encodePacked(account));
        return MerklePatriciaProofVerifier.extractProofValue({
            rootHash: stateRoot,
            path: abi.encodePacked(accountHash),
            stack: _convertProofItems(accountProof)
        }).toRlpItem().toList();
    }

    /// @dev Verifies the proof of a storage slot and returns the value stored at that slot.
    ///
    /// @param slot The storage slot to verify.
    /// @param slotProof The Merkle proof for the storage slot.
    /// @param storageRoot The root hash of the storage trie.
    /// @return The value stored at the specified storage slot.
    function verifySlotProof(bytes32 slot, bytes[] memory slotProof, bytes32 storageRoot) internal pure returns (bytes32) {
        bytes32 slotHash = keccak256(abi.encodePacked(slot));
        RLPReader.RLPItem memory slotRlp = MerklePatriciaProofVerifier.extractProofValue({
            rootHash: storageRoot,
            path: abi.encodePacked(slotHash),
            stack: _convertProofItems(slotProof)
        }).toRlpItem();

        if (slotRlp.len == 0) {
            return bytes32(0);
        }
        return bytes32(slotRlp.toUint());
    }

    function _convertProofItems(bytes[] memory proof) internal pure returns (RLPReader.RLPItem[] memory) {
        RLPReader.RLPItem[] memory proofItems = new RLPReader.RLPItem[](proof.length);
        for (uint256 i = 0; i < proof.length; i++) {
            proofItems[i] = proof[i].toRlpItem();
        }
        return proofItems;
    }
}
