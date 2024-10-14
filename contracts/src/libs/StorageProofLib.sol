// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {MerkleTrie} from "optimism/libraries/trie/MerkleTrie.sol";
import {RLPReader} from "Solidity-RLP/RLPReader.sol";

library StorageProofLib {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    /**
     * @dev Verifies the storage proof for a given account and slot.
     *
     * This function takes an account address, a slot hash, account proof, slot proof, and state root,
     * and verifies the storage proof using Merkle Trie. It returns the value stored at the given slot.
     *
     * @param account The address of the account whose storage is being verified.
     * @param slot The storage slot being verified.
     * @param accountProof The Merkle proof for the account.
     * @param slotProof The Merkle proof for the storage slot.
     * @param stateRoot The root hash of the state trie.
     * @return The value stored at the given slot.
     *
     * @notice The call will revert if any of the proofs fail.
     */         
    function verifyStorageProof(address account, bytes32 slot, bytes[] memory accountProof, bytes[] memory slotProof, bytes32 stateRoot) internal pure returns (bytes32) {
        bytes32 accountHash = keccak256(abi.encodePacked(account));
        bytes32 storageRoot = bytes32(
            MerkleTrie.get({
                _key: abi.encodePacked(accountHash),
                _proof: accountProof,
                _root: stateRoot
            }).toRlpItem().toList()[2].toUint()
        );

        return verifySlotProof(slot, slotProof, storageRoot);
    }

    /// @dev Verifies the proof of a storage slot and returns the value stored at that slot.
    ///
    /// @param slot The storage slot to verify.
    /// @param slotProof The Merkle proof for the storage slot.
    /// @param storageRoot The root hash of the storage trie.
    /// @return The value stored at the specified storage slot.
    function verifySlotProof(bytes32 slot, bytes[] memory slotProof, bytes32 storageRoot) internal pure returns (bytes32) {
        bytes32 slotHash = keccak256(abi.encodePacked(slot));
        bytes32 slotValue = bytes32(
            MerkleTrie.get({
                _key: abi.encodePacked(slotHash),
                _proof: slotProof,
                _root: storageRoot
            }).toRlpItem().toUint()
        );

        return slotValue;
    }
}
