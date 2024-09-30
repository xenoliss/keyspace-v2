// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IRecordController} from "./IRecordController.sol";

/// @dev The preimages of a Keyspace record value.
struct RecordPreimages {
    /// @dev The controller address, responsible for authorizing the update.
    address controller;
    /// @dev The record nonce.
    uint96 nonce;
    /// @dev The current storage hash commited in the Keyspace record.
    bytes32 storageHash;
}

library KeystoreLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keyspace record is updated.
    ///
    /// @param id The ID of the Keyspace record updated.
    /// @param previousValueHash The previous Keyspace record value hash.
    /// @param newValueHash The new Keyspace record value hash.
    event RecordSet(bytes32 id, bytes32 previousValueHash, bytes32 newValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided `valueHash` and `valueHashFromPreimages` do not match.
    ///
    /// @param valueHash The Keyspace record value hash.
    /// @param valueHashFromPreimages The Keyspace record value hash recomputed from the preimages.
    error RecordValueMismatch(bytes32 valueHash, bytes32 valueHashFromPreimages);

    /// @notice Thrown when the provided new nonce is not strictly increasing compared to the current one.
    error InvalidNonce(uint256 currentNonce, uint256 newNonce);

    /// @notice Thrown the Keyspace record update authorization fails.
    error Unhauthorized();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Perfoms an authorized update of a Keyspace record.
    ///
    /// @param records The Keyspace records storage pointer.
    /// @param id The ID of the Keyspace record to update.
    /// @param currentValueHash The Keyspace record current value hash.
    /// @param currentValueHashPreimages The Keyspace record current value hash preimages.
    /// @param newValueHash The Keyspace record new value.
    /// @param newValueHashPreimages The Keyspace record new value hash preimages.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function set(
        mapping(bytes32 id => bytes32 value) storage records,
        bytes32 id,
        bytes32 currentValueHash,
        RecordPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        RecordPreimages calldata newValueHashPreimages,
        bytes calldata proof
    ) internal {
        // Ensure the record values match with the provided preimages.
        _verifyRecordValue({valueHash: currentValueHash, valueHashPreimages: currentValueHashPreimages});
        _verifyRecordValue({valueHash: newValueHash, valueHashPreimages: newValueHashPreimages});

        // Ensure the nonce is strictly incrementing.
        if (newValueHashPreimages.nonce != currentValueHashPreimages.nonce + 1) {
            revert InvalidNonce({currentNonce: currentValueHashPreimages.nonce, newNonce: newValueHashPreimages.nonce});
        }

        bool authorized = IRecordController(currentValueHashPreimages.controller).authorize({
            id: id,
            currentValueHash: currentValueHash,
            newValueHash: newValueHash,
            proof: proof
        });

        if (!authorized) {
            revert Unhauthorized();
        }

        records[id] = newValueHash;
        emit RecordSet({id: id, previousValueHash: currentValueHash, newValueHash: newValueHash});

        // TODO: We could require data availability here for both the new storageHash preimage and the newValue
        //       preimage. They could either be stored onchain or emitted as events.
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Recompute the Keyspace record value hash from the provided preimages and ensure it maches with the given
    ///         `valueHash` parameter.
    ///
    /// @dev Reverts if the parameters hashes do not match.
    ///
    /// @param valueHash The Keyspace record value hash.
    /// @param valueHashPreimages The value hash preimages.
    function _verifyRecordValue(bytes32 valueHash, RecordPreimages calldata valueHashPreimages) private pure {
        // Recompute the Keyspace record value hash from the provided preimages and ensure it maches with the given
        // `valueHash` parameter.
        bytes32 valueHashFromPreimages = keccak256(
            abi.encodePacked(valueHashPreimages.controller, valueHashPreimages.nonce, valueHashPreimages.storageHash)
        );
        if (valueHashFromPreimages != valueHash) {
            revert RecordValueMismatch({valueHash: valueHash, valueHashFromPreimages: valueHashFromPreimages});
        }
    }
}
