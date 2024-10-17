// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RecordController} from "../RecordController.sol";

/// @dev The preimages of a ValueHash stored in a Keystore record.
struct ValueHashPreimages {
    /// @dev The address of the controller responsible for authorizing updates.
    address controller;
    /// @dev The nonce associated with the Keystore record.
    uint96 nonce;
    /// @dev The current storage hash committed in the Keystore record.
    bytes32 storageHash;
}

library KeystoreLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided `valueHash` does not match the recomputed `valueHashFromPreimages`.
    ///
    /// @param valueHash The original ValueHash of the Keystore record.
    /// @param valueHashFromPreimages The recomputed ValueHash from the provided preimages.
    error RecordValueMismatch(bytes32 valueHash, bytes32 valueHashFromPreimages);

    /// @notice Thrown when the provided new nonce is not strictly greater than the current nonce.
    ///
    /// @param currentNonce The current nonce of the Keystore record.
    /// @param newNonce The provided new nonce, which is not strictly greater than the current one.
    error InvalidNonce(uint256 currentNonce, uint256 newNonce);

    /// @notice Thrown when the Keystore record controller prevents the update.
    error Unauthorized();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Authorizes a Keystore record update.
    ///
    /// @dev Reverts if the authorization fails.
    ///
    /// @param id The ID of the Keystore record being updated.
    /// @param currentValueHash The current ValueHash of the Keystore record.
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keystore record.
    /// @param newValueHash The new ValueHash to be stored in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash in the Keystore record.
    /// @param controllerProof A proof provided to the Keystore record `controller` to authorize the update.
    function verifyNewValueHash(
        bytes32 id,
        bytes32 currentValueHash,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata controllerProof
    ) internal {
        // Ensure that the current and new `ValueHash` preimages are correct.
        verifyRecordPreimages({valueHash: currentValueHash, valueHashPreimages: currentValueHashPreimages});
        verifyRecordPreimages({valueHash: newValueHash, valueHashPreimages: newValueHashPreimages});

        // Ensure the nonce is strictly incrementing.
        require(
            newValueHashPreimages.nonce == currentValueHashPreimages.nonce + 1,
            InvalidNonce({currentNonce: currentValueHashPreimages.nonce, newNonce: newValueHashPreimages.nonce})
        );

        // Authorize the update from the controller.
        require(
            RecordController(currentValueHashPreimages.controller).authorize({
                id: id,
                currentValueHash: currentValueHash,
                newValueHash: newValueHash,
                proof: controllerProof
            }),
            Unauthorized()
        );
    }

    /// @notice Recomputes the ValueHash from the provided preimages and ensures it maches with the given `valueHash`.
    ///
    /// @dev Reverts if the parameters hashes do not match.
    ///
    /// @param valueHash The Keystore record value hash.
    /// @param valueHashPreimages The value hash preimages.
    function verifyRecordPreimages(bytes32 valueHash, ValueHashPreimages calldata valueHashPreimages) internal pure {
        // Recompute the Keystore record value hash from the provided preimages.
        bytes32 valueHashFromPreimages = keccak256(
            abi.encodePacked(valueHashPreimages.controller, valueHashPreimages.nonce, valueHashPreimages.storageHash)
        );

        // Ensure the recomputed ValueHash matches witht the given valueHash` parameter.
        require(
            valueHashFromPreimages == valueHash,
            RecordValueMismatch({valueHash: valueHash, valueHashFromPreimages: valueHashFromPreimages})
        );
    }
}
