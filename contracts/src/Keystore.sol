// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib, ValueHashPreimages} from "./libs/KeystoreLib.sol";

contract Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore record is updated.
    ///
    /// @param id The Keystore identifier of the updated record.
    /// @param newValueHash The new ValueHash stored in the record.
    event KeystoreRecordSet(bytes32 id, bytes32 newValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STORAGE                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The Keystore records.
    mapping(bytes32 id => bytes32 valueHash) public records;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Updates a Keystore record to a new `newValueHash`.
    ///
    /// @param id The identifier of the Keystore record to update.
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keystore record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param controllerProof A proof provided to the Keystore record `controller` to authorize the update.
    function set(
        bytes32 id,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata controllerProof
    ) public {
        // Use the `records[id]` ValueHash to authorize the `newValueHash`.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: records[id],
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            controllerProof: controllerProof
        });

        records[id] = newValueHash;

        emit KeystoreRecordSet({id: id, newValueHash: newValueHash});
    }
}
