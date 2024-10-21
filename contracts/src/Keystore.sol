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

    /// @notice Updates a Keystore record to a new ValueHash.
    ///
    /// @param id The identifier of the Keystore record to update.
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keystore record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProof A proof provided to the Keystore record `controller` to authorize the update.
    function set(
        bytes32 id,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        bytes calldata controllerProof
    ) public {
        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: records[id],
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProof: controllerProof
        });

        records[id] = newValueHash;

        emit KeystoreRecordSet({id: id, newValueHash: newValueHash});
    }
}
