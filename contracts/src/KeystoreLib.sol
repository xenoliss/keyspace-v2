// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IRecordController} from "./IRecordController.sol";

// TODO: Use custom errors.

library KeystoreLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keyspace record is updated.
    ///
    /// @param id The ID of the Keyspace record updated.
    /// @param previousValue The previous Keyspace record value.
    /// @param newValue The new Keyspace record value.
    event RecordSet(bytes32 id, bytes32 previousValue, bytes32 newValue);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Perfoms an authorized update of a Keyspace record.
    ///
    /// @param records The Keyspace records storage pointer.
    /// @param id The ID of the Keyspace record to update.
    /// @param currentValue The Keyspace record current value.
    /// @param newValue The Keyspace record new value.
    /// @param controller The controller address, responsible for authorizing the update.
    /// @param storageHash The current storage hash commited in the Keyspace record.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function set(
        mapping(bytes32 id => bytes32 value) storage records,
        bytes32 id,
        bytes32 currentValue,
        bytes32 newValue,
        address controller,
        bytes32 storageHash,
        bytes calldata proof
    ) internal {
        bytes32 expectedValue = keccak256(abi.encodePacked(controller, storageHash));
        require(
            currentValue == expectedValue,
            "The provided controller and storage hash do not match the current value of the record."
        );

        // TODO: here shouldn't we rather pass in the `storageHash` directly instead of the `currentValue`?
        require(
            IRecordController(controller).authorize({
                id: id,
                currentValue: currentValue,
                newValue: newValue,
                proof: proof
            }),
            "The provided proof is invalid."
        );

        // TODO: We could require data availability here for both the new storageHash preimage and the newValue
        // preimage.
        //       They could either be stored onchain or emitted as events.

        records[id] = newValue;
        emit RecordSet({id: id, previousValue: currentValue, newValue: newValue});
    }
}
