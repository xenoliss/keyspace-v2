// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib, RecordValuePreimages} from "./KeystoreLib.sol";

contract Keystore {
    /// @notice The Keyspace records.
    mapping(bytes32 id => bytes32 value) public records;

    /// @notice Update a Keyspace record to a `newValue`.
    ///
    /// @param id The ID of the Keyspace record to update.
    /// @param currentValuePreimages The Keyspace record current value preimages.
    /// @param newValue The new Keyspace value to store.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function set(
        bytes32 id,
        RecordValuePreimages calldata currentValuePreimages,
        bytes32 newValue,
        bytes calldata proof
    ) public {
        bytes32 currentValue = records[id];

        // Perform the authorized update on the records.
        KeystoreLib.set({
            records: records,
            id: id,
            currentValue: currentValue,
            currentValuePreimages: currentValuePreimages,
            newValue: newValue,
            proof: proof
        });
    }
}
