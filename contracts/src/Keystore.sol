// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib, RecordPreimages} from "./KeystoreLib.sol";

contract Keystore {
    /// @notice The Keyspace records.
    mapping(bytes32 id => bytes32 value) public records;

    /// @notice Update a Keyspace record to a `newValueHash`.
    ///
    /// @param id The ID of the Keyspace record to update.
    /// @param currentValueHashPreimages The Keyspace record current value preimages.
    /// @param newValueHash The new Keyspace value to store.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function set(
        bytes32 id,
        RecordPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        RecordPreimages calldata newValueHashPreimages,
        bytes calldata proof
    ) public {
        bytes32 currentValueHash = records[id];

        // Perform the authorized update on the records.
        KeystoreLib.set({
            records: records,
            id: id,
            currentValueHash: currentValueHash,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            proof: proof
        });
    }
}
