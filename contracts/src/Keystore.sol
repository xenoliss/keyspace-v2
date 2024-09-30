// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib} from "./KeystoreLib.sol";

contract Keystore {
    /// @notice The Keyspace records.
    mapping(bytes32 id => bytes32 value) public records;

    /// @notice Update a Keyspace record to a `newValue`.
    ///
    /// @param id The ID of the Keyspace record to update.
    /// @param newValue The new Keyspace value to store.
    /// @param controller The controller address, responsible for authorizing the update.
    /// @param storageHash The current storage hash commited in the Keyspace record.
    /// @param proof A proof provided to the `controller` to authorize the update.
    function set(bytes32 id, bytes32 newValue, address controller, bytes32 storageHash, bytes calldata proof) public {
        bytes32 currentValue = records[id];

        // Perform the authorized update on the preconfirmed records.
        KeystoreLib.set({
            records: records,
            id: id,
            currentValue: currentValue,
            newValue: newValue,
            controller: controller,
            storageHash: storageHash,
            proof: proof
        });
    }
}
