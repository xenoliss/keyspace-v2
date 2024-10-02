// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib, ValueHashPreimages} from "./libs/KeystoreLib.sol";

contract Keystore {
    /// @notice The Keyspace records.
    mapping(bytes32 id => bytes32 valueHash) public records;

    /// @notice Updates a Keyspace record to a new `newValueHash`.
    ///
    /// @param id The ID of the Keyspace record to update.
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keyspace record.
    /// @param newValueHash The new ValueHash to store in the Keyspace record.
    /// @param controllerProof A proof provided to the Keyspace record `controller` to authorize the update.
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

        // TODO: Emit event.
    }
}
