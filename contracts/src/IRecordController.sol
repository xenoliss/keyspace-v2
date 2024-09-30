// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

interface IRecordController {
    /// @notice Authorizes (or not) the update of a Keyspace record.
    ///
    /// @param id The ID of the Keyspace record being updated.
    /// @param currentValue The Keyspace record current value.
    /// @param newValue The Keyspace record new value.
    /// @param proof A proof authorizing the update.
    ///
    /// @return authorized Whether or not the update is authorized.
    function authorize(bytes32 id, bytes32 currentValue, bytes32 newValue, bytes calldata proof)
        external
        returns (bool authorized);
}
