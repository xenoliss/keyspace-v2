// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

interface IRecordController {
    /// @notice Authorizes (or not) a Keyspace record update.
    ///
    /// @param id The ID of the Keyspace record being updated.
    /// @param currentValueHash The Keyspace record current value hash.
    /// @param newValueHash The Keyspace record new value hash.
    /// @param proof A proof authorizing the update.
    ///
    /// @return authorized Whether or not the update is authorized.
    function authorize(bytes32 id, bytes32 currentValueHash, bytes32 newValueHash, bytes calldata proof)
        external
        returns (bool authorized);
}
