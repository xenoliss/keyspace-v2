// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, BlockLib} from "./libs/BlockLib.sol";

abstract contract RecordController {
    /// @notice Authorizes (or not) a Keyspace record update.
    ///
    /// @param id The ID of the Keyspace record being updated.
    /// @param currentValueHash The Keyspace record current value hash.
    /// @param newValueHash The Keyspace record new value hash.
    // /// @param l1BlockHash The L1 block hash used for proving L1 state.
    /// @param proof A proof authorizing the update.
    ///
    /// @return authorized Whether or not the update is authorized.
    function authorize(
        bytes32 id,
        bytes32 currentValueHash,
        bytes32 newValueHash,
        // TODO: add the l1BlockHash parameter.
        // bytes32 l1BlockHash,
        bytes calldata proof
    ) external returns (bool authorized) {
        // TODO: Parse the blockheader and validate it against the L1 bock hash.
        BlockHeader memory blockHeader;

        // Delegate to the wallet authorize implentation.
        return _authorize({
            id: id,
            currentValueHash: currentValueHash,
            newValueHash: newValueHash,
            blockHeader: blockHeader,
            proof: proof
        });
    }

    /// @notice Authorizes (or not) a Keyspace record update.
    ///
    /// @param id The ID of the Keyspace record being updated.
    /// @param currentValueHash The Keyspace record current value hash.
    /// @param newValueHash The Keyspace record new value hash.
    /// @param blockHeader The L1 block header used for proving L1 state.
    /// @param proof A proof authorizing the update.
    ///
    /// @return authorized Whether or not the update is authorized.
    function _authorize(
        bytes32 id,
        bytes32 currentValueHash,
        bytes32 newValueHash,
        BlockHeader memory blockHeader,
        bytes calldata proof
    ) internal virtual returns (bool authorized);
}
