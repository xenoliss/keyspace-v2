// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader} from "../libs/BlockLib.sol";

interface IRecordController {
    /// @notice Authorizes (or not) a Keystore record update.
    ///
    /// @param id The identifier of the Keystore record being updated.
    /// @param currentValueHash The Keystore record current value hash.
    /// @param newValueHash The Keystore record new value hash.
    /// @param l1BlockHeader The L1 block header used to prove the L1 state.
    /// @param proof A proof authorizing the update.
    ///
    /// @return True if the update is authorized, else false.
    function authorize(
        bytes32 id,
        bytes32 currentValueHash,
        bytes32 newValueHash,
        BlockHeader calldata l1BlockHeader,
        bytes calldata proof
    ) external returns (bool);
}
