// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader} from "../libs/BlockLib.sol";

interface IRecordController {
    /// @notice Authorizes (or not) a Keystore record update.
    ///
    /// @dev The `l1BlockHeader` is OPTIONAL. If using this parameter, the implementation MUST check that the provided
    ///      L1 block header is not the default one. This can be done by using `require(l1BlockHeader.number > 0)`.
    ///
    /// @param id The identifier of the Keystore record being updated.
    /// @param currentValueHash The current value hash of the Keystore record.
    /// @param newValueHash The new value hash of the Keystore record.
    /// @param l1BlockHeader OPTIONAL: The L1 block header to access and prove L1 state.
    /// @param proof A proof authorizing the update.
    ///
    /// @return True if the update is authorized, otherwise false.
    function authorize(
        bytes32 id,
        bytes32 currentValueHash,
        bytes32 newValueHash,
        BlockHeader calldata l1BlockHeader,
        bytes calldata proof
    ) external returns (bool);
}
