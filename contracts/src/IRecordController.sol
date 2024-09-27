// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

interface IRecordController {
    function validate(bytes32 id, bytes32 currentValue, bytes32 newValue, bytes calldata proof)
        external
        returns (bool valid);
}
