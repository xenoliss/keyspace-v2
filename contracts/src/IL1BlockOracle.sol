// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

interface IL1BlockOracle {
    /// @notice The latest L1 block hash.
    function hash() external returns (bytes32);
}
