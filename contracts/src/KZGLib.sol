// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

struct BLS12381Element {
    bytes32 low;
    bytes16 high;
}

library KZGLib {
    function verify(
        bytes32 versionHash, // VERSIONED_HASH_VERSION_KZG + sha256(commitment)[1:]
        BLS12381Element calldata com,
        bytes32 z,
        bytes32 y,
        BLS12381Element calldata proof
    ) internal returns (bool) {
        (bool success,) = address(0xa).staticcall(abi.encode(versionHash, z, y, com, proof));
        return success;
    }
}
