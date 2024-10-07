// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {console} from "forge-std/console.sol";

bytes1 constant VERSIONED_HASH_VERSION_KZG = bytes1(0x01);

library KZGLib {
    // TODO: Notworking because
    // https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/deneb/polynomial-commitments.md#verify_kzg_proof_impl
    // has the KZG_SETUP_G2[1] hardcoded in it.
    function verify(bytes memory com, bytes memory proof, bytes32 z, bytes32 y)
        internal
        view
        returns (bool, bytes memory)
    {
        require(com.length == 48);
        require(proof.length == 48);

        bytes32 versionHash_ = versionHash(com);
        (bool success, bytes memory b) = address(0xa).staticcall(abi.encodePacked(versionHash_, z, y, com, proof));
        return (success, b);
    }

    // VERSIONED_HASH_VERSION_KZG + sha256(commitment)[1:]
    function versionHash(bytes memory com) internal pure returns (bytes32) {
        bytes32 sha = sha256(com);
        return (sha << 8 >> 8) | bytes32(uint256(uint8(VERSIONED_HASH_VERSION_KZG)) << 248);
    }
}
