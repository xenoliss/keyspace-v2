// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {StorageProofLib} from "../../src/libs/StorageProofLib.sol";

import {Proof, StorageProof, parseProof} from "../_utils/StorageProofStructs.sol";

contract StorageProofLibTest is Test {
    function test_extractAccountStorageValue() public view {
        Proof memory proof = parseProof({vm: vm, path: "./test/_res/usdc_storage_proof.base.21442537.json"});

        for (uint256 i; i < proof.storageProofs.length; i++) {
            StorageProof memory storageProof = proof.storageProofs[i];

            bytes32 value = StorageProofLib.extractAccountStorageValue({
                stateRoot: 0x892b8fba153f875f92bcb2c1ce06a67858a5e1e647535aefdb155ec2c50814b3,
                account: proof.address_,
                accountProof: proof.accountProof,
                slot: storageProof.key,
                storageProof: storageProof.proof
            });

            assertEq(value, storageProof.value);
        }
    }

    function test_extractAccountStorageRoot() public view {
        Proof memory proof = parseProof({vm: vm, path: "./test/_res/usdc_storage_proof.base.21442537.json"});

        bytes32 storageRoot = StorageProofLib.extractAccountStorageRoot({
            stateRoot: 0x892b8fba153f875f92bcb2c1ce06a67858a5e1e647535aefdb155ec2c50814b3,
            account: proof.address_,
            accountProof: proof.accountProof
        });

        assertEq(storageRoot, proof.storageHash);
    }

    function test_extractSlotValue() public view {
        Proof memory proof = parseProof({vm: vm, path: "./test/_res/usdc_storage_proof.base.21442537.json"});

        for (uint256 i; i < proof.storageProofs.length; i++) {
            StorageProof memory storageProof = proof.storageProofs[i];

            bytes32 value = StorageProofLib.extractSlotValue({
                storageRoot: proof.storageHash,
                slot: storageProof.key,
                storageProof: storageProof.proof
            });

            assertEq(value, storageProof.value);
        }
    }
}
