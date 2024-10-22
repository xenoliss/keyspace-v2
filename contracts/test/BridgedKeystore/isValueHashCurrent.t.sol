// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {BridgedKeystore} from "../../src/BridgedKeystore.sol";

import {parseProof} from "../_utils/StorageProofStructs.sol";

contract IsValueHashCurrentTest is Test {
    function test_ForkBaseSepolia() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block number + a small offset to simulate some elapsed time.
        //       Also proving the current l2 block is not supported yet as `blockhash(currentBlockNumber)` returns 0.
        vm.createSelectFork("https://sepolia.base.org", 16924995 + 42);

        // Generate the storage proof for the Keystore on the L2 (for a Keystore identifier of 1).
        // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        // 0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d --rpc-url https://sepolia.base.org
        // --block 16771890 > test/_res/Keystore_storage_proof.json
        (bytes32 keystoreStorageRoot,, bytes[] memory keystoreStorageProof) =
            parseProof({vm: vm, path: "./test/_res/Keystore_storage_proof.json"});

        // Deploys the BridgedKeystore to that L2.
        BridgedKeystore sut = new BridgedKeystore({
            anchorStateRegistry_: 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            keystore_: 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        });

        // Mock a synchronization of the Keystore storage root.
        vm.store({target: address(sut), slot: bytes32(0), value: keystoreStorageRoot});

        bytes32 keystoreId = bytes32(uint256(1));

        assertTrue(
            sut.isValueHashCurrent({
                id: keystoreId,
                valueHash: keystoreId,
                confirmedValueHashStorageProof: keystoreStorageProof
            })
        );
    }
}
