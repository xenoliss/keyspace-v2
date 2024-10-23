// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {KeystoreStorageRootProof} from "../src/libs/KeystoreLib.sol";
import {L1BlockHashProof, L1ProofType, OPStackProofData} from "../src/libs/L1ProofLib.sol";

import {BridgedKeystore} from "../src/BridgedKeystore.sol";

import {Proof, parseProof} from "./_utils/StorageProofStructs.sol";

contract SyncKeystoreStorageRootTest is Test {
    function test_isValueHashCurrent_EmptyRecord() public {
        // TODO: Write test for a not empty record.

        // Deploys the BridgedKeystore.
        BridgedKeystore sut = new BridgedKeystore({
            anchorStateRegistry_: 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            keystore_: 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        });

        // Get the account proof for the Keystore on the L2.
        // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2 0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d --rpc-url https://sepolia.base.org --block 16802894 > test/_res/keystore_storage_proof.base-sepolia.16802894.json
        Proof memory keystoreProof =
            parseProof({vm: vm, path: "./test/_res/keystore_storage_proof.base-sepolia.16802894.json"});

        vm.store({target: address(sut), slot: 0x0, value: keystoreProof.storageHash});

        bytes32 keystoreId = bytes32(uint256(1));

        assertFalse(
            sut.isValueHashCurrent({
                id: keystoreId,
                valueHash: bytes32(uint256(0xcafe)),
                confirmedValueHashStorageProof: keystoreProof.storageProofs[0].proof
            })
        );

        assertTrue(
            sut.isValueHashCurrent({
                id: keystoreId,
                valueHash: keystoreId,
                confirmedValueHashStorageProof: keystoreProof.storageProofs[0].proof
            })
        );
    }

    function test_syncKeystoreStorageRoot() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block number + a small offset to simulate some elapsed time.
        //       Also proving the current l2 block is not supported as `blockhash(currentBlockNumber)` returns 0.
        vm.createSelectFork("https://sepolia.base.org", 16954442 + 42);

        // Deploys the BridgedKeystore to that L2.
        BridgedKeystore sut = new BridgedKeystore({
            anchorStateRegistry_: 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            keystore_: 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        });

        // Build the L1 block proof.
        OPStackProofData memory l1BlockProofData;
        {
            // Get the storage proof for the L1Block on the L2.
            // cast proof 0x4200000000000000000000000000000000000015 2 --rpc-url https://sepolia.base.org --block 16954442 > test/_res/l1Block_storage_proof.base-sepolia.16954442.json
            Proof memory l1BlockProof =
                parseProof({vm: vm, path: "./test/_res/l1Block_storage_proof.base-sepolia.16954442.json"});

            // Block https://sepolia.basescan.org/block/16954442
            bytes memory l2BlockHeaderRlp =
                hex"f90245a080b5c058ff243f88d6424c3690080f2f99e96160105654fe9031ea54811fce5ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a00052ec1011f1d7411810f5ca496600c9b4923602af1760e86710c89a628c06ada0914f22481c066720e5633e3700d7cd28feb33e1b53b17fda48ae8043507e8e28a05243b74a937da53f6b7b7bfb208cbd46c25aa87def1c204c897c0735d9921395b901009020000000000000000220202010000000090812020008c0040c090420200000004000100000800040900a000900000000170010000000000000040000000080002410404100800800014008000020000800000403040102200201113202006000008101028000000000000000000d020000480009000000000024100100000003440a0040080004200400000000041010001840006090000021002004040000810812001004000402000080001008000000080000010001000000c0100004010000080208400000016004004008020800000008004800040a10000000002222000004000000000060420000000040420000080000000002000800010000800080840102b44a84039387008346e9c8846718c77480a0269788445cf43ed7d7acd44d6032d0eabeae380b3868a72e9a64b7909bb170e888000000000000000084626b6b06a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a04dd76c16f6e4177701c31b1ef6c2280709b1d3dd29130f4e4ebd77c4346cdfa5";

            l1BlockProofData = OPStackProofData({
                l2BlockHeaderRlp: l2BlockHeaderRlp,
                l1BlockAccountProof: l1BlockProof.accountProof,
                l1BlockStorageProof: l1BlockProof.storageProofs[0].proof
            });
        }

        // Build the 2 levels Keystore Storage proof.
        KeystoreStorageRootProof memory keystoreStorageRootProof;
        {
            // Block https://sepolia.etherscan.io/block/6928356
            bytes memory l1BlockHeaderRlp =
                hex"f90264a0f936afdd8b3fefdd518f1c73280dcf1aaa25b8aa7a46269d5824c4bc9e892bd5a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347949b984d5a03980d8dc0a24506c968465424c81dbea08bcef2a5a891212f97e044aa093b93e43fda70bb17fbf97829dbebb7e3a7844fa03a785192dbcc242fa393cd94e32332e9c2fb5528d0833139453d8c27f809ea3ba0e5cedb146cfb7ebef194f9970645b5d161a1e134e37cd8b38b16141fc2fe7503b90100004808e9a824448c3091019a83092008c001e4e0003752010110898a0492850800c08200800d005404005000231c418004101010024004058842958414222032083050440b0e044a5658250a1828e2800d44904aa24a0624044441089920b093000240c1a60732418260242290b0e9200ec806d0500c0c890684081c520c100202e2341050b8e460e0004400a13202d2480bad498010c200e08340080581934226a868f9036650005903000c21a4381cc822e669d0b2149380c0306204045ac3a6c415a300800284194200039d87006043e50b000500808e4163e0302460601000160100712854804230802b600042001008a02c481146680402298308005004808369b7e48401c9c38083db8e03846718c60899d883010e07846765746888676f312e32322e35856c696e7578a0269788445cf43ed7d7acd44d6032d0eabeae380b3868a72e9a64b7909bb170e88800000000000000008501445b8baea004345e41459b5f4034e9ccc017cf2d55cdcc96ce335b423a079a8016557326808308000083180000a04dd76c16f6e4177701c31b1ef6c2280709b1d3dd29130f4e4ebd77c4346cdfa5";

            // Get the storage proof for the AnchorStateRegistry on the L1.
            // cast proof 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49 --rpc-url https://eth-sepolia.public.blastapi.io --block 6928356 > test/_res/anchorStateRegistry_storage_proof.eth-sepolia.6928356.json
            Proof memory anchorStateRegistryProof =
                parseProof({vm: vm, path: "./test/_res/anchorStateRegistry_storage_proof.eth-sepolia.6928356.json"});

            // Get the account proof for the Keystore on the L2.
            // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2 0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d --rpc-url https://sepolia.base.org --block 16802894 > test/_res/keystore_storage_proof.base-sepolia.16802894.json
            Proof memory keystoreProof =
                parseProof({vm: vm, path: "./test/_res/keystore_storage_proof.base-sepolia.16802894.json"});

            keystoreStorageRootProof = KeystoreStorageRootProof({
                l1BlockHeaderRlp: l1BlockHeaderRlp,
                l1BlockHashProof: L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockProofData)}),
                anchorStateRegistryAccountProof: anchorStateRegistryProof.accountProof,
                anchorStateRegistryStorageProof: anchorStateRegistryProof.storageProofs[0].proof,
                keystoreAccountProof: keystoreProof.accountProof,
                l2StateRoot: 0xff27420e4f50ff20d3d75021fa1cdb37a931274bbb251a64b863534305732b14,
                l2MessagePasserStorageRoot: 0x998ff6a91706f713ef91fe369cf189326a9ce30641204035da20461c476c9429,
                l2BlockHash: 0x7d759236609004cbe94f29c87f60443d2257b9abad0c12485315c95341aebb97
            });
        }

        sut.syncKeystoreStorageRoot(keystoreStorageRootProof);
    }
}
