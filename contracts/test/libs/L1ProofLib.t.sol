// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {L1BlockHashProof, L1ProofLib, L1ProofType, OPStackProofData} from "../../src/libs/L1ProofLib.sol";

import {Proof, StorageProof, parseProof} from "../_utils/StorageProofStructs.sol";

contract L1ProofLibTest is Test {
    function test_verifyL1BlockHash_OPStack_reverts_whenBlockHashIsTooOld() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block number + a small offset to simulate some elapsed time.
        //       Also proving the current l2 block is not supported as `blockhash(currentBlockNumber)` returns 0.
        vm.createSelectFork("https://sepolia.base.org", 16954442 + 257);

        // Block https://sepolia.basescan.org/block/16954442
        bytes memory l2BlockHeaderRlp =
            hex"f90245a080b5c058ff243f88d6424c3690080f2f99e96160105654fe9031ea54811fce5ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a00052ec1011f1d7411810f5ca496600c9b4923602af1760e86710c89a628c06ada0914f22481c066720e5633e3700d7cd28feb33e1b53b17fda48ae8043507e8e28a05243b74a937da53f6b7b7bfb208cbd46c25aa87def1c204c897c0735d9921395b901009020000000000000000220202010000000090812020008c0040c090420200000004000100000800040900a000900000000170010000000000000040000000080002410404100800800014008000020000800000403040102200201113202006000008101028000000000000000000d020000480009000000000024100100000003440a0040080004200400000000041010001840006090000021002004040000810812001004000402000080001008000000080000010001000000c0100004010000080208400000016004004008020800000008004800040a10000000002222000004000000000060420000000040420000080000000002000800010000800080840102b44a84039387008346e9c8846718c77480a0269788445cf43ed7d7acd44d6032d0eabeae380b3868a72e9a64b7909bb170e888000000000000000084626b6b06a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a04dd76c16f6e4177701c31b1ef6c2280709b1d3dd29130f4e4ebd77c4346cdfa5";

        OPStackProofData memory l1BlockProofData;
        l1BlockProofData.l2BlockHeaderRlp = l2BlockHeaderRlp;

        vm.expectRevert(abi.encodeWithSelector(L1ProofLib.BlockHashNotAvailable.selector, 16954442));
        L1ProofLib.verifyL1BlockHash({
            proof: L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockProofData)}),
            expectedL1BlockHash: bytes32(uint256(0xcafe))
        });
    }

    function test_verifyL1BlockHash_OPStack_reverts_whenBlockHeaderIsInvalid() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block that is more than 256 blocks ahead of the block being proven to trigger the error.
        vm.createSelectFork("https://sepolia.base.org", 16954442 + 42);

        // Block https://sepolia.basescan.org/block/16954442
        // NOTE: The RLP encoding has been altered to store a block number of 16954443 (0x102b44b) instead of the
        //       correct one 16954442 (0x102b44a).
        bytes memory l2BlockHeaderRlp =
            hex"f90245a080b5c058ff243f88d6424c3690080f2f99e96160105654fe9031ea54811fce5ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a00052ec1011f1d7411810f5ca496600c9b4923602af1760e86710c89a628c06ada0914f22481c066720e5633e3700d7cd28feb33e1b53b17fda48ae8043507e8e28a05243b74a937da53f6b7b7bfb208cbd46c25aa87def1c204c897c0735d9921395b901009020000000000000000220202010000000090812020008c0040c090420200000004000100000800040900a000900000000170010000000000000040000000080002410404100800800014008000020000800000403040102200201113202006000008101028000000000000000000d020000480009000000000024100100000003440a0040080004200400000000041010001840006090000021002004040000810812001004000402000080001008000000080000010001000000c0100004010000080208400000016004004008020800000008004800040a10000000002222000004000000000060420000000040420000080000000002000800010000800080840102b44b84039387008346e9c8846718c77480a0269788445cf43ed7d7acd44d6032d0eabeae380b3868a72e9a64b7909bb170e888000000000000000084626b6b06a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a04dd76c16f6e4177701c31b1ef6c2280709b1d3dd29130f4e4ebd77c4346cdfa5";

        OPStackProofData memory l1BlockProofData;
        l1BlockProofData.l2BlockHeaderRlp = l2BlockHeaderRlp;

        vm.expectRevert(
            abi.encodeWithSelector(
                L1ProofLib.InvalidBlockHeader.selector,
                0xa5d4b70ed7639d0b36cc2405a8223cbb3fd61a8985df4bcc631330a0b3554dfb, // blockHeaderHash
                0xc2d58e5b1d989dc1680a87f177832ea2fa1a7aae6d307d29e55c14c6420a24d0 // blockHash
            )
        );
        L1ProofLib.verifyL1BlockHash({
            proof: L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockProofData)}),
            expectedL1BlockHash: bytes32(uint256(0xcafe))
        });
    }

    function test_verifyL1BlockHash_OPStack_reverts_whenExtractedL1BlockHasIsNotTheExpectedOne() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block number + a small offset to simulate some elapsed time.
        //       Also proving the current l2 block is not supported as `blockhash(currentBlockNumber)` returns 0.
        vm.createSelectFork("https://sepolia.base.org", 16954442 + 42);

        // Block https://sepolia.basescan.org/block/16954442
        bytes memory l2BlockHeaderRlp =
            hex"f90245a080b5c058ff243f88d6424c3690080f2f99e96160105654fe9031ea54811fce5ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a00052ec1011f1d7411810f5ca496600c9b4923602af1760e86710c89a628c06ada0914f22481c066720e5633e3700d7cd28feb33e1b53b17fda48ae8043507e8e28a05243b74a937da53f6b7b7bfb208cbd46c25aa87def1c204c897c0735d9921395b901009020000000000000000220202010000000090812020008c0040c090420200000004000100000800040900a000900000000170010000000000000040000000080002410404100800800014008000020000800000403040102200201113202006000008101028000000000000000000d020000480009000000000024100100000003440a0040080004200400000000041010001840006090000021002004040000810812001004000402000080001008000000080000010001000000c0100004010000080208400000016004004008020800000008004800040a10000000002222000004000000000060420000000040420000080000000002000800010000800080840102b44a84039387008346e9c8846718c77480a0269788445cf43ed7d7acd44d6032d0eabeae380b3868a72e9a64b7909bb170e888000000000000000084626b6b06a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a04dd76c16f6e4177701c31b1ef6c2280709b1d3dd29130f4e4ebd77c4346cdfa5";

        // Get the storage proof for the L1Block on the L2.
        // cast proof 0x4200000000000000000000000000000000000015 2 --rpc-url https://sepolia.base.org --block 16954442 > test/_res/l1Block_storage_proof.base-sepolia.16954442.json
        Proof memory l1BlockProof =
            parseProof({vm: vm, path: "./test/_res/l1Block_storage_proof.base-sepolia.16954442.json"});
        StorageProof memory l1BlockStorageProof = l1BlockProof.storageProofs[0];

        OPStackProofData memory l1BlockProofData = OPStackProofData({
            l2BlockHeaderRlp: l2BlockHeaderRlp,
            l1BlockAccountProof: l1BlockProof.accountProof,
            l1BlockStorageProof: l1BlockStorageProof.proof
        });

        bytes32 expectedL1BlockHash = bytes32(uint256(0xcafe));

        vm.expectRevert(
            abi.encodeWithSelector(
                L1ProofLib.BlockHashMismatch.selector,
                0xe55c9979ce4c7e7f897e9eb5dd499f052900a951b86a86b255f1d67b1bc5e3aa, // l1Blockhash
                expectedL1BlockHash // expectedL1BlockHash
            )
        );
        L1ProofLib.verifyL1BlockHash({
            proof: L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockProofData)}),
            expectedL1BlockHash: expectedL1BlockHash
        });
    }

    function test_verifyL1BlockHash_OPStack() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block number + a small offset to simulate some elapsed time.
        //       Also proving the current l2 block is not supported as `blockhash(currentBlockNumber)` returns 0.
        vm.createSelectFork("https://sepolia.base.org", 16954442 + 42);

        // Block https://sepolia.basescan.org/block/16954442
        bytes memory l2BlockHeaderRlp =
            hex"f90245a080b5c058ff243f88d6424c3690080f2f99e96160105654fe9031ea54811fce5ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a00052ec1011f1d7411810f5ca496600c9b4923602af1760e86710c89a628c06ada0914f22481c066720e5633e3700d7cd28feb33e1b53b17fda48ae8043507e8e28a05243b74a937da53f6b7b7bfb208cbd46c25aa87def1c204c897c0735d9921395b901009020000000000000000220202010000000090812020008c0040c090420200000004000100000800040900a000900000000170010000000000000040000000080002410404100800800014008000020000800000403040102200201113202006000008101028000000000000000000d020000480009000000000024100100000003440a0040080004200400000000041010001840006090000021002004040000810812001004000402000080001008000000080000010001000000c0100004010000080208400000016004004008020800000008004800040a10000000002222000004000000000060420000000040420000080000000002000800010000800080840102b44a84039387008346e9c8846718c77480a0269788445cf43ed7d7acd44d6032d0eabeae380b3868a72e9a64b7909bb170e888000000000000000084626b6b06a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a04dd76c16f6e4177701c31b1ef6c2280709b1d3dd29130f4e4ebd77c4346cdfa5";

        // Get the storage proof for the L1Block on the L2.
        // cast proof 0x4200000000000000000000000000000000000015 2 --rpc-url https://sepolia.base.org --block 16954442 > test/_res/l1Block_storage_proof.base-sepolia.16954442.json
        Proof memory l1BlockProof =
            parseProof({vm: vm, path: "./test/_res/l1Block_storage_proof.base-sepolia.16954442.json"});
        StorageProof memory l1BlockStorageProof = l1BlockProof.storageProofs[0];

        OPStackProofData memory l1BlockProofData = OPStackProofData({
            l2BlockHeaderRlp: l2BlockHeaderRlp,
            l1BlockAccountProof: l1BlockProof.accountProof,
            l1BlockStorageProof: l1BlockStorageProof.proof
        });

        L1ProofLib.verifyL1BlockHash({
            proof: L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockProofData)}),
            expectedL1BlockHash: l1BlockStorageProof.value
        });
    }
}
