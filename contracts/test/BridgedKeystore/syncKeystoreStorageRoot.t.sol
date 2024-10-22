// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {KeystoreStorageRootProof} from "../../src/libs/KeystoreLib.sol";
import {L1BlockHashProof, L1ProofType, OPStackProofData} from "../../src/libs/L1ProofLib.sol";

import {BridgedKeystore} from "../../src/BridgedKeystore.sol";

import {parseProof} from "../_utils/StorageProofStructs.sol";

contract SyncKeystoreStorageRootTest is Test {
    function test_ForkBaseSepolia() public {
        // Fork L2 at specific block number.
        // NOTE: Set at a block number + a small offset to simulate some elapsed time.
        //       Also proving the current l2 block is not supported yet as `blockhash(currentBlockNumber)` returns 0.
        vm.createSelectFork("https://sepolia.base.org", 16924995 + 42);

        // Deploys the BridgedKeystore to that L2.
        BridgedKeystore sut = new BridgedKeystore({
            anchorStateRegistry_: 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            keystore_: 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        });

        // Build the L1 block proof.
        OPStackProofData memory l1BlockProofData;
        {
            // Generate the storage proof for the L1Block on the L2.
            // cast proof 0x4200000000000000000000000000000000000015 2 --rpc-url https://sepolia.base.org --block
            // 16924995 > test/_res/L1Block_storage_proof.json
            (, bytes[] memory l1BlockAccountProof, bytes[] memory l1BlockStorageProof) =
                parseProof({vm: vm, path: "./test/_res/L1Block_storage_proof.json"});

            // Block https://sepolia.basescan.org/block/16924995
            bytes memory l2BlockHeaderRlp =
                hex"f90244a082d2f50042dc60653cd77f8cfb54a6c47e703dc2980b4644b22365876c8a6f19a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0596376a77ac467d334b1da4ed5e7fc0c874d8038f751eda52875289105560b0aa0c1671d82919359fcfa99fee30f30f63c6200d7969473afd90b00811a490108a9a079fd3895e5883c03f3116c38c7dad03b1d8e9b43f737316ebd2e6c8f34dea1ffb9010000000102480020000102000800000400000c0a7a0008000000042100300808200000400b8000808004002830000c4000000010000482080000018c18102420080281208800008a00000000380800c4000000032098840280041401a0000286480000010102004081000402810008480001000004480000008800001800081008200040e0000115010000104812c0448004010000022008800002c000002000000780260800040028a10080001000c23040008a100806040000180000020b0404000101024820000002020001000484840201000828880001020180800000626000310200000a28074002000000224481000204000110400400400c2008012900808401024143840393870083733f84846717e16680a0d75fcb7c9785f6a89ca2e2ff324760ba9eae27961faaf27a95dd909db2ada68d88000000000000000083d4ae70a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a079801f9c36e839d7e67fff0c95da2f0b53c27659b95c3f971e13d78a35b5a79e";

            l1BlockProofData = OPStackProofData({
                l2BlockHeaderRlp: l2BlockHeaderRlp,
                l1BlockAccountProof: l1BlockAccountProof,
                l1BlockStorageProof: l1BlockStorageProof
            });
        }

        // Build the 2 levels Keystore Storage proof.
        KeystoreStorageRootProof memory keystoreStorageRootProof;
        {
            // Block https://sepolia.etherscan.io/block/6923997
            bytes memory l1BlockHeaderRlp =
                hex"f90261a0c56b3c632363db878837b1168a95351fd94f543fa725151cae8b461ea15baccea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c4bfccb1668d6e464f33a76badd8c8d7d341e04aa05d2634ed8f902e63c274e788000097a477b55b90e8445a99eeacf171f13ec9a0a02a96a1e1ca0bcc9cb48139cf9f0d9f30b3f02327a724a4dd630b72f6357a2fcda00961f550c1b038e0708f5cee7afb0a75ab5ec0315f9dd5dec0a94b6b12417d7fb90100210100049200c04464d0103a820904acb30082740103127092600d04088304d203e4312822a0029040084514210421b82312911201000684210279846c24085054020ae0210c40024128064a091b88851706c234210402060443c9e35014da12068400dc6600046320232520100148700a0920e8084428809660201c040842004a21a50201d6604b6044410022241018084d8c4470000202d015034904090018338a4258880058040903431960a891362e86f0692202170a41a80066a30018c11026154230903280005300913b52006170c002010118880241a7d4802d6068ba03114202760a28876a622cc16180e2049846003a48900008051001418821d304808369a6dd8401c9c380840121d0cb846717e01c99d883010e08846765746888676f312e32322e32856c696e7578a0d75fcb7c9785f6a89ca2e2ff324760ba9eae27961faaf27a95dd909db2ada68d88000000000000000084e875980da0b5149cb7787e511ad0fc965eb1fd3b1d8ca87869ae55e307994bc3652582d5b580831e0000a079801f9c36e839d7e67fff0c95da2f0b53c27659b95c3f971e13d78a35b5a79e";

            // Generate the storage proof for the AnchorStateRegistry on the L1.
            // cast proof 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205
            // 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49 --rpc-url
            // https://eth-sepolia.public.blastapi.io --block 6923997 > test/_res/AnchorStateRegistry_storage_proof.json
            (, bytes[] memory anchorStateRegistryAccountProof, bytes[] memory anchorStateRegistryStorageProof) =
                parseProof({vm: vm, path: "./test/_res/AnchorStateRegistry_storage_proof.json"});

            // Generate the account proof for the Keystore on the L2.
            // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
            // 0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d --rpc-url https://sepolia.base.org
            // --block 16771890 > test/_res/Keystore_storage_proof.json
            (, bytes[] memory keystoreAccountProof,) =
                parseProof({vm: vm, path: "./test/_res/Keystore_storage_proof.json"});

            keystoreStorageRootProof = KeystoreStorageRootProof({
                l1BlockHeaderRlp: l1BlockHeaderRlp,
                l1BlockHashProof: L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockProofData)}),
                anchorStateRegistryAccountProof: anchorStateRegistryAccountProof,
                anchorStateRegistryStorageProof: anchorStateRegistryStorageProof,
                keystoreAccountProof: keystoreAccountProof,
                l2StateRoot: 0x629df7c6f95fcb810e4490ab3a1f7d576e9195137aadbb68bc0c8bb851e6291b,
                l2MessagePasserStorageRoot: 0x8726d0a18c1b9c39ef692a25406a08d5b1a0e10bc8423e668ab6d98988a1a18c,
                l2BlockHash: 0xf2c0ae554e7c6c382b27b2ce8f203c15b14c2577ae7fab5e14801b689ee7a11a
            });
        }

        sut.syncKeystoreStorageRoot(keystoreStorageRootProof);
    }
}
