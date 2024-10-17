// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {BridgedKeystore} from "../src/BridgedKeystore.sol";

import {KeystoreStorageRootProof} from "../src/libs/KeystoreProofLib.sol";
import {L1BlockHashProof, L1ProofType, OPStackProofData} from "../src/libs/L1ProofLib.sol";

struct StorageProofItem {
    bytes32 key;
    bytes[] proof;
    bytes32 value;
}

struct Proof {
    bytes[] accountProof;
    address address_;
    bytes32 balance;
    bytes32 codeHash;
    bytes32 nonce;
    bytes32 storageHash;
    StorageProofItem[] storageProof;
}

contract BridgedKeystoreTest is Test {
    function test_syncKeystoreStorageRoot_ForkBaseSepolia() public {
        // Generate the proof for the AnchorStateRegistry state on the L1.
        // NOTE: The proof must be generated for the L1 block number that is currently available on the L2.
        // cast proof 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205  0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49
        // --rpc-url https://eth-sepolia.public.blastapi.io --block 6771802 > test/res/proof_l2_state.json

        // Generate the proof for the Keystore storage root on the L2.
        // NOTE: The proof must be generated for the L2 block number that was commited in the AnchorStateRegistry
        // output.
        // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2 --rpc-url https://sepolia.base.org --block 15702959 >
        // test/res/proof_keystore_state.json

        // Generate the proof for L1Block.hash on the L2.
        // cast proof 0x4200000000000000000000000000000000000015 2
        // --rpc-url https://sepolia.base.org --block 15856044 > test/res/proof_l1block_state.json

        string memory json = vm.readFile("./test/res/proof_l2_state.json");
        bytes memory data = vm.parseJson(json);
        Proof memory anchorStateRegistryProof = abi.decode(data, (Proof));

        json = vm.readFile("./test/res/proof_keystore_state.json");
        data = vm.parseJson(json);
        Proof memory keystoreProof = abi.decode(data, (Proof));

        json = vm.readFile("./test/res/proof_l1block_state.json");
        data = vm.parseJson(json);
        Proof memory l1BlockHashProof = abi.decode(data, (Proof));

        // Advance one block ahead to make the blockhash(15856044) call succeed.
        vm.createSelectFork("https://sepolia.base.org", 15856045);

        BridgedKeystore sut = new BridgedKeystore({
            anchorStateRegistry_: 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            keystore_: 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        });

        // Block https://sepolia.etherscan.io/block/6771802
        bytes memory blockHeaderRlp =
            hex"f90264a00d34aac15e5ba62302c8e4dc403c8b5bec24ddca7d211a04af21874637ab50b3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c4bfccb1668d6e464f33a76badd8c8d7d341e04aa0de022241601fc767f9b8ef610a1f27f0e6328b026d1e02c3374038b545b7dc0ca0b46477c942ac0f10dc1133fc4317db17c34f63ab363b019f45358afaf0fee3a5a0818e559d217ea53171a2583fda17ee899b1805abee8676a498360dd24ed3c980b901000000400c0101420420180442040020f002020000005190900024c84902c300002018810020004c1410020001821430a04410004082034408000292000124201c88e14000192100024008000a0010c0000420004a0004008241500800010000210c2e88100a80200000d0241080000901000a000001020108080000100000800102a200804298358020600420010080420800200800080008400110c00444000412084080258010154960c1545000200820010209810000a2000536000003009240041002010090000051000188060c880004a1604201240100040830040060840c1400000140200000ab304232080410200100104810020a0c01886201110425808367545a8401c9c38083a90b8d8466f740c499d883010e08846765746888676f312e32322e32856c696e7578a073391a0fa7f323e1dafceb82ec68c4106ce0042b2f3960fd19c080704c367bd58800000000000000008509a26be9eca0c85d42413e6861e268c5bcb35a6b5d06f7e55ae9fdd81c12e40312cb15061bd48308000083e60000a0aae837caff85d8efdcde1128d88e1b0a8195877399c3adbca606e6f70f95be0b";

        bytes[] memory anchorStateRegistryAccountProof = anchorStateRegistryProof.accountProof;
        bytes[] memory anchorStateRegistryStorageProof = anchorStateRegistryProof.storageProof[0].proof;
        bytes[] memory keystoreAccountProof = keystoreProof.accountProof;

        // Block https://sepolia.basescan.org/block/15856044
        // RLP-encoded header via https://blockhash.ardis.lu/
        bytes memory l2BlockHeaderRlp =
            hex"f90241a0a1a742b6a7f4d19adbc6a89ceb31839cbe4c1150fc822567fda483fea6d8d8aba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a03907c82a28483bf07507e9e9d0d5b814624a1165a6a12bc47c72274b6710ffa5a0c75dbcc0f068bd7c0ed665aa667d133e714caad6a827e562dbf1d0a1a43232f3a02687914fef633eb65fff275d682d86e58febf614474963d4411ce9f92f699544b90100000000000000000000000000000000100000008000000000100004000000000000000000000000000000000000000000000000000000000000000008000000001000000000000000000100080044000000000000000000000000000000000000000000000200008000000000000008000000000000000000000000100000000000000000000010002000020000000000000000000000020000000004040000000008000000000000000000000000008000000008400000000000000000000000000000020000000000000000000000080000000000000000000000000000200000000000000000000000040020000000000040000000000000000000000000008083f1f1ac8402aea540830359228466f7423880a073391a0fa7f323e1dafceb82ec68c4106ce0042b2f3960fd19c080704c367bd588000000000000000081fda056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a0aae837caff85d8efdcde1128d88e1b0a8195877399c3adbca606e6f70f95be0b";
        OPStackProofData memory l1BlockHashProofData = OPStackProofData({
            localBlockHeader: l2BlockHeaderRlp,
            l1BlockAccountProof: l1BlockHashProof.accountProof,
            l1BlockStorageProof: l1BlockHashProof.storageProof[0].proof
        });

        sut.syncKeystoreStorageRoot(
            KeystoreStorageRootProof({
                l1BlockHeaderRlp: blockHeaderRlp,
                l1BlockHashProof: L1BlockHashProof({
                    proofType: L1ProofType.OPStack,
                    proofData: abi.encode(l1BlockHashProofData)
                }),
                anchorStateRegistryAccountProof: anchorStateRegistryAccountProof,
                anchorStateRegistryStorageProof: anchorStateRegistryStorageProof,
                keystoreAccountProof: keystoreAccountProof,
                l2StateRoot: 0xc371603ef835569a2be8200f88a1484f274a207d7ff9e9c8e8e22c66b3da6338,
                l2MessagePasserStorageRoot: 0xcad265862b914488fe259095b992220f8c6185f12f9d99519c19322782c496ef,
                l2BlockHash: 0x9109f32441d997ce6948c285664e1e7ac7a229a1f538ff262e03652cce752bb8
            })
        );
    }

    function test_isValueCurrent_ForkBaseSepolia() public {
        // Generate the proof for the AnchorStateRegistry state on the L1.
        // NOTE: The proof must be generated for the L1 block number that is currently available on the L2.
        // cast proof 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205  0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49
        // --rpc-url https://eth-sepolia.public.blastapi.io --block 6771802 > test/res/proof_l2_state.json

        // Generate the proof for the Keystore storage root on the L2.
        // NOTE: The proof must be generated for the L2 block number that was commited in the AnchorStateRegistry
        // output.
        // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2 --rpc-url https://sepolia.base.org --block 15702959 >
        // test/res/proof_keystore_state.json

        // Generate the proof for the Keystore storage slot for Keyspace ID 1 on the L2.
        // NOTE: The proof must be generated for the L2 block number that was commited in the AnchorStateRegistry
        // output.
        // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        // 0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d
        // --rpc-url https://sepolia.base.org --block 15702959 > test/res/proof_keystore_id_1.json

        // Generate the proof for L1Block.hash on the L2.
        // cast proof 0x4200000000000000000000000000000000000015 2
        // --rpc-url https://sepolia.base.org --block 15856044 > test/res/proof_l1block_state.json

        string memory json = vm.readFile("./test/res/proof_l2_state.json");
        bytes memory data = vm.parseJson(json);
        Proof memory anchorStateRegistryProof = abi.decode(data, (Proof));

        json = vm.readFile("./test/res/proof_keystore_state.json");
        data = vm.parseJson(json);
        Proof memory keystoreProof = abi.decode(data, (Proof));

        json = vm.readFile("./test/res/proof_l1block_state.json");
        data = vm.parseJson(json);
        Proof memory l1BlockHashProof = abi.decode(data, (Proof));

        // Advance one block ahead to make the blockhash(15856044) call succeed.
        vm.createSelectFork("https://sepolia.base.org", 15856045);

        BridgedKeystore sut = new BridgedKeystore({
            anchorStateRegistry_: 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            keystore_: 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        });

        // Block https://sepolia.etherscan.io/block/6771802
        bytes memory blockHeaderRlp =
            hex"f90264a00d34aac15e5ba62302c8e4dc403c8b5bec24ddca7d211a04af21874637ab50b3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c4bfccb1668d6e464f33a76badd8c8d7d341e04aa0de022241601fc767f9b8ef610a1f27f0e6328b026d1e02c3374038b545b7dc0ca0b46477c942ac0f10dc1133fc4317db17c34f63ab363b019f45358afaf0fee3a5a0818e559d217ea53171a2583fda17ee899b1805abee8676a498360dd24ed3c980b901000000400c0101420420180442040020f002020000005190900024c84902c300002018810020004c1410020001821430a04410004082034408000292000124201c88e14000192100024008000a0010c0000420004a0004008241500800010000210c2e88100a80200000d0241080000901000a000001020108080000100000800102a200804298358020600420010080420800200800080008400110c00444000412084080258010154960c1545000200820010209810000a2000536000003009240041002010090000051000188060c880004a1604201240100040830040060840c1400000140200000ab304232080410200100104810020a0c01886201110425808367545a8401c9c38083a90b8d8466f740c499d883010e08846765746888676f312e32322e32856c696e7578a073391a0fa7f323e1dafceb82ec68c4106ce0042b2f3960fd19c080704c367bd58800000000000000008509a26be9eca0c85d42413e6861e268c5bcb35a6b5d06f7e55ae9fdd81c12e40312cb15061bd48308000083e60000a0aae837caff85d8efdcde1128d88e1b0a8195877399c3adbca606e6f70f95be0b";

        bytes[] memory anchorStateRegistryAccountProof = anchorStateRegistryProof.accountProof;
        bytes[] memory anchorStateRegistryStorageProof = anchorStateRegistryProof.storageProof[0].proof;
        bytes[] memory keystoreAccountProof = keystoreProof.accountProof;

        // Block https://sepolia.basescan.org/block/15856044
        // RLP-encoded header via https://blockhash.ardis.lu/
        bytes memory l2BlockHeaderRlp =
            hex"f90241a0a1a742b6a7f4d19adbc6a89ceb31839cbe4c1150fc822567fda483fea6d8d8aba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a03907c82a28483bf07507e9e9d0d5b814624a1165a6a12bc47c72274b6710ffa5a0c75dbcc0f068bd7c0ed665aa667d133e714caad6a827e562dbf1d0a1a43232f3a02687914fef633eb65fff275d682d86e58febf614474963d4411ce9f92f699544b90100000000000000000000000000000000100000008000000000100004000000000000000000000000000000000000000000000000000000000000000008000000001000000000000000000100080044000000000000000000000000000000000000000000000200008000000000000008000000000000000000000000100000000000000000000010002000020000000000000000000000020000000004040000000008000000000000000000000000008000000008400000000000000000000000000000020000000000000000000000080000000000000000000000000000200000000000000000000000040020000000000040000000000000000000000000008083f1f1ac8402aea540830359228466f7423880a073391a0fa7f323e1dafceb82ec68c4106ce0042b2f3960fd19c080704c367bd588000000000000000081fda056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a0aae837caff85d8efdcde1128d88e1b0a8195877399c3adbca606e6f70f95be0b";
        OPStackProofData memory l1BlockHashProofData = OPStackProofData({
            localBlockHeader: l2BlockHeaderRlp,
            l1BlockAccountProof: l1BlockHashProof.accountProof,
            l1BlockStorageProof: l1BlockHashProof.storageProof[0].proof
        });
        L1BlockHashProof memory l1BlockHashProofStruct =
            L1BlockHashProof({proofType: L1ProofType.OPStack, proofData: abi.encode(l1BlockHashProofData)});

        bytes32 keyspaceID = bytes32(uint256(1));

        json = vm.readFile("./test/res/proof_keystore_id_1.json");
        data = vm.parseJson(json);
        Proof memory keystoreRecordProof = abi.decode(data, (Proof));

        assertTrue(
            sut.isValueCurrent({
                id: keyspaceID,
                valueHash: keyspaceID,
                keystoreStorageRootProof: abi.encode(
                    KeystoreStorageRootProof({
                        l1BlockHeaderRlp: blockHeaderRlp,
                        l1BlockHashProof: l1BlockHashProofStruct,
                        anchorStateRegistryAccountProof: anchorStateRegistryAccountProof,
                        anchorStateRegistryStorageProof: anchorStateRegistryStorageProof,
                        keystoreAccountProof: keystoreAccountProof,
                        l2StateRoot: 0xc371603ef835569a2be8200f88a1484f274a207d7ff9e9c8e8e22c66b3da6338,
                        l2MessagePasserStorageRoot: 0xcad265862b914488fe259095b992220f8c6185f12f9d99519c19322782c496ef,
                        l2BlockHash: 0x9109f32441d997ce6948c285664e1e7ac7a229a1f538ff262e03652cce752bb8
                    })
                ),
                storageProof: keystoreRecordProof.storageProof[0].proof
            })
        );
    }
}
