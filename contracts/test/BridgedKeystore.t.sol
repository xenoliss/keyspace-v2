// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {BridgedKeystore} from "../src/BridgedKeystore.sol";

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
    function testForkBaseSepolia() public {
        // Generate the proof for the AnchorStateRegistry state on the L1.
        // NOTE: The proof must be generated for the L1 block number that is currently available on the L2.
        // cast proof 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49 --rpc-url https://eth-sepolia.public.blastapi.io --block 6771802 > test/proof_l2.json

        // Generate the proof for the Keystore storage root on the L2.
        // NOTE: The proof must be generated for the L2 block number that was commited in the AnchorStateRegistry output.
        // cast proof 0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2 --rpc-url https://sepolia.base.org --block 15702959 > test/proof_keystore.json

        string memory json = vm.readFile("./test/proof_l2.json");
        bytes memory data = vm.parseJson(json);
        Proof memory anchorStateRegistryProof = abi.decode(data, (Proof));

        json = vm.readFile("./test/proof_keystore.json");
        data = vm.parseJson(json);
        Proof memory keystoreProof = abi.decode(data, (Proof));

        vm.createSelectFork("https://sepolia.base.org", 15856044);

        BridgedKeystore sut = new BridgedKeystore(
            0x4200000000000000000000000000000000000015,
            0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205,
            0x610A7e97C6D2F1E09e6390F013BFCc39B8EE49e2
        );

        // Block https://sepolia.etherscan.io/block/6771623
        bytes memory blockHeaderRlp =
            hex"f90264a00d34aac15e5ba62302c8e4dc403c8b5bec24ddca7d211a04af21874637ab50b3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c4bfccb1668d6e464f33a76badd8c8d7d341e04aa0de022241601fc767f9b8ef610a1f27f0e6328b026d1e02c3374038b545b7dc0ca0b46477c942ac0f10dc1133fc4317db17c34f63ab363b019f45358afaf0fee3a5a0818e559d217ea53171a2583fda17ee899b1805abee8676a498360dd24ed3c980b901000000400c0101420420180442040020f002020000005190900024c84902c300002018810020004c1410020001821430a04410004082034408000292000124201c88e14000192100024008000a0010c0000420004a0004008241500800010000210c2e88100a80200000d0241080000901000a000001020108080000100000800102a200804298358020600420010080420800200800080008400110c00444000412084080258010154960c1545000200820010209810000a2000536000003009240041002010090000051000188060c880004a1604201240100040830040060840c1400000140200000ab304232080410200100104810020a0c01886201110425808367545a8401c9c38083a90b8d8466f740c499d883010e08846765746888676f312e32322e32856c696e7578a073391a0fa7f323e1dafceb82ec68c4106ce0042b2f3960fd19c080704c367bd58800000000000000008509a26be9eca0c85d42413e6861e268c5bcb35a6b5d06f7e55ae9fdd81c12e40312cb15061bd48308000083e60000a0aae837caff85d8efdcde1128d88e1b0a8195877399c3adbca606e6f70f95be0b";

        bytes[] memory anchorStateRegistryAccountProof = anchorStateRegistryProof.accountProof;
        bytes[] memory anchorStateRegistryStorageProof = anchorStateRegistryProof.storageProof[0].proof;
        bytes[] memory keystoreAccountProof = keystoreProof.accountProof;

        sut.syncRoot({
            blockHeaderRlp: blockHeaderRlp,
            anchorStateRegistryAccountProof: anchorStateRegistryAccountProof,
            anchorStateRegistryStorageProof: anchorStateRegistryStorageProof,
            keystoreAccountProof: keystoreAccountProof,
            l2StateRoot: 0xc371603ef835569a2be8200f88a1484f274a207d7ff9e9c8e8e22c66b3da6338,
            l2MessagePasserStorageRoot: 0xcad265862b914488fe259095b992220f8c6185f12f9d99519c19322782c496ef,
            l2BlockHash: 0x9109f32441d997ce6948c285664e1e7ac7a229a1f538ff262e03652cce752bb8
        });
    }
}
