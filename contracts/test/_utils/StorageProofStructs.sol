// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";

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

function parseProof(Vm vm, string memory path)
    view
    returns (bytes32 storageRoot, bytes[] memory accountProof, bytes[] memory storageProof)
{
    string memory json = vm.readFile(path);
    bytes memory data = vm.parseJson(json);
    Proof memory proof = abi.decode(data, (Proof));

    storageRoot = proof.storageHash;
    accountProof = proof.accountProof;
    storageProof = proof.storageProof[0].proof;
}
