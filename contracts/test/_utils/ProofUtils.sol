// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/console.sol";

import {VM} from "./VmExport.sol";

struct StorageProof {
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
    StorageProof[] storageProofs;
}

function parseProof(string memory path) view returns (Proof memory proof) {
    string memory json = VM.readFile(path);
    bytes memory data = VM.parseJson(json);
    return abi.decode(data, (Proof));
}
