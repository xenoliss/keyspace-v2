// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib} from "./KeystoreLib.sol";

contract Keystore {
    mapping(bytes32 id => bytes32 value) public records;

    function set(bytes32 id, bytes32 newValue, bytes calldata proof, address controller, bytes32 storageHash) public {
        bytes32 currentValue = records[id];
        KeystoreLib.set({
            records: records,
            id: id,
            currentValue: currentValue,
            newValue: newValue,
            controller: controller,
            storageHash: storageHash,
            proof: proof
        });
    }

    function get(bytes32 id) public view returns (bytes32) {
        return records[id];
    }
}
