// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IRecordController} from "./IRecordController.sol";

library KeystoreLib {
    event RecordSet(bytes32 id, bytes32 oldValue, bytes32 newValue);

    function set(
        mapping(bytes32 id => bytes32 value) storage records,
        bytes32 id,
        bytes32 currentValue,
        bytes32 newValue,
        address controller,
        bytes32 storageHash,
        bytes calldata proof
    ) internal {
        bytes32 expectedValue = keccak256(abi.encodePacked(controller, storageHash));
        require(
            currentValue == expectedValue,
            "The provided controller and storage hash do not match the current value of the record."
        );

        // TODO: here shouldn't we rather pass in the `storageHash` directly instead of the `currentValue`?
        require(
            IRecordController(controller).validate(id, currentValue, newValue, proof), "The provided proof is invalid."
        );

        // TODO: We could require data availability here for both the new storageHash preimage and the newValue preimage.
        //       They could either be stored onchain or emitted as events.

        records[id] = newValue;
        emit RecordSet(id, currentValue, newValue);
    }
}
