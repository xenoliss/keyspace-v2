// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ValueHashPreimages} from "../libs/KeystoreLib.sol";


interface IBridgedKeystore {
    function isValueCurrent(bytes32 id, bytes32 valueHash, bytes memory recordProof) external view returns (bool);

    function syncRoot(
        bytes memory blockHeaderRlp,
        bytes memory l1BlockHashProof,
        bytes[] memory anchorStateRegistryAccountProof,
        bytes[] memory anchorStateRegistryStorageProof,
        bytes[] memory keystoreAccountProof,
        bytes32 l2StateRoot,
        bytes32 l2MessagePasserStorageRoot,
        bytes32 l2BlockHash
    ) external;

    function preconfirmUpdate(
        bytes32 id,
        bytes[] calldata confirmedValueHashInclusionProof,
        uint256 confirmedIndex,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata controllerProof
    ) external;
    
    function preconfirmUpdateWithFork(
        bytes32 id,
        bytes[] calldata confirmedValueHashInclusionProof,
        ValueHashPreimages calldata confirmedValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        uint256 conflictingIndex,
        ValueHashPreimages calldata conflictingValueHashPreimages,
        bytes calldata controllerProof
    ) external;
}
