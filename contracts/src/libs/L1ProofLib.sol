// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, BlockLib} from "./BlockLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

enum L1ProofType {
    Hashi,
    OPStack
}

struct L1BlockHashProof {
    L1ProofType proofType;
    bytes proofData;
}

struct HashiProofData {
    uint256 blockNumber;
}

struct OPStackProofData {
    bytes localBlockHeader;
    bytes[] l1BlockAccountProof;
    bytes[] l1BlockStorageProof;
}

library L1ProofLib {
    address constant L1BLOCK_PREDEPLOY_ADDRESS = 0x4200000000000000000000000000000000000015;
    // cast storage 0x4200000000000000000000000000000000000015 --rpc-url https://sepolia.base.org --api-key $API_KEY
    bytes32 constant L1BLOCK_HASH_SLOT = bytes32(uint256(2));

    /**
     * @notice Proves the block hash based on the proof type.
     * @param proof The L1 block proof data.
     * @param expectedBlockHash The expected block hash to verify against.
     */
    function verifyBlockHash(
        L1BlockHashProof memory proof,
        bytes32 expectedBlockHash
    ) internal view returns (bool) {
        if (proof.proofType == L1ProofType.Hashi) {
            revert("ProofLib: NOT_IMPLEMENTED_YET");
        } else if (proof.proofType == L1ProofType.OPStack) {
            // Decode OPStack proof data
            OPStackProofData memory opStackProof = abi.decode(proof.proofData, (OPStackProofData));
            // Verify OPStack proof
            return _verifyBlockHashOPStack(opStackProof, expectedBlockHash);
        } else {
            revert("ProofLib: INVALID_PROOF_TYPE");
        }
    }

    /**
     * @notice Internal function to verify OPStack block hashes within the 256-block limit.
     * @param proofData The OPStack proof data.
     * @param expectedBlockHash The expected block hash to verify against.
     */
    function _verifyBlockHashOPStack(
        OPStackProofData memory proofData,
        bytes32 expectedBlockHash
    ) internal view returns (bool) {
        BlockHeader memory localHeader = BlockLib.parseBlockHeader(proofData.localBlockHeader);
        bytes32 localBlockHash = blockhash(localHeader.number);
        require(
            localBlockHash != bytes32(0),
            "ProofLib: BLOCKHASH_NOT_AVAILABLE (OPStack)"
        );
        require(
            localBlockHash == localHeader.hash,
            "ProofLib: INVALID_BLOCK_HASH (OPStack)"
        );

        bytes32 l1BlockValue = StorageProofLib.verifyStorageProof(
            L1BLOCK_PREDEPLOY_ADDRESS,
            L1BLOCK_HASH_SLOT,
            proofData.l1BlockAccountProof,
            proofData.l1BlockStorageProof,
            localHeader.stateRootHash
        );
        return l1BlockValue == expectedBlockHash;
    }
}
