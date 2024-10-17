// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, BlockLib} from "./BlockLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

/// @dev The suported L1 block hash proof types.
enum L1ProofType {
    Hashi,
    OPStack
}

/// @dev An agnostic L1 block hash proof.
struct L1BlockHashProof {
    /// @dev The proof type to use.
    L1ProofType proofType;
    /// @dev The proof data to decode.
    bytes proofData;
}

/// @dev A generic L1 block hash proof using Hashi oracle.
struct HashiProofData {
    uint256 blockNumber;
}

/// @dev An L1 block hash proof specific to OPStack L2 chains.
struct OPStackProofData {
    /// @dev The L2 block header.
    bytes localBlockHeader;
    /// @dev The L1Block oracle account proof on the L2.
    bytes[] l1BlockAccountProof;
    /// @dev The L1Block oracle hash slot storage proof on the L2.
    bytes[] l1BlockStorageProof;
}

library L1ProofLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Address of the L1Block oracle on OP stack chains.
    address constant L1BLOCK_PREDEPLOY_ADDRESS = 0x4200000000000000000000000000000000000015;

    /// @notice Storage slot where the L1 block hash is stored on the L1Block oracle.
    bytes32 constant L1BLOCK_HASH_SLOT = bytes32(uint256(2));

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Proves the L1 block hash based on the proof type.
    ///
    /// @param proof The L1 block proof data.
    /// @param expectedL1BlockHash The expected block hash to verify against.
    ///
    /// @return True if the expected L1 block hash is valid, flase otherwise.
    function verifyL1BlockHash(L1BlockHashProof memory proof, bytes32 expectedL1BlockHash)
        internal
        view
        returns (bool)
    {
        if (proof.proofType == L1ProofType.Hashi) {
            revert("ProofLib: NOT_IMPLEMENTED_YET");
        }

        if (proof.proofType == L1ProofType.OPStack) {
            // Decode OPStack proof data.
            OPStackProofData memory opStackProof = abi.decode(proof.proofData, (OPStackProofData));

            // Verify OPStack proof.
            return _verifyBlockhashOPStack({proofData: opStackProof, expectedL1BlockHash: expectedL1BlockHash});
        }

        revert("ProofLib: INVALID_PROOF_TYPE");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         PRIVATE FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Verifies OPStack block hashes within the 256-block limit.
    ///
    /// @param proofData The OPStack proof data.
    /// @param expectedL1BlockHash The expected block hash to verify against.
    ///
    /// @return True if the expected L1 block hash is valid, flase otherwise.
    function _verifyBlockhashOPStack(OPStackProofData memory proofData, bytes32 expectedL1BlockHash)
        private
        view
        returns (bool)
    {
        BlockHeader memory localHeader = BlockLib.parseBlockHeader(proofData.localBlockHeader);

        // Get the block hash corresponding to the provided block number.
        bytes32 localBlockhash = blockhash(localHeader.number);

        // Ensure the block hash exists (i.e the block number provided is in the latest 256 most recent blocks).
        require(localBlockhash != bytes32(0), "ProofLib: BLOCKHASH_NOT_AVAILABLE (OPStack)");

        // Ensure the block header is valid against the block hash being used.
        require(localBlockhash == localHeader.hash, "ProofLib: INVALID_BLOCK_HASH (OPStack)");

        // Extract the L1 block hash value from the L1Block account and storage proofs.
        bytes32 l1Blockhash = StorageProofLib.extractAccountStorageValue({
            stateRoot: localHeader.stateRootHash,
            account: L1BLOCK_PREDEPLOY_ADDRESS,
            accountProof: proofData.l1BlockAccountProof,
            slot: L1BLOCK_HASH_SLOT,
            storageProof: proofData.l1BlockStorageProof
        });

        // Ensure the extracted L1 block hash matches with the expected one.
        return l1Blockhash == expectedL1BlockHash;
    }
}
