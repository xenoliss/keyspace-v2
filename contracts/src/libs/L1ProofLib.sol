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
    /// @dev The L2 block header RLP encoded.
    bytes l2BlockHeaderRlp;
    /// @dev The L1Block oracle account proof on the L2.
    bytes[] l1BlockAccountProof;
    /// @dev The L1Block oracle hash slot storage proof on the L2.
    bytes[] l1BlockStorageProof;
}

library L1ProofLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when verifying an OPStackProofData if the block number is not within the 256 most recent blocks.
    ///
    /// @param blockNumber The block number provided from which to get the hash.
    error BlockHashNotAvailable(uint256 blockNumber);

    /// @notice Thrown when verifying an OPStackProofData if the block header does not match the block hash fetched
    ///         from the block number using `blockhash`.
    ///
    /// @param blockHeaderHash The block header hash.
    /// @param blockHash The block hash obtained by calling `blockhash(header.number)`.
    error InvalidBlockHeader(bytes32 blockHeaderHash, bytes32 blockHash);

    /// @notice Thrown when verifying an OPStackProofData if the extracted L1 block hash from the proof does not equal
    ///         the expected L1 block hash to verify.
    ///
    /// @param l1Blockhash The L1 block hash extracted from the OPStackProofData.
    /// @param expectedL1BlockHash The L1 block hash that was expected for verification.
    error BlockHashMismatch(bytes32 l1Blockhash, bytes32 expectedL1BlockHash);

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
    function verifyL1BlockHash(L1BlockHashProof memory proof, bytes32 expectedL1BlockHash) internal view {
        if (proof.proofType == L1ProofType.Hashi) {
            revert("ProofLib: NOT_IMPLEMENTED_YET");
        } else if (proof.proofType == L1ProofType.OPStack) {
            // Decode OPStack proof data and verify it.
            OPStackProofData memory opStackProof = abi.decode(proof.proofData, (OPStackProofData));
            _verifyBlockHashOPStack({proofData: opStackProof, expectedL1BlockHash: expectedL1BlockHash});
        } else {
            revert("ProofLib: INVALID_PROOF_TYPE");
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         PRIVATE FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Verifies OPStack block hashes within the 256 blocks limit.
    ///
    /// @param proofData The OPStack proof data.
    /// @param expectedL1BlockHash The expected block hash to verify against.
    function _verifyBlockHashOPStack(OPStackProofData memory proofData, bytes32 expectedL1BlockHash) private view {
        BlockHeader memory blockHeader = BlockLib.parseBlockHeader(proofData.l2BlockHeaderRlp);

        // TODO: If we're trying to prove the current block this will fail. Should we allow proving the current block
        //       by comparing the block number) and if so directly read the L1Block contract to get the L1 block hash?

        // Get the block hash corresponding to the provided block number.
        bytes32 blockHash = blockhash(blockHeader.number);

        // Ensure the block hash is available (the block number provided is withinh the latest 256 most recent blocks).
        require(blockHash != bytes32(0), BlockHashNotAvailable(blockHeader.number));

        // Ensure the block header is valid against the block hash being used.
        require(
            blockHash == blockHeader.hash, InvalidBlockHeader({blockHeaderHash: blockHeader.hash, blockHash: blockHash})
        );

        // Extract the L1 block hash value from the L1Block account and storage proofs.
        bytes32 l1Blockhash = StorageProofLib.extractAccountStorageValue({
            stateRoot: blockHeader.stateRoot,
            account: L1BLOCK_PREDEPLOY_ADDRESS,
            accountProof: proofData.l1BlockAccountProof,
            slot: L1BLOCK_HASH_SLOT,
            storageProof: proofData.l1BlockStorageProof
        });

        // Ensure the extracted L1 block hash matches with the expected one.
        require(
            l1Blockhash == expectedL1BlockHash,
            BlockHashMismatch({l1Blockhash: l1Blockhash, expectedL1BlockHash: expectedL1BlockHash})
        );
    }
}
