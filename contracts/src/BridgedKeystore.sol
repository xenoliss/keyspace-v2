// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreLib, ValueHashPreimages} from "./libs/KeystoreLib.sol";
import {KeystoreProofLib, KeystoreStorageRootProof} from "./libs/KeystoreProofLib.sol";
import {StorageProofLib} from "./libs/StorageProofLib.sol";

contract BridgedKeystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when the Keystore storage root from the reference L2 is successfully synchronized.
    ///
    /// @param keystoreStorageRoot The new synchronized Keystore storage root.
    /// @param l1BlockNumber The L1 block number used to prove the Keystore storage root.
    event KeystoreRootSynchronized(bytes32 keystoreStorageRoot, uint256 l1BlockNumber);

    /// @notice Emitted when a Keystore record update is preconfirmed.
    ///
    /// @param id The Keystore identifier of the updated record.
    /// @param newValueHash The new ValueHash stored in the record.
    event KeystoreRecordUpdatePreconfirmed(bytes32 id, bytes32 newValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to preconfirm a Keystore record update (forking method), but the confirmed
    ///         ValueHash (recovered from the `keystoreStorageRoot`) and the ValueHash at the given lookup index in the
    ///         active fork are the same.
    ///
    /// @param valueHash The common ValueHash.
    error NoValueHashConflict(bytes32 valueHash);

    /// @notice Thrown when attempting to preconfirm a Keystore record update (non-forking method), but the nonces
    ///         committed in the conflicting ValueHashes are not equal.
    ///
    /// @param confirmedNonce The nonce committed in the confirmed ValueHash recovered from the `keystoreStorageRoot`.
    /// @param preconfirmedNonce The nonce committed in the preconfirmed ValueHash found at the provided lookup index.
    error InvalidConflictingNonce(uint256 confirmedNonce, uint256 preconfirmedNonce);

    /// @notice Thrown when the L1 block number used by the provided Keystore storage root proof is older than the one
    ///         used to prove the latest Keystore storage root.
    ///
    /// @param provenL1BlockNumber The L1 block number used to prove the latest Keystore storage root.
    /// @param provingL1BlockNumber The L1 block number used byt the provided (stale) Keystore storage root proof.
    error KeystoreStorageRootProofStale(uint256 provenL1BlockNumber, uint256 provingL1BlockNumber);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the `AnchorStateRegistry` contract on L1.
    address public immutable anchorStateRegistry;

    /// @notice The address of the `Keystore` contract on the reference L2.
    address public immutable keystore;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STORAGE                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The latest proven reference L2 Keystore storage root.
    bytes32 public keystoreStorageRoot;

    /// @notice The latest L1 block number used to prove the reference L2 Keystore storage root.
    uint256 public l1BlockNumber;

    /// @notice The active fork for each Keystore identifier.
    ///
    /// @dev Preconfirmations are organized into "forks," which are sequences of successive ValueHashes set for a
    ///      given Keystore record. A new fork is created if a conflict arises between the active fork and the confirmed
    ///      ValueHash (recovered from the L2 Keystore storage root). The active fork for any Keystore record is always
    ///      the most recent one created.
    mapping(bytes32 id => uint256 activeFork) public activeForks;

    /// @notice Preconfirmed Keystore records for each fork.
    mapping(bytes32 id => mapping(uint256 fork => bytes32[] valueHashes)) public preconfirmedValueHashes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Deploys a `BridgedKeystore` contract.
    ///
    /// @param anchorStateRegistry_ The address of the `AnchorStateRegistry` contract on L1.
    /// @param keystore_ The address of the `Keystore` contract on the reference L2.
    constructor(address anchorStateRegistry_, address keystore_) {
        anchorStateRegistry = anchorStateRegistry_;
        keystore = keystore_;

        // FIXME: This allows a BridgedKeystore to be deployed uninitialized, which will allow old keystore states to be
        // used on alt-L1s. We can require initialization and use the timestamp from the keystore proof's L1 block
        // header to restrict the age of the keystoreStorageRoot.
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Checks if the provided ValueHash is current for the given Keystore record identifier.
    ///
    /// @dev This function verifies the provided ValueHash against the current state proof of the Keystore record
    ///      identifier. It first checks if the proof is rooted at the stored keystoreStorageRoot or a more recent L1
    ///      block. On L3 chains and L2s of alt-L1s, proofs against L1 blocks are prohibited, and the
    ///      keystoreStorageRoot must be synced with a deposit transaction.
    ///
    ///      If the proof contains a root proof, it verifies the root proof and ensures it is not older than the
    ///      already synced on-chain state. The function then verifies the ValueHash against the Keystore record proof
    ///      root.
    ///
    ///      If the verified ValueHash is on the current fork for the Keystore record, the function uses the latest
    ///      ValueHash on the fork.
    ///
    /// @param id The identifier of the Keystore record.
    /// @param valueHash The ValueHash of the Keystore record that is being checked.
    /// @param keystoreStorageRootProof OPTIONAL: A Keystore account proof, proving a more recent Keystore root.
    /// @param confirmedValueHashStorageProof The storage proof from which to extract the confirmed ValueHash of the
    ///                                       Keystore record.
    ///
    /// @return bool True if the ValueHash is current, false otherwise.
    function isValueHashCurrent(
        bytes32 id,
        bytes32 valueHash,
        bytes calldata keystoreStorageRootProof,
        bytes[] calldata confirmedValueHashStorageProof
    ) external view returns (bool) {
        // Defaults to the latest Keystore storage root known.
        bytes32 keystoreStorageRoot_ = keystoreStorageRoot;

        // Try to extract a more recent Keystore storage root if a `keystoreStorageRootProof` was provided.
        if (keystoreStorageRootProof.length > 0) {
            // TODO: Disallow proofs against L1 blocks on L3 chains and alt-L1 L2s.
            bool isRootProofAllowed = true;
            require(
                isRootProofAllowed,
                "Keystore root proofs are not allowed on this chain. Use deposit transactions instead."
            );

            uint256 l1BlockNumber_;
            (keystoreStorageRoot_, l1BlockNumber_) = KeystoreProofLib.extractKeystoreStorageRoot({
                anchorStateRegistry: anchorStateRegistry,
                keystore: keystore,
                keystoreStorageRootProof: abi.decode(keystoreStorageRootProof, (KeystoreStorageRootProof))
            });

            // Ensure the L1 block number used by the provided Keystore storage root proof is not older than the one
            // used to prove the latest Keystore storage root.
            require(
                l1BlockNumber_ >= l1BlockNumber,
                KeystoreStorageRootProofStale({provenL1BlockNumber: l1BlockNumber, provingL1BlockNumber: l1BlockNumber_})
            );
        }

        // Get the current ValueHash to use.
        (,, bytes32 currentValueHash) = _recordValueHashes({
            id: id,
            keystoreStorageRoot_: keystoreStorageRoot_,
            confirmedValueHashStorageProof: confirmedValueHashStorageProof
        });

        // Check if the provided ValueHash is current.
        return valueHash == currentValueHash;
    }

    /// @notice Synchronizes the Keystore storage root from the reference L2.
    ///
    /// @param keystoreStorageRootProof The KeystoreStorageRootProof struct.
    function syncKeystoreStorageRoot(KeystoreStorageRootProof calldata keystoreStorageRootProof) external {
        (bytes32 keystoreStorageRoot_, uint256 l1BlockNumber_) = KeystoreProofLib.extractKeystoreStorageRoot({
            anchorStateRegistry: anchorStateRegistry,
            keystore: keystore,
            keystoreStorageRootProof: keystoreStorageRootProof
        });

        // Ensure the L1 block number used by the provided Keystore storage root proof is not older than the one
        // used to prove the latest Keystore storage root.
        require(
            l1BlockNumber_ >= l1BlockNumber,
            KeystoreStorageRootProofStale({provenL1BlockNumber: l1BlockNumber, provingL1BlockNumber: l1BlockNumber_})
        );

        // Update the Keystore storage root and the corresponding L1 block number.
        keystoreStorageRoot = keystoreStorageRoot_;
        l1BlockNumber = l1BlockNumber_;

        emit KeystoreRootSynchronized({keystoreStorageRoot: keystoreStorageRoot_, l1BlockNumber: l1BlockNumber_});
    }

    /// @notice Preconfirms a new update for a Keystore record.
    ///
    /// @dev This function should only be called if the new preconfirmed update can be added on top of the active fork
    ///      of the targeted Keystore record.
    ///
    /// @param id The identifier of the Keystore record being updated.
    /// @param confirmedValueHashStorageProof The storage proof from which to extract the confirmed ValueHash of the
    ///                                       Keystore record from the `keystoreStorageRoot`.
    /// @param currentValueHashPreimages The preimages of the ValuHash used. For the very first preconfirmation the
    ///                                  ValueHash used will be the confirmed ValueHash recovered from the current
    ///                                  `keystoreStorageRoot`. Otherwise the ValueHash used will be the latest
    ///                                  ValueHash of the current active fork associated with that Keystore
    ///                                  record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param controllerProof A proof provided to the Keystore record `controller` to authorize the update.
    function preconfirmUpdate(
        bytes32 id,
        bytes[] calldata confirmedValueHashStorageProof,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata controllerProof
    ) external {
        // Get the active fork and ValueHashes of the Keystore record.
        (bytes32[] storage preconfirmedValueHashes_, bytes32 confirmedValueHash, bytes32 currentValueHash) =
        _recordValueHashes({
            id: id,
            keystoreStorageRoot_: keystoreStorageRoot,
            confirmedValueHashStorageProof: confirmedValueHashStorageProof
        });

        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: currentValueHash,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            controllerProof: controllerProof
        });

        // If the active fork is empty push the `confirmedValueHash` to ensure it's part of its history.
        // NOTE: Only happens the very first time the user is doing a preconfirmation on the chain.
        // NOTE: If no ValueHash was confirmed yet for the Keystore record, the returned `confirmedValueHash` is the
        //       Keystore identifier.
        if (preconfirmedValueHashes_.length == 0) {
            preconfirmedValueHashes_.push(confirmedValueHash);
        }

        // Add the `newValueHash` to the active fork.
        preconfirmedValueHashes_.push(newValueHash);

        emit KeystoreRecordUpdatePreconfirmed({id: id, newValueHash: newValueHash});
    }

    /// @notice Preconfirms a new Keystore record update in case of a conflict.
    ///
    /// @dev This function should only be called if the new preconfirmed update cannot be added on top of the active
    ///      fork history of the targeted Keystore record. This situation occurs when the new confirmed ValueHash
    ///      (recovered from the `keystoreStorageRoot`) conflicts with an existing ValueHash in the Keystore record’s
    ///      fork history.
    ///
    /// @param id The identifier of the Keystore record being updated.
    /// @param confirmedValueHashStorageProof The storage proof from which to extract the confirmed ValueHash of the
    ///                                       Keystore record from the `keystoreStorageRoot`.
    /// @param confirmedValueHashPreimages The preimages of the confirmed ValueHash recovered from the
    ///                                    `keystoreStorageRoot`.
    /// @param newValueHash The new ValueHash store in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param conflictingIndex The index of the conflicting ValueHash in the active fork of the Keystore
    ///                         record.
    /// @param conflictingValueHashPreimages The preimages of the ValueHash expected at the `conflictingIndex` in the
    ///                                      active fork.
    /// @param controllerProof A proof provided to the Keystore record `controller` to authorize the update.
    function preconfirmUpdateWithFork(
        bytes32 id,
        bytes[] calldata confirmedValueHashStorageProof,
        ValueHashPreimages calldata confirmedValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        uint256 conflictingIndex,
        ValueHashPreimages calldata conflictingValueHashPreimages,
        bytes calldata controllerProof
    ) external {
        bytes32 confirmedValueHash = KeystoreProofLib.extractKeystoreRecordValueHash({
            keystoreStorageRoot: keystoreStorageRoot,
            id: id,
            storageProof: confirmedValueHashStorageProof
        });

        // NOTE: We do not check that the `confirmedValueHashPreimages` effectively hash to `confirmedValueHash`.
        //       This check is performed later in `KeystoreLib.verifyNewValueHash` where we use `confirmedValueHash`
        //       as the current ValueHash.

        // Get the conflicting ValueHash from the latest fork history.
        uint256 activeFork = activeForks[id];
        bytes32[] storage preconfirmedValueHashes_ = preconfirmedValueHashes[id][activeFork];
        bytes32 conflictingValueHash = preconfirmedValueHashes_[conflictingIndex];

        // Ensure the ValueHashes are effectively different (else there is no conflict).
        require(conflictingValueHash != confirmedValueHash, NoValueHashConflict({valueHash: confirmedValueHash}));

        // Ensure that the `conflictingValueHashPreimages` hash to `conflictingValueHash`.
        KeystoreLib.verifyRecordPreimages({
            valueHash: conflictingValueHash,
            valueHashPreimages: conflictingValueHashPreimages
        });

        // Ensure the nonce of the conflicting ValueHashes are equal.
        require(
            confirmedValueHashPreimages.nonce == conflictingValueHashPreimages.nonce,
            InvalidConflictingNonce({
                confirmedNonce: confirmedValueHashPreimages.nonce,
                preconfirmedNonce: conflictingValueHashPreimages.nonce
            })
        );

        // Check if the `newValueHash` update is authorized, using the confirmed ValueHash as current.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: confirmedValueHash,
            currentValueHashPreimages: confirmedValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            controllerProof: controllerProof
        });

        // Avoid stack too deep error...
        bytes32 id_ = id;

        // Create a new fork history.
        activeFork += 1;
        activeForks[id_] = activeFork;
        preconfirmedValueHashes_ = preconfirmedValueHashes[id_][activeFork];
        preconfirmedValueHashes_.push(confirmedValueHash);
        preconfirmedValueHashes_.push(newValueHash);

        emit KeystoreRecordUpdatePreconfirmed({id: id, newValueHash: newValueHash});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns the Keystore record active fork as well as its confirmed and current ValueHashes.
    ///
    /// @dev Looks for the provided `confirmedValueHash` in the active fork of the Keystore record and, if found,
    ///      returns the latest preconfirmed ValueHash. If not found, returns the `confirmedValueHash`.
    ///
    /// @param id The Keystore identifier.
    /// @param keystoreStorageRoot_ The Keystore storage root to use when exracting the confirmed ValueHash.
    /// @param confirmedValueHashStorageProof The storage proof from which to extract the confirmed ValueHash of the
    ///                                       Keystore record.
    ///
    /// @return preconfirmedValueHashes_ The active fork of the Keystore record.
    /// @return confirmedValueHash The Keystore record confirmed ValueHash.
    /// @return currentValueHash The Keystore record current ValueHash.
    function _recordValueHashes(
        bytes32 id,
        bytes32 keystoreStorageRoot_,
        bytes[] calldata confirmedValueHashStorageProof
    )
        private
        view
        returns (bytes32[] storage preconfirmedValueHashes_, bytes32 confirmedValueHash, bytes32 currentValueHash)
    {
        // Get the active fork of the Keystore record.
        uint256 activeFork = activeForks[id];
        preconfirmedValueHashes_ = preconfirmedValueHashes[id][activeFork];

        // Extract the confirmed ValueHash from the storage proof.
        confirmedValueHash = KeystoreProofLib.extractKeystoreRecordValueHash({
            keystoreStorageRoot: keystoreStorageRoot_,
            id: id,
            storageProof: confirmedValueHashStorageProof
        });

        // If no ValueHash is confirmed yet for the Keystore record, use its identifier.
        if (confirmedValueHash == bytes32(0)) {
            confirmedValueHash = id;
        }

        // Default the current ValueHash to the confirmed one.
        currentValueHash = confirmedValueHash;

        // Search for the confirmed ValueHash in the active fork and if found set the current ValueHash to be
        // the latest preconfirmed ValueHash.
        for (uint256 i; i < preconfirmedValueHashes_.length; i++) {
            if (preconfirmedValueHashes_[i] == confirmedValueHash) {
                currentValueHash = preconfirmedValueHashes_[preconfirmedValueHashes_.length - 1];
                break;
            }
        }
    }
}
