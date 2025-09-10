// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import {RulesEngineStorageLib as StorageLib} from "src/engine/facets/RulesEngineStorageLib.sol";

/**
 * @title Rules Engine Component Facet
 * @dev This contract serves as the data facet for the Rules Engine subcomponents. It provides functionality for managing
 *      foreign calls, trackers, calling functions, and policy subscriptions. It enforces role-based access control
 *      and ensures that only authorized users can modify or retrieve data. The contract also supports policy cementing
 *      to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible data management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineComponentFacet is FacetCommonImports {
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Tracker Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Adds a tracker to the tracker storage mapping.
     * @dev Creates a new tracker and associates it with the specified policy ID.
     * @param policyId The policy ID the tracker is associated with.
     * @param tracker The tracker to add.
     * @param trackerName Name of the tracker
     * @return trackerIndex The index of the created tracker.
     */
    function createTracker(
        uint256 policyId,
        Trackers calldata tracker,
        string calldata trackerName,
        TrackerArrayTypes arrayType
    ) external returns (uint256) {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (tracker.mapped) revert(INVALID_TYPE);
        // ensure tracker value types (pType) of arrays are not VOID type (used for non array tracker types)
        if (
            (tracker.pType == ParamTypes.STATIC_TYPE_ARRAY || tracker.pType == ParamTypes.DYNAMIC_TYPE_ARRAY) &&
            arrayType == TrackerArrayTypes.VOID
        ) revert(INVALID_TYPE);
        _validateTrackerType(tracker);
        // Step 1: Increment tracker index
        uint256 trackerIndex = _incrementTrackerIndex(policyId);
        // Step 2: Store tracker data without mapping
        _storeTrackerData(policyId, trackerIndex, tracker);
        // Step 3: Store tracker metadata
        _storeTrackerMetadata(policyId, trackerIndex, trackerName, tracker.trackerValue, arrayType);
        // Emit event
        emit TrackerCreated(policyId, trackerIndex);

        return trackerIndex;
    }

    /**
     * @notice Adds a mapped tracker to tracker storage.
     * @dev Creates a new tracker and associates it with the specified policy ID and assigns the tracker to addresses.
     * @param policyId The policy ID the tracker is associated with.
     * @param tracker The tracker to add.
     * @param trackerName Names of the trackers
     * @return trackerIndex The index of the created tracker.
     */
    function createMappedTracker(
        uint256 policyId,
        Trackers calldata tracker,
        string calldata trackerName,
        bytes[] calldata trackerKeys,
        bytes[] calldata trackerValues,
        TrackerArrayTypes arrayType
    ) external returns (uint256) {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (!tracker.mapped) revert(INVALID_TYPE);
        // ensure mapped tracker value types (pType) of arrays are not VOID type (used for non array value types)
        if (
            (tracker.pType == ParamTypes.STATIC_TYPE_ARRAY || tracker.pType == ParamTypes.DYNAMIC_TYPE_ARRAY) &&
            arrayType == TrackerArrayTypes.VOID
        ) revert(INVALID_TYPE);
        _validateTrackerType(tracker);
        if (trackerKeys.length != trackerValues.length) revert(KEY_AND_VALUE_SAME);
        uint256 trackerIndex = lib._getTrackerStorage().trackerIndexCounter[policyId];
        trackerIndex = _incrementTrackerIndex(policyId);
        for (uint256 i = 0; i < trackerKeys.length; i++) {
            // Step 2: Store tracker data
            _storeTrackerData(policyId, trackerIndex, tracker, trackerKeys[i], trackerValues[i]);
        }
        // Step 3: Store tracker metadata
        _storeMappedTrackerMetadata(policyId, trackerIndex, trackerName, trackerKeys, trackerValues, arrayType);
        // return the final tracker index and the created tracker array
        return trackerIndex;
    }

    function _validateTrackerType(Trackers calldata _tracker) internal pure {
        // Ensure tracker value pType is a valid type
        require(
            _tracker.pType == ParamTypes.STR ||
                _tracker.pType == ParamTypes.UINT ||
                _tracker.pType == ParamTypes.BOOL ||
                _tracker.pType == ParamTypes.BYTES ||
                _tracker.pType == ParamTypes.ADDR ||
                _tracker.pType == ParamTypes.STATIC_TYPE_ARRAY ||
                _tracker.pType == ParamTypes.DYNAMIC_TYPE_ARRAY,
            INVALID_TYPE
        );
        // Ensure the tracker key is of a valid type
        if (_tracker.mapped) {
            require(
                _tracker.trackerKeyType == ParamTypes.STR ||
                    _tracker.trackerKeyType == ParamTypes.UINT ||
                    _tracker.trackerKeyType == ParamTypes.BOOL ||
                    _tracker.trackerKeyType == ParamTypes.BYTES ||
                    _tracker.trackerKeyType == ParamTypes.ADDR,
                INVALID_TRACKER_KEY_TYPE
            );
        }
    }

    function _validateCallingFunctionPType(ParamTypes[] memory types) internal pure {
        for (uint256 i = 0; i < types.length; i++) {
            // Ensure tracker value pType is a valid type
            require(uint(types[i]) < MAX_PTYPES, INVALID_TYPE);
        }
    }

    /**
     * @dev Helper function to increment tracker index
     * @param _policyId The policy ID the tracker is associated with.
     */
    function _incrementTrackerIndex(uint256 _policyId) private returns (uint256) {
        TrackerStorage storage data = lib._getTrackerStorage();
        return ++data.trackerIndexCounter[_policyId];
    }

    /**
     * @dev Helper function to store tracker data
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to store
     * @param _tracker The tracker to store.
     * @param _trackerKey The key for the tracker mapping.
     * @param _trackerValue The value for the tracker mapping.
     */
    function _storeTrackerData(
        uint256 _policyId,
        uint256 _trackerIndex,
        Trackers calldata _tracker,
        bytes calldata _trackerKey,
        bytes calldata _trackerValue
    ) internal {
        TrackerStorage storage data = lib._getTrackerStorage();
        _storeTrackerMapping(data, _policyId, _trackerIndex, _tracker, _trackerKey, _trackerValue);
    }

    /**
     * @dev Helper function to store tracker metadata
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker
     * @param _trackerName Name of the tracker
     */
    function _storeTrackerMetadata(
        uint256 _policyId,
        uint256 _trackerIndex,
        string calldata _trackerName,
        bytes calldata initialValue,
        TrackerArrayTypes arrayType
    ) internal {
        require(keccak256(bytes(_trackerName)) != EMPTY_STRING_HASH, NAME_REQ);
        TrackerMetadataStruct memory struc;
        struc.trackerName = _trackerName;
        struc.initialValue = initialValue;
        struc.arrayType = arrayType;
        lib._getTrackerMetadataStorage().trackerMetadata[_policyId][_trackerIndex] = struc;
    }

    function _storeMappedTrackerMetadata(
        uint256 _policyId,
        uint256 _trackerIndex,
        string calldata _trackerName,
        bytes[] calldata initialKeys,
        bytes[] calldata initialValues,
        TrackerArrayTypes arrayType
    ) internal {
        require(keccak256(bytes(_trackerName)) != EMPTY_STRING_HASH, NAME_REQ);
        TrackerMetadataStruct memory struc;
        struc.trackerName = _trackerName;
        struc.initialKeys = initialKeys;
        struc.initialValues = initialValues;
        struc.arrayType = arrayType;
        lib._getTrackerMetadataStorage().trackerMetadata[_policyId][_trackerIndex] = struc;
    }

    /**
     * @notice Stores a tracker in the tracker storage mapping.
     * @dev Sets the tracker data and marks it as active.
     * @param _data The tracker storage structure.
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to store.
     * @param _tracker The tracker data to store.
     */
    function _storeTracker(TrackerStorage storage _data, uint256 _policyId, uint256 _trackerIndex, Trackers memory _tracker) internal {
        require(_trackerIndex < MAX_LOOP, MAX_TRACKERS);
        _tracker.set = true;
        _tracker.mapped = false;
        _tracker.trackerIndex = _trackerIndex;
        if (_tracker.pType == ParamTypes.STR || _tracker.pType == ParamTypes.BYTES) {
            _tracker.trackerValue = abi.encode(keccak256(_tracker.trackerValue));
        }
        _data.trackers[_policyId][_trackerIndex] = _tracker;
    }

    /**
     * @notice Stores mapping data in the tracker storage mapping.
     * @dev Sets the tracker mapped bool to active.
     * @param _data The tracker storage structure.
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to store.
     * @param _tracker The tracker data to store.
     * @param _trackerKey The keys for the tracker mapping.
     * @param _trackerValue The values for the tracker mapping.
     */
    function _storeTrackerMapping(
        TrackerStorage storage _data,
        uint256 _policyId,
        uint256 _trackerIndex,
        Trackers memory _tracker,
        bytes memory _trackerKey,
        bytes memory _trackerValue
    ) internal {
        require(_trackerIndex < MAX_LOOP, MAX_TRACKERS);
        _tracker.mapped = true;
        _tracker.set = true;
        _tracker.trackerIndex = _trackerIndex;
        _data.trackers[_policyId][_trackerIndex] = _tracker;
        if (_tracker.trackerKeyType == ParamTypes.BYTES || _tracker.trackerKeyType == ParamTypes.STR) {
            _trackerKey = abi.encode(keccak256(_trackerKey));
        }
        // use trackerKey and assign value
        if (_tracker.pType == ParamTypes.STR || _tracker.pType == ParamTypes.BYTES) {
            _trackerValue = abi.encode(keccak256(_trackerValue));
        }
        _data.mappedTrackerValues[_policyId][_trackerIndex][_trackerKey] = _trackerValue;
    }

    /**
     * @dev Helper function to store tracker data
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to store
     */
    function _storeTrackerData(uint256 _policyId, uint256 _trackerIndex, Trackers calldata _tracker) internal {
        TrackerStorage storage data = lib._getTrackerStorage();
        _storeTracker(data, _policyId, _trackerIndex, _tracker);
    }

    /**
     * @notice retrieves the tracker metadata
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerId The identifier for the tracker
     * @return the metadata for the tracker
     */
    function getTrackerMetadata(uint256 policyId, uint256 trackerId) public view returns (TrackerMetadataStruct memory) {
        return lib._getTrackerMetadataStorage().trackerMetadata[policyId][trackerId];
    }

    /**
     * @notice Retrieves all trackers associated with a specific policy ID.
     * @param policyId The policy ID the trackers are associated with.
     * @return trackers An array of tracker data.
     */
    function getAllTrackers(uint256 policyId) external view returns (Trackers[] memory) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib._getTrackerStorage();
        // return trackers for contract address at speficic index
        uint256 trackerCount = data.trackerIndexCounter[policyId];
        Trackers[] memory trackers = new Trackers[](trackerCount);
        uint256 j = 0;
        // Loop through all the trackers and load for return. Data entry validation will never let trackerCount be > MAX_LOOP
        for (uint256 i = 1; i <= trackerCount; i++) {
            if (data.trackers[policyId][i].set) {
                trackers[j] = data.trackers[policyId][i];
                j++;
            }
        }
        return trackers;
    }

    /**
     * @notice Retrieves a tracker from the tracker storage mapping.
     * @param policyId The policy ID the tracker is associated with.
     * @param index The index of the tracker to retrieve.
     * @return The tracker data.
     */
    function getTracker(uint256 policyId, uint256 index) public view returns (Trackers memory) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib._getTrackerStorage();
        // return trackers for contract address at speficic index
        return data.trackers[policyId][index];
    }

    /**
     * @notice Retrieves the rule IDs associated with a specific tracker index for a given policy ID.
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerIndex The index of the tracker to retrieve rule IDs for.
     * @return An array of rule IDs associated with the specified tracker index.
     */
    function getTrackerToRuleIds(uint256 policyId, uint256 trackerIndex) external view returns (uint256[] memory) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib._getTrackerStorage();
        // return trackers for contract address at speficic index
        return data.trackerIdToRuleIds[policyId][trackerIndex];
    }

    /**
     * @notice Retrieves a tracker from the tracker storage mapping.
     * @param policyId The policy ID the tracker is associated with.
     * @param index The index of the tracker to retrieve.
     * @return tracker The tracker data.
     */
    function getMappedTrackerValue(uint256 policyId, uint256 index, bytes memory trackerKey) public view returns (bytes memory) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib._getTrackerStorage();
        ParamTypes trackerKeyType = data.trackers[policyId][index].trackerKeyType;
        if (trackerKeyType == ParamTypes.BYTES || trackerKeyType == ParamTypes.STR) {
            trackerKey = abi.encode(keccak256(trackerKey));
        }
        // return trackers for contract address at speficic index
        return data.mappedTrackerValues[policyId][index][trackerKey];
    }

    /**
     * @notice Updates an existing tracker in the tracker storage mapping.
     * @dev Modifies the tracker associated with the specified policy ID and tracker index.
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerIndex The index of the tracker to update.
     * @param tracker The updated tracker data.
     */
    function updateTracker(uint256 policyId, uint256 trackerIndex, Trackers calldata tracker) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (!StorageLib._isTrackerSet(policyId, trackerIndex)) revert(TRACKER_NOT_SET);
        // Load the Tracker data from storage
        TrackerStorage storage data = lib._getTrackerStorage();
        _storeTracker(data, policyId, trackerIndex, tracker);
        emit TrackerUpdated(policyId, trackerIndex);
    }

    /**
     * @notice Updates an existing tracker in the tracker storage mapping.
     * @dev Modifies the tracker associated with the specified policy ID and tracker index.
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to update.
     * @param _tracker The updated tracker data.
     * @param _trackerKey The keys for the tracker mapping.
     * @param _trackerValue The values for the tracker mapping.
     */
    function updateTracker(
        uint256 _policyId,
        uint256 _trackerIndex,
        Trackers calldata _tracker,
        bytes calldata _trackerKey,
        bytes calldata _trackerValue
    ) external {
        _policyAdminOnly(_policyId, msg.sender);
        _notCemented(_policyId);
        // Load the Tracker data from storage
        TrackerStorage storage data = lib._getTrackerStorage();
        if (!StorageLib._isTrackerSet(_policyId, _trackerIndex)) revert(TRACKER_NOT_SET);
        _storeTrackerMapping(data, _policyId, _trackerIndex, _tracker, _trackerKey, _trackerValue);
        emit TrackerUpdated(_policyId, _trackerIndex);
    }

    /**
     * @dev Helper function to store tracker data
     * @notice Tracker mappings are not deleted, since trackerIds are not reused that data will never clash with new trackers.
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerIndex The index of the tracker to store
     */
    function deleteTracker(uint256 policyId, uint256 trackerIndex) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        delete lib._getTrackerStorage().trackers[policyId][trackerIndex];
        emit TrackerDeleted(policyId, trackerIndex);
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Calling Function Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a new calling function and stores it in the calling function storage mapping.
     * @dev Associates the calling function with the specified policy ID and parameter types.
     * @param policyId The policy ID the calling function is associated with.
     * @param functionSignature The function signature of the calling function.
     * @param pTypes The parameter types for the calling function.
     * @param callingFunctionName the name of the calling function (to be stored in metadata)
     * @param encodedValues the string representation of the values encoded with the calling function (to be stored in metadata)
     * @return functionId The index of the created calling function.
     */
    function createCallingFunction(
        uint256 policyId,
        bytes4 functionSignature,
        ParamTypes[] memory pTypes,
        string memory callingFunctionName,
        string memory encodedValues
    ) external returns (bytes4) {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (!lib._getPolicyStorage().policyStorageSets[policyId].set) revert(POLICY_DOES_NOT_EXIST);
        if (StorageLib._isCallingFunctionSet(policyId, functionSignature)) revert(CALLING_FUNCTION_ALREADY_EXISTS);

        // Step 2: Store calling function data
        _storeCallingFunctionData(policyId, functionSignature, pTypes);

        // Step 3: Store calling function metadata
        _storeCallingFunctionMetadata(policyId, functionSignature, callingFunctionName, encodedValues);

        // Emit event
        emit CallingFunctionCreated(policyId, functionSignature);

        return functionSignature;
    }

    /**
     * @notice Updates an existing calling function by appending new parameter types.
     * @dev Ensures that the new parameter types are compatible with the existing ones.
     * @param policyId The policy ID the calling function is associated with.
     * @param functionSignature The function signature of the calling function.
     * @param pTypes The new parameter types to append.
     * @return functionId The updated calling function ID.
     */
    function updateCallingFunction(uint256 policyId, bytes4 functionSignature, ParamTypes[] memory pTypes) external returns (bytes4) {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        // Load the calling function data from storage
        CallingFunctionStruct storage data = lib._getCallingFunctionStorage();
        // increment the callingFunctionId if necessary
        CallingFunctionStorageSet storage callingFunction = data.callingFunctionStorageSets[policyId][functionSignature];
        require(callingFunction.set, CALLING_FUNCTION_NOT_SET);
        require(callingFunction.parameterTypes.length <= pTypes.length, PARM_GT_EQ);
        for (uint256 i = 0; i < callingFunction.parameterTypes.length; i++) {
            require(pTypes[i] == callingFunction.parameterTypes[i], PARM_NOT_SAME_TYPE);
        }
        if (callingFunction.parameterTypes.length < pTypes.length) {
            for (uint256 i = callingFunction.parameterTypes.length; i < pTypes.length; i++) {
                callingFunction.parameterTypes.push(pTypes[i]);
            }
        }
        emit CallingFunctionUpdated(policyId, functionSignature);
        return functionSignature;
    }

    /**
     * @notice Deletes a calling function from storage.
     * @dev Removes the calling function and its associated rules and mappings.
     * @param policyId The policy ID the calling function is associated with.
     * @param sig The selector of the calling function to delete.
     */
    function deleteCallingFunction(uint256 policyId, bytes4 sig) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        // retrieve policy from storage
        PolicyStorageSet storage data = lib._getPolicyStorage().policyStorageSets[policyId];
        // delete the calling function storage set struct
        delete lib._getCallingFunctionStorage().callingFunctionStorageSets[policyId][sig];
        // Capture the rules tied to the function being deleted
        uint256[] memory toCheckRuleIds = data.policy.callingFunctionsToRuleIds[sig];

        // For each rule, see if it appears under any other calling function
        for (uint256 i = 0; i < toCheckRuleIds.length; i++) {
            uint256 rid = toCheckRuleIds[i];
            bool presentElsewhere = false;

            // Iterate every calling function signature
            bytes4[] memory allSigs = data.policy.callingFunctions;
            for (uint256 s = 0; s < allSigs.length && !presentElsewhere; s++) {
                bytes4 otherSig = allSigs[s];
                if (otherSig == sig) continue;

                uint256[] storage otherRuleIds = data.policy.callingFunctionsToRuleIds[otherSig];
                for (uint256 k = 0; k < otherRuleIds.length; k++) {
                    if (otherRuleIds[k] == rid) {
                        presentElsewhere = true;
                        break;
                    }
                }
            }

            // Only delete the rule if it isn't used by any other calling function
            if (!presentElsewhere) {
                delete lib._getRuleStorage().ruleStorageSets[policyId][rid];
                emit AssociatedRuleDeleted(policyId, sig);
            }
        }

        // After this, you can clear the mapping for this function's ruleIds
        delete data.policy.callingFunctionsToRuleIds[sig];

        for (uint256 i = 0; i < data.policy.callingFunctions.length; i++) {
            if (data.policy.callingFunctions[i] == sig) {
                data.policy.callingFunctions[i] = data.policy.callingFunctions[data.policy.callingFunctions.length - 1];
                data.policy.callingFunctions.pop();
                break;
            }
        }

        emit CallingFunctionDeleted(policyId, sig);
    }

    /**
     * @notice Retrieves a calling function from storage.
     * @param policyId The policy ID the calling function is associated with.
     * @param sig The selector of the calling function to retrieve.
     * @return CallngFunctionStorageSet The calling function data.
     */
    function getCallingFunction(uint256 policyId, bytes4 sig) public view returns (CallingFunctionStorageSet memory) {
        // Load the calling function data from storage
        return lib._getCallingFunctionStorage().callingFunctionStorageSets[policyId][sig];
    }

    /**
     * @notice retrieves the calling function metadata
     * @param policyId The policy ID the calling function is associated with.
     * @param sig The selector for the calling function
     * @return the metadata for the calling function
     */
    function getCallingFunctionMetadata(uint256 policyId, bytes4 sig) public view returns (CallingFunctionHashMapping memory) {
        return lib._getCallingFunctioneMetadataStorage().callingFunctionMetadata[policyId][sig];
    }

    /**
     * @notice Retrieves all calling functions associated with a specific policy ID.
     * @param policyId The policy ID the calling functions are associated with.
     * @return CallingFunctionStorageSet An array of calling function data.
     */
    function getAllCallingFunctions(uint256 policyId) public view returns (CallingFunctionStorageSet[] memory) {
        // Load the calling function data from storage
        CallingFunctionStruct storage data = lib._getCallingFunctionStorage();
        bytes4[] memory sigs = lib._getPolicyStorage().policyStorageSets[policyId].policy.callingFunctions;
        uint256 functionIdCount = sigs.length;
        CallingFunctionStorageSet[] memory callingFunctionStorageSets = new CallingFunctionStorageSet[](functionIdCount);
        uint256 j = 0;
        for (uint256 i = 0; i < functionIdCount; i++) {
            if (data.callingFunctionStorageSets[policyId][sigs[i]].set) {
                callingFunctionStorageSets[j] = data.callingFunctionStorageSets[policyId][sigs[i]];
                j++;
            }
        }
        return callingFunctionStorageSets;
    }

    /**
     * @dev Helper function to store calling function data
     * @param _policyId The policy ID the calling function is associated with.
     * @param _functionSignature The function signature of the calling function
     * @param _pTypes The parameter types for the calling function.
     */
    function _storeCallingFunctionData(uint256 _policyId, bytes4 _functionSignature, ParamTypes[] memory _pTypes) private {
        if (EMPTY_SIG == _functionSignature) revert(SIG_REQ);
        _validateCallingFunctionPType(_pTypes);
        CallingFunctionStruct storage data = lib._getCallingFunctionStorage();
        data.callingFunctionStorageSets[_policyId][_functionSignature].set = true;
        data.callingFunctionStorageSets[_policyId][_functionSignature].signature = _functionSignature;
        data.callingFunctionStorageSets[_policyId][_functionSignature].parameterTypes = _pTypes;
    }

    /**
     * @dev Helper function to store calling function metadata
     * @param _policyId The policy ID the calling function is associated with.
     * @param _functionSignature The function signature of the calling function
     * @param _callingFunctionName Name of the calling function
     * @param _encodedValues Arguments to be encoded
     */
    function _storeCallingFunctionMetadata(
        uint256 _policyId,
        bytes4 _functionSignature,
        string memory _callingFunctionName,
        string memory _encodedValues
    ) private {
        if (keccak256(bytes(_callingFunctionName)) == EMPTY_STRING_HASH) revert(NAME_REQ);
        CallingFunctionMetadataStruct storage metaData = lib._getCallingFunctioneMetadataStorage();
        metaData.callingFunctionMetadata[_policyId][_functionSignature].callingFunction = _callingFunctionName;
        metaData.callingFunctionMetadata[_policyId][_functionSignature].signature = _functionSignature;
        metaData.callingFunctionMetadata[_policyId][_functionSignature].encodedValues = _encodedValues;
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Subscription Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Adds an address to the subscriber list of a specified policy.
     * @dev Only callable by a policy admin. The policy must not be cemented.
     * @param policyId The ID of the policy.
     * @param subscriber The address to add to the policy subscription.
     */
    function addClosedPolicySubscriber(uint256 policyId, address subscriber) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (subscriber == address(0)) revert(ZERO_ADDRESS);
        lib._getPolicyStorage().policyStorageSets[policyId].policy.closedPolicySubscribers[subscriber] = true;
        emit PolicySubsciberAdded(policyId, subscriber);
    }

    /**
     * @notice Removes an address from the subscriber list of a specified policy.
     * @dev Only callable by a policy admin. The policy must not be cemented.
     * @param policyId The ID of the policy.
     * @param subscriber The address to remove from the policy subscription.
     */
    function removeClosedPolicySubscriber(uint256 policyId, address subscriber) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        if (subscriber == address(0)) revert(ZERO_ADDRESS);
        delete lib._getPolicyStorage().policyStorageSets[policyId].policy.closedPolicySubscribers[subscriber];
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        address[] memory callingContracts = lib._getCallingContractAdminStorage().callingContractAdminToCallingContracts[subscriber];
        for (uint256 i = 0; i < callingContracts.length; i++) {
            _unapplyPolicy(callingContracts[i], policyIds);
        }
        emit PolicySubsciberRemoved(policyId, subscriber);
    }

    /**
     * @notice Checks if an address is a subscriber of the specified policy.
     * @param policyId The ID of the policy.
     * @param subscriber The address to check for policy subscription.
     * @return bool True if the address is a subscriber, false otherwise.
     */
    function isClosedPolicySubscriber(uint256 policyId, address subscriber) external view returns (bool) {
        return lib._getPolicyStorage().policyStorageSets[policyId].policy.closedPolicySubscribers[subscriber];
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Cementing
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Checks that a policy is not cemented.
     * @param _policyId The ID of the policy.
     */
    function _notCemented(uint256 _policyId) internal view {
        if (lib._getPolicyStorage().policyStorageSets[_policyId].policy.cemented) revert("Not allowed for cemented policy");
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _policyId The ID of the policy.
     * @param _address The address to check for policy admin status.
     */
    function _policyAdminOnly(uint256 _policyId, address _address) internal {
        // 0x901cee11 = isPolicyAdmin(uint256,address)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x901cee11,
            abi.encodeWithSignature("isPolicyAdmin(uint256,address)", _policyId, _address)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert("Not Authorized To Policy");
        }
    }
}
