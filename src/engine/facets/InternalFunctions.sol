// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {PolicyAssociationStorage} from "src/engine/RulesEngineStorageStructure.sol";
import {PolicyUnapplied} from "src/engine/RulesEngineEvents.sol";
import {RulesEngineStoragePositionLib as lib} from "src/engine/RulesEngineStoragePositionLib.sol";
import "src/engine/RulesEngineErrors.sol";

contract InternalFunctions {
    /**
     * @dev Unapplies policies from a specified contract.
     * @notice this function doesn't check for permissions.
     * @param _contractAddress The address of the contract from which policies will be unapplied.
     * @param _policyIds The IDs of the policies to unapply.
     */
    function _unapplyPolicy(address _contractAddress, uint256[] memory _policyIds) internal {
        if (_contractAddress == address(0)) revert(ZERO_ADDRESS);
        PolicyAssociationStorage storage data = lib._getPolicyAssociationStorage();
        // Get the currently applied policyIds
        uint256[] memory allPolicyIds = data.contractPolicyIdMap[_contractAddress];
        // Blow away the contract to policyId association data in order to keep the associated id's array length in line with the amount of policies associated.
        delete data.contractPolicyIdMap[_contractAddress];
        bool found;
        for (uint256 i = 0; i < allPolicyIds.length; i++) {
            found = false;
            for (uint256 j = 0; j < _policyIds.length; j++) {
                // if the id exists in the unapply list, don't carry it forward
                if (allPolicyIds[i] == _policyIds[j]) found = true;
            }
            if (!found) data.contractPolicyIdMap[_contractAddress].push(allPolicyIds[i]);
        }

        // Loop through the policyId to contract arrays, clear them and add back only the correct addresses
        for (uint256 i = 0; i < _policyIds.length; i++) {
            // Get the currently applied policyIds
            address[] memory allContracts = data.policyIdContractMap[_policyIds[i]];

            // Blow away the policyId to contract association data in order to keep the associated id's array length in line with the amount of contracts associated.
            delete data.policyIdContractMap[_policyIds[i]];
            for (uint256 j = 0; j < allContracts.length; j++) {
                // if the address is not the current address, add it back to the array.
                if (allContracts[j] != _contractAddress) data.policyIdContractMap[_policyIds[i]].push(allContracts[j]);
            }
        }
        emit PolicyUnapplied(_policyIds, _contractAddress);
    }
}
