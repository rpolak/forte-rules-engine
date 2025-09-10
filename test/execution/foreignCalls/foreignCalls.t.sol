/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/execution/foreignCalls/foreignCallsEdgeCases.t.sol";

abstract contract foreignCalls is RulesEngineCommon, foreignCallsEdgeCases {
    /**
     *
     *
     * Execution tests for foreign calls within the rules engine
     *
     *
     */
    function testRulesEngine_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        _setup_checkRule_ForeignCall_Positive(ruleValue, userContractAddress);
        vm.startSnapshotGas("checkRule_ForeignCall");
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), transferValue);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // change values in order to violate rule
        ruleValue = 15;
        transferValue = 10;
        _setup_checkRule_ForeignCall_Negative(ruleValue, userContractAddress);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), transferValue);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        vm.startPrank(address(userContract));
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_TrackerValuesUsed_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallSquaringReferencedTrackerVals(2, EffectTypes.REVERT, false); // rule's lower limit is 2
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.startSnapshotGas("checkRule_ForeignCall_TrackerValuesUsed");
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_createRule_ForeignCall_TrackerValuesUsed_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallSquaringReferencedTrackerVals(0, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_ForeignCallReferenced_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallWithSquaredFCValues(EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2); // rule's lower limit is 2
        vm.startSnapshotGas("checkRule_ForeignCall_ForeignCallReferenced");
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_createRule_ForeignCall_ForeignCallReferenced_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallWithSquaredFCValues(EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 0);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        // The Foreign call will be placed during the effect for the single rule in this policy.
        // The value being set in the foreign contract is then polled to verify that it has been udpated.
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(testContract.getInternalValue(), 5);
    }

    // todo: fix this test so that it uses a proper transferFrom signature
    function testRulesEngine_Unit_ForeignCall_Bytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.skip(true);
        uint256 policyId;
        uint256 ruleId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setMsgDataSelector = ExampleUserContract.setMsgData.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.BYTES;
                ForeignCall memory fc;
                fc.encodedIndices = new ForeignCallEncodedIndex[](1);
                fc.encodedIndices[0].index = 0;
                fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setMsgDataSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "setMsgData(bytes)");
            }

            // Effect for the foreign call
            Effect memory effect;
            effect.valid = true;
            effect.dynamicParam = false;
            effect.effectType = EffectTypes.EXPRESSION;
            effect.pType = ParamTypes.VOID;
            effect.param = abi.encodePacked(foreignCallId);
            effect.text = "";
            effect.errorMessage = "";
            effect.instructionSet = new uint256[](0);

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1;

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: msg.data
            rule.placeHolders[0].pType = ParamTypes.BYTES;
            rule.placeHolders[0].typeSpecificIndex = 2;
            //rule.placeHolders[0].flags = uint8(GLOBAL_MSG_DATA << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

            rule.positiveEffectPlaceHolders = new Placeholder[](1);
            rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
            rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 0;
            rule.positiveEffectPlaceHolders[0].flags = 0;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

            {
                bytes4 transferSelector = bytes4(keccak256(bytes("transferFrom(address,uint256,bytes)")));
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY,
                    policyName,
                    policyDescription
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSignature(
                "transferFrom(address,uint256,bytes)",
                to,
                value,
                abi.encode("TESTER")
            );

            vm.startSnapshotGas("checkRule_ForeignCall_Bytes");
            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);
            vm.stopSnapshotGas();

            bytes memory actualMsgData = ExampleUserContract(userContractAddress).msgData();
            assertEq(actualMsgData, transferCalldata, "Foreign call should set msgData to the transfer calldata");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_MultipleMappedTrackerKeys_EncodedValueType_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {
        uint256 policyId;
        uint256 ruleId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            ParamTypes[] memory fcArgs = new ParamTypes[](5);
            fcArgs[0] = ParamTypes.UINT;
            fcArgs[1] = ParamTypes.STR;
            fcArgs[2] = ParamTypes.UINT;
            fcArgs[3] = ParamTypes.STR;
            fcArgs[4] = ParamTypes.ADDR;

            uint256 foreignCallId;
            {
                ForeignCall memory fc;
                fc.encodedIndices = new ForeignCallEncodedIndex[](5);
                fc.encodedIndices[0].index = 1;
                fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.encodedIndices[1].index = 2;
                fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
                fc.encodedIndices[2].index = 2;
                fc.encodedIndices[2].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.encodedIndices[3].index = 3;
                fc.encodedIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
                fc.encodedIndices[4].index = 1;
                fc.encodedIndices[4].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](3);
                fc.mappedTrackerKeyIndices[0].index = 1;
                fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
                fc.mappedTrackerKeyIndices[1].index = 0;
                fc.mappedTrackerKeyIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
                fc.mappedTrackerKeyIndices[2].index = 4;
                fc.mappedTrackerKeyIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
                fc.foreignCallAddress = address(pfcContractAddress);
                fc.signature = bytes4(keccak256(bytes("testSig(uint256,string,uint256,string,address)")));
                fc.returnType = ParamTypes.UINT;
                fc.parameterTypes = fcArgs;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
                    policyId,
                    fc,
                    "testSig(uint256,string,uint256,string,address)"
                );
            }

            {
                // Effect for the foreign call
                Trackers memory tracker1;
                tracker1.pType = ParamTypes.UINT;
                tracker1.trackerKeyType = ParamTypes.UINT;
                tracker1.mapped = true;

                bytes[] memory tracker1Keys = new bytes[](2);
                tracker1Keys[0] = abi.encode(11);
                tracker1Keys[1] = abi.encode(22);

                bytes[] memory tracker1Values = new bytes[](2);
                tracker1Values[0] = abi.encode(1000000000);
                tracker1Values[1] = abi.encode(0x1234567);

                Trackers memory tracker2;
                tracker2.pType = ParamTypes.UINT;
                tracker2.trackerKeyType = ParamTypes.ADDR;
                tracker2.mapped = true;

                bytes[] memory tracker2Keys = new bytes[](2);
                tracker2Keys[0] = abi.encode(address(0x7654321));
                tracker2Keys[1] = abi.encode(address(0x1234567));

                bytes[] memory tracker2Values = new bytes[](2);
                tracker2Values[0] = abi.encode(22);
                tracker2Values[1] = abi.encode(33);

                RulesEngineComponentFacet(address(red)).createMappedTracker(
                    policyId,
                    tracker1,
                    "tracker1",
                    tracker1Keys,
                    tracker1Values,
                    TrackerArrayTypes.VOID
                );
                RulesEngineComponentFacet(address(red)).createMappedTracker(
                    policyId,
                    tracker2,
                    "tracker2",
                    tracker2Keys,
                    tracker2Values,
                    TrackerArrayTypes.VOID
                );
            }

            Rule memory rule;
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 2;
            rule.instructionSet[2] = uint(LogicalOp.NUM);
            rule.instructionSet[3] = 0;
            rule.instructionSet[4] = uint(LogicalOp.EQ);
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;

            rule.placeHolders = new Placeholder[](3);
            // Placeholder 0: msg.data
            rule.placeHolders[0].flags = uint8(FLAG_TRACKER_VALUE);
            rule.placeHolders[0].typeSpecificIndex = uint128(1);
            rule.placeHolders[1].flags = uint8(FLAG_TRACKER_VALUE);
            rule.placeHolders[1].typeSpecificIndex = uint128(2);
            rule.placeHolders[2].flags = uint8(FLAG_FOREIGN_CALL);
            rule.placeHolders[2].typeSpecificIndex = uint128(foreignCallId);

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

            {
                bytes4 transferSelector = ExampleUserContract.transferSigTest.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](5);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.STR;
                pTypes[3] = ParamTypes.STR;
                pTypes[4] = ParamTypes.UINT;
                RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferSigTest(address,uint256,string,string)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;

                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY,
                    policyName,
                    policyDescription
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            vm.startPrank(userContractAddress);
            address to = address(0x1234567);
            uint256 value = 11;
            string memory str = "TESTER";
            string memory str2 = "TESTER2";
            bytes memory transferCalldata = abi.encodeWithSelector(ExampleUserContract.transferSigTest.selector, to, value, str, str2, 22);

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedIntOne(), 1000000000);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedIntTwo(), 33);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedStrOne(), str);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedStrTwo(), str2);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedAddr(), to);
        }
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_MultipleMappedTrackerKeys_TrackerType_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {
        uint256 policyId;
        uint256 ruleId;
        bytes4 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            ParamTypes[] memory fcArgs = new ParamTypes[](5);
            fcArgs[0] = ParamTypes.UINT;
            fcArgs[1] = ParamTypes.STR;
            fcArgs[2] = ParamTypes.UINT;
            fcArgs[3] = ParamTypes.STR;
            fcArgs[4] = ParamTypes.ADDR;

            uint256 foreignCallId;
            {
                ForeignCall memory fc;
                fc.encodedIndices = new ForeignCallEncodedIndex[](5);
                fc.encodedIndices[0].index = 1;
                fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.encodedIndices[1].index = 2;
                fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
                fc.encodedIndices[2].index = 2;
                fc.encodedIndices[2].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.encodedIndices[3].index = 3;
                fc.encodedIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
                fc.encodedIndices[4].index = 1;
                fc.encodedIndices[4].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](3);
                fc.mappedTrackerKeyIndices[0].index = 1;
                fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
                fc.mappedTrackerKeyIndices[1].index = 2; // Use placeholder index 2 (tracker3) value as key
                fc.mappedTrackerKeyIndices[1].eType = EncodedIndexType.TRACKER;
                fc.mappedTrackerKeyIndices[2].index = 4;
                fc.mappedTrackerKeyIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
                fc.foreignCallAddress = address(pfcContractAddress);
                fc.signature = bytes4(keccak256(bytes("testSig(uint256,string,uint256,string,address)")));
                fc.returnType = ParamTypes.UINT;
                fc.parameterTypes = fcArgs;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
                    policyId,
                    fc,
                    "testSig(uint256,string,uint256,string,address)"
                );
            }

            {
                // Same tracker setup as original, but tracker2 now uses BYTES keys instead of ADDR
                Trackers memory tracker1;
                tracker1.pType = ParamTypes.UINT;
                tracker1.trackerKeyType = ParamTypes.UINT;
                tracker1.mapped = true;

                bytes[] memory tracker1Keys = new bytes[](2);
                tracker1Keys[0] = abi.encode(11);
                tracker1Keys[1] = abi.encode(22);

                bytes[] memory tracker1Values = new bytes[](2);
                tracker1Values[0] = abi.encode(1000000000);
                tracker1Values[1] = abi.encode(0x1234567);

                Trackers memory tracker2;
                tracker2.pType = ParamTypes.UINT;
                tracker2.trackerKeyType = ParamTypes.BYTES;
                tracker2.mapped = true;

                bytes[] memory tracker2Keys = new bytes[](2);
                tracker2Keys[0] = abi.encode(bytes("TEST")); // BYTES key
                tracker2Keys[1] = abi.encode(bytes("TEST1234")); // BYTES key that matches tracker3

                bytes[] memory tracker2Values = new bytes[](2);
                tracker2Values[0] = abi.encode(22);
                tracker2Values[1] = abi.encode(33); // This should be retrieved when using tracker3 as key

                RulesEngineComponentFacet(address(red)).createMappedTracker(
                    policyId,
                    tracker1,
                    "tracker1",
                    tracker1Keys,
                    tracker1Values,
                    TrackerArrayTypes.VOID
                );
                RulesEngineComponentFacet(address(red)).createMappedTracker(
                    policyId,
                    tracker2,
                    "tracker2",
                    tracker2Keys,
                    tracker2Values,
                    TrackerArrayTypes.VOID
                );

                // Add tracker3 with BYTES value that will be used as key for tracker2 lookup
                // The key is that tracker3 contains the BYTES data "TEST1234" which should match tracker2's key
                Trackers memory tracker3;
                tracker3.pType = ParamTypes.BYTES;
                tracker3.trackerValue = abi.encode(bytes("TEST1234")); // Store the actual BYTES data, not the hash
                RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker3, "tracker3", TrackerArrayTypes.VOID);
            }

            Rule memory rule;
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 3; // Use foreign call placeholder (index 3)
            rule.instructionSet[2] = uint(LogicalOp.NUM);
            rule.instructionSet[3] = 0;
            rule.instructionSet[4] = uint(LogicalOp.EQ);
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;

            rule.placeHolders = new Placeholder[](4);
            rule.placeHolders[0].flags = uint8(FLAG_TRACKER_VALUE);
            rule.placeHolders[0].typeSpecificIndex = uint128(1);
            rule.placeHolders[1].flags = uint8(FLAG_TRACKER_VALUE);
            rule.placeHolders[1].typeSpecificIndex = uint128(2);
            rule.placeHolders[2].flags = uint8(FLAG_TRACKER_VALUE);
            rule.placeHolders[2].typeSpecificIndex = uint128(3);
            rule.placeHolders[3].flags = uint8(FLAG_FOREIGN_CALL);
            rule.placeHolders[3].typeSpecificIndex = uint128(foreignCallId);

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

            {
                bytes4 transferSelector = ExampleUserContract.transferSigTest.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](5);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.STR;
                pTypes[3] = ParamTypes.STR;
                pTypes[4] = ParamTypes.UINT;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferSigTest(address,uint256,string,string)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;

                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY,
                    policyName,
                    policyDescription
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            vm.startPrank(userContractAddress);
            address to = address(0x1234567);
            uint256 value = 11;
            string memory str = "TESTER";
            string memory str2 = "TESTER2";
            bytes memory transferCalldata = abi.encodeWithSelector(ExampleUserContract.transferSigTest.selector, to, value, str, str2, 22);

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedIntOne(), 1000000000);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedIntTwo(), 33); // Should now find the correct key
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedStrOne(), str);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedStrTwo(), str2);
            assertEq(PermissionedForeignCallTestContract(pfcContractAddress).getDecodedAddr(), to);
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // PERMISSIONED FOREIGN CALL TESTS
    ////////////////////////////////////////////////////////////////////////

    function testRulesEngine_Unit_PermissionedForeignCall_SetAdmin_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );
    }

    function testRulesEngine_Unit_PermissionedForeignCall_SetAdmin_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertFalse(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x6666666),
                foreignCallSelector
            )
        );
    }

    function testRulesEngine_Unit_PermissionedForeignCall_SetAdminByCallingFacetDirectly_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        vm.expectRevert("Only Foreign Call Contract Can Create Admin Role");
        RulesEngineAdminRolesFacet(address(red)).grantForeignCallAdminRole(pfcContractAddress, address(0x55556666), foreignCallSelector);
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddAdminsToList_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        // add multiple admins to the permissions list
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x77777777), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x88888888), foreignCallSelector);

        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 4, "There should be four permissioned foreign call admins");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddAdminsToList_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        vm.expectRevert("Not An Authorized Foreign Call Admin");
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector2);

        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 1, "There should be one permissioned foreign call admins");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_RemoveForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);

        // add multiple foreign calls to the master list
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector2);
        bytes4 foreignCallSelector3 = PermissionedForeignCallTestContract.getInternalValue.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector3);

        PermissionedForeignCallStorage memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 3, "There should be three permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 3, "There should be three permissioned foreign call signatures");

        // remove the foreign call from the master list
        RulesEngineForeignCallFacet(address(red)).removeForeignCallPermissions(pfcContractAddress, foreignCallSelector2);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 2, "There should be two permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 2, "There should be two permissioned foreign call signatures");
        // check that the foreign call is no longer in the master list
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[0],
            foreignCallSelector,
            "The first foreign call signature should be the simpleCheck"
        );
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[1],
            foreignCallSelector3,
            "The second foreign call signature should be the getInternalValue"
        );
    }

    function testRulesEngine_Unit_PermissionedForeignCall_GetAllForeignCalls_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);

        // add multiple foreign calls to the master list
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector2);
        bytes4 foreignCallSelector3 = PermissionedForeignCallTestContract.getInternalValue.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector3);

        PermissionedForeignCallStorage memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 3, "There should be three permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 3, "There should be three permissioned foreign call signatures");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddPermissionedFCToPolicy_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(policyAdmin), foreignCallSelector);

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddPermissionedFCToPolicy_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(
            pfcContractAddress,
            address(address(0x66666666)),
            foreignCallSelector
        );

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert("Not Permissioned For Foreign Call");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_UpdatePermissionedFC_Simple() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(policyAdmin), foreignCallSelector);

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");

        ForeignCall[] memory fcs = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(fcs.length, 1, "There should be one foreign call in the policy");
        assertEq(fcs[0].signature, bytes4(keccak256(bytes("simpleCheck(uint256)"))), "The foreign call signature should match");
        assertEq(fcs[0].foreignCallAddress, address(pfcContractAddress), "The foreign call address should match");
        assertEq(fcs[0].foreignCallIndex, 1, "The foreign call index should be 0");

        ForeignCall memory fc2;
        fc2.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc2.encodedIndices[0].index = 2;
        fc2.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc2.parameterTypes = fcArgs;
        fc2.foreignCallAddress = address(pfcContractAddress);
        fc2.signature = bytes4(keccak256(bytes("anotherSimpleCheck(uint256)")));
        fc2.returnType = ParamTypes.UINT;
        fc2.foreignCallIndex = 2;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc2, "anotherSimpleCheck(uint256)");

        fcs = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(fcs.length, 2, "There should be two foreign calls in the policy");
        assertEq(fcs[1].signature, bytes4(keccak256(bytes("anotherSimpleCheck(uint256)"))), "The foreign call signature should match");
        assertEq(fcs[1].foreignCallAddress, address(pfcContractAddress), "The foreign call address should match");
        assertEq(fcs[1].foreignCallIndex, 2, "The foreign call index should be 1");

        ForeignCall memory fc3;
        fc3.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc3.encodedIndices[0].index = 1;
        fc3.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc3.parameterTypes = fcArgs;
        fc3.foreignCallAddress = address(0x1234);
        fc3.signature = bytes4(keccak256(bytes("aThirdSimpleCheck(uint256)")));
        fc3.returnType = ParamTypes.UINT;
        fc3.foreignCallIndex = 1;

        RulesEngineForeignCallFacet(address(red)).updateForeignCall(
            policyId,
            1, // foreign call index
            fc3
        );

        fcs = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(fcs.length, 2, "There should still be two foreign calls in the policy after update");
        assertEq(
            fcs[0].signature,
            bytes4(keccak256(bytes("aThirdSimpleCheck(uint256)"))),
            "The foreign call signature should match the third call"
        );
        assertEq(fcs[0].foreignCallAddress, address(0x1234), "The foreign call address should match the third call");
        assertEq(fcs[0].foreignCallIndex, 1, "The foreign call index should be 1");
        assertEq(fcs[1].signature, bytes4(keccak256(bytes("anotherSimpleCheck(uint256)"))), "The foreign call signature should match");
        assertEq(fcs[1].foreignCallAddress, address(pfcContractAddress), "The foreign call address should match");
        assertEq(fcs[1].foreignCallIndex, 2, "The foreign call index should be 2");
        vm.startPrank(policyAdmin);

        // Negative path - hit MAX_LOOP require statement

        for (uint i; i < 9_997; i++) {
            vm.pauseGasMetering();
            RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
        }
        vm.expectRevert("Max foreign calls reached");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_UpdatePermissionedFC_NewPolicyAdmin_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(policyAdmin), foreignCallSelector);

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        uint foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");

        // transfer policyAdmin role to new, non permissioned address and test update fails as expected
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyId);
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(policyId);

        vm.expectRevert("Not Permissioned For Foreign Call");
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyId, foreignCallId, fc);
    }

    function testRulesEngine_Unit_PermissionedForeignCall_removeAll_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        // add multiple admins to the permissions list
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x77777777), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x88888888), foreignCallSelector);
        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 4, "There should be four permissioned foreign call admins");
        RulesEngineForeignCallFacet(address(red)).removeAllFromPermissionList(pfcContractAddress, foreignCallSelector);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(pfcContractAddress, foreignCallSelector);
        assertTrue(pfcStorage.length == 0, "There should be no permissioned foreign call admins");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_removeAll_AddToPolicyAfterRemoval_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);

        // add multiple foreign calls to the master list
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector2);
        bytes4 foreignCallSelector3 = PermissionedForeignCallTestContract.getInternalValue.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector3);

        PermissionedForeignCallStorage memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 3, "There should be three permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 3, "There should be three permissioned foreign call signatures");

        address[] memory pfcAdmins = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector2
        );
        assertTrue(pfcAdmins.length == 1, "There should be one permissioned foreign call admin");

        // remove the foreign call from the master list
        RulesEngineForeignCallFacet(address(red)).removeForeignCallPermissions(pfcContractAddress, foreignCallSelector2);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 2, "There should be two permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 2, "There should be two permissioned foreign call signatures");
        pfcAdmins = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(pfcContractAddress, foreignCallSelector2);
        assertTrue(pfcAdmins.length == 0, "There should be no permissioned foreign call admins");
        // check that the foreign call is no longer in the master list
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[0],
            foreignCallSelector,
            "The first foreign call signature should be the simpleCheck"
        );
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[1],
            foreignCallSelector3,
            "The second foreign call signature should be the getInternalValue"
        );

        // now add the non permissioned FC to a policy
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("square(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "square(uint256)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_updatePermissionList_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        address[] memory initialAdmins = new address[](3);
        initialAdmins[0] = address(0x66666666);
        initialAdmins[1] = address(0x77777777);
        initialAdmins[2] = address(0x88888888);

        RulesEngineForeignCallFacet(address(red)).updatePermissionList(pfcContractAddress, foreignCallSelector, initialAdmins);

        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 3, "There should be three permissioned foreign call admins");

        address[] memory secondAdmins = new address[](2);
        secondAdmins[0] = address(0x1337);
        secondAdmins[1] = address(0x1338);

        RulesEngineForeignCallFacet(address(red)).updatePermissionList(pfcContractAddress, foreignCallSelector, secondAdmins);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(pfcContractAddress, foreignCallSelector);
        assertTrue(pfcStorage.length == 2, "There should be two permissioned foreign call admins");

        address[] memory thirdAdmins = new address[](0);
        RulesEngineForeignCallFacet(address(red)).updatePermissionList(pfcContractAddress, foreignCallSelector, thirdAdmins);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(pfcContractAddress, foreignCallSelector);
        assertTrue(pfcStorage.length == 0, "There should be no permissioned foreign call admins");
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_UintToUintMappedTracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1);
        trackerKeys[1] = abi.encode(2);
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000);
        trackerValues[1] = abi.encode(2000000000);
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRule(
            policyIds,
            ParamTypes.UINT,
            ParamTypes.UINT,
            trackerKeys,
            trackerValues,
            1,
            2000000000
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        vm.expectRevert();
        userContract.transfer(address(0x7654321), 1);

        userContract.transfer(address(0x7654321), 2);

        assertEq(testContract.getInternalValue(), 2000000000, "The internal value should be updated to 2000000000");
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_AddressToUintMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321));
        trackerKeys[1] = abi.encode(address(0x7654322));
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000);
        trackerValues[1] = abi.encode(2000000000);
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRule(
            policyIds,
            ParamTypes.UINT,
            ParamTypes.UINT,
            trackerKeys,
            trackerValues,
            0,
            2000000000
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        vm.expectRevert();
        userContract.transfer(address(0x7654321), 10);

        userContract.transfer(address(0x7654322), 15);

        assertEq(testContract.getInternalValue(), 2000000000, "The internal value should be updated to 2000000000");
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_UintToAddressMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1000000000);
        trackerKeys[1] = abi.encode(2000000000);
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321));
        trackerValues[1] = abi.encode(address(0x7654322));
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRule(
            policyIds,
            ParamTypes.ADDR,
            ParamTypes.ADDR,
            trackerKeys,
            trackerValues,
            1,
            uint256(uint160(address(0x7654322)))
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        vm.expectRevert();
        userContract.transfer(address(0x7654321), 1000000000);

        userContract.transfer(address(0x7654322), 2000000000);

        assertEq(
            testContract.getInternalValue(),
            uint256(uint160(address(0x7654322))),
            "The internal value should be updated to the `to` address"
        );
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_BytesToAddressMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.BOOL;
        pTypes[4] = ParamTypes.STR;
        _addCallingFunctionToPolicy(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,uint256,bytes)")))),
            pTypes,
            string("transferFom(address,uint256,bytes)")
        );
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode("TestKey1");
        trackerKeys[1] = abi.encode("TestKey2");
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321));
        trackerValues[1] = abi.encode(address(0x7654322));
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRuleBytes32(
            policyIds,
            ParamTypes.ADDR,
            ParamTypes.BYTES,
            trackerKeys,
            trackerValues,
            2,
            uint256(uint160(address(0x7654322)))
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        // validate tracker exists
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 1);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyIds[0], 1, abi.encode("TestKey1"));
        assertEq(value, abi.encode(address(0x7654321)));

        vm.expectRevert();
        userContract.transferFrom(address(0x7654321), 1000000000, "TestKey1");
        assertEq(testContract.getInternalValue(), 0);

        userContract.transferFrom(address(0x7654322), 2000000000, "TestKey2");

        assertEq(
            testContract.getInternalValue(),
            uint256(uint160(address(0x7654322))),
            "The internal value should be updated to the `to` address"
        );
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_StringToAddressMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.BOOL;
        pTypes[4] = ParamTypes.STR;
        _addCallingFunctionToPolicy(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFromString(address,uint256,string)")))),
            pTypes,
            string("transferFomString(address,uint256,string)")
        );
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode("TestKey1");
        trackerKeys[1] = abi.encode("TestKey2");
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321));
        trackerValues[1] = abi.encode(address(0x7654322));
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRuleBytes32(
            policyIds,
            ParamTypes.ADDR,
            ParamTypes.STR,
            trackerKeys,
            trackerValues,
            2,
            uint256(uint160(address(0x7654322)))
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        // validate tracker exists
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 1);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyIds[0], 1, abi.encode("TestKey1"));
        assertEq(value, abi.encode(address(0x7654321)));

        vm.expectRevert();
        userContract.transferFromString(address(0x7654321), 1000000000, "TestKey1");
        assertEq(testContract.getInternalValue(), 0);

        userContract.transferFromString(address(0x7654322), 2000000000, "TestKey2");

        assertEq(
            testContract.getInternalValue(),
            uint256(uint160(address(0x7654322))),
            "The internal value should be updated to the `to` address"
        );
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_AddressToStringMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        //vm.skip(true);
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.BOOL;
        pTypes[4] = ParamTypes.STR;
        _addCallingFunctionToPolicy(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFromString(address,uint256,string)")))),
            pTypes,
            string("transferFomString(address,uint256,string)")
        );
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321));
        trackerKeys[1] = abi.encode(address(0x7654322));
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(
            "This is a string to test that the value string is above a bytes32 and does not get sliced weirdly. If you are seeing this we win!"
        );
        trackerValues[1] = abi.encode(
            "This is a long string but not the same string so that we can ensure this is working as we think it will work. You are now the player. Good luck."
        );
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRuleString(
            policyIds,
            ParamTypes.STR,
            ParamTypes.ADDR,
            trackerKeys,
            trackerValues,
            0,
            uint256(bytes32(abi.encode(true)))
        );

        console.log(
            "rule value keccak: ",
            uint256(
                keccak256(
                    abi.encodePacked(
                        "This is a long string but not the same string so that we can ensure this is working as we think it will work. You are now the player. Good luck."
                    )
                )
            )
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        // validate tracker exists
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 1);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyIds[0], 1, abi.encode(address(0x7654321)));
        assertEq(
            value,
            abi.encode(
                "This is a string to test that the value string is above a bytes32 and does not get sliced weirdly. If you are seeing this we win!"
            )
        );

        // vm.expectRevert();
        userContract.transferFromString(address(0x7654321), 1000000000, "Test String 1");

        assertEq(
            testContract.getDecodedStrOne(),
            "This is a string to test that the value string is above a bytes32 and does not get sliced weirdly. If you are seeing this we win!",
            "The internal value should be updated to the string above"
        );

        userContract.transferFromString(address(0x7654322), 2000000000, "Test String 2");

        assertEq(
            testContract.getDecodedStrOne(),
            "This is a long string but not the same string so that we can ensure this is working as we think it will work. You are now the player. Good luck.",
            "The internal value should be updated to the string above"
        );

        /** 
        25837056493731107400212975313110805414715314646597854337469320516987899609613
        25837056493731107400212975313110805414715314646597854337469320516987899609613
        */
    }

    function testRulesEngine_Unit_ForeignCall_MintPosEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        uint ruleAmount = 1e18;
        // we setup the rule: if amount > ruleAmount -> mint NFT else get banned
        _setupRuleWithMintEffect(ruleAmount, address(userContract));
        // we check the nft balance of user1 before we make the transfer that triggers a mint
        uint balanceBefore = nftContract.balanceOf(user1);
        bool statusBefore = testContract2.getNaughty(user1);
        
        assertFalse(statusBefore);
        vm.startPrank(user1);
        vm.startSnapshotGas("checkRule_Effect_Positive_ForeignCallMint");
        // the transfer should trigger the mint effect since we are transferring above the rule's amount
        userContract.transferFrom(address(user1), address(0x7654321), ruleAmount + 1);
        vm.stopSnapshotGas();
        // we check that the nft balance increased by 1, and that the user didn't get banned
        assertEq(balanceBefore + 1, nftContract.balanceOf(user1), "NFT balance should increase by 1");
        assertFalse(testContract2.getNaughty(user1), "user should not be banned");
    }

    function testRulesEngine_Unit_ForeignCall_BanNegEffect() public {
        uint ruleAmount = 1e18;
        // we setup the rule: if amount > ruleAmount -> mint NFT else get banned
        _setupRuleWithMintEffect(ruleAmount, address(userContract));
        // we check the nft balance of user1 before we make the transfer that triggers a mint
        uint balanceBefore = nftContract.balanceOf(user1);
        bool statusBefore = testContract2.getNaughty(user1);
        assertFalse(statusBefore);
        vm.startPrank(user1);
        vm.startSnapshotGas("checkRule_Effect_Negative_ForeignCallBan");
        // the transfer should trigger the mint effect since we are transferring above the rule's amount
        userContract.transferFrom(address(user1), address(0x7654321), ruleAmount - 1);
        // we check that the nft balance didn't increased, and that user got banned
        assertTrue(testContract2.getNaughty(user1), "user should be banned");
        assertEq(balanceBefore, nftContract.balanceOf(user1), "NFT balance should stay the same");
    }
}
