// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/src/Test.sol";
import "forge-std/src/console2.sol";

import "test/utils/ForeignCallTestCommon.sol";
import "test/utils/ExampleUserContractEncoding.sol";
import "src/utils/DiamondMine.sol";
import "test/utils/PermissionedForeignCalls.sol";

import "src/engine/facets/RulesEngineComponentFacet.sol";
import "src/engine/facets/RulesEngineForeignCallFacet.sol";

import "src/example/ExampleERC20.sol";
import "test/clientContractExamples/ExampleUserContract.sol";
import "test/clientContractExamples/ExampleUserOwnableContract.sol";
import "test/clientContractExamples/ExampleUserAccessControl.sol";

import "test/clientContractExamples/ERC721A/ExampleERC721A.sol";
import "src/example/ExampleERC721.sol";
import "src/example/ExampleERC20.sol";
import "test/clientContractExamples/ExampleERC1155.sol";

/**
 * Shared testing logic, set ups, helper functions and global test variables for Rules Engine Testing Framework
 * Code used across multiple testing directories belongs here
 */

contract RulesEngineCommon is DiamondMine, Test {
    // contract objects
    ForeignCallTestContract testContract;
    ForeignCallTestContractOFAC testContract2;
    ExampleUserContract newUserContract;
    ExampleUserContract userContract;

    ExampleERC721A userContract721A;
    ExampleERC721 userContract721;
    ExampleERC20 userContractERC20;
    ExampleERC1155 userContract1155;

    PermissionedForeignCallTestContract permissionedForeignCallContract;

    // strings
    string callingFunction = "transfer(address,uint256)";
    string callingFunction2 = "updateInfo(address _to, string info)";
    string callingFunction3 = "transferFrom(address,uint256)";
    string callingFunctionBytes = "transferBytes(address,uint256)";
    string callingFunctionWithBytes = "transferWithBytes(address,uint256,bytes)";
    string callingFunctionString = "transferString(address,uint256)";
    string callingFunctionWithString = "transferWithString(address,uint256,string)";
    string callingFunctionBool = "transferBool(address,uint256)";
    string callingFunctionArrayStatic = "transferArray(address,uint256)";
    string callingFunctionArrayDynamic = "transferDynamicArray(address,uint256)";
    string constant event_text = "Rules Engine Event";
    string constant revert_text = "Rules Engine Revert";
    string constant event_text2 = "Rules Engine Event 2";
    string constant revert_text2 = "Rules Engine Revert 2";
    string constant customEventText = "Custom Event";
    string ruleName = "ruleName";
    string ruleDescription = "ruleDescription";
    string policyName = "policyName";
    string policyDescription = "policyDescription";
    ExampleERC721 nftContract;

    //bytes32
    bytes32 public constant EVENTTEXT = bytes32("Rules Engine Event");
    bytes32 public constant EVENTTEXT2 = bytes32("Rules Engine Event 2");

    uint8 constant FLAG_FOREIGN_CALL = 0x01; // 00000001
    uint8 constant FLAG_TRACKER_VALUE = 0x02; // 00000010
    // uint8 constant MASK_GLOBAL_VAR = 0x1C; // 00011100

    // Global variable type constants
    uint8 constant SHIFT_GLOBAL_VAR = 2;
    uint8 constant GLOBAL_MSG_SENDER = 1;
    uint8 constant GLOBAL_MSG_DATA = 3;
    uint8 constant GLOBAL_NONE = 0;
    uint8 constant GLOBAL_BLOCK_TIMESTAMP = 2;
    uint8 constant GLOBAL_BLOCK_NUMBER = 4;
    uint8 constant GLOBAL_TX_ORIGIN = 5;

    //bytes4
    bytes4[] callingFunctions;

    // Effect structures
    Effect effectId_revert;
    Effect effectId_revert2;
    Effect effectId_event;
    Effect effectId_event2;
    Effect effectId_Log1;
    Effect effectId_Log2;
    Effect effectId_Log3;
    Effect effectId_Log;
    Effect effectId_expression;
    Effect effectId_expression2;
    Effect effectId_expression3;
    Effect effectId_expression4;

    //uint256 arrays
    uint256[] callingFunctionIds;
    uint256[][] ruleIds;

    // uint256
    uint256 ruleValue = 10;
    uint256 transferValue = 15;
    uint256 constant ATTO = 10 ** 18;

    // bool
    bool public testDeployments = true;

    // address arrays
    address[] testAddressArray = [
        address(0xFF1),
        address(0xFF2),
        address(0xFF3),
        address(0xFF4),
        address(0xFF5),
        address(0xFF6),
        address(0xFF7),
        address(0xFF8)
    ];

    // addresses
    address user1 = address(0x001);
    address policyAdmin = address(0x54321);
    address newPolicyAdmin = address(0x0Add);
    address callingContractAdmin = address(0x12345);
    address constant USER_ADDRESS = address(0xd00d);
    address constant USER_ADDRESS_2 = address(0xBADd00d);
    address userContractAddress;
    address newUserContractAddress;
    address userContractExtraParamAddress;
    address userContract1155Address;
    address userContract721AAddress;
    address userContract721Address;
    address userContractERC20Address;
    address pfcContractAddress;

    //test modifiers
    modifier ifDeploymentTestsEnabled() {
        if (testDeployments) {
            _;
        }
    }

    modifier endWithStopPrank() {
        _;
        vm.stopPrank();
    }

    modifier resetsGlobalVariables() {
        _resetGlobalVariables();
        _;
    }

    /// Set up functions
    function setupRuleWithoutForeignCall() public ifDeploymentTestsEnabled endWithStopPrank {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        // Apply the policy
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function setUpRuleSimple() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 policyId, uint256 ruleId) {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Apply the policy
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return (policyIds[0], ruleId);
    }

    function setUpRuleSimpleGTEQL() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 policyId, uint256 ruleId) {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the calling function  to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: amount >= 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.GTEQL, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet("GTEQL", 4, LogicalOp.GTEQL);

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Apply the policy
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return (policyIds[0], ruleId);
    }

    function setUpRuleSimpleLTEQL() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 policyId, uint256 ruleId) {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: amount <= 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.LTEQL, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet("LTEQL", 4, LogicalOp.LTEQL);

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Apply the policy
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return (policyIds[0], ruleId);
    }

    function setupRuleWithStringComparison() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 ruleId) {
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Rule: info == "Bad Info" -> revert -> updateInfo(address _to, string info) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, *uint256 representation of Bad Info*, LogicalOp.EQ, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode("Bad Info")));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.STR;
        rule.rawData.dataValues[0] = abi.encode("Bad Info");
        rule.rawData.instructionSetIndex[0] = 3;

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.STR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.STR;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes,
            callingFunction2,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction2))));

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function setupRuleWithAddressComparison() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 ruleId) {
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Rule: _to == 0x1234567 -> revert -> updateInfo(address _to, string info) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, *uint256 representation of 0x1234567o*, LogicalOp.EQ, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(address(0x1234567)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.STR;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes,
            callingFunction2,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction2))));
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function setupEffectWithTrackerUpdateUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 ruleId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: 1 == 1 -> TRU:someTracker += FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)

        Rule memory rule;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_expression2;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](2);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.positiveEffectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.positiveEffectPlaceHolders[1].typeSpecificIndex = 1;

        rule.negativeEffectPlaceHolders = new Placeholder[](2);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.negativeEffectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.negativeEffectPlaceHolders[1].typeSpecificIndex = 1;
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(2);
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        console2.log("*****************trackerId", trackerId);
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        fc; //added to silence warnings during testing revamp
        return policyIds[0];
    }

    function setupEffectWithTrackerUpdate(
        uint256 _policyId,
        Trackers memory tracker
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 ruleId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: 1 == 1 -> TRU:someTracker += FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)

        Rule memory rule;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_expression2;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](2);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 1;
        rule.positiveEffectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.positiveEffectPlaceHolders[1].typeSpecificIndex = 1;

        rule.negativeEffectPlaceHolders = new Placeholder[](2);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 1;
        rule.negativeEffectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.negativeEffectPlaceHolders[1].typeSpecificIndex = 1;

        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        fc; //added to silence warnings during testing revamp
        return policyIds[0];
    }

    function createArrayOfRules() public view returns (Rule[] memory rules) {
        rules = new Rule[](3);
        Rule memory rule1;
        rule1.instructionSet = new uint256[](7);
        rule1.instructionSet[0] = uint(LogicalOp.NUM);
        rule1.instructionSet[1] = 1;
        rule1.instructionSet[2] = uint(LogicalOp.NUM);
        rule1.instructionSet[3] = 1;
        rule1.instructionSet[4] = uint(LogicalOp.EQ);
        rule1.instructionSet[5] = 0;
        rule1.instructionSet[6] = 1;
        rule1.positiveEffectPlaceHolders = new Placeholder[](1);
        rule1.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule1.positiveEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule1.negativeEffectPlaceHolders = new Placeholder[](1);
        rule1.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule1.negativeEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule1.posEffects = new Effect[](1);
        rule1.posEffects[0] = effectId_revert;
        rule1.negEffects = new Effect[](1);
        rule1.negEffects[0] = effectId_revert;

        Rule memory rule2;
        rule2.instructionSet = new uint256[](7);
        rule2.instructionSet[0] = uint(LogicalOp.NUM);
        rule2.instructionSet[1] = 1;
        rule2.instructionSet[2] = uint(LogicalOp.NUM);
        rule2.instructionSet[3] = 1;
        rule2.instructionSet[4] = uint(LogicalOp.GT);
        rule2.instructionSet[5] = 0;
        rule2.instructionSet[6] = 1;
        rule2.positiveEffectPlaceHolders = new Placeholder[](1);
        rule2.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule2.positiveEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule2.negativeEffectPlaceHolders = new Placeholder[](1);
        rule2.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule2.negativeEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule2.posEffects = new Effect[](1);
        rule2.posEffects[0] = effectId_event;
        rule2.negEffects = new Effect[](1);
        rule2.negEffects[0] = effectId_revert;

        Rule memory rule3;
        rule3.instructionSet = new uint256[](7);
        rule3.instructionSet[0] = uint(LogicalOp.PLH);
        rule3.instructionSet[1] = 0;
        rule3.instructionSet[2] = uint(LogicalOp.NUM);
        rule3.instructionSet[3] = 1;
        rule3.instructionSet[4] = uint(LogicalOp.GT);
        rule3.instructionSet[5] = 0;
        rule3.instructionSet[6] = 1;
        rule3.positiveEffectPlaceHolders = new Placeholder[](1);
        rule3.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule3.positiveEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule3.negativeEffectPlaceHolders = new Placeholder[](1);
        rule3.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule3.negativeEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule3.posEffects = new Effect[](1);
        rule3.posEffects[0] = effectId_revert;
        rule3.negEffects = new Effect[](1);
        rule3.negEffects[0] = effectId_revert;

        rules[0] = rule1;
        rules[1] = rule2;
        rules[2] = rule3;
        return rules;
    }

    function setupRuleWithForeignCall(
        uint256 _amount,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the foreign call placeholder

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_amount);

        rule = _setUpEffect(rule, _effectType, isPositive);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return policyIds[0];
    }

    // Same as setupRuleWithForeignCall except that it contains a foreign call that is referenced by another foreign call that is then squared by the foreign call and then checked to see if it's greater than the original value
    function setupRuleWithForeignCallWithSquaredFCValues(
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[1].typeSpecificIndex = 2;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(1, 0); // is placeholder 1 > placeholder 0?

        rule = _setUpEffect(rule, _effectType, isPositive);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");

        ForeignCall memory fc2;
        fc2.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc2.encodedIndices[0].index = 1;
        fc2.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        fc2.parameterTypes = fcArgs;
        fc2.foreignCallAddress = address(testContract);
        fc2.signature = bytes4(keccak256(bytes("square(uint256)")));
        fc2.returnType = ParamTypes.UINT;
        fc2.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc2, "square(uint256)");
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return policyIds[0];
    }

    // Same as setupRuleWithForeignCall except that it contais a tracker value that is then squared by the foreign call and then checked to see if it's greater than the tracker value
    function setupRuleWithForeignCallSquaringReferencedTrackerVals(
        uint256 _amount,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[1].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(1, 0); // FC placeholder > tracker placeholder

        rule = _setUpEffect(rule, _effectType, isPositive);

        Trackers memory tracker;

        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(_amount);
        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.TRACKER;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("square(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "square(uint256)");
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return policyIds[0];
    }

    function _setUpForeignCallWithAlwaysTrueRuleValueTypeArg(
        ForeignCall memory fc,
        string memory callingSignature,
        string memory fcSignature,
        ParamTypes _pType
    ) public returns (Rule memory rule) {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](1);
        pTypes[0] = _pType;

        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingSignature)))),
            pTypes,
            callingSignature,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingSignature))));

        uint foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, fcSignature);

        rule.instructionSet = _createInstructionSet();
        // placeholder for foreign call we just created
        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = uint128(foreignCallId);

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = uint128(foreignCallId);

        // positive effect
        uint256[] memory effectBytecode = new uint256[](0);
        Effect memory positiveEffect = Effect({
            valid: true,
            dynamicParam: false,
            effectType: EffectTypes.EXPRESSION,
            pType: ParamTypes.ADDR,
            param: "",
            text: EVENTTEXT,
            errorMessage: "foreign call failed",
            instructionSet: effectBytecode
        });
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = positiveEffect;

        // negative effect
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        // _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
    }

    function _setUpForeignCallAndCompareAgainstExpected(
        ForeignCall memory fc,
        string memory callingSignature,
        string memory fcSignature,
        ParamTypes _pType,
        uint256 expectedValue
    ) public {
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](1);
        pTypes[0] = _pType;

        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingSignature)))),
            pTypes,
            callingSignature,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingSignature))));

        uint foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, fcSignature);

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);

        // instruction set: is "expectedValue" == returned value from foreign call at index 0 ?
        rule.instructionSet = new uint[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; // placeholder at index 0
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = expectedValue; // we place in memory our expected value
        rule.instructionSet[4] = uint(LogicalOp.EQ); // we run equality check against these 2 values
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.posEffects = new Effect[](0);

        // negative effect
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
    }

    function _setUpForeignCallWithAlwaysTrueRuleDynamicArrayArg(
        ForeignCall memory fc,
        string memory callingSignature,
        string memory fcSignature,
        uint arrayAmount
    ) public {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        vm.startPrank(policyAdmin);
        // we fuzz the amount of arrays
        ParamTypes[] memory pTypes = new ParamTypes[](arrayAmount);
        // we assign the same type to all the arrays
        for (uint array; array < arrayAmount; array++) pTypes[array] = ParamTypes.DYNAMIC_TYPE_ARRAY;

        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingSignature)))),
            pTypes,
            callingSignature,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingSignature))));
        uint foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, fcSignature);

        Rule memory rule;
        rule.instructionSet = _createInstructionSet();
        // placeholder for the foreign call
        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = uint128(foreignCallId);

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = uint128(foreignCallId);

        // positive effect
        uint256[] memory effectBytecode = new uint256[](0);
        Effect memory positiveEffect = Effect({
            valid: true,
            dynamicParam: false,
            effectType: EffectTypes.EXPRESSION,
            pType: ParamTypes.ADDR,
            param: "",
            text: EVENTTEXT,
            errorMessage: "foreign call failed",
            instructionSet: effectBytecode
        });
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = positiveEffect;

        // negative effect
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        // _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
    }

    function _setUpEffect(Rule memory rule, EffectTypes _effectType, bool isPositive) public view returns (Rule memory _rule) {
        if (isPositive) {
            rule.posEffects = new Effect[](1);
            if (_effectType == EffectTypes.REVERT) {
                rule.posEffects[0] = effectId_revert;
            }
            if (_effectType == EffectTypes.EVENT) {
                rule.posEffects[0] = effectId_event;
            }
        } else {
            rule.negEffects = new Effect[](1);
            if (_effectType == EffectTypes.REVERT) {
                rule.negEffects[0] = effectId_revert;
            }
            if (_effectType == EffectTypes.EVENT) {
                rule.negEffects[0] = effectId_event;
            }
        }
        return rule;
    }

    function _setupRuleWithRevert(address userContractMinTransferAddress) public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(policyIds[0], 4);
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LogicalOp.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.posEffects[0] = effectId_revert;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractMinTransferAddress, policyIds);
    }

    function _setupRuleWithPosEvent() public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithMintEffect(uint256 _transferValue, address _userContractAddr) public returns (address nftAddress) {
        // setup
        nftContract = new ExampleERC721("Token Name", "SYMB");
        nftContract.transferOwnership(address(red));
        testContract2 = new ForeignCallTestContractOFAC();

        // policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        {
            ParamTypes[] memory pTypes = new ParamTypes[](3);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.ADDR;
            pTypes[2] = ParamTypes.UINT;
            // Save the calling function
            RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyIds[0],
                bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))),
                pTypes,
                "transferFrom(address,address,uint256)",
                ""
            );
        }

        uint256 mintCallId;
        {
            ParamTypes[] memory fcArgs = new ParamTypes[](1);
            fcArgs[0] = ParamTypes.ADDR;
            ForeignCall memory fc;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 0;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES; // the from, to, and msg.sender are all part of the regular encoded values (calldata)
            fc.parameterTypes = fcArgs;
            fc.foreignCallAddress = address(nftContract);
            fc.signature = bytes4(keccak256(("safeMint(address)")));
            fc.returnType = ParamTypes.VOID;
            fc.foreignCallIndex = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "safeMint(address)");
            mintCallId = fc.foreignCallIndex;
        }
        uint256 banCallId;
        {
            ParamTypes[] memory fcArgs = new ParamTypes[](1);
            fcArgs[0] = ParamTypes.ADDR;
            ForeignCall memory fc;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = 0;
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES; // the from, to, and msg.sender are all part of the regular encoded values (calldata)
            fc.parameterTypes = fcArgs;
            fc.foreignCallAddress = address(testContract2);
            fc.signature = bytes4(keccak256(("addToNaughtyList(address)")));
            fc.returnType = ParamTypes.VOID;
            fc.foreignCallIndex = RulesEngineForeignCallFacet(address(red)).createForeignCall(
                policyIds[0],
                fc,
                "addToNaughtyList(address)"
            );
            banCallId = fc.foreignCallIndex;
        }

        // Rule: amount > 1e18 -> mint -> transferFrom(address _from, address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 2; // amount

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH); // amount
        rule.instructionSet[1] = 0; //
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = _transferValue;
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = uint128(mintCallId);

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = uint128(banCallId);

        {
            // positive effect
            uint256[] memory mintEffectBytecode = new uint256[](2);
            mintEffectBytecode[0] = uint(LogicalOp.PLH);
            mintEffectBytecode[1] = 0; // we flag that we will be using placeholder 0
            Effect memory mintEffect = Effect({
                valid: true,
                dynamicParam: false,
                effectType: EffectTypes.EXPRESSION,
                pType: ParamTypes.ADDR,
                param: "",
                text: EVENTTEXT,
                errorMessage: "",
                instructionSet: mintEffectBytecode
            });
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = mintEffect;

            // negative effect
            uint256[] memory banEffectBytecode = new uint256[](2);
            banEffectBytecode[0] = uint(LogicalOp.PLH);
            banEffectBytecode[1] = 0; // we flag that we will be using placeholder 1
            Effect memory banEffect = Effect({
                valid: true,
                dynamicParam: false,
                effectType: EffectTypes.EXPRESSION,
                pType: ParamTypes.ADDR,
                param: "",
                text: EVENTTEXT,
                errorMessage: "",
                instructionSet: banEffectBytecode
            });
            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = banEffect;
        }
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        bytes4[] memory functions = new bytes4[](1);
        bytes memory _callingFunction = bytes("transferFrom(address,address,uint256)");
        functions[0] = bytes4(keccak256(_callingFunction));
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        // _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            functions,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(_userContractAddr, policyIds);
        nftAddress = address(nftContract);
    }

    function _setupRuleWithPosEventParams(
        bytes memory param,
        ParamTypes pType
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRuleWithCustomEventParams(4, param, pType);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(
        ParamTypes pType
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);
        Rule memory rule;
        uint[] memory effectInstructionSet = new uint[](2);
        effectInstructionSet[0] = uint(LogicalOp.PLH);
        effectInstructionSet[1] = 0;
        Effect memory posEffect = Effect({
            valid: true,
            dynamicParam: true,
            effectType: EffectTypes.EVENT,
            pType: ParamTypes.STR,
            param: "",
            text: EVENTTEXT,
            errorMessage: "",
            instructionSet: effectInstructionSet
        });
        Effect memory negEffect = Effect({
            valid: true,
            dynamicParam: true,
            effectType: EffectTypes.EVENT,
            pType: ParamTypes.STR,
            param: "",
            text: EVENTTEXT2,
            errorMessage: "",
            instructionSet: effectInstructionSet
        });
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        if (pType == ParamTypes.ADDR) {
            rule = _createGTRuleWithDynamicEventParamsAddress(4);
            // Add a negative/positive effects

            rule.posEffects[0] = posEffect;
            rule.negEffects[0] = negEffect;
        } else {
            rule = _createGTRuleWithDynamicEventParams(4);
            rule.posEffects[0] = posEffect;
            rule.negEffects[0] = negEffect;
        }

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupMinTransferWithPosEvent(
        uint256 threshold,
        address contractAddress
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(threshold);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        if (ruleIds.length == 0) ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(contractAddress), policyIds);
    }

    function _resetGlobalVariables() public {
        delete callingFunctions;
        delete callingFunctionIds;
        delete ruleIds;
    }

    function _setupPolicyWithMultipleRulesWithPosEvents() public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule 1: GT 4
        Rule memory rule = _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](4));
        ruleIds[0][0] = ruleId;

        // Rule 2: GT 5
        rule = _createGTRule(5);
        rule.posEffects[0] = effectId_event2;

        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        // // Save the fKureIds.push(callingFunctionId);
        ruleIds[0][1] = ruleId;

        // Rule 3: GT 6
        rule = _createGTRule(6);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        // // Save the fKureIds.push(callingFunctionId);
        ruleIds[0][2] = ruleId;

        // Rule 4: GT 7
        rule = _createGTRule(7);
        rule.posEffects[0] = effectId_event2;

        // Save the rule
        ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        // // Save the fKureIds.push(callingFunctionId);
        ruleIds[0][3] = ruleId;

        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWith2PosEvent() public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(4);
        rule.posEffects = new Effect[](2);
        rule.posEffects[0] = effectId_event;
        rule.posEffects[1] = effectId_event2;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    // set up a rule with a uint256 tracker value for testing
    function setupRuleWithTracker(
        uint256 trackerValue
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Build the tracker
        Trackers memory tracker;

        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTracker(
        uint256 _policyId,
        Trackers memory tracker
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameter();
        rule.posEffects[0] = effectId_event;

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTracker2(
        uint256 _policyId,
        Trackers memory tracker,
        TrackerArrayTypes arrayType
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();
        // rule.posEffects[0] = effectId_event;

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", arrayType);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerAddr(
        uint256 _policyId,
        Trackers memory tracker
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerFlag(
        uint256 _policyId,
        Trackers memory tracker
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.positiveEffectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.negativeEffectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerBool(
        uint256 _policyId,
        Trackers memory tracker
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BOOL;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.BOOL;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerUint(
        uint256 _policyId,
        Trackers memory tracker
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.UINT;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function _setupRuleWithMappedTracker(
        uint256 _policyId,
        Trackers memory tracker,
        ParamTypes keyValueType,
        ParamTypes valueType,
        ParamTypes trackerValueType,
        uint128 keyTypeSpecificIndex,
        uint128 valueTypeSpecificIndex,
        bytes[] memory trackerKeys,
        bytes[] memory trackerValues,
        string memory trackerName
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 trackerIndex) {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _policyId;

        // set function signature
        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // PLH, 0, PLHM, 1, 0, PLH, 1, EQ, 1, 2
        rule.instructionSet = _createInstructionSetMappedTracker();

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = keyValueType;
        rule.placeHolders[0].typeSpecificIndex = keyTypeSpecificIndex;
        rule.placeHolders[1].pType = valueType;
        rule.placeHolders[1].typeSpecificIndex = valueTypeSpecificIndex;
        rule.placeHolders[2].pType = trackerValueType;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // Add the tracker
        trackerIndex = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return (trackerIndex);
    }

    function _setupRuleWithMappedTrackerUpdatedFromEffect(
        uint256 _policyId,
        Trackers memory tracker,
        bytes[] memory trackerKeys,
        bytes[] memory trackerValues,
        ParamTypes trackerKeyType,
        string memory trackerName
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 trackerIndex) {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _policyId;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](2);
        rule.positiveEffectPlaceHolders[0].pType = trackerKeyType;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.positiveEffectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[1].typeSpecificIndex = 0;

        rule.negativeEffectPlaceHolders = new Placeholder[](2);
        rule.negativeEffectPlaceHolders[0].pType = trackerKeyType;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.negativeEffectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[1].typeSpecificIndex = 0;

        if (trackerKeyType == ParamTypes.UINT) {
            // Add a negative/positive effects
            rule.negEffects = new Effect[](1);
            rule.posEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects[0] = _createEffectExpressionMappedTrackerUpdateParameterPlaceHolderUint();
        } else if (trackerKeyType == ParamTypes.ADDR) {
            // Add a negative/positive effects
            rule.negEffects = new Effect[](1);
            rule.posEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects[0] = _createEffectExpressionMappedTrackerUpdateParameterPlaceHolderADDR();
        } else if (trackerKeyType == ParamTypes.BOOL) {
            // Add a negative/positive effects
            rule.negEffects = new Effect[](1);
            rule.posEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects[0] = _createEffectExpressionMappedTrackerUpdateParameterPlaceHolderBool();
        }

        // Add the tracker
        trackerIndex = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return trackerIndex;
    }

    function _setupRuleWithMappedTrackerUpdatedFromEffectMemory(
        uint256 _policyId,
        Trackers memory tracker,
        bytes[] memory trackerKeys,
        bytes[] memory trackerValues,
        ParamTypes trackerKeyType,
        string memory trackerName
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 trackerIndex) {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _policyId;

        _addCallingFunctionToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.positiveEffectPlaceHolders = new Placeholder[](2);
        rule.positiveEffectPlaceHolders[0].pType = trackerKeyType;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.positiveEffectPlaceHolders[1].pType = trackerKeyType;
        rule.positiveEffectPlaceHolders[1].typeSpecificIndex = 0;

        rule.negativeEffectPlaceHolders = new Placeholder[](2);
        rule.negativeEffectPlaceHolders[0].pType = trackerKeyType;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;
        rule.negativeEffectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[1].typeSpecificIndex = 0;

        if (trackerKeyType == ParamTypes.UINT) {
            // Add a negative/positive effects
            rule.negEffects = new Effect[](1);
            rule.posEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects[0] = _createEffectExpressionMappedTrackerUpdateParameterMemoryUint();
        } else if (trackerKeyType == ParamTypes.ADDR) {
            // Add a negative/positive effects
            rule.negEffects = new Effect[](1);
            rule.posEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects[0] = _createEffectExpressionMappedTrackerUpdateParameterMemoryADDR();
        } else if (trackerKeyType == ParamTypes.BOOL) {
            // Add a negative/positive effects
            rule.negEffects = new Effect[](1);
            rule.posEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects[0] = _createEffectExpressionMappedTrackerUpdateParameterMemoryBool();
        }

        // Add the tracker
        trackerIndex = RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return trackerIndex;
    }

    function _createForeignCallUsingMappedTrackerValueRule(
        uint256[] memory policyIds,
        ParamTypes trackerPType,
        ParamTypes trackerKeyType,
        bytes[] memory trkKeys,
        bytes[] memory trackerVls,
        uint256 mappedTrackerKeyIndex,
        uint256 ruleConditional
    ) internal returns (Rule memory rule, ForeignCall memory fc) {
        // create mapped tracker
        _createMappedTrackerHelper(policyIds, trackerPType, trackerKeyType, trkKeys, trackerVls);
        // decode rule param

        /// set up rule
        // Rule: FC:simpleCheck(mappedTrackerValue) = ruleParam -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = trackerPType; // keyValueType;
        rule.placeHolders[0].typeSpecificIndex = 2; //keyTypeSpecificIndex;
        rule.placeHolders[1].pType = trackerPType; //valueType;
        rule.placeHolders[1].typeSpecificIndex = 1; //valueTypeSpecificIndex;
        rule.placeHolders[2].pType = trackerPType; // trackerValueType;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // create foreign call
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = ruleConditional; // dynamic
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = mappedTrackerKeyIndex; // dynamic
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;

        return (rule, fc);
    }

    function _createForeignCallUsingMappedTrackerValueRuleBytes32(
        uint256[] memory policyIds,
        ParamTypes trackerPType,
        ParamTypes trackerKeyType,
        bytes[] memory trkKeys,
        bytes[] memory trackerVls,
        uint256 mappedTrackerKeyIndex,
        uint256 ruleConditional
    ) internal returns (Rule memory rule, ForeignCall memory fc) {
        // create mapped tracker
        _createMappedTrackerHelper(policyIds, trackerPType, trackerKeyType, trkKeys, trackerVls);

        /// set up rule
        // Rule: FC:simpleCheck(mappedTrackerValue) = ruleParam -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.BYTES; // keyValueType;
        rule.placeHolders[0].typeSpecificIndex = 2; //keyTypeSpecificIndex;
        rule.placeHolders[1].pType = ParamTypes.ADDR; //valueType;
        rule.placeHolders[1].typeSpecificIndex = 1; //valueTypeSpecificIndex;
        rule.placeHolders[2].pType = ParamTypes.ADDR; // trackerValueType;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // create foreign call
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = ruleConditional; // dynamic
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = mappedTrackerKeyIndex; // dynamic
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;

        return (rule, fc);
    }

    function _createForeignCallUsingMappedTrackerValueRuleString(
        uint256[] memory policyIds,
        ParamTypes trackerPType,
        ParamTypes trackerKeyType,
        bytes[] memory trkKeys,
        bytes[] memory trackerVls,
        uint256 mappedTrackerKeyIndex,
        uint256 ruleConditional
    ) internal returns (Rule memory rule, ForeignCall memory fc) {
        // create mapped tracker
        _createMappedTrackerHelper(policyIds, trackerPType, trackerKeyType, trkKeys, trackerVls);

        /// set up rule
        // Rule: FC:simpleCheck(mappedTrackerValue) = ruleParam -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        rule.placeHolders = new Placeholder[](4);
        rule.placeHolders[0].pType = ParamTypes.BYTES; // keyValueType;
        rule.placeHolders[0].typeSpecificIndex = 2; //keyTypeSpecificIndex;
        rule.placeHolders[1].pType = ParamTypes.ADDR; //valueType;
        rule.placeHolders[1].typeSpecificIndex = 1; //valueTypeSpecificIndex;
        rule.placeHolders[2].pType = ParamTypes.ADDR; // trackerValueType;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 1;
        // Build the foreign call placeholder
        rule.placeHolders[3].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[3].typeSpecificIndex = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 2;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.BYTES;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 2;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 3;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = ruleConditional; // dynamic
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = mappedTrackerKeyIndex; // dynamic
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("testSig(string)")));
        fc.returnType = ParamTypes.BOOL;
        fc.foreignCallIndex = 0;

        return (rule, fc);
    }

    function _createMappedTrackerHelper(
        uint256[] memory policyIds,
        ParamTypes trackerPType,
        ParamTypes trackerKeyType,
        bytes[] memory trkKeys,
        bytes[] memory trackerVls
    ) internal {
        Trackers memory tracker;
        tracker.mapped = true;
        tracker.pType = trackerPType;
        tracker.trackerKeyType = trackerKeyType;

        /// create tracker key arrays
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = trkKeys[0]; // key 1
        trackerKeys[1] = trkKeys[1]; // key 2

        /// create tracker value arrays
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = trackerVls[0]; // value 1
        trackerValues[1] = trackerVls[1]; // value

        /// create tracker name
        string memory trackerName = "tracker1";
        // Add the tracker
        RulesEngineComponentFacet(address(red)).createMappedTracker(
            policyIds[0],
            tracker,
            trackerName,
            trackerKeys,
            trackerValues,
            TrackerArrayTypes.VOID
        );
    }

    function _createForeignCallUsingMappedTrackerValueHelper(
        Rule memory rule,
        uint256[] memory policyId,
        ForeignCall memory fc,
        EffectTypes _effectType,
        bool isPositive
    ) public {
        rule = _setUpEffect(rule, _effectType, isPositive);

        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId[0], fc, "simpleCheck(uint256)");

        // update rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyId[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyId);
    }

    /// Test helper functions
    function _createBlankPolicy() internal returns (uint256) {
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY, policyName, policyDescription);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);
        return policyId;
    }

    function _createBlankPolicyOpen() internal returns (uint256) {
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.OPEN_POLICY, policyName, policyDescription);
        return policyId;
    }

    function _createBlankPolicyWithAdminRoleString() internal returns (uint256) {
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY, policyName, policyDescription);
        return policyId;
    }

    // internal rule builder
    function _createGTRule(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.instructionSet = _createInstructionSet(_amount);
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleWithCustomEventParams(uint256 _amount, bytes memory param, ParamTypes paramType) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up custom event param effect.
        effectId_event = _createCustomEffectEvent(param, paramType);
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(_amount);
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleWithDynamicEventParams(uint256 _amount) public returns (Rule memory) {
        return _createGTRuleWithDynamicEventParams(_amount, true);
    }

    function _createGTRuleWithDynamicEventParams(uint256 _amount, bool isPositiveEffect) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up custom event param effect.
        effectId_event = isPositiveEffect ? _createEffectEventDynamicParams() : _createEffectEventDynamicParams2();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(_amount);
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 1;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 1;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleWithDynamicEventParamsAddress(uint256 _amount) public returns (Rule memory) {
        return _createGTRuleWithDynamicEventParamsAddress(_amount, true);
    }

    function _createGTRuleWithDynamicEventParamsAddress(uint256 _amount, bool isPositiveEffect) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up custom event param effect.
        effectId_event = isPositiveEffect ? _createEffectEventDynamicParamsAddress() : _createEffectEventDynamicParamsAddress2();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.instructionSet = _createInstructionSet(_amount);
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        rule.positiveEffectPlaceHolders = new Placeholder[](1);
        rule.positiveEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.positiveEffectPlaceHolders[0].typeSpecificIndex = 0;

        rule.negativeEffectPlaceHolders = new Placeholder[](1);
        rule.negativeEffectPlaceHolders[0].pType = ParamTypes.ADDR;
        rule.negativeEffectPlaceHolders[0].typeSpecificIndex = 0;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createLTRule() public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.NUM);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 2;
        rule.instructionSet[4] = uint(LogicalOp.LT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _addCallingFunctionToPolicy(uint256 policyId) internal returns (bytes4) {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        // Save the calling function
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction)))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        if (callingFunctions.length == 0) callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        return bytes4(bytes4(keccak256(bytes(callingFunction))));
    }

    function _addCallingFunctionToPolicyWithString(uint256 policyId) internal returns (bytes4) {
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.BOOL;
        pTypes[4] = ParamTypes.STR;
        // Save the calling function
        bytes4 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(bytes4(keccak256(bytes(callingFunction)))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        uint256[][] memory blankRuleIds = new uint256[][](0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        return callingFunctionId;
    }

    function _addCallingFunctionToPolicy(
        uint256 policyId,
        bytes4 _callingFunction,
        ParamTypes[] memory pTypes,
        string memory functionName
    ) internal returns (bytes4) {
        // Save the calling function
        bytes4 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(_callingFunction),
            pTypes,
            functionName,
            ""
        );
        // Save the Policy
        callingFunctions.push(_callingFunction);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        return callingFunctionId;
    }

    function _addCallingFunctionToPolicyOpen(
        uint256 policyId,
        bytes4 _callingFunction,
        ParamTypes[] memory pTypes,
        string memory functionName
    ) internal returns (bytes4) {
        // Save the calling function
        bytes4 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(_callingFunction),
            pTypes,
            functionName,
            ""
        );
        // Save the Policy
        callingFunctions.push(_callingFunction);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        return callingFunctionId;
    }

    function _addRuleIdsToPolicy(uint256 policyId, uint256[][] memory _ruleIds) internal {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            _ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
    }

    function _addRuleIdsToPolicyOpen(uint256 policyId, uint256[][] memory _ruleIds) internal {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            _ruleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
    }

    function _setupEffectProcessor() public {
        _createAllEffects();
    }

    function _createAllEffects() public {
        effectId_event = _createEffectEvent(event_text); // effectId = 1
        effectId_revert = _createEffectRevert(revert_text); // effectId = 2
        effectId_event2 = _createEffectEvent(event_text2); // effectId = 3
        effectId_revert2 = _createEffectRevert(revert_text2); // effectId = 4
        effectId_expression = _createEffectExpression(); // effectId = 5;
        effectId_expression2 = _createEffectExpressionTrackerUpdate(); // effectId = 6;
        effectId_expression3 = _createEffectExpressionTrackerUpdateParameterMemory(); // effectId = 7;
        effectId_expression4 = _createEffectExpressionTrackerUpdateParameterPlaceHolder(); // effectId = 8;
    }

    function _createEffectEvent(string memory _text) public pure returns (Effect memory) {
        uint256[] memory emptyArray = new uint256[](1);
        // Create a event effect
        return
            Effect({
                valid: true,
                dynamicParam: false,
                effectType: EffectTypes.EVENT,
                pType: ParamTypes.STR,
                param: abi.encode(_text),
                text: EVENTTEXT,
                errorMessage: _text,
                instructionSet: emptyArray
            });
    }

    function _createCustomEffectEvent(bytes memory param, ParamTypes paramType) public pure returns (Effect memory) {
        uint256[] memory emptyArray = new uint256[](1);
        bytes memory encodedParam;
        if (paramType == ParamTypes.UINT) {
            encodedParam = abi.encode(abi.decode(param, (uint)));
        } else if (paramType == ParamTypes.ADDR) {
            encodedParam = abi.encode(abi.decode(param, (address)));
        } else if (paramType == ParamTypes.BOOL) {
            encodedParam = abi.encode(abi.decode(param, (bool)));
        } else if (paramType == ParamTypes.STR) {
            encodedParam = abi.encode(abi.decode(param, (string)));
        } else if (paramType == ParamTypes.BYTES) {
            encodedParam = abi.encode(abi.decode(param, (bytes32)));
        }
        // Create a event effect
        return
            Effect({
                valid: true,
                dynamicParam: false,
                effectType: EffectTypes.EVENT,
                pType: paramType,
                param: encodedParam,
                text: EVENTTEXT,
                errorMessage: event_text,
                instructionSet: emptyArray
            });
    }

    function _createEffectEventDynamicParams() public pure returns (Effect memory) {
        return _createEffectEventDynamicParams(EVENTTEXT);
    }

    function _createEffectEventDynamicParams2() public pure returns (Effect memory) {
        return _createEffectEventDynamicParams(EVENTTEXT2);
    }

    function _createEffectEventDynamicParams(bytes32 text) public pure returns (Effect memory) {
        Effect memory effect;
        effect.valid = true;
        effect.dynamicParam = true;
        effect.effectType = EffectTypes.EVENT;
        effect.text = text;
        effect.instructionSet = new uint256[](4);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LogicalOp.NUM);
        effect.instructionSet[1] = 0;
        // // Tracker Placeholder
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;

        return effect;
    }

    function _createEffectEventDynamicParamsAddress() public pure returns (Effect memory) {
        return _createEffectEventDynamicParamsAddress(EVENTTEXT);
    }

    function _createEffectEventDynamicParamsAddress2() public pure returns (Effect memory) {
        return _createEffectEventDynamicParamsAddress(EVENTTEXT2);
    }

    function _createEffectEventDynamicParamsAddress(bytes32 text) public pure returns (Effect memory) {
        Effect memory effect;
        effect.valid = true;
        effect.dynamicParam = true;
        effect.effectType = EffectTypes.EVENT;
        effect.text = text;
        effect.instructionSet = new uint256[](4);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LogicalOp.NUM);
        effect.instructionSet[1] = 1;
        // // Tracker Placeholder
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;

        return effect;
    }

    function _createEffectRevert(string memory _text) public pure returns (Effect memory) {
        uint256[] memory emptyArray = new uint256[](1);
        // Create a revert effect
        return
            Effect({
                valid: true,
                dynamicParam: false,
                effectType: EffectTypes.REVERT,
                pType: ParamTypes.STR,
                param: abi.encode(_text),
                text: EVENTTEXT,
                errorMessage: revert_text,
                instructionSet: emptyArray
            });
    }

    function _createEffectExpression() public pure returns (Effect memory) {
        Effect memory effect;

        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](1);

        return effect;
    }

    function _createEffectExpressionTrackerUpdate() public pure returns (Effect memory) {
        // Effect: TRU:someTracker += FC:simpleCheck(amount)
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](11);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        // Tracker Placeholder
        effect.instructionSet[2] = uint(LogicalOp.PLH);
        effect.instructionSet[3] = 1;
        effect.instructionSet[4] = uint(LogicalOp.ADD);
        effect.instructionSet[5] = 0;
        effect.instructionSet[6] = 1;
        effect.instructionSet[7] = uint(LogicalOp.TRU);
        effect.instructionSet[8] = 1;
        effect.instructionSet[9] = 2;
        effect.instructionSet[10] = 0;

        return effect;
    }

    function _createEffectExpressionTrackerUpdateParameterPlaceHolder() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](6);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        // Tracker Placeholder
        effect.instructionSet[2] = uint(LogicalOp.TRU);
        effect.instructionSet[3] = 1;
        effect.instructionSet[4] = 0;
        effect.instructionSet[5] = uint(TrackerTypes.PLACE_HOLDER);

        return effect;
    }

    function _createEffectExpressionTrackerUpdateMultiTrackerUpdate() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](30);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        // Tracker Placeholder
        effect.instructionSet[2] = uint(LogicalOp.TRU);
        effect.instructionSet[3] = 1;
        effect.instructionSet[4] = 0;
        effect.instructionSet[5] = uint(TrackerTypes.PLACE_HOLDER);

        effect.instructionSet[6] = uint(LogicalOp.PLH);
        effect.instructionSet[7] = 1;
        // Tracker Placeholder
        effect.instructionSet[8] = uint(LogicalOp.TRU);
        effect.instructionSet[9] = 2;
        effect.instructionSet[10] = 0;
        effect.instructionSet[11] = uint(TrackerTypes.PLACE_HOLDER);

        effect.instructionSet[12] = uint(LogicalOp.PLH);
        effect.instructionSet[13] = 1;
        // Tracker Placeholder
        effect.instructionSet[14] = uint(LogicalOp.TRU);
        effect.instructionSet[15] = 3;
        effect.instructionSet[16] = 0;
        effect.instructionSet[17] = uint(TrackerTypes.PLACE_HOLDER);

        effect.instructionSet[18] = uint(LogicalOp.PLH);
        effect.instructionSet[19] = 1;
        // Tracker Placeholder
        effect.instructionSet[20] = uint(LogicalOp.TRU);
        effect.instructionSet[21] = 4;
        effect.instructionSet[22] = 0;
        effect.instructionSet[23] = uint(TrackerTypes.PLACE_HOLDER);

        effect.instructionSet[24] = uint(LogicalOp.PLH);
        effect.instructionSet[25] = 2;
        // Tracker Placeholder
        effect.instructionSet[26] = uint(LogicalOp.TRU);
        effect.instructionSet[27] = 5;
        effect.instructionSet[28] = 0;
        effect.instructionSet[29] = uint(TrackerTypes.PLACE_HOLDER);

        return effect;
    }

    function _createEffectExpressionMappedTrackerUpdateParameterPlaceHolderUint() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](9);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1;
        effect.instructionSet[8] = uint(TrackerTypes.PLACE_HOLDER);
        return effect;
    }

    function _createEffectExpressionMappedTrackerUpdateParameterPlaceHolderADDR() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](9);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = uint256(uint160(address(0x7654321)));
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1;
        effect.instructionSet[8] = uint(TrackerTypes.PLACE_HOLDER);
        return effect;
    }

    function _createEffectExpressionMappedTrackerUpdateParameterPlaceHolderBool() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](9);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = uint256(uint160(address(0x7654321)));
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1;
        effect.instructionSet[8] = uint(TrackerTypes.PLACE_HOLDER);
        return effect;
    }

    function _createEffectExpressionMappedTrackerUpdateParameterMemoryADDR() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](9);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.PLH);
        effect.instructionSet[3] = uint256(uint160(address(0x7654321)));
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1;
        effect.instructionSet[8] = uint(TrackerTypes.MEMORY);

        return effect;
    }

    function _createEffectExpressionMappedTrackerUpdateParameterMemoryUint() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](9);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 1;
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1;
        effect.instructionSet[8] = uint(TrackerTypes.MEMORY);

        return effect;
    }

    function _createEffectExpressionMappedTrackerUpdateParameterMemoryBool() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](9);
        effect.instructionSet[0] = uint(LogicalOp.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = uint(LogicalOp.NUM);
        effect.instructionSet[3] = 0;
        // Tracker Placeholder
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1; // false
        effect.instructionSet[8] = uint(TrackerTypes.MEMORY);

        return effect;
    }

    function _createEffectExpressionTrackerUpdateParameterMemory() public pure returns (Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = EffectTypes.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](6);
        // Tracker Placeholder
        effect.instructionSet[0] = uint(LogicalOp.TRU);
        effect.instructionSet[1] = 1;
        effect.instructionSet[2] = 0;
        effect.instructionSet[3] = uint(TrackerTypes.MEMORY);

        return effect;
    }

    // internal instruction set builder: overload as needed
    function _createInstructionSet() public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](2);
        // instruction set: TRUE
        instructionSet[0] = uint(LogicalOp.NUM);
        instructionSet[1] = 1; // always return true
    }

    function _createInstructionSet(uint256 plh1) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(
        string memory testString, // string added to identify this overloaded function vs the two uint256 param version
        uint256 plh1,
        LogicalOp plcType
    ) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(plcType);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        console.log("testString: %s", testString);
    }

    function _createInstructionSet(uint256 plh1, LogicalOp plcType) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(plcType);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(uint256 plh1, uint256 plh2) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = plh1;
        instructionSet[2] = uint(LogicalOp.PLH);
        instructionSet[3] = plh2;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSetMappedTracker() public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](10);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.PLHM);
        instructionSet[3] = 1;
        instructionSet[4] = 0;
        instructionSet[5] = uint(LogicalOp.PLH);
        instructionSet[6] = 1;
        instructionSet[7] = uint(LogicalOp.EQ);
        instructionSet[8] = 1;
        instructionSet[9] = 2;
    }

    function _setup_checkRule_ForeignCall_Positive(
        uint256 _transferValue,
        address _userContractAddr
    ) public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 _policyId) {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicyOpen();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_transferValue);
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(_userContractAddr, policyIds);
        return policyIds[0];
    }

    function _setup_checkRule_TransferFrom_ForeignCall_Positive(
        uint256 _transferValue,
        address _callingContractAddr
    ) public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicyOpen();
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 2;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_transferValue);
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(_callingContractAddr, policyIds);
    }

    function _setup_checkRule_ForeignCall_Negative(
        uint256 _transferValue,
        address _userContractAddr
    ) public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_transferValue);
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;

        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(_userContractAddr, policyIds);
    }

    function _setUpForeignCallSimple(uint256 _policyId) public ifDeploymentTestsEnabled returns (ForeignCall memory foreignCall) {
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(_policyId, fc, "simpleCheck(uint256)");
        return fc;
    }

    function _setUpForeignCallSimpleReturnID(
        uint256 _policyId
    ) public ifDeploymentTestsEnabled returns (ForeignCall memory foreignCall, uint256 fcId) {
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(_policyId, fc, "simpleCheck(uint256)");
        return (fc, foreignCallId);
    }

    function _switchCallingContractAdminRole(address newAdmin, address _userContract) public ifDeploymentTestsEnabled {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(newAdmin, _userContract);

        vm.stopPrank();
        vm.startPrank(newAdmin);
        RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(_userContract);
    }

    /**
     * @dev modifies a selector by changing its least significant bits according to the iterator.
     * @param _selector to be modified
     * @param i the iterator to be used to modify the selector
     * @return selector the modified selector
     * @notice the returned selector doesn't mean anything, and it is only intended to be used for testing purposes
     */
    function _modifySelectorWithIterator(bytes4 _selector, uint i) internal pure returns (bytes4 selector) {
        // bytes4 grabs the 4 most significant bytes of a 32-byte word. We XOR against "i" shifted to the left 28 bytes so it can align with the
        // selector's bytes4 which allows us to produce a different selector for each iteration after the first one (since i = 0 the first iteration)
        selector = bytes4(_selector ^ (bytes32(i) << (256 - 4 * 8)));
    }
}
