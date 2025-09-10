// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./GasHelpers.sol";
import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractWithMinTransfer.sol";
import "test/utils/ExampleUserContractWithMinTransferFC.sol";
import "test/utils/ExampleUserContractBase.sol";
import "test/clientContractExamples/ExampleUserContract.sol";
import "test/utils/ExampleUserContractWithDenyList.sol";
import "test/utils/ExampleUserContractWithMinTransferAndDenyList.sol";
import "test/utils/ExampleUserContractWithMinTransferRevert.sol";
import "test/utils/ExampleUserContractWithMinTransferMaxTransferAndDenyList.sol";
import "test/utils/ExampleERC20WithMinTransfer.sol";
import "test/utils/ExampleERC20WithDenyList.sol";
import "test/utils/ExampleERC20WithDenyListAndMinTransfer.sol";
import "test/utils/ExampleERC20Hardcoded.sol";
import "src/example/ExampleERC20.sol";
import "test/utils/ExampleERC20WithDenyListMinAndMax.sol";
import "test/utils/ExampleERC20WithManyConditionMinTransfer.sol";

contract GasReports is GasHelpers, RulesEngineCommon {
    uint256 gasUsed;

    // ERC20's for Tests with Rules Engine
    //-------------------------------------------------------------------------------------
    ExampleERC20 userContractNoPolicy;
    ExampleERC20 userContractMinTransfer;
    ExampleERC20 userContractFC;
    ExampleERC20 userContractFCPlusMin;
    ExampleERC20 userContractFCPlusMinPlusMax;
    ExampleERC20 userContractFCPlusMinPlusMaxOneRule;
    ExampleERC20 userContractFCPlusMinSeparatePolicy;
    ExampleERC20 userContractManyChecksMin;
    ExampleERC20 userContractMTplusEvent;
    ExampleERC20 userContractMTplusEventDynamic;

    ExampleERC20 userContractPause;
    ExampleERC20 userContractOracleFlex;
    ExampleERC20 userContractMinMaxBalance;

    //-------------------------------------------------------------------------------------

    function setUp() public {
        vm.startPrank(policyAdmin);
        red = createRulesEngineDiamond(address(0xB0b));
        //R2V2 Setup
        //-------------------------------------------------------------------------------------
        // No Policy
        userContractNoPolicy = new ExampleERC20("Token Name", "SYMB");
        userContractNoPolicy.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractNoPolicy.setRulesEngineAddress(address(red));
        userContractNoPolicy.setCallingContractAdmin(callingContractAdmin);
        // Min Transfer
        userContractMinTransfer = new ExampleERC20("Token Name", "SYMB");
        userContractMinTransfer.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractMinTransfer.setRulesEngineAddress(address(red));
        userContractMinTransfer.setCallingContractAdmin(callingContractAdmin);
        _setupRuleWithRevert(address(userContractMinTransfer));
        // OFAC
        userContractFC = new ExampleERC20("Token Name", "SYMB");
        userContractFC.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFC.setRulesEngineAddress(address(red));
        userContractFC.setCallingContractAdmin(callingContractAdmin);
        testContract2 = new ForeignCallTestContractOFAC();
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setupRuleWithOFACForeignCall(address(testContract2), EffectTypes.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        // OFAC Plus Min Transfer
        userContractFCPlusMin = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMin.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMin.setRulesEngineAddress(address(red));
        userContractFCPlusMin.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setupRulesWithForeignCallAndMinTransfer(address(testContract2), EffectTypes.REVERT, true);
        // OFAC Plus Min In One Rule
        userContractFCPlusMinPlusMaxOneRule = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMinPlusMaxOneRule.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMinPlusMaxOneRule.setRulesEngineAddress(address(red));
        userContractFCPlusMinPlusMaxOneRule.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setupRulesWithForeignCallPlusMinTransferAndMaxTransferInOneRule(address(testContract2), EffectTypes.REVERT, true);
        // OFAC Plus Min In Separate Policies
        userContractFCPlusMinSeparatePolicy = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMinSeparatePolicy.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMinSeparatePolicy.setRulesEngineAddress(address(red));
        userContractFCPlusMinSeparatePolicy.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setupRulesWithForeignCallAndMinTransferSeparatePolicies(address(testContract2), EffectTypes.REVERT, true);
        // Min Transfer 20 iterations
        userContractManyChecksMin = new ExampleERC20("Token Name", "SYMB");
        userContractManyChecksMin.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractManyChecksMin.setRulesEngineAddress(address(red));
        userContractManyChecksMin.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        _setupRuleWithRevertManyCondition();
        // OFAC Plus Min Plus Max Transfer
        userContractFCPlusMinPlusMax = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMinPlusMax.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMinPlusMax.setRulesEngineAddress(address(red));
        userContractFCPlusMinPlusMax.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setupRulesWithForeignCallPlusMinTransferAndMaxTransfer(address(testContract2), EffectTypes.REVERT, true);
        // Pause Rule
        userContractPause = new ExampleERC20("Token Name", "SYMB");
        userContractPause.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractPause.setRulesEngineAddress(address(red));
        userContractPause.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setUpRuleWithPauseTrackers();
        // Oracle Flex
        userContractOracleFlex = new ExampleERC20("Token Name", "SYMB");
        userContractOracleFlex.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractOracleFlex.setRulesEngineAddress(address(red));
        userContractOracleFlex.setCallingContractAdmin(callingContractAdmin);
        testContract2.addToNaughtyList(address(0xD00d));
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setupRuleWithOracleFlexForeignCall(address(testContract2), EffectTypes.REVERT, true);
        // Min Max Balance
        userContractMinMaxBalance = new ExampleERC20("Token Name", "SYMB");
        userContractMinMaxBalance.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractMinMaxBalance.setRulesEngineAddress(address(red));
        userContractMinMaxBalance.setCallingContractAdmin(callingContractAdmin);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        setUpRuleWithMinMaxBalanceLimits();
        //-------------------------------------------------------------------------------------

        testContract = new ForeignCallTestContract();
        _setupEffectProcessor();
    }
    function testGasExampleContract_NoPoliciesActive() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(1, address(userContractNoPolicy), "Using REv2 No Policies Active");
    }

    function testGasExampleSimpleMinTransferTriggeredWithRevertEffect() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(3, address(userContractMinTransfer), "Using REv2 Min Transfer Triggered With Revert Effect");
    }

    /**********  OFAC Prep functions to ensure warm storage comparisons **********/
    function testGasExampleOFAC() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFC), "Using REv2 OFAC gas report");
    }

    function testGasExampleOFACWithMinTransfer() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFCPlusMin), "Using REv2 OFAC with min transfer gas report");
    }

    function testGasExampleOFACWithMinTransferAndMaxTransfer() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(1, address(userContractFCPlusMinPlusMax), "Using REv2 OFAC with min and max transfer gas report");
    }

    function testGasExampleOFACWithMinTransferInOneRule() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFCPlusMinPlusMaxOneRule), "Using REv2 OFAC with min transfer gas report");
    }

    function testGasExampleOFACWithMinTransferInSeparatePolicies() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFCPlusMinSeparatePolicy), "Using REv2 OFAC with min transfer gas report");
    }

    function testGasExampleMinTransferMany() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractManyChecksMin), "Using REv2 min transfer 20 iterations");
    }

    function _testGasExampleMinTransferWithSetEventParams() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 5);
        _exampleContractGasReport(5, address(userContractMTplusEvent), "Using REv2 Event Effect with min transfer gas report");
    }

    function _testGasExampleMinTransferWithDynamicEventParams() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 5);
        _exampleContractGasReport(5, address(userContractMTplusEventDynamic), "Using REv2 Event Effect with min transfer gas report");
    }

    function testGasExamplePause() public endWithStopPrank {
        vm.warp(1000000001); // set block time greater than the tracker to allow txn to pass
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractPause), "Using REv2 Pause Rule gas report");
    }

    function testGasExampleOracleFlex() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractOracleFlex), "Using REv2 Oracle Flex gas report");
    }

    function testGasExampleMinMax() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractMinMaxBalance), "Using REv2 Event Effect with min transfer gas report");
    }

    function setupRuleWithOFACForeignCall(
        address _contractAddress,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyIds[0],
            fc,
            "getNaughty(address)",
            "getNaughty(address addr)"
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        // Swapping isPositive to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule = _setUpEffect(rule, _effectType, !isPositive);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractFC), policyIds);
    }

    function setupRulesWithForeignCallAndMinTransfer(
        address _contractAddress,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyIds[0],
            fc,
            "getNaughty(address)",
            "getNaughty(address addr)"
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        Rule memory rule2;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule1.placeHolders[1].pType = ParamTypes.UINT;
        rule1.placeHolders[1].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        // We don't want this one to trigger the revert effect, we want both rules to be captured in the gas test
        // forcing this rule to fail
        rule1.instructionSet = new uint256[](7);
        rule1.instructionSet[0] = uint(LogicalOp.PLH);
        rule1.instructionSet[1] = 0;
        rule1.instructionSet[2] = uint(LogicalOp.NUM);
        rule1.instructionSet[3] = 0;
        rule1.instructionSet[4] = uint(LogicalOp.EQ);
        rule1.instructionSet[5] = 0;
        rule1.instructionSet[6] = 1;

        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule1, ruleName, ruleDescription);
        rule2 = _createGTRule(4);
        // Swapping from posEffect to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule2.negEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule2, ruleName, ruleDescription);

        ruleIds.push(new uint256[](2));
        ruleIds[0][0] = ruleId1;
        ruleIds[0][1] = ruleId2;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractFCPlusMin), policyIds);
    }

    function setupRulesWithForeignCallPlusMinTransferAndMaxTransferInOneRule(
        address _contractAddress,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyIds[0],
            fc,
            "getNaughty(address)",
            "getNaughty(address addr)"
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule1.placeHolders[1].pType = ParamTypes.UINT;
        rule1.placeHolders[1].typeSpecificIndex = 1;

        rule1.instructionSet = new uint256[](17);
        rule1.instructionSet[0] = uint(LogicalOp.PLH);
        rule1.instructionSet[1] = 0; // register 0
        rule1.instructionSet[2] = uint(LogicalOp.NUM);
        rule1.instructionSet[3] = 1; // register 1
        rule1.instructionSet[4] = uint(LogicalOp.EQ);
        rule1.instructionSet[5] = 0;
        rule1.instructionSet[6] = 1; // register 2
        rule1.instructionSet[7] = uint(LogicalOp.PLH);
        rule1.instructionSet[8] = 1; // register 3
        rule1.instructionSet[9] = uint(LogicalOp.NUM);
        rule1.instructionSet[10] = 4; // register 4
        rule1.instructionSet[11] = uint(LogicalOp.GT);
        rule1.instructionSet[12] = 3;
        rule1.instructionSet[13] = 4; // register 5
        rule1.instructionSet[14] = uint256(LogicalOp.AND);
        rule1.instructionSet[15] = 2;
        rule1.instructionSet[16] = 5;
        // Swapping isPositive to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule1, ruleName, ruleDescription);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId1;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractFCPlusMinPlusMaxOneRule), policyIds);
    }

    function setupRulesWithForeignCallAndMinTransferSeparatePolicies(
        address _contractAddress,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](2);

        policyIds[0] = _createBlankPolicy();
        policyIds[1] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        _addCallingFunctionToPolicy(policyIds[1]);
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyIds[0],
            fc,
            "getNaughty(address)",
            "getNaughty(address addr)"
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        Rule memory rule2;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule1.placeHolders[1].pType = ParamTypes.UINT;
        rule1.placeHolders[1].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        // We don't want this one to trigger the revert effect, we want both rules to be captured in the gas test
        // forcing this rule to fail
        rule1.instructionSet = new uint256[](7);
        rule1.instructionSet[0] = uint(LogicalOp.PLH);
        rule1.instructionSet[1] = 0;
        rule1.instructionSet[2] = uint(LogicalOp.NUM);
        rule1.instructionSet[3] = 0;
        rule1.instructionSet[4] = uint(LogicalOp.EQ);
        rule1.instructionSet[5] = 0;
        rule1.instructionSet[6] = 1;
        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule1, ruleName, ruleDescription);
        rule2 = _createGTRule(4);
        // Swapping from posEffects to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule2.negEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule2, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId1;

        bytes4[] memory callingFunctionsNew = new bytes4[](1);
        callingFunctionsNew[0] = bytes4(keccak256(bytes(callingFunction)));
        // ruleIds[0][1] = ruleId2;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctionsNew,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        // Add rules for the second policy
        ruleId1 = RulesEngineRuleFacet(address(red)).createRule(policyIds[1], rule1, ruleName, ruleDescription);
        ruleId2 = RulesEngineRuleFacet(address(red)).createRule(policyIds[1], rule2, ruleName, ruleDescription);
        ruleIds[0][0] = ruleId2;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[1],
            callingFunctionsNew,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractFCPlusMinSeparatePolicy), policyIds);
    }

    function setupRulesWithForeignCallPlusMinTransferAndMaxTransfer(
        address _contractAddress,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId;
        {
            foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
                policyIds[0],
                fc,
                "getNaughty(address)",
                "getNaughty(address addr)"
            );
        }

        {
            // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
            Rule memory rule1;
            Rule memory rule2;
            Rule memory rule3;
            // Build the foreign call placeholder
            rule1.placeHolders = new Placeholder[](2);
            rule1.placeHolders[0].flags = FLAG_FOREIGN_CALL;
            rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
            rule1.placeHolders[1].pType = ParamTypes.UINT;
            rule1.placeHolders[1].typeSpecificIndex = 1;
            // Build the instruction set for the rule (including placeholders)
            // We don't want this one to trigger the revert effect, we want both rules to be captured in the gas test
            // forcing this rule to fail
            rule1.instructionSet = new uint256[](7);
            rule1.instructionSet[0] = uint(LogicalOp.PLH);
            rule1.instructionSet[1] = 0;
            rule1.instructionSet[2] = uint(LogicalOp.NUM);
            rule1.instructionSet[3] = 0;
            rule1.instructionSet[4] = uint(LogicalOp.EQ);
            rule1.instructionSet[5] = 0;
            rule1.instructionSet[6] = 1;
            rule1 = _setUpEffect(rule1, _effectType, isPositive);
            // Save the rule
            uint256 ruleId1 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule1, ruleName, ruleDescription);
            rule2 = _createGTRule(4);
            rule3 = _createLTRule();
            rule2.posEffects[0] = effectId_revert;
            // Swapping from posEffect to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
            rule3.negEffects[0] = effectId_revert;
            uint256 ruleId2 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule2, ruleName, ruleDescription);
            uint256 ruleId3 = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule3, ruleName, ruleDescription);
            ruleIds.push(new uint256[](3));
            ruleIds[0][0] = ruleId1;
            ruleIds[0][1] = ruleId2;
            ruleIds[0][2] = ruleId3;
            _addRuleIdsToPolicy(policyIds[0], ruleIds);
        }

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractFCPlusMinPlusMax), policyIds);
    }

    function _setupRuleWithRevertManyCondition() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(4);
        Rule memory rule;
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](194);
        rule.instructionSet[0] = uint(LogicalOp.PLH); // register 0
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM); // register 1
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LogicalOp.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.instructionSet[7] = uint(LogicalOp.PLH); // register 3
        rule.instructionSet[8] = 0;
        rule.instructionSet[9] = uint(LogicalOp.NUM); // register 4
        rule.instructionSet[10] = 4;
        rule.instructionSet[11] = uint(LogicalOp.GT); // register 5
        rule.instructionSet[12] = 3;
        rule.instructionSet[13] = 4;

        rule.instructionSet[14] = uint(LogicalOp.PLH); // register 6
        rule.instructionSet[15] = 0;
        rule.instructionSet[16] = uint(LogicalOp.NUM); // register 7
        rule.instructionSet[17] = 4;
        rule.instructionSet[18] = uint(LogicalOp.GT); // register 8
        rule.instructionSet[19] = 6;
        rule.instructionSet[20] = 7;

        rule.instructionSet[21] = uint(LogicalOp.PLH); // register 9
        rule.instructionSet[22] = 0;
        rule.instructionSet[23] = uint(LogicalOp.NUM); // register 10
        rule.instructionSet[24] = 4;
        rule.instructionSet[25] = uint(LogicalOp.GT); // register 11
        rule.instructionSet[26] = 9;
        rule.instructionSet[27] = 10;

        rule.instructionSet[28] = uint(LogicalOp.PLH); // register 12
        rule.instructionSet[29] = 0;
        rule.instructionSet[30] = uint(LogicalOp.NUM); // register 13
        rule.instructionSet[31] = 4;
        rule.instructionSet[32] = uint(LogicalOp.GT); // register 14
        rule.instructionSet[33] = 12;
        rule.instructionSet[34] = 13;

        rule.instructionSet[35] = uint(LogicalOp.PLH); // register 15
        rule.instructionSet[36] = 0;
        rule.instructionSet[37] = uint(LogicalOp.NUM); // register 16
        rule.instructionSet[38] = 4;
        rule.instructionSet[39] = uint(LogicalOp.GT); // register 17
        rule.instructionSet[40] = 15;
        rule.instructionSet[41] = 16;

        rule.instructionSet[42] = uint(LogicalOp.PLH); // register 18
        rule.instructionSet[43] = 0;
        rule.instructionSet[44] = uint(LogicalOp.NUM); // register 19
        rule.instructionSet[45] = 4;
        rule.instructionSet[46] = uint(LogicalOp.GT); // register 20
        rule.instructionSet[47] = 18;
        rule.instructionSet[48] = 19;

        rule.instructionSet[49] = uint(LogicalOp.PLH); // register 21
        rule.instructionSet[50] = 0;
        rule.instructionSet[51] = uint(LogicalOp.NUM); // register 22
        rule.instructionSet[52] = 4;
        rule.instructionSet[53] = uint(LogicalOp.GT); // register 23
        rule.instructionSet[54] = 21;
        rule.instructionSet[55] = 22;

        rule.instructionSet[56] = uint(LogicalOp.PLH); // register 24
        rule.instructionSet[57] = 0;
        rule.instructionSet[58] = uint(LogicalOp.NUM); // register 25
        rule.instructionSet[59] = 4;
        rule.instructionSet[60] = uint(LogicalOp.GT); // register 26
        rule.instructionSet[61] = 24;
        rule.instructionSet[62] = 25;

        rule.instructionSet[63] = uint(LogicalOp.PLH); // register 27
        rule.instructionSet[64] = 0;
        rule.instructionSet[65] = uint(LogicalOp.NUM); // register 28
        rule.instructionSet[66] = 4;
        rule.instructionSet[67] = uint(LogicalOp.GT); // register 29
        rule.instructionSet[68] = 27;
        rule.instructionSet[69] = 28;

        rule.instructionSet[70] = uint(LogicalOp.PLH); // register 30
        rule.instructionSet[71] = 0;
        rule.instructionSet[72] = uint(LogicalOp.NUM); // register 31
        rule.instructionSet[73] = 4;
        rule.instructionSet[74] = uint(LogicalOp.GT); // register 32
        rule.instructionSet[75] = 30;
        rule.instructionSet[76] = 31;

        rule.instructionSet[77] = uint(LogicalOp.PLH); // register 33
        rule.instructionSet[78] = 0;
        rule.instructionSet[79] = uint(LogicalOp.NUM); // register 34
        rule.instructionSet[80] = 4;
        rule.instructionSet[81] = uint(LogicalOp.GT); // register 35
        rule.instructionSet[82] = 33;
        rule.instructionSet[83] = 34;

        rule.instructionSet[84] = uint(LogicalOp.PLH); // register 36
        rule.instructionSet[85] = 0;
        rule.instructionSet[86] = uint(LogicalOp.NUM); // register 37
        rule.instructionSet[87] = 4;
        rule.instructionSet[88] = uint(LogicalOp.GT); // register 38
        rule.instructionSet[89] = 36;
        rule.instructionSet[90] = 37;

        rule.instructionSet[91] = uint(LogicalOp.PLH); // register 39
        rule.instructionSet[92] = 0;
        rule.instructionSet[93] = uint(LogicalOp.NUM); // register 40
        rule.instructionSet[94] = 4;
        rule.instructionSet[95] = uint(LogicalOp.GT); // register 41
        rule.instructionSet[96] = 39;
        rule.instructionSet[97] = 40;

        rule.instructionSet[98] = uint(LogicalOp.PLH); // register 42
        rule.instructionSet[99] = 0;
        rule.instructionSet[100] = uint(LogicalOp.NUM); // register 43
        rule.instructionSet[101] = 4;
        rule.instructionSet[102] = uint(LogicalOp.GT); // register 44
        rule.instructionSet[103] = 42;
        rule.instructionSet[104] = 43;

        rule.instructionSet[105] = uint(LogicalOp.PLH); // register 45
        rule.instructionSet[106] = 0;
        rule.instructionSet[107] = uint(LogicalOp.NUM); // register 46
        rule.instructionSet[108] = 4;
        rule.instructionSet[109] = uint(LogicalOp.GT); // register 47
        rule.instructionSet[110] = 45;
        rule.instructionSet[111] = 46;

        rule.instructionSet[112] = uint(LogicalOp.PLH); // register 48
        rule.instructionSet[113] = 0;
        rule.instructionSet[114] = uint(LogicalOp.NUM); // register 49
        rule.instructionSet[115] = 4;
        rule.instructionSet[116] = uint(LogicalOp.GT); // register 50
        rule.instructionSet[117] = 48;
        rule.instructionSet[118] = 49;

        rule.instructionSet[119] = uint(LogicalOp.PLH); // register 51
        rule.instructionSet[120] = 0;
        rule.instructionSet[121] = uint(LogicalOp.NUM); // register 52
        rule.instructionSet[122] = 4;
        rule.instructionSet[123] = uint(LogicalOp.GT); // register 53
        rule.instructionSet[124] = 51;
        rule.instructionSet[125] = 52;

        rule.instructionSet[126] = uint(LogicalOp.PLH); // register 54
        rule.instructionSet[127] = 0;
        rule.instructionSet[128] = uint(LogicalOp.NUM); // register 55
        rule.instructionSet[129] = 4;
        rule.instructionSet[130] = uint(LogicalOp.GT); // register 56
        rule.instructionSet[131] = 54;
        rule.instructionSet[132] = 55;

        rule.instructionSet[133] = uint(LogicalOp.PLH); // register 57
        rule.instructionSet[134] = 0;
        rule.instructionSet[135] = uint(LogicalOp.NUM); // register 58
        rule.instructionSet[136] = 4;
        rule.instructionSet[137] = uint(LogicalOp.GT); // register 59
        rule.instructionSet[138] = 56;
        rule.instructionSet[139] = 57;

        rule.instructionSet[140] = uint(LogicalOp.AND); // register 60
        rule.instructionSet[141] = 2;
        rule.instructionSet[142] = 5;

        rule.instructionSet[140] = uint(LogicalOp.AND); // register 61
        rule.instructionSet[141] = 60;
        rule.instructionSet[142] = 8;

        rule.instructionSet[143] = uint(LogicalOp.AND); // register 62
        rule.instructionSet[144] = 61;
        rule.instructionSet[145] = 11;

        rule.instructionSet[146] = uint(LogicalOp.AND); // register 63
        rule.instructionSet[147] = 62;
        rule.instructionSet[148] = 14;

        rule.instructionSet[149] = uint(LogicalOp.AND); // register 64
        rule.instructionSet[150] = 63;
        rule.instructionSet[151] = 17;

        rule.instructionSet[152] = uint(LogicalOp.AND); // register 65
        rule.instructionSet[153] = 64;
        rule.instructionSet[154] = 20;

        rule.instructionSet[155] = uint(LogicalOp.AND); // register 66
        rule.instructionSet[156] = 65;
        rule.instructionSet[157] = 23;

        rule.instructionSet[158] = uint(LogicalOp.AND); // register 67
        rule.instructionSet[159] = 66;
        rule.instructionSet[160] = 26;

        rule.instructionSet[161] = uint(LogicalOp.AND); // register 68
        rule.instructionSet[162] = 67;
        rule.instructionSet[163] = 29;

        rule.instructionSet[164] = uint(LogicalOp.AND); // register 69
        rule.instructionSet[165] = 68;
        rule.instructionSet[166] = 32;

        rule.instructionSet[167] = uint(LogicalOp.AND); // register 70
        rule.instructionSet[168] = 69;
        rule.instructionSet[169] = 35;

        rule.instructionSet[170] = uint(LogicalOp.AND); // register 71
        rule.instructionSet[171] = 70;
        rule.instructionSet[172] = 38;

        rule.instructionSet[173] = uint(LogicalOp.AND); // register 72
        rule.instructionSet[174] = 71;
        rule.instructionSet[175] = 41;

        rule.instructionSet[176] = uint(LogicalOp.AND); // register 73
        rule.instructionSet[177] = 72;
        rule.instructionSet[178] = 44;

        rule.instructionSet[179] = uint(LogicalOp.AND); // register 74
        rule.instructionSet[180] = 73;
        rule.instructionSet[181] = 47;

        rule.instructionSet[182] = uint(LogicalOp.AND); // register 75
        rule.instructionSet[183] = 74;
        rule.instructionSet[184] = 50;

        rule.instructionSet[185] = uint(LogicalOp.AND); // register 76
        rule.instructionSet[186] = 75;
        rule.instructionSet[187] = 53;

        rule.instructionSet[188] = uint(LogicalOp.AND); // register 77
        rule.instructionSet[189] = 76;
        rule.instructionSet[190] = 56;

        rule.instructionSet[191] = uint(LogicalOp.AND); // register 78
        rule.instructionSet[192] = 77;
        rule.instructionSet[193] = 59;

        rule.posEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractManyChecksMin), policyIds);
    }

    function _setupRuleWithEventParamsMinTransfer(
        bytes memory param,
        ParamTypes pType
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(4);
        Rule memory rule;
        effectId_event = _createCustomEffectEvent(param, pType);
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

    function setupRuleWithOracleFlexForeignCall(
        address _contractAddress,
        EffectTypes _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;

        _addCallingFunctionToPolicy(policyIds[0]);
        // There is no reason to incorporate a toggle like the oracle flex rule in V1
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.BOOL;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyIds[0],
            fc,
            "getNaughty(address)",
            "getNaughty(address addr)"
        );

        // Add additional check for second address
        ForeignCall memory newfc;
        newfc.encodedIndices = new ForeignCallEncodedIndex[](1);
        newfc.encodedIndices[0].index = 2;
        newfc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        newfc.parameterTypes = fcArgs;
        newfc.foreignCallAddress = _contractAddress;
        newfc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        newfc.returnType = ParamTypes.BOOL;
        newfc.foreignCallIndex = 1;
        uint256 foreignCallId2 = RulesEngineForeignCallFacet(address(red)).createForeignCall(
            policyIds[0],
            newfc,
            "getNaughty(address)",
            "getNaughty(address addr)"
        );

        // Rule: FC:OFAClist(address) > bool -> revert -> transfer(address _to, uint256 amount) returns (bool)
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](4);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[2].typeSpecificIndex = uint128(foreignCallId2);
        rule.placeHolders[3].pType = ParamTypes.UINT;
        rule.placeHolders[3].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](14);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.instructionSet[7] = uint(LogicalOp.PLH);
        rule.instructionSet[8] = 3; //plh 3
        rule.instructionSet[9] = uint(LogicalOp.NUM);
        rule.instructionSet[10] = 3; // register 3
        rule.instructionSet[11] = uint(LogicalOp.EQ);
        rule.instructionSet[12] = 3;
        rule.instructionSet[13] = 3;

        // Swapping isPositive to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule = _setUpEffect(rule, _effectType, !isPositive);
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractOracleFlex), policyIds);
    }

    function setUpRuleWithPauseTrackers() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;

        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,address,uint256)")))),
            pTypes,
            "transferFrom(address,address,uint256)",
            "address,address,uint256"
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes("transferFrom(address,address,uint256)"))));
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        // Rule:uintTracker BlockTime > currentBlockTime -> revert -> transfer(address _to, uint256 amount) returns (bool)
        Rule memory rule;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LogicalOp.PLH);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.LT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 5;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(1000000000);
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName", TrackerArrayTypes.VOID);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractPause), policyIds);
    }

    function setUpRuleWithMinMaxBalanceLimits() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;

        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("func(address,uint256)")))),
            pTypes,
            "func(address,uint256)",
            "address,uint256"
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes("func(address,uint256)"))));
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        // Rule:balanceOf(to) - amount < ruleMin -> balanceOf(from) + amount > ruleMax -> revert -> transfer(address _to, uint256 amount) returns (bool)
        Rule memory rule;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.instructionSet = new uint256[](22);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; //register 0
        rule.instructionSet[2] = uint(LogicalOp.PLH);
        rule.instructionSet[3] = 1; //register 1
        rule.instructionSet[4] = uint(LogicalOp.SUB);
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = 0; //register 2 (balance to - amount)
        rule.instructionSet[7] = uint(LogicalOp.NUM);
        rule.instructionSet[8] = 1; // register 3 (rule min balance)
        rule.instructionSet[9] = uint(LogicalOp.LT);
        rule.instructionSet[10] = 3;
        rule.instructionSet[11] = 2; // check that amount + balanceOf to > 10
        rule.instructionSet[12] = uint(LogicalOp.PLH);
        rule.instructionSet[13] = 1; //register 5
        rule.instructionSet[14] = uint(LogicalOp.ADD);
        rule.instructionSet[15] = 5;
        rule.instructionSet[16] = 0; //register 6 (amount + balance to)
        rule.instructionSet[17] = uint(LogicalOp.NUM);
        rule.instructionSet[18] = 10; // register 7 (rule max balance)
        rule.instructionSet[19] = uint(LogicalOp.GT);
        rule.instructionSet[20] = 6;
        rule.instructionSet[21] = 7; // check that amount + balanceOf to > 10

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1; // amount
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 3; // balance from
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 4; // balance to

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContractMinMaxBalance), policyIds);
    }

    /**********  Rule Setup Helpers **********/
    function _exampleContractGasReport(uint256 _amount, address contractAddress, string memory _label) public {
        startMeasuringGas(_label);
        ExampleERC20(contractAddress).transfer(address(0x7654321), _amount);
        gasUsed = stopMeasuringGas();
        console.log(_label, gasUsed);
    }
}
