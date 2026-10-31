// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {RedactionRegistry} from "../src/RedactionRegistry.sol";

contract RedactionRegistryTest is Test {
    RedactionRegistry internal registry;
    bytes32 internal constant DOC = keccak256("redacted-output");
    bytes32 internal constant REPORT = keccak256("report-projection");

    function setUp() public {
        registry = new RedactionRegistry(address(this));
    }

    function test_onReportStoresAndEmits() public {
        bytes memory payload = abi.encode(DOC, REPORT, uint8(2), uint64(1_762_000_000));
        vm.expectEmit(true, false, false, true);
        emit RedactionRegistry.RedactionAttested(DOC, REPORT, 2, 1_762_000_000);
        registry.onReport("", payload);

        (bytes32 reportHash, uint8 riskLevel, uint64 ts, uint64 blockTime) = registry.getAttestation(DOC);
        assertEq(reportHash, REPORT);
        assertEq(riskLevel, 2);
        assertEq(ts, 1_762_000_000);
        assertGt(blockTime, 0);
    }

    function test_rejectsACallerThatIsNotTheForwarder() public {
        RedactionRegistry locked = new RedactionRegistry(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(RedactionRegistry.InvalidSender.selector, address(this)));
        locked.onReport("", abi.encode(DOC, REPORT, uint8(1), uint64(1)));
    }

    function test_rejectsAnOutOfRangeRiskLevel() public {
        vm.expectRevert(abi.encodeWithSelector(RedactionRegistry.InvalidRiskLevel.selector, uint8(4)));
        registry.onReport("", abi.encode(DOC, REPORT, uint8(4), uint64(1)));
    }

    function test_missingDocHashReadsAsEmpty() public view {
        (bytes32 reportHash, uint8 riskLevel, uint64 ts, uint64 blockTime) =
            registry.getAttestation(keccak256("absent"));
        assertEq(reportHash, bytes32(0));
        assertEq(riskLevel, 0);
        assertEq(ts, 0);
        assertEq(blockTime, 0);
    }
}
