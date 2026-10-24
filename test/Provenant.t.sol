// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Provenant} from "../src/Provenant.sol";

contract ProvenantTest is Test {
    Provenant internal provenant;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal stranger = makeAddr("stranger");

    bytes32 internal constant SALT = bytes32(bytes16(0x0123456789abcdef0123456789abcdef));
    bytes32 internal constant HASH_V1 = keccak256("manifest-v1");
    bytes32 internal constant HASH_V2 = keccak256("manifest-v2");
    bytes32 internal constant EVENT_ID = bytes32(bytes16(0xfedcba9876543210fedcba9876543210));
    bytes32 internal constant EVENT_TYPE = keccak256("RELEASE_PUBLISHED");
    bytes32 internal constant EVENT_HASH = keccak256("event-body");

    bytes32 internal projectId;

    function setUp() public {
        provenant = new Provenant();
        vm.prank(owner);
        projectId = provenant.createProject(SALT, "Provenant", 1, HASH_V1);
    }

    // ---------------------------------------------------------------------
    // createProject
    // ---------------------------------------------------------------------

    function test_CreateProject_StoresProjectAndManifest() public view {
        Provenant.Project memory p = provenant.getProject(projectId);
        assertEq(p.name, "Provenant");
        assertEq(p.owner, owner);
        assertEq(p.pendingOwner, address(0));
        assertEq(p.currentVersion, 1);
        assertEq(uint8(p.status), uint8(Provenant.ProjectStatus.Active));
        assertTrue(p.exists);

        (bytes32 hash, uint64 ts) = provenant.getManifest(projectId, 1);
        assertEq(hash, HASH_V1);
        assertEq(ts, block.timestamp);

        assertEq(provenant.getMaintainers(projectId).length, 0);
    }

    function test_CreateProject_ReturnsComputedIdAndEmits() public {
        bytes32 salt = bytes32(uint256(42));
        bytes32 expectedId = provenant.computeProjectId(alice, salt);

        vm.expectEmit(address(provenant));
        emit Provenant.ProjectCreated(expectedId, alice, salt, "Other", 7, HASH_V1);

        vm.prank(alice);
        assertEq(provenant.createProject(salt, "Other", 7, HASH_V1), expectedId);
    }

    /// The ID is bound to the creator, so copying someone's salt (e.g. by
    /// front-running) yields a different project, not a hijack.
    function test_CreateProject_SameSaltDifferentCreatorIsIndependent() public {
        vm.prank(stranger);
        bytes32 copyId = provenant.createProject(SALT, "Squatter", 1, HASH_V2);

        assertTrue(copyId != projectId);
        assertEq(provenant.getProject(projectId).owner, owner);
        assertEq(provenant.getProject(copyId).owner, stranger);
    }

    function test_CreateProject_RevertsOnDuplicate() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.ProjectAlreadyExists.selector);
        provenant.createProject(SALT, "Again", 2, HASH_V2);
    }

    function test_CreateProject_RevertsOnInvalidInput() public {
        bytes32 salt = bytes32(uint256(1));
        vm.startPrank(alice);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(bytes32(0), "Name", 1, HASH_V1);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(salt, "Name", 0, HASH_V1);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(salt, "Name", 1, bytes32(0));

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(salt, "", 1, HASH_V1);

        vm.stopPrank();
    }

    function test_CreateProject_NameLengthBoundary() public {
        uint256 max = provenant.MAX_NAME_LENGTH();

        vm.startPrank(alice);
        provenant.createProject(bytes32(uint256(1)), _repeat("a", max), 1, HASH_V1);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(bytes32(uint256(2)), _repeat("a", max + 1), 1, HASH_V1);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------
    // updateProject
    // ---------------------------------------------------------------------

    function test_UpdateProject_AllowsVersionGapsAndKeepsHistory() public {
        vm.warp(1_000);
        vm.expectEmit(address(provenant));
        emit Provenant.ProjectUpdated(projectId, 5, HASH_V2, owner);

        vm.prank(owner);
        provenant.updateProject(projectId, 5, HASH_V2);

        assertEq(provenant.getProject(projectId).currentVersion, 5);

        (bytes32 h1,) = provenant.getManifest(projectId, 1);
        (bytes32 h5, uint64 ts5) = provenant.getManifest(projectId, 5);
        assertEq(h1, HASH_V1);
        assertEq(h5, HASH_V2);
        assertEq(ts5, 1_000);

        // Skipped versions were never anchored.
        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.getManifest(projectId, 3);
    }

    function test_UpdateProject_RevertsOnStaleOrDuplicateVersion() public {
        vm.startPrank(owner);
        provenant.updateProject(projectId, 3, HASH_V2);

        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.updateProject(projectId, 3, keccak256("dup"));

        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.updateProject(projectId, 2, keccak256("stale"));
        vm.stopPrank();

        // A rejected update must not overwrite the existing anchor.
        (bytes32 h3,) = provenant.getManifest(projectId, 3);
        assertEq(h3, HASH_V2);
    }

    function test_UpdateProject_RevertsOnZeroHash() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.updateProject(projectId, 2, bytes32(0));
    }

    function test_UpdateProject_MaintainerCanPublish() public {
        _addMaintainer(alice);

        vm.prank(alice);
        provenant.updateProject(projectId, 2, HASH_V2);
        assertEq(provenant.getProject(projectId).currentVersion, 2);
    }

    function test_UpdateProject_RevertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.updateProject(projectId, 2, HASH_V2);
    }

    function test_UpdateProject_RevertsForUnknownProject() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.updateProject(keccak256("nope"), 2, HASH_V2);
    }

    // ---------------------------------------------------------------------
    // Maintainers
    // ---------------------------------------------------------------------

    function test_AddMaintainer_UpdatesStateAndEmits() public {
        vm.expectEmit(address(provenant));
        emit Provenant.MaintainerUpdated(projectId, alice, true);
        _addMaintainer(alice);

        assertTrue(provenant.isMaintainer(projectId, alice));
        address[] memory list = provenant.getMaintainers(projectId);
        assertEq(list.length, 1);
        assertEq(list[0], alice);
    }

    function test_AddMaintainer_RevertsOnInvalidTargets() public {
        vm.startPrank(owner);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.addMaintainer(projectId, address(0));

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.addMaintainer(projectId, owner);

        provenant.addMaintainer(projectId, alice);
        vm.expectRevert(Provenant.MaintainerAlreadyExists.selector);
        provenant.addMaintainer(projectId, alice);

        vm.stopPrank();
    }

    /// Maintainers can publish but must not be able to manage the project.
    function test_Maintainer_CannotPerformOwnerActions() public {
        _addMaintainer(alice);
        vm.startPrank(alice);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.addMaintainer(projectId, bob);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.removeMaintainer(projectId, alice);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.transferOwnership(projectId, alice);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);

        vm.stopPrank();
    }

    /// Swap-and-pop: removing a middle entry moves the last one into its
    /// slot. Removing the moved entry afterwards proves its index was updated.
    function test_RemoveMaintainer_SwapAndPopKeepsIndexConsistent() public {
        _addMaintainer(alice);
        _addMaintainer(bob);
        _addMaintainer(carol);

        vm.expectEmit(address(provenant));
        emit Provenant.MaintainerUpdated(projectId, alice, false);
        vm.prank(owner);
        provenant.removeMaintainer(projectId, alice);

        address[] memory list = provenant.getMaintainers(projectId);
        assertEq(list.length, 2);
        assertEq(list[0], carol);
        assertEq(list[1], bob);
        assertFalse(provenant.isMaintainer(projectId, alice));

        vm.prank(owner);
        provenant.removeMaintainer(projectId, carol);

        list = provenant.getMaintainers(projectId);
        assertEq(list.length, 1);
        assertEq(list[0], bob);
        assertTrue(provenant.isMaintainer(projectId, bob));

        // Removed addresses can be re-added cleanly.
        _addMaintainer(alice);
        assertEq(provenant.getMaintainers(projectId).length, 2);
    }

    function test_RemoveMaintainer_RevertsWhenNotMaintainer() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.MaintainerNotFound.selector);
        provenant.removeMaintainer(projectId, alice);
    }

    function test_RemovedMaintainer_LosesRightsButHistoryRemains() public {
        _addMaintainer(alice);

        vm.prank(alice);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        vm.prank(owner);
        provenant.removeMaintainer(projectId, alice);

        vm.prank(alice);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.updateProject(projectId, 2, HASH_V2);

        (,, address submittedBy,) = provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(submittedBy, alice);
    }

    /// Maintainer rights are scoped per project.
    function test_Maintainer_IsScopedToProject() public {
        _addMaintainer(alice);

        vm.prank(bob);
        bytes32 otherId = provenant.createProject(SALT, "Bob's", 1, HASH_V1);

        vm.prank(alice);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.updateProject(otherId, 2, HASH_V2);
    }

    // ---------------------------------------------------------------------
    // Ownership
    // ---------------------------------------------------------------------

    function test_Ownership_TwoStepTransfer() public {
        vm.expectEmit(address(provenant));
        emit Provenant.OwnershipTransferStarted(projectId, owner, alice);
        vm.prank(owner);
        provenant.transferOwnership(projectId, alice);

        // Nothing changes until accepted.
        assertEq(provenant.getProject(projectId).owner, owner);
        assertEq(provenant.getProject(projectId).pendingOwner, alice);

        vm.expectEmit(address(provenant));
        emit Provenant.OwnershipTransferred(projectId, owner, alice);
        vm.prank(alice);
        provenant.acceptOwnership(projectId);

        Provenant.Project memory p = provenant.getProject(projectId);
        assertEq(p.owner, alice);
        assertEq(p.pendingOwner, address(0));

        // Project ID is stable across ownership changes.
        assertEq(projectId, provenant.computeProjectId(owner, SALT));

        // Previous owner keeps no rights.
        vm.startPrank(owner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.updateProject(projectId, 2, HASH_V2);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.addMaintainer(projectId, bob);
        vm.stopPrank();

        // New owner has full rights.
        vm.prank(alice);
        provenant.updateProject(projectId, 2, HASH_V2);
    }

    function test_TransferOwnership_RevertsOnInvalidTarget() public {
        vm.startPrank(owner);
        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.transferOwnership(projectId, address(0));

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.transferOwnership(projectId, owner);
        vm.stopPrank();
    }

    function test_TransferOwnership_RevertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.transferOwnership(projectId, stranger);
    }

    function test_AcceptOwnership_OnlyPendingOwner() public {
        // No pending transfer: nobody can accept.
        vm.prank(alice);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);

        vm.prank(owner);
        provenant.transferOwnership(projectId, alice);

        vm.prank(stranger);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);

        // The current owner cannot short-circuit the handshake either.
        vm.prank(owner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);
    }

    function test_AcceptOwnership_CannotBeReplayed() public {
        vm.prank(owner);
        provenant.transferOwnership(projectId, alice);
        vm.prank(alice);
        provenant.acceptOwnership(projectId);

        vm.prank(alice);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);
    }

    function test_TransferOwnership_SecondCallReplacesPendingOwner() public {
        vm.startPrank(owner);
        provenant.transferOwnership(projectId, alice);
        provenant.transferOwnership(projectId, bob);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);

        vm.prank(bob);
        provenant.acceptOwnership(projectId);
        assertEq(provenant.getProject(projectId).owner, bob);
    }

    /// A maintainer promoted to owner is removed from the maintainer list,
    /// and the list stays consistent for the remaining maintainers.
    function test_AcceptOwnership_RemovesNewOwnerFromMaintainers() public {
        _addMaintainer(alice);
        _addMaintainer(bob);
        _addMaintainer(carol);

        vm.prank(owner);
        provenant.transferOwnership(projectId, alice);

        vm.expectEmit(address(provenant));
        emit Provenant.MaintainerUpdated(projectId, alice, false);
        vm.prank(alice);
        provenant.acceptOwnership(projectId);

        assertFalse(provenant.isMaintainer(projectId, alice));
        address[] memory list = provenant.getMaintainers(projectId);
        assertEq(list.length, 2);
        assertEq(list[0], carol);
        assertEq(list[1], bob);

        // carol was swapped into index 0; removing her must still work.
        vm.prank(alice);
        provenant.removeMaintainer(projectId, carol);
        assertEq(provenant.getMaintainers(projectId).length, 1);
    }

    // ---------------------------------------------------------------------
    // Status
    // ---------------------------------------------------------------------

    function test_Archive_BlocksPublishingButKeepsHistory() public {
        _addMaintainer(alice);

        vm.expectEmit(address(provenant));
        emit Provenant.ProjectStatusChanged(projectId, Provenant.ProjectStatus.Archived, owner);
        vm.prank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);

        vm.prank(owner);
        vm.expectRevert(Provenant.InvalidStatus.selector);
        provenant.updateProject(projectId, 2, HASH_V2);

        vm.prank(alice);
        vm.expectRevert(Provenant.InvalidStatus.selector);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        (bytes32 h1,) = provenant.getManifest(projectId, 1);
        assertEq(h1, HASH_V1);
    }

    function test_Archive_StillAllowsAdminActions() public {
        vm.startPrank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);
        provenant.addMaintainer(projectId, alice);
        provenant.removeMaintainer(projectId, alice);
        provenant.transferOwnership(projectId, bob);
        vm.stopPrank();

        vm.prank(bob);
        provenant.acceptOwnership(projectId);
        assertEq(provenant.getProject(projectId).owner, bob);
    }

    function test_Reactivate_RestoresPublishing() public {
        vm.startPrank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Active);
        provenant.updateProject(projectId, 2, HASH_V2);
        vm.stopPrank();

        assertEq(provenant.getProject(projectId).currentVersion, 2);
    }

    function test_SetProjectStatus_RevertsWhenUnchanged() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.InvalidStatus.selector);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Active);
    }

    /// Out-of-range enum values are rejected by the ABI decoder before the
    /// function body runs, so the explicit range check is never reached.
    function test_SetProjectStatus_RejectsOutOfRangeEnum() public {
        vm.prank(owner);
        (bool ok,) = address(provenant).call(
            abi.encodeWithSelector(provenant.setProjectStatus.selector, projectId, uint8(2))
        );
        assertFalse(ok);
        assertEq(uint8(provenant.getProject(projectId).status), uint8(Provenant.ProjectStatus.Active));
    }

    // ---------------------------------------------------------------------
    // anchorEvent
    // ---------------------------------------------------------------------

    function test_AnchorEvent_StoresAndEmits() public {
        vm.warp(5_000);
        vm.expectEmit(address(provenant));
        emit Provenant.ProjectEventAnchored(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH, owner);

        vm.prank(owner);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        (bytes32 eventType, bytes32 contentHash, address submittedBy, uint64 ts) =
            provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(eventType, EVENT_TYPE);
        assertEq(contentHash, EVENT_HASH);
        assertEq(submittedBy, owner);
        assertEq(ts, 5_000);
    }

    function test_AnchorEvent_IsWriteOnce() public {
        vm.startPrank(owner);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        vm.expectRevert(Provenant.EventAlreadyExists.selector);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, keccak256("tampered"));
        vm.stopPrank();

        (, bytes32 contentHash,,) = provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(contentHash, EVENT_HASH);
    }

    /// Event IDs are unique per project, not globally.
    function test_AnchorEvent_SameIdAcrossProjects() public {
        vm.prank(alice);
        bytes32 otherId = provenant.createProject(SALT, "Alice's", 1, HASH_V1);

        vm.prank(owner);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);
        vm.prank(alice);
        provenant.anchorEvent(otherId, EVENT_ID, EVENT_TYPE, keccak256("alice-event"));

        (, bytes32 h1,,) = provenant.getProjectEvent(projectId, EVENT_ID);
        (, bytes32 h2,,) = provenant.getProjectEvent(otherId, EVENT_ID);
        assertEq(h1, EVENT_HASH);
        assertEq(h2, keccak256("alice-event"));
    }

    function test_AnchorEvent_RevertsOnInvalidInput() public {
        vm.startPrank(owner);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.anchorEvent(projectId, bytes32(0), EVENT_TYPE, EVENT_HASH);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.anchorEvent(projectId, EVENT_ID, bytes32(0), EVENT_HASH);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, bytes32(0));

        vm.stopPrank();
    }

    function test_AnchorEvent_RevertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function test_Views_RevertForUnknownProjectOrRecord() public {
        bytes32 unknown = keccak256("unknown");

        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getProject(unknown);

        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getMaintainers(unknown);

        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getManifest(unknown, 1);

        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getProjectEvent(unknown, EVENT_ID);

        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.getManifest(projectId, 2);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.getProjectEvent(projectId, EVENT_ID);
    }

    // ---------------------------------------------------------------------
    // Fuzz
    // ---------------------------------------------------------------------

    /// Random add/remove sequences must keep the enumerable list, the index
    /// map and isMaintainer in sync with a simple reference model.
    function testFuzz_MaintainerSetStaysConsistent(uint8[32] calldata ops) public {
        address[5] memory pool = [alice, bob, carol, stranger, makeAddr("dave")];
        bool[5] memory expected;

        vm.startPrank(owner);
        for (uint256 i = 0; i < ops.length; i++) {
            uint256 who = ops[i] % 5;
            if (expected[who]) {
                provenant.removeMaintainer(projectId, pool[who]);
                expected[who] = false;
            } else {
                provenant.addMaintainer(projectId, pool[who]);
                expected[who] = true;
            }
        }
        vm.stopPrank();

        address[] memory list = provenant.getMaintainers(projectId);
        uint256 expectedCount;
        for (uint256 i = 0; i < 5; i++) {
            assertEq(provenant.isMaintainer(projectId, pool[i]), expected[i]);
            if (expected[i]) {
                expectedCount++;
                assertTrue(_contains(list, pool[i]));
            }
        }
        assertEq(list.length, expectedCount);
    }

    function testFuzz_UpdateProject_VersionMustStrictlyIncrease(uint64 next) public {
        vm.prank(owner);
        provenant.updateProject(projectId, 10, HASH_V2);

        vm.prank(owner);
        if (next <= 10) {
            vm.expectRevert(Provenant.InvalidVersion.selector);
            provenant.updateProject(projectId, next, HASH_V1);
        } else {
            provenant.updateProject(projectId, next, HASH_V1);
            assertEq(provenant.getProject(projectId).currentVersion, next);
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    function _addMaintainer(address who) internal {
        vm.prank(owner);
        provenant.addMaintainer(projectId, who);
    }

    function _contains(address[] memory list, address who) internal pure returns (bool) {
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == who) return true;
        }
        return false;
    }

    function _repeat(string memory s, uint256 n) internal pure returns (string memory out) {
        bytes memory b = new bytes(n);
        bytes1 c = bytes(s)[0];
        for (uint256 i = 0; i < n; i++) {
            b[i] = c;
        }
        out = string(b);
    }
}
