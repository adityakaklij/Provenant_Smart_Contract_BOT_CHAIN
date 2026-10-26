// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, stdError} from "forge-std/Test.sol";
import {Provenant} from "../src/Provenant.sol";

contract ProvenantTest is Test {
    Provenant internal provenant;

    address internal owner = makeAddr("owner");
    address internal maintainer = makeAddr("maintainer");
    address internal newOwner = makeAddr("newOwner");
    address internal stranger = makeAddr("stranger");

    bytes32 internal constant SALT = bytes32(bytes16(0x0123456789abcdef0123456789abcdef));
    bytes32 internal constant MANIFEST_1 = keccak256("manifest-1");
    bytes32 internal constant MANIFEST_2 = keccak256("manifest-2");
    bytes32 internal constant EVENT_ID = bytes32(bytes16(0xfedcba9876543210fedcba9876543210));
    bytes32 internal constant EVENT_TYPE = keccak256("RELEASE_PUBLISHED");
    bytes32 internal constant EVENT_HASH = keccak256("event-body");

    bytes32 internal constant MAX_BYTES32 = bytes32(type(uint256).max);

    bytes32 internal projectId;

    /// Every test starts from: `owner` owns an active project with one
    /// anchored manifest, and `maintainer` is its only maintainer.
    function setUp() public {
        provenant = new Provenant();

        vm.startPrank(owner);
        projectId = provenant.createProject(SALT, "Provenant", MANIFEST_1);
        provenant.addMaintainer(projectId, maintainer);
        vm.stopPrank();
    }

    // =====================================================================
    // Access control
    // =====================================================================

    function test_OwnerOnly_RevertsForMaintainer() public {
        _assertOwnerOnlyReverts(maintainer);
    }

    function test_OwnerOnly_RevertsForStranger() public {
        _assertOwnerOnlyReverts(stranger);
    }

    /// Being nominated grants nothing until the transfer is accepted.
    function test_OwnerOnly_RevertsForPendingOwner() public {
        vm.prank(owner);
        provenant.transferOwnership(projectId, newOwner);

        _assertOwnerOnlyReverts(newOwner);
    }

    function test_Publish_AllowedForOwnerAndMaintainer() public {
        vm.prank(owner);
        provenant.updateProject(projectId, MANIFEST_2);
        vm.prank(owner);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        vm.prank(maintainer);
        provenant.updateProject(projectId, keccak256("manifest-3"));
        vm.prank(maintainer);
        provenant.anchorEvent(projectId, bytes32(uint256(2)), EVENT_TYPE, EVENT_HASH);

        assertEq(provenant.getProject(projectId).anchorCount, 3);
    }

    function test_Publish_RevertsForStranger() public {
        _assertPublishReverts(stranger, Provenant.Unauthorized.selector);
    }

    function test_Publish_RevertsForPendingOwner() public {
        vm.prank(owner);
        provenant.transferOwnership(projectId, newOwner);

        _assertPublishReverts(newOwner, Provenant.Unauthorized.selector);
    }

    function test_Publish_RevertsForRemovedMaintainer() public {
        vm.prank(owner);
        provenant.removeMaintainer(projectId, maintainer);

        _assertPublishReverts(maintainer, Provenant.Unauthorized.selector);
    }

    /// After a transfer the previous owner has no rights of any kind.
    function test_FormerOwner_LosesAllRights() public {
        _transferOwnership(newOwner);

        _assertOwnerOnlyReverts(owner);
        _assertPublishReverts(owner, Provenant.Unauthorized.selector);
    }

    /// Roles are per project: owning or maintaining one project gives no
    /// rights over another.
    function test_Roles_AreScopedPerProject() public {
        vm.prank(stranger);
        bytes32 otherId = provenant.createProject(SALT, "Other", MANIFEST_1);

        vm.startPrank(owner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.addMaintainer(otherId, maintainer);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.updateProject(otherId, MANIFEST_2);
        vm.stopPrank();

        vm.prank(maintainer);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.updateProject(otherId, MANIFEST_2);
    }

    function test_AllFunctions_RevertForUnknownProject() public {
        bytes32 unknown = keccak256("unknown");
        vm.startPrank(owner);

        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.updateProject(unknown, MANIFEST_2);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.anchorEvent(unknown, EVENT_ID, EVENT_TYPE, EVENT_HASH);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.addMaintainer(unknown, stranger);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.removeMaintainer(unknown, maintainer);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.transferOwnership(unknown, newOwner);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.cancelOwnershipTransfer(unknown);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.acceptOwnership(unknown);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.setProjectStatus(unknown, Provenant.ProjectStatus.Archived);

        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getProject(unknown);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getMaintainers(unknown);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getManifest(unknown, 1);
        vm.expectRevert(Provenant.ProjectNotFound.selector);
        provenant.getProjectEvent(unknown, EVENT_ID);

        vm.stopPrank();

        // anchorOf is a plain lookup and returns 0 instead of reverting.
        assertEq(provenant.anchorOf(unknown, MANIFEST_1), 0);
    }

    // =====================================================================
    // createProject
    // =====================================================================

    function test_CreateProject_StoresInitialState() public {
        bytes32 salt = bytes32(uint256(42));
        bytes32 expectedId = provenant.computeProjectId(stranger, salt);

        vm.warp(1_000);
        vm.expectEmit(address(provenant));
        emit Provenant.ProjectCreated(expectedId, stranger, salt, "Fresh", MANIFEST_1);

        vm.prank(stranger);
        assertEq(provenant.createProject(salt, "Fresh", MANIFEST_1), expectedId);

        Provenant.Project memory p = provenant.getProject(expectedId);
        assertEq(p.name, "Fresh");
        assertEq(p.owner, stranger);
        assertEq(p.pendingOwner, address(0));
        assertEq(p.anchorCount, 1);
        assertEq(uint8(p.status), uint8(Provenant.ProjectStatus.Active));
        assertTrue(p.exists);

        (bytes32 hash, uint64 ts) = provenant.getManifest(expectedId, 1);
        assertEq(hash, MANIFEST_1);
        assertEq(ts, 1_000);
        assertEq(provenant.anchorOf(expectedId, MANIFEST_1), 1);
        assertEq(provenant.getMaintainers(expectedId).length, 0);
    }

    function test_CreateProject_RevertsOnInvalidInput() public {
        bytes32 salt = bytes32(uint256(1));
        vm.startPrank(stranger);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(bytes32(0), "Name", MANIFEST_1);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(salt, "Name", bytes32(0));

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(salt, "", MANIFEST_1);

        vm.stopPrank();
    }

    function test_CreateProject_RevertsOnDuplicate() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.ProjectAlreadyExists.selector);
        provenant.createProject(SALT, "Again", MANIFEST_2);
    }

    /// The limit counts bytes, not characters: "é" is 2 bytes in UTF-8.
    function test_CreateProject_NameLengthBoundaries() public {
        uint256 max = provenant.MAX_NAME_LENGTH();
        vm.startPrank(stranger);

        provenant.createProject(bytes32(uint256(1)), "a", MANIFEST_1);
        provenant.createProject(bytes32(uint256(2)), _repeat("a", max), MANIFEST_1);
        provenant.createProject(bytes32(uint256(3)), _repeat(unicode"é", max / 2), MANIFEST_1);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(bytes32(uint256(4)), _repeat("a", max + 1), MANIFEST_1);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.createProject(bytes32(uint256(5)), _repeat(unicode"é", max / 2 + 1), MANIFEST_1);

        vm.stopPrank();
    }

    /// All-ones values are as valid as any other non-zero bytes32.
    function test_CreateProject_AcceptsMaxValues() public {
        vm.prank(stranger);
        bytes32 id = provenant.createProject(MAX_BYTES32, "Max", MAX_BYTES32);

        assertEq(id, provenant.computeProjectId(stranger, MAX_BYTES32));
        assertEq(provenant.anchorOf(id, MAX_BYTES32), 1);
    }

    /// The ID is bound to the creator, so copying someone's salt (e.g. by
    /// front-running) creates a separate project instead of taking theirs.
    function testFuzz_CreateProject_IdIsBoundToCreator(address creator, address other, bytes32 salt) public {
        vm.assume(creator != address(0) && creator != other && salt != bytes32(0));
        vm.assume(!(creator == owner && salt == SALT));

        bytes32 expected = provenant.computeProjectId(creator, salt);
        assertEq(expected, keccak256(abi.encode(creator, salt)));
        assertTrue(expected != provenant.computeProjectId(other, salt));

        vm.prank(creator);
        assertEq(provenant.createProject(salt, "Fuzz", MANIFEST_1), expected);
        assertEq(provenant.getProject(expected).owner, creator);
    }

    // =====================================================================
    // updateProject / manifests
    // =====================================================================

    function test_UpdateProject_AssignsNextAnchorAndKeepsHistory() public {
        vm.warp(2_000);
        vm.expectEmit(address(provenant));
        emit Provenant.ProjectUpdated(projectId, 2, MANIFEST_2, maintainer);

        vm.prank(maintainer);
        assertEq(provenant.updateProject(projectId, MANIFEST_2), 2);

        assertEq(provenant.getProject(projectId).anchorCount, 2);
        assertEq(provenant.anchorOf(projectId, MANIFEST_2), 2);

        (bytes32 h1,) = provenant.getManifest(projectId, 1);
        (bytes32 h2, uint64 ts2) = provenant.getManifest(projectId, 2);
        assertEq(h1, MANIFEST_1);
        assertEq(h2, MANIFEST_2);
        assertEq(ts2, 2_000);
    }

    function test_UpdateProject_RevertsOnZeroHash() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.updateProject(projectId, bytes32(0));
    }

    /// A resubmitted manifest (retry, double-click, or a second publisher
    /// sending the same one) is rejected and leaves state untouched.
    function test_UpdateProject_RejectsDuplicateHash() public {
        vm.prank(owner);
        provenant.updateProject(projectId, MANIFEST_2);

        vm.prank(maintainer);
        vm.expectRevert(Provenant.ManifestAlreadyAnchored.selector);
        provenant.updateProject(projectId, MANIFEST_2);

        // The initial manifest counts as anchored too.
        vm.prank(owner);
        vm.expectRevert(Provenant.ManifestAlreadyAnchored.selector);
        provenant.updateProject(projectId, MANIFEST_1);

        assertEq(provenant.getProject(projectId).anchorCount, 2);
        assertEq(provenant.anchorOf(projectId, MANIFEST_2), 2);
    }

    /// Duplicate detection is per project.
    function test_UpdateProject_SameHashAllowedAcrossProjects() public {
        vm.prank(stranger);
        bytes32 otherId = provenant.createProject(SALT, "Other", MANIFEST_2);

        vm.prank(owner);
        provenant.updateProject(projectId, MANIFEST_2);

        assertEq(provenant.anchorOf(projectId, MANIFEST_2), 2);
        assertEq(provenant.anchorOf(otherId, MANIFEST_2), 1);
    }

    function test_GetManifest_RevertsOutsideAnchorRange() public {
        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.getManifest(projectId, 0);

        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.getManifest(projectId, 2);

        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.getManifest(projectId, type(uint64).max);
    }

    /// Unreachable in practice (~1.8e19 anchors), but if anchorCount ever hit
    /// type(uint64).max the update must revert, not wrap to 0.
    function test_UpdateProject_RevertsOnAnchorCountOverflow() public {
        _setAnchorCount(type(uint64).max);

        Provenant.Project memory p = provenant.getProject(projectId);
        assertEq(p.anchorCount, type(uint64).max);
        assertEq(p.owner, owner);
        assertTrue(p.exists);

        vm.prank(owner);
        vm.expectRevert(stdError.arithmeticError);
        provenant.updateProject(projectId, MANIFEST_2);
    }

    /// Every anchor gets exactly the next number, whoever sends it, and
    /// anchorOf maps each hash back to that number.
    function testFuzz_UpdateProject_AnchorNumberIsSequential(uint8 count) public {
        for (uint64 i = 0; i < count; i++) {
            bytes32 hash = keccak256(abi.encode(i));

            vm.prank(i % 2 == 0 ? owner : maintainer);
            assertEq(provenant.updateProject(projectId, hash), i + 2);

            (bytes32 stored,) = provenant.getManifest(projectId, i + 2);
            assertEq(stored, hash);
            assertEq(provenant.anchorOf(projectId, hash), i + 2);
        }

        assertEq(provenant.getProject(projectId).anchorCount, uint64(count) + 1);

        vm.expectRevert(Provenant.InvalidVersion.selector);
        provenant.getManifest(projectId, uint64(count) + 2);
    }

    // =====================================================================
    // Maintainers
    // =====================================================================

    function test_AddMaintainer_UpdatesStateAndEmits() public {
        vm.expectEmit(address(provenant));
        emit Provenant.MaintainerUpdated(projectId, stranger, true);

        vm.prank(owner);
        provenant.addMaintainer(projectId, stranger);

        assertTrue(provenant.isMaintainer(projectId, stranger));
        address[] memory list = provenant.getMaintainers(projectId);
        assertEq(list.length, 2);
        assertEq(list[1], stranger);
    }

    function test_AddMaintainer_RevertsOnInvalidTarget() public {
        vm.startPrank(owner);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.addMaintainer(projectId, address(0));

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.addMaintainer(projectId, owner);

        vm.expectRevert(Provenant.MaintainerAlreadyExists.selector);
        provenant.addMaintainer(projectId, maintainer);

        vm.stopPrank();
    }

    function test_RemoveMaintainer_RevertsWhenNotMaintainer() public {
        vm.startPrank(owner);

        vm.expectRevert(Provenant.MaintainerNotFound.selector);
        provenant.removeMaintainer(projectId, stranger);

        vm.expectRevert(Provenant.MaintainerNotFound.selector);
        provenant.removeMaintainer(projectId, owner);

        provenant.removeMaintainer(projectId, maintainer);
        vm.expectRevert(Provenant.MaintainerNotFound.selector);
        provenant.removeMaintainer(projectId, maintainer);

        vm.stopPrank();
    }

    /// Swap-and-pop: removing a middle entry moves the last one into its
    /// slot. Removing the moved entry afterwards proves its index was updated.
    function test_RemoveMaintainer_SwapAndPopKeepsListConsistent() public {
        address second = makeAddr("second");
        address third = makeAddr("third");

        vm.startPrank(owner);
        provenant.addMaintainer(projectId, second);
        provenant.addMaintainer(projectId, third);

        vm.expectEmit(address(provenant));
        emit Provenant.MaintainerUpdated(projectId, maintainer, false);
        provenant.removeMaintainer(projectId, maintainer);

        address[] memory list = provenant.getMaintainers(projectId);
        assertEq(list.length, 2);
        assertEq(list[0], third);
        assertEq(list[1], second);

        provenant.removeMaintainer(projectId, third);
        list = provenant.getMaintainers(projectId);
        assertEq(list.length, 1);
        assertEq(list[0], second);

        // Removed addresses can be re-added cleanly.
        provenant.addMaintainer(projectId, maintainer);
        vm.stopPrank();

        assertEq(provenant.getMaintainers(projectId).length, 2);
        assertFalse(provenant.isMaintainer(projectId, third));
    }

    /// Past anchors by a removed maintainer stay valid and attributed.
    function test_RemoveMaintainer_KeepsTheirHistory() public {
        vm.prank(maintainer);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        vm.prank(owner);
        provenant.removeMaintainer(projectId, maintainer);

        (,, address submittedBy,) = provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(submittedBy, maintainer);
    }

    /// Random add/remove sequences must keep the list, the index map and
    /// isMaintainer in sync with a simple reference model.
    function testFuzz_Maintainers_StayConsistent(uint8[32] calldata ops) public {
        address[5] memory pool = [maintainer, stranger, newOwner, makeAddr("d"), makeAddr("e")];
        bool[5] memory expected = [true, false, false, false, false];

        vm.startPrank(owner);
        for (uint256 i = 0; i < ops.length; i++) {
            uint256 who = ops[i] % 5;
            if (expected[who]) {
                provenant.removeMaintainer(projectId, pool[who]);
            } else {
                provenant.addMaintainer(projectId, pool[who]);
            }
            expected[who] = !expected[who];
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

    // =====================================================================
    // Ownership
    // =====================================================================

    function test_Ownership_TwoStepTransfer() public {
        vm.expectEmit(address(provenant));
        emit Provenant.OwnershipTransferStarted(projectId, owner, newOwner);
        vm.prank(owner);
        provenant.transferOwnership(projectId, newOwner);

        // Nothing changes until accepted.
        assertEq(provenant.getProject(projectId).owner, owner);
        assertEq(provenant.getProject(projectId).pendingOwner, newOwner);

        vm.expectEmit(address(provenant));
        emit Provenant.OwnershipTransferred(projectId, owner, newOwner);
        vm.prank(newOwner);
        provenant.acceptOwnership(projectId);

        Provenant.Project memory p = provenant.getProject(projectId);
        assertEq(p.owner, newOwner);
        assertEq(p.pendingOwner, address(0));

        // The project ID never changes, and the new owner has full rights.
        assertEq(projectId, provenant.computeProjectId(owner, SALT));
        vm.startPrank(newOwner);
        provenant.updateProject(projectId, MANIFEST_2);
        provenant.addMaintainer(projectId, owner);
        vm.stopPrank();
    }

    function test_TransferOwnership_RevertsOnInvalidTarget() public {
        vm.startPrank(owner);

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.transferOwnership(projectId, address(0));

        vm.expectRevert(Provenant.InvalidInput.selector);
        provenant.transferOwnership(projectId, owner);

        vm.stopPrank();
    }

    function test_TransferOwnership_SecondCallReplacesPendingOwner() public {
        vm.startPrank(owner);
        provenant.transferOwnership(projectId, newOwner);
        provenant.transferOwnership(projectId, stranger);
        vm.stopPrank();

        vm.prank(newOwner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);

        vm.prank(stranger);
        provenant.acceptOwnership(projectId);
        assertEq(provenant.getProject(projectId).owner, stranger);
    }

    function test_AcceptOwnership_OnlyPendingOwnerAndOnlyOnce() public {
        // Nothing pending: nobody can accept.
        vm.prank(newOwner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);

        vm.prank(owner);
        provenant.transferOwnership(projectId, newOwner);

        // Neither a stranger nor the current owner can complete it.
        vm.prank(stranger);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);
        vm.prank(owner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);

        vm.prank(newOwner);
        provenant.acceptOwnership(projectId);

        vm.prank(newOwner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);
    }

    /// A maintainer promoted to owner leaves the maintainer list, and the
    /// list stays consistent for everyone else.
    function test_AcceptOwnership_RemovesNewOwnerFromMaintainers() public {
        address second = makeAddr("second");
        vm.startPrank(owner);
        provenant.addMaintainer(projectId, second);
        provenant.transferOwnership(projectId, maintainer);
        vm.stopPrank();

        vm.expectEmit(address(provenant));
        emit Provenant.MaintainerUpdated(projectId, maintainer, false);
        vm.prank(maintainer);
        provenant.acceptOwnership(projectId);

        assertFalse(provenant.isMaintainer(projectId, maintainer));
        address[] memory list = provenant.getMaintainers(projectId);
        assertEq(list.length, 1);
        assertEq(list[0], second);

        // `second` was swapped into index 0; removing it must still work.
        vm.prank(maintainer);
        provenant.removeMaintainer(projectId, second);
        assertEq(provenant.getMaintainers(projectId).length, 0);
    }

    function test_CancelOwnershipTransfer_ClearsPendingOwner() public {
        vm.prank(owner);
        provenant.transferOwnership(projectId, newOwner);

        vm.expectEmit(address(provenant));
        emit Provenant.OwnershipTransferCancelled(projectId, newOwner);
        vm.prank(owner);
        provenant.cancelOwnershipTransfer(projectId);

        assertEq(provenant.getProject(projectId).pendingOwner, address(0));

        vm.prank(newOwner);
        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.acceptOwnership(projectId);
        assertEq(provenant.getProject(projectId).owner, owner);
    }

    function test_CancelOwnershipTransfer_RevertsWhenNothingPending() public {
        vm.prank(owner);
        vm.expectRevert(Provenant.NoPendingTransfer.selector);
        provenant.cancelOwnershipTransfer(projectId);

        // A completed transfer leaves nothing to cancel either.
        _transferOwnership(newOwner);
        vm.prank(newOwner);
        vm.expectRevert(Provenant.NoPendingTransfer.selector);
        provenant.cancelOwnershipTransfer(projectId);
    }

    // =====================================================================
    // Project status
    // =====================================================================

    function test_Archive_BlocksPublishingButKeepsHistory() public {
        vm.prank(maintainer);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        vm.expectEmit(address(provenant));
        emit Provenant.ProjectStatusChanged(projectId, Provenant.ProjectStatus.Archived, owner);
        vm.prank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);

        _assertPublishReverts(owner, Provenant.InvalidStatus.selector);
        _assertPublishReverts(maintainer, Provenant.InvalidStatus.selector);

        (bytes32 h1,) = provenant.getManifest(projectId, 1);
        (, bytes32 eventHash,,) = provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(h1, MANIFEST_1);
        assertEq(eventHash, EVENT_HASH);
    }

    /// The permission check runs before the status check, so a stranger
    /// gets Unauthorized, not InvalidStatus, on an archived project.
    function test_Archive_StrangerStillGetsUnauthorized() public {
        vm.prank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);

        _assertPublishReverts(stranger, Provenant.Unauthorized.selector);
    }

    function test_Archive_StillAllowsAdminActions() public {
        vm.startPrank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);
        provenant.addMaintainer(projectId, stranger);
        provenant.removeMaintainer(projectId, stranger);
        provenant.transferOwnership(projectId, newOwner);
        vm.stopPrank();

        vm.prank(newOwner);
        provenant.acceptOwnership(projectId);
        assertEq(provenant.getProject(projectId).owner, newOwner);
    }

    function test_Reactivate_RestoresPublishing() public {
        vm.startPrank(owner);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Active);
        vm.stopPrank();

        vm.prank(maintainer);
        provenant.updateProject(projectId, MANIFEST_2);
        assertEq(provenant.getProject(projectId).anchorCount, 2);
    }

    function test_SetProjectStatus_RevertsWhenUnchanged() public {
        vm.startPrank(owner);

        vm.expectRevert(Provenant.InvalidStatus.selector);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Active);

        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);
        vm.expectRevert(Provenant.InvalidStatus.selector);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);

        vm.stopPrank();
    }

    /// Out-of-range enum values (2 and uint8 max) are rejected by the ABI
    /// decoder before the function body runs.
    function test_SetProjectStatus_RejectsOutOfRangeEnum() public {
        uint8[2] memory bad = [uint8(2), type(uint8).max];

        for (uint256 i = 0; i < bad.length; i++) {
            vm.prank(owner);
            (bool ok,) =
                address(provenant).call(abi.encodeWithSelector(provenant.setProjectStatus.selector, projectId, bad[i]));
            assertFalse(ok);
        }

        assertEq(uint8(provenant.getProject(projectId).status), uint8(Provenant.ProjectStatus.Active));
    }

    // =====================================================================
    // Events
    // =====================================================================

    function test_AnchorEvent_StoresAndEmits() public {
        vm.warp(5_000);
        vm.expectEmit(address(provenant));
        emit Provenant.ProjectEventAnchored(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH, maintainer);

        vm.prank(maintainer);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        (bytes32 eventType, bytes32 contentHash, address submittedBy, uint64 ts) =
            provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(eventType, EVENT_TYPE);
        assertEq(contentHash, EVENT_HASH);
        assertEq(submittedBy, maintainer);
        assertEq(ts, 5_000);
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

    /// An event ID can be anchored once per project; a different publisher
    /// cannot overwrite it.
    function test_AnchorEvent_IsWriteOnce() public {
        vm.prank(owner);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);

        vm.prank(maintainer);
        vm.expectRevert(Provenant.EventAlreadyExists.selector);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, keccak256("tampered"));

        (, bytes32 contentHash, address submittedBy,) = provenant.getProjectEvent(projectId, EVENT_ID);
        assertEq(contentHash, EVENT_HASH);
        assertEq(submittedBy, owner);
    }

    function test_AnchorEvent_SameIdAllowedAcrossProjects() public {
        vm.prank(stranger);
        bytes32 otherId = provenant.createProject(SALT, "Other", MANIFEST_1);

        vm.prank(owner);
        provenant.anchorEvent(projectId, EVENT_ID, EVENT_TYPE, EVENT_HASH);
        vm.prank(stranger);
        provenant.anchorEvent(otherId, EVENT_ID, EVENT_TYPE, keccak256("other-event"));

        (, bytes32 h1,,) = provenant.getProjectEvent(projectId, EVENT_ID);
        (, bytes32 h2,,) = provenant.getProjectEvent(otherId, EVENT_ID);
        assertEq(h1, EVENT_HASH);
        assertEq(h2, keccak256("other-event"));
    }

    function test_AnchorEvent_AcceptsMaxValues() public {
        vm.prank(owner);
        provenant.anchorEvent(projectId, MAX_BYTES32, MAX_BYTES32, MAX_BYTES32);

        (bytes32 eventType, bytes32 contentHash,,) = provenant.getProjectEvent(projectId, MAX_BYTES32);
        assertEq(eventType, MAX_BYTES32);
        assertEq(contentHash, MAX_BYTES32);
    }

    function test_GetProjectEvent_RevertsWhenNotAnchored() public {
        vm.expectRevert(Provenant.EventNotFound.selector);
        provenant.getProjectEvent(projectId, EVENT_ID);

        vm.expectRevert(Provenant.EventNotFound.selector);
        provenant.getProjectEvent(projectId, bytes32(0));
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    /// Every owner-only function must revert with Unauthorized for `caller`.
    function _assertOwnerOnlyReverts(address caller) internal {
        address candidate = makeAddr("candidate");
        vm.startPrank(caller);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.addMaintainer(projectId, candidate);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.removeMaintainer(projectId, maintainer);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.transferOwnership(projectId, candidate);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.cancelOwnershipTransfer(projectId);

        vm.expectRevert(Provenant.Unauthorized.selector);
        provenant.setProjectStatus(projectId, Provenant.ProjectStatus.Archived);

        vm.stopPrank();
    }

    /// Both publishing functions must revert with `err` for `caller`.
    function _assertPublishReverts(address caller, bytes4 err) internal {
        vm.startPrank(caller);

        vm.expectRevert(err);
        provenant.updateProject(projectId, keccak256("blocked-manifest"));

        vm.expectRevert(err);
        provenant.anchorEvent(projectId, keccak256("blocked-event"), EVENT_TYPE, EVENT_HASH);

        vm.stopPrank();
    }

    function _transferOwnership(address to) internal {
        vm.prank(owner);
        provenant.transferOwnership(projectId, to);
        vm.prank(to);
        provenant.acceptOwnership(projectId);
    }

    /// Overwrites anchorCount in storage. `projects` is slot 0; within the
    /// struct, slot +2 packs pendingOwner (bits 0-159) and anchorCount
    /// (bits 160-223), with status and exists above them.
    function _setAnchorCount(uint64 value) internal {
        bytes32 slot = bytes32(uint256(keccak256(abi.encode(projectId, uint256(0)))) + 2);
        uint256 word = uint256(vm.load(address(provenant), slot));
        uint256 mask = uint256(type(uint64).max) << 160;
        word = (word & ~mask) | (uint256(value) << 160);
        vm.store(address(provenant), slot, bytes32(word));
    }

    function _contains(address[] memory list, address who) internal pure returns (bool) {
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == who) return true;
        }
        return false;
    }

    function _repeat(string memory unit, uint256 n) internal pure returns (string memory) {
        bytes memory out;
        for (uint256 i = 0; i < n; i++) {
            out = bytes.concat(out, bytes(unit));
        }
        return string(out);
    }
}
