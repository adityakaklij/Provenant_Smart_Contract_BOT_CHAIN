// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Provenant
/// @notice Registry for project identity, maintainers, manifest history,
/// project status, and verifiable event commitments.
/// @dev Only hashes are stored; the canonical bytes live off-chain and are
/// re-hashed by verifiers. Hashes are opaque bytes32 (the app uses SHA-256).
/// An anchor proves a record existed unchanged at that block; it does not
/// prove the record is current or true.
/// Not upgradeable.
contract Provenant {
    uint256 public constant MAX_NAME_LENGTH = 100;

    enum ProjectStatus {
        Active,
        Archived
    }

    struct Project {
        string name;
        address owner;
        address pendingOwner;
        // Number of anchored manifests (the anchor counter, not the off-chain
        // manifest version). 1 at creation, +1 per update, so anchors
        // 1..anchorCount all exist.
        uint64 anchorCount;
        ProjectStatus status;
        bool exists;
    }

    struct Manifest {
        bytes32 contentHash;
        uint64 timestamp;
    }

    struct ProjectEvent {
        bytes32 eventType;
        bytes32 contentHash;
        address submittedBy;
        uint64 timestamp;
    }

    // Project ID => project details
    mapping(bytes32 => Project) private projects;

    // Project ID => anchor number => manifest
    mapping(bytes32 => mapping(uint64 => Manifest)) private manifests;

    // Project ID => manifest hash => anchor number (0 = never anchored).
    // Lets verifiers check a manifest by its hash alone, and blocks duplicates.
    mapping(bytes32 => mapping(bytes32 => uint64)) public anchorOf;

    // Project ID => maintainer => authorization
    mapping(bytes32 => mapping(address => bool)) public isMaintainer;

    // Project ID => enumerable list of maintainers
    mapping(bytes32 => address[]) private maintainers;

    // Project ID => maintainer => array index + 1
    // Zero means the address is not in the array.
    mapping(bytes32 => mapping(address => uint256)) private maintainerIndexPlusOne;

    // Project ID => event ID => event details
    mapping(bytes32 => mapping(bytes32 => ProjectEvent)) private projectEvents;

    error ProjectAlreadyExists();
    error ProjectNotFound();
    error Unauthorized();
    error InvalidInput();
    error InvalidVersion();
    error InvalidStatus();
    error MaintainerAlreadyExists();
    error MaintainerNotFound();
    error EventAlreadyExists();
    error ManifestAlreadyAnchored();
    error NoPendingTransfer();
    error EventNotFound();

    event ProjectCreated(
        bytes32 indexed projectId, address indexed owner, bytes32 indexed salt, string name, bytes32 initialManifestHash
    );

    event ProjectUpdated(
        bytes32 indexed projectId, uint64 indexed anchorNumber, bytes32 manifestHash, address indexed updatedBy
    );

    event MaintainerUpdated(bytes32 indexed projectId, address indexed maintainer, bool authorized);

    event OwnershipTransferStarted(
        bytes32 indexed projectId, address indexed currentOwner, address indexed pendingOwner
    );

    event OwnershipTransferCancelled(bytes32 indexed projectId, address indexed cancelledPendingOwner);

    event OwnershipTransferred(bytes32 indexed projectId, address indexed previousOwner, address indexed newOwner);

    event ProjectStatusChanged(bytes32 indexed projectId, ProjectStatus newStatus, address indexed changedBy);

    event ProjectEventAnchored(
        bytes32 indexed projectId,
        bytes32 indexed eventId,
        bytes32 indexed eventType,
        bytes32 eventHash,
        address submittedBy
    );

    /// @dev Reverts with ProjectNotFound if the project was never created.
    modifier projectExists(bytes32 projectId) {
        if (!projects[projectId].exists) {
            revert ProjectNotFound();
        }
        _;
    }

    /// @dev Caller must be the project owner.
    modifier onlyOwner(bytes32 projectId) {
        if (projects[projectId].owner != msg.sender) {
            revert Unauthorized();
        }
        _;
    }

    /// @dev Caller must be the owner or a maintainer.
    modifier onlyPublisher(bytes32 projectId) {
        Project storage project = projects[projectId];

        if (project.owner != msg.sender && !isMaintainer[projectId][msg.sender]) {
            revert Unauthorized();
        }
        _;
    }

    /// @dev Blocks publishing while the project is archived.
    modifier onlyActive(bytes32 projectId) {
        if (projects[projectId].status != ProjectStatus.Active) {
            revert InvalidStatus();
        }
        _;
    }

    /// @notice Derive the project ID for a creator and salt.
    /// @dev Binding the ID to the creator means nobody else can register it,
    /// and a front-run copy of the transaction produces a different ID.
    /// Call this off-chain to know the ID before sending createProject.
    /// @param creator Address that will call createProject (the first owner).
    /// @param salt Off-chain project UUID as bytes16, left-aligned in bytes32.
    /// @return The project ID. It never changes, even after ownership transfer.
    function computeProjectId(address creator, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(creator, salt));
    }

    /// @notice Register a new project with its first anchored manifest
    /// (anchor 1). The caller becomes the owner.
    /// @dev The name is stored once and never updated on-chain; later
    /// renames are covered by the manifest hash.
    /// @param salt Off-chain project UUID (see computeProjectId). Non-zero.
    /// @param name Display name, 1 to MAX_NAME_LENGTH bytes.
    /// @param initialManifestHash Hash of that manifest's canonical bytes.
    /// @return projectId computeProjectId(msg.sender, salt).
    function createProject(bytes32 salt, string calldata name, bytes32 initialManifestHash)
        external
        returns (bytes32 projectId)
    {
        if (
            salt == bytes32(0) || initialManifestHash == bytes32(0) || bytes(name).length == 0
                || bytes(name).length > MAX_NAME_LENGTH
        ) {
            revert InvalidInput();
        }

        projectId = computeProjectId(msg.sender, salt);

        if (projects[projectId].exists) {
            revert ProjectAlreadyExists();
        }

        projects[projectId] = Project({
            name: name,
            owner: msg.sender,
            pendingOwner: address(0),
            anchorCount: 1,
            status: ProjectStatus.Active,
            exists: true
        });

        manifests[projectId][1] = Manifest({contentHash: initialManifestHash, timestamp: uint64(block.timestamp)});
        anchorOf[projectId][initialManifestHash] = 1;

        emit ProjectCreated(projectId, msg.sender, salt, name, initialManifestHash);
    }

    /// @notice Anchor a new manifest as the next anchor number.
    /// Owner or maintainer only; project must be active.
    /// @dev The contract assigns the anchor number (anchorCount + 1), so
    /// callers cannot skip ahead or exhaust the number space. Each hash can be
    /// anchored once per project; this relies on every off-chain manifest
    /// embedding its own version and previous_manifest_hash, so only a
    /// resubmission repeats a hash. Anchors need not arrive in off-chain
    /// order; the off-chain version is inside the hashed manifest.
    /// @param projectId Project to update.
    /// @param manifestHash Hash of the manifest's canonical bytes. Non-zero.
    /// @return anchorNumber The anchor number assigned to this manifest.
    function updateProject(bytes32 projectId, bytes32 manifestHash)
        external
        projectExists(projectId)
        onlyPublisher(projectId)
        onlyActive(projectId)
        returns (uint64 anchorNumber)
    {
        if (manifestHash == bytes32(0)) {
            revert InvalidInput();
        }

        if (anchorOf[projectId][manifestHash] != 0) {
            revert ManifestAlreadyAnchored();
        }

        Project storage project = projects[projectId];

        anchorNumber = project.anchorCount + 1;
        project.anchorCount = anchorNumber;

        manifests[projectId][anchorNumber] = Manifest({contentHash: manifestHash, timestamp: uint64(block.timestamp)});
        anchorOf[projectId][manifestHash] = anchorNumber;

        emit ProjectUpdated(projectId, anchorNumber, manifestHash, msg.sender);
    }

    /// @notice Add a maintainer. Only the project owner can do this.
    /// Maintainers can anchor manifests and events but cannot manage
    /// maintainers, ownership or status.
    /// @param projectId Project to modify.
    /// @param maintainer Address to authorize; not zero and not the owner.
    function addMaintainer(bytes32 projectId, address maintainer)
        external
        projectExists(projectId)
        onlyOwner(projectId)
    {
        if (maintainer == address(0) || maintainer == projects[projectId].owner) {
            revert InvalidInput();
        }

        if (isMaintainer[projectId][maintainer]) {
            revert MaintainerAlreadyExists();
        }

        maintainers[projectId].push(maintainer);
        maintainerIndexPlusOne[projectId][maintainer] = maintainers[projectId].length;
        isMaintainer[projectId][maintainer] = true;

        emit MaintainerUpdated(projectId, maintainer, true);
    }

    /// @notice Remove a maintainer. Only the project owner can do this.
    /// @dev O(1) swap-and-pop, so getMaintainers order is not stable.
    /// Past anchors by this address remain valid.
    /// @param projectId Project to modify.
    /// @param maintainer Address to deauthorize; must be a current maintainer.
    function removeMaintainer(bytes32 projectId, address maintainer)
        external
        projectExists(projectId)
        onlyOwner(projectId)
    {
        if (!isMaintainer[projectId][maintainer]) {
            revert MaintainerNotFound();
        }

        _removeMaintainer(projectId, maintainer);
    }

    /// @notice Begin a two-step ownership transfer. Only the owner can do this.
    /// @dev Nothing changes until newOwner calls acceptOwnership. Calling
    /// again replaces the pending owner.
    /// @param projectId Project to transfer.
    /// @param newOwner Proposed owner; not zero and not the current owner.
    function transferOwnership(bytes32 projectId, address newOwner)
        external
        projectExists(projectId)
        onlyOwner(projectId)
    {
        if (newOwner == address(0) || newOwner == msg.sender) {
            revert InvalidInput();
        }

        projects[projectId].pendingOwner = newOwner;

        emit OwnershipTransferStarted(projectId, msg.sender, newOwner);
    }

    /// @notice Cancel a pending ownership transfer. Only the owner can do this.
    /// @dev Use when the transfer was started to a wrong or compromised address.
    /// @param projectId Project whose pending transfer is cancelled.
    function cancelOwnershipTransfer(bytes32 projectId) external projectExists(projectId) onlyOwner(projectId) {
        Project storage project = projects[projectId];
        address pending = project.pendingOwner;

        if (pending == address(0)) {
            revert NoPendingTransfer();
        }

        project.pendingOwner = address(0);

        emit OwnershipTransferCancelled(projectId, pending);
    }

    /// @notice Accept a pending ownership transfer. Only the pending owner
    /// can call this.
    /// @dev If the new owner was a maintainer, they are removed from the
    /// maintainer list. The previous owner keeps no rights.
    /// @param projectId Project being transferred.
    function acceptOwnership(bytes32 projectId) external projectExists(projectId) {
        Project storage project = projects[projectId];

        if (project.pendingOwner != msg.sender) {
            revert Unauthorized();
        }

        address previousOwner = project.owner;

        // A new owner must not also remain in the maintainer list.
        if (isMaintainer[projectId][msg.sender]) {
            _removeMaintainer(projectId, msg.sender);
        }

        project.owner = msg.sender;
        project.pendingOwner = address(0);

        emit OwnershipTransferred(projectId, previousOwner, msg.sender);
    }

    /// @notice Archive or reactivate a project. Only the owner can do this.
    /// @dev Archiving keeps all history and blocks new manifests and events.
    /// Maintainer and ownership changes still work while archived.
    /// @param projectId Project to change.
    /// @param newStatus Target status; must differ from the current one.
    function setProjectStatus(bytes32 projectId, ProjectStatus newStatus)
        external
        projectExists(projectId)
        onlyOwner(projectId)
    {
        Project storage project = projects[projectId];

        if (newStatus == project.status) {
            revert InvalidStatus();
        }

        project.status = newStatus;

        emit ProjectStatusChanged(projectId, newStatus, msg.sender);
    }

    /// @notice Anchor the hash of a single project event. Owner or maintainer
    /// only; project must be active.
    /// @dev Each eventId can be anchored once per project; fix mistakes by
    /// anchoring a new correction event.
    /// @param projectId Project the event belongs to.
    /// @param eventId Off-chain event UUID (bytes16, left-aligned). Non-zero.
    /// @param eventType keccak256 of a label, e.g. keccak256("RELEASE_PUBLISHED").
    /// @param eventHash Hash of the event's canonical bytes. Non-zero.
    function anchorEvent(bytes32 projectId, bytes32 eventId, bytes32 eventType, bytes32 eventHash)
        external
        projectExists(projectId)
        onlyPublisher(projectId)
        onlyActive(projectId)
    {
        if (eventId == bytes32(0) || eventType == bytes32(0) || eventHash == bytes32(0)) {
            revert InvalidInput();
        }

        // eventHash is non-zero, so a stored event always has a non-zero contentHash.
        if (projectEvents[projectId][eventId].contentHash != bytes32(0)) {
            revert EventAlreadyExists();
        }

        projectEvents[projectId][eventId] = ProjectEvent({
            eventType: eventType, contentHash: eventHash, submittedBy: msg.sender, timestamp: uint64(block.timestamp)
        });

        emit ProjectEventAnchored(projectId, eventId, eventType, eventHash, msg.sender);
    }

    /// @notice Read the current project record.
    /// @param projectId Project to read.
    /// @return Name, owner, pending owner, anchor count, status.
    function getProject(bytes32 projectId) external view projectExists(projectId) returns (Project memory) {
        return projects[projectId];
    }

    /// @notice Return the current maintainers (owner not included).
    /// @param projectId Project to read.
    /// @return Maintainer addresses, in no guaranteed order.
    function getMaintainers(bytes32 projectId) external view projectExists(projectId) returns (address[] memory) {
        return maintainers[projectId];
    }

    /// @notice Read an anchored manifest by its anchor number.
    /// @dev Reverts with InvalidVersion outside 1..anchorCount. To find the
    /// anchor number for a hash, use anchorOf.
    /// @param projectId Project to read.
    /// @param anchorNumber Anchor number, 1..anchorCount.
    /// @return contentHash Anchored hash of the manifest's canonical bytes.
    /// @return timestamp Block time when it was anchored.
    function getManifest(bytes32 projectId, uint64 anchorNumber)
        external
        view
        projectExists(projectId)
        returns (bytes32 contentHash, uint64 timestamp)
    {
        Manifest storage manifest = manifests[projectId][anchorNumber];

        if (manifest.contentHash == bytes32(0)) {
            revert InvalidVersion();
        }

        return (manifest.contentHash, manifest.timestamp);
    }

    /// @notice Read a previously anchored event.
    /// @dev Reverts with EventNotFound if the event was never anchored.
    /// @param projectId Project the event belongs to.
    /// @param eventId Off-chain event ID used in anchorEvent.
    /// @return eventType keccak256 label of the event type.
    /// @return contentHash Anchored hash of the event's canonical bytes.
    /// @return submittedBy Owner or maintainer who anchored it.
    /// @return timestamp Block time when it was anchored.
    function getProjectEvent(bytes32 projectId, bytes32 eventId)
        external
        view
        projectExists(projectId)
        returns (bytes32 eventType, bytes32 contentHash, address submittedBy, uint64 timestamp)
    {
        ProjectEvent storage projectEvent = projectEvents[projectId][eventId];

        if (projectEvent.contentHash == bytes32(0)) {
            revert EventNotFound();
        }

        return (projectEvent.eventType, projectEvent.contentHash, projectEvent.submittedBy, projectEvent.timestamp);
    }

    /// @dev Swap-and-pop removal shared by removeMaintainer and acceptOwnership.
    /// No-op if `maintainer` is not in the list.
    function _removeMaintainer(bytes32 projectId, address maintainer) internal {
        uint256 indexPlusOne = maintainerIndexPlusOne[projectId][maintainer];

        if (indexPlusOne == 0) {
            return;
        }

        address[] storage list = maintainers[projectId];
        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = list.length - 1;

        if (index != lastIndex) {
            address lastMaintainer = list[lastIndex];

            list[index] = lastMaintainer;
            maintainerIndexPlusOne[projectId][lastMaintainer] = index + 1;
        }

        list.pop();

        delete maintainerIndexPlusOne[projectId][maintainer];
        isMaintainer[projectId][maintainer] = false;

        emit MaintainerUpdated(projectId, maintainer, false);
    }
}
