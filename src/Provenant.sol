// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Provenant
/// @notice Registry for project identity, maintainers, manifest history,
/// project status, and verifiable event commitments.
/// @dev Only hashes are stored; the canonical bytes live off-chain and are
/// re-hashed by verifiers. Hashes are opaque bytes32 (the app uses SHA-256).
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
        // Latest anchored off-chain manifest version. Not every off-chain
        // version is anchored, so versions may have gaps.
        uint64 currentVersion;
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

    // Project ID => off-chain manifest version => manifest
    mapping(bytes32 => mapping(uint64 => Manifest)) private manifests;

    // Project ID => maintainer => authorization
    mapping(bytes32 => mapping(address => bool)) public isMaintainer;

    // Project ID => enumerable list of maintainers
    mapping(bytes32 => address[]) private maintainers;

    // Project ID => maintainer => array index + 1
    // Zero means the address is not in the array.
    mapping(bytes32 => mapping(address => uint256)) private maintainerIndexPlusOne;

    // Project ID => event ID => event details
    mapping(bytes32 => mapping(bytes32 => ProjectEvent)) private projectEvents;

    // Project ID => event ID => existence
    mapping(bytes32 => mapping(bytes32 => bool)) private eventExists;

    error ProjectAlreadyExists();
    error ProjectNotFound();
    error Unauthorized();
    error InvalidInput();
    error InvalidVersion();
    error InvalidStatus();
    error MaintainerAlreadyExists();
    error MaintainerNotFound();
    error EventAlreadyExists();

    event ProjectCreated(
        bytes32 indexed projectId,
        address indexed owner,
        bytes32 indexed salt,
        string name,
        uint64 version,
        bytes32 initialManifestHash
    );

    event ProjectUpdated(
        bytes32 indexed projectId, uint64 indexed version, bytes32 manifestHash, address indexed updatedBy
    );

    event MaintainerUpdated(bytes32 indexed projectId, address indexed maintainer, bool authorized);

    event OwnershipTransferStarted(
        bytes32 indexed projectId, address indexed currentOwner, address indexed pendingOwner
    );

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

    /// @notice Register a new project with its first anchored manifest.
    /// The caller becomes the owner.
    /// @dev The name is stored once and never updated on-chain; later
    /// renames are covered by the manifest hash.
    /// @param salt Off-chain project UUID (see computeProjectId). Non-zero.
    /// @param name Display name, 1 to MAX_NAME_LENGTH bytes.
    /// @param version Off-chain manifest version being anchored. Non-zero;
    /// need not be 1 if earlier versions were never anchored.
    /// @param initialManifestHash Hash of that manifest's canonical bytes.
    /// @return projectId computeProjectId(msg.sender, salt).
    function createProject(bytes32 salt, string calldata name, uint64 version, bytes32 initialManifestHash)
        external
        returns (bytes32 projectId)
    {
        if (
            salt == bytes32(0) || version == 0 || initialManifestHash == bytes32(0) || bytes(name).length == 0
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
            currentVersion: version,
            status: ProjectStatus.Active,
            exists: true
        });

        manifests[projectId][version] = Manifest({contentHash: initialManifestHash, timestamp: uint64(block.timestamp)});

        emit ProjectCreated(projectId, msg.sender, salt, name, version, initialManifestHash);
    }

    /// @notice Anchor a newer off-chain manifest version.
    /// Owner or maintainer only; project must be active.
    /// @dev Versions must strictly increase but may skip (only major updates
    /// are anchored). This also rejects stale or duplicate submissions.
    /// @param projectId Project to update.
    /// @param version Off-chain manifest version; must be > currentVersion.
    /// @param manifestHash Hash of that manifest's canonical bytes. Non-zero.
    function updateProject(bytes32 projectId, uint64 version, bytes32 manifestHash)
        external
        projectExists(projectId)
        onlyPublisher(projectId)
        onlyActive(projectId)
    {
        if (manifestHash == bytes32(0)) {
            revert InvalidInput();
        }

        Project storage project = projects[projectId];

        if (version <= project.currentVersion) {
            revert InvalidVersion();
        }

        project.currentVersion = version;

        manifests[projectId][version] = Manifest({contentHash: manifestHash, timestamp: uint64(block.timestamp)});

        emit ProjectUpdated(projectId, version, manifestHash, msg.sender);
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
        uint256 indexPlusOne = maintainerIndexPlusOne[projectId][maintainer];

        if (indexPlusOne == 0) {
            revert MaintainerNotFound();
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

        if (newStatus == project.status || uint8(newStatus) > uint8(ProjectStatus.Archived)) {
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

        if (eventExists[projectId][eventId]) {
            revert EventAlreadyExists();
        }

        eventExists[projectId][eventId] = true;

        projectEvents[projectId][eventId] = ProjectEvent({
            eventType: eventType, contentHash: eventHash, submittedBy: msg.sender, timestamp: uint64(block.timestamp)
        });

        emit ProjectEventAnchored(projectId, eventId, eventType, eventHash, msg.sender);
    }

    /// @notice Read the current project record.
    /// @param projectId Project to read.
    /// @return Name, owner, pending owner, latest anchored version, status.
    function getProject(bytes32 projectId) external view projectExists(projectId) returns (Project memory) {
        return projects[projectId];
    }

    /// @notice Return the current maintainers (owner not included).
    /// @param projectId Project to read.
    /// @return Maintainer addresses, in no guaranteed order.
    function getMaintainers(bytes32 projectId) external view projectExists(projectId) returns (address[] memory) {
        return maintainers[projectId];
    }

    /// @notice Read an anchored manifest version.
    /// @dev Reverts with InvalidVersion for versions that were never anchored.
    /// @param projectId Project to read.
    /// @param version Off-chain manifest version.
    /// @return contentHash Anchored hash of the manifest's canonical bytes.
    /// @return timestamp Block time when it was anchored.
    function getManifest(bytes32 projectId, uint64 version)
        external
        view
        projectExists(projectId)
        returns (bytes32 contentHash, uint64 timestamp)
    {
        Manifest storage manifest = manifests[projectId][version];

        if (manifest.contentHash == bytes32(0)) {
            revert InvalidVersion();
        }

        return (manifest.contentHash, manifest.timestamp);
    }

    /// @notice Read a previously anchored event.
    /// @dev Reverts with InvalidInput if the event was never anchored.
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
        if (!eventExists[projectId][eventId]) {
            revert InvalidInput();
        }

        ProjectEvent storage projectEvent = projectEvents[projectId][eventId];

        return (projectEvent.eventType, projectEvent.contentHash, projectEvent.submittedBy, projectEvent.timestamp);
    }

    /// @dev Swap-and-pop removal used by acceptOwnership. No-op if
    /// `maintainer` is not in the list.
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
