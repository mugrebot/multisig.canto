// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

pragma experimental ABIEncoderV2;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./MultiSigFactory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Custom errors
//custom errors
error DUPLICATE_OR_UNORDERED_SIGNATURES();
error INVALID_OWNER();
error INVALID_SIGNER();
error INVALID_SIGNATURES_REQUIRED();
error INSUFFICIENT_VALID_SIGNATURES();
error NOT_ENOUGH_SIGNERS();
error NOT_OWNER();
error NOT_SELF();
error NOT_FACTORY();
error TX_FAILED();
error NO_FEE_TO_DISTRIBUTE();
error NO_FEE_TO_WITHDRAW();

interface MuliSigTurnstile {
  function register(address) external returns (uint256);

  function withdraw(uint256, address payable, uint256) external returns (uint256);

  function balances(uint256 _tokenId) external view returns (uint256);
}

contract MultiSigWallet {
  using ECDSA for bytes32;
  MultiSigFactory private immutable multiSigFactory;
  uint256 public immutable chainId;
  uint256 public constant factoryVersion = 1;
  MuliSigTurnstile turnstile = MuliSigTurnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);
  uint256 private csrNFTTokenId;

  // Additional state variables for Contract Secured Revenue
  mapping(address => uint256) public allocation;
  IERC20 public revenueToken;
  uint256 public feePercentage = 20; // 20% fee for first approver and executor

  // Events
  event Deposit(address indexed sender, uint256 amount, uint256 balance);
  event ExecuteTransaction(
    address indexed owner,
    address payable to,
    uint256 value,
    bytes data,
    uint256 nonce,
    bytes32 hash,
    bytes result
  );
  event Owner(address indexed owner, bool added);

  // Modifiers
  mapping(address => bool) public isOwner;

  address[] public owners;

  uint256 public signaturesRequired;
  uint256 public nonce;
  string public name;

  modifier onlyOwner() {
    if (!isOwner[msg.sender]) {
      revert NOT_OWNER();
    }
    _;
  }

  modifier onlySelf() {
    if (msg.sender != address(this)) {
      revert NOT_SELF();
    }
    _;
  }

  modifier onlyValidSignaturesRequired() {
    _;
    if (signaturesRequired == 0) {
      revert INVALID_SIGNATURES_REQUIRED();
    }
    if (owners.length < signaturesRequired) {
      revert NOT_ENOUGH_SIGNERS();
    }
  }
  modifier onlyFactory() {
    if (msg.sender != address(multiSigFactory)) {
      revert NOT_FACTORY();
    }
    _;
  }

  constructor(string memory _name, address _factory) payable {
    name = _name;
    multiSigFactory = MultiSigFactory(_factory);
    chainId = block.chainid;
  }

  function getMultiSigDetails() public view returns (string memory, address[] memory, uint256) {
    return (name, owners, signaturesRequired);
  }

  function init(
    address[] calldata _owners,
    uint256 _signaturesRequired
  ) public payable onlyFactory onlyValidSignaturesRequired {
    // ...
    signaturesRequired = _signaturesRequired;

    // get a local reference of the length to save gas
    uint256 ownerLength = _owners.length;
    for (uint256 i = 0; i < ownerLength; ) {
      address owner = _owners[i];
      if (owner == address(0) || isOwner[owner]) {
        revert INVALID_OWNER();
      }
      isOwner[owner] = true;
      owners.push(owner);

      emit Owner(owner, true);
      unchecked {
        ++i;
      }
    }

    csrNFTTokenId = turnstile.register(address(this));
  }

  // Other functions
  function addSigner(address newSigner, uint256 newSignaturesRequired) public onlySelf onlyValidSignaturesRequired {
    if (newSigner == address(0) || isOwner[newSigner]) {
      revert INVALID_SIGNER();
    }

    isOwner[newSigner] = true;
    owners.push(newSigner);
    signaturesRequired = newSignaturesRequired;

    emit Owner(newSigner, true);
    multiSigFactory.emitOwners(address(this), owners, newSignaturesRequired);
  }

  function removeSigner(address oldSigner, uint256 newSignaturesRequired) public onlySelf onlyValidSignaturesRequired {
    if (!isOwner[oldSigner]) {
      revert NOT_OWNER();
    }

    _removeOwner(oldSigner);
    signaturesRequired = newSignaturesRequired;

    emit Owner(oldSigner, false);
    multiSigFactory.emitOwners(address(this), owners, newSignaturesRequired);
  }

  function _removeOwner(address _oldSigner) private {
    isOwner[_oldSigner] = false;
    uint256 ownersLength = owners.length;
    address lastElement = owners[ownersLength - 1];
    // check if the last element of the array is the owner t be removed
    if (lastElement == _oldSigner) {
      owners.pop();
      return;
    } else {
      // if not then iterate through the array and swap the owner to be removed with the last element in the array
      for (uint256 i = ownersLength - 2; i >= 0; ) {
        if (owners[i] == _oldSigner) {
          address temp = owners[i];
          owners[i] = lastElement;
          lastElement = temp;
          owners.pop();
          return;
        }
        unchecked {
          --i;
        }
      }
    }
    allocation[_oldSigner] = 0;
  }

  function updateSignaturesRequired(uint256 newSignaturesRequired) public onlySelf onlyValidSignaturesRequired {
    signaturesRequired = newSignaturesRequired;
  }

  function executeBatch(
    address[] calldata to,
    uint256[] calldata value,
    bytes[] calldata data,
    bytes[][] calldata signatures
  ) public onlyOwner returns (bytes[] memory) {
    uint256 toLength = to.length;
    bytes[] memory results = new bytes[](toLength);
    for (uint256 i = 0; i < toLength; i++) {
      results[i] = executeTransaction(payable(to[i]), value[i], data[i], signatures[i]);
    }
    return results;
  }

  function executeTransaction(
    address payable to,
    uint256 value,
    bytes calldata data,
    bytes[] calldata signatures
  ) public onlyOwner returns (bytes memory) {
    uint256 _nonce = nonce;
    bytes32 _hash = getTransactionHash(_nonce, to, value, data);

    nonce = _nonce + 1;

    uint256 validSignatures;
    address duplicateGuard;
    // get a local reference of the length to save gas
    uint256 signatureLength = signatures.length;
    for (uint256 i = 0; i < signatureLength; ) {
      address recovered = recover(_hash, signatures[i]);
      if (recovered <= duplicateGuard) {
        revert DUPLICATE_OR_UNORDERED_SIGNATURES();
      }
      duplicateGuard = recovered;

      if (isOwner[recovered]) {
        validSignatures++;
      }
      unchecked {
        ++i;
      }
    }

    if (validSignatures < signaturesRequired) {
      revert INSUFFICIENT_VALID_SIGNATURES();
    }

    _distributeFees(to, value, data, signatures);

    (bool success, bytes memory result) = to.call{value: value}(data);
    if (!success) {
      revert TX_FAILED();
    }

    emit ExecuteTransaction(msg.sender, to, value, data, _nonce, _hash, result);
    return result;
  }

  function getTransactionHash(
    uint256 _nonce,
    address to,
    uint256 value,
    bytes memory data
  ) public view returns (bytes32) {
    return keccak256(abi.encodePacked(address(this), chainId, _nonce, to, value, data));
  }

  // New functions for Contract Secured Revenue
  // ...

  // Additional function to distribute fees
  function _distributeFees(
    address payable to,
    uint256 value,
    bytes calldata data,
    bytes[] calldata signatures
  ) private {
    uint256 totalFee = turnstile.balances(csrNFTTokenId);
    // if (totalFee == 0) {
    //   revert NO_FEE_TO_DISTRIBUTE();  /** This could prevent execution of transactions: executeTransaction() */
    // }

    if (totalFee > 0) {
      uint256 feeFirstApproverAndExecutor = (totalFee * feePercentage) / 100;
      //   uint256 feeExecutor = (totalFee * feePercentage) / 100;
      uint256 remainingFee = totalFee - feeFirstApproverAndExecutor - feeFirstApproverAndExecutor;

      //   uint256 feePerApprover = remainingFee / (signatures.length - 2);

      /** Changed to one, the executor should stiil be eligible for approval fee? */
      /** The for loop below allocates fee to all but one */
      uint256 feePerApprover = remainingFee / (signatures.length - 1);

      turnstile.withdraw(csrNFTTokenId, payable(address(this)), totalFee);

      // Distribute fee to the first approver
      address firstApprover = recover(getTransactionHash(nonce, to, value, data), signatures[0]);
      allocation[firstApprover] += feeFirstApproverAndExecutor;

      // Distribute fee to the executor
      allocation[msg.sender] += feeFirstApproverAndExecutor;

      // Distribute equal fee to the rest of the approvers
      for (uint256 i = 1; i < signatures.length; i++) {
        address approver = recover(getTransactionHash(nonce, to, value, data), signatures[i]);
        allocation[approver] += feePerApprover;
      }

      //still need to distribute the remaining fee to the approvers
    }
  }

  //write a function to view the fee allocation for each owner
  function viewAllocation(address _owner) public view returns (uint256) {
    return allocation[_owner];
  }

  function recover(bytes32 _hash, bytes calldata _signature) public pure returns (address) {
    return _hash.toEthSignedMessageHash().recover(_signature);
  }

  function withdraw() public {
    if (address(this).balance == 0) {
      revert NO_FEE_TO_WITHDRAW();
    }

    /**Loop through the owners and send their allocations */
    for (uint i = 0; i < owners.length; i++) {
      if (allocation[owners[i]] > 0) {
        uint256 amount = allocation[owners[i]];
        allocation[owners[i]] = 0;
        payable(owners[i]).transfer(amount);
      }
    }

    uint256 leftOver = address(this).balance;

    if (leftOver > 0) {
      uint256 leftOverFee = leftOver / owners.length;
      for (uint i = 0; i < owners.length; i++) {
        payable(owners[i]).transfer(leftOverFee);
      }
    }

    // if (allocation[msg.sender] > 0) {
    //   uint256 amount = allocation[msg.sender];
    //   allocation[msg.sender] = 0;
    //   payable(msg.sender).transfer(amount);
    // } else {
    //   revert NO_FEE_TO_WITHDRAW();
    // }
  }

  receive() external payable {
    emit Deposit(msg.sender, msg.value, address(this).balance);
  }

  function numberOfOwners() public view returns (uint256) {
    return owners.length;
  }
}
