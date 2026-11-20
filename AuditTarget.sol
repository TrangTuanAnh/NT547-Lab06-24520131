// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// NT547 - Lab 06 - Hop dong rieng cua MSSV 24520131. KHONG deploy len mainnet.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract LotteryHub_0131 {
    address public owner;
    mapping(address => uint256) public stakes;
    uint256 public rateBps = 250;
    uint256 public releaseTime;
    mapping(bytes32 => bool) public redeemed;
    address payable internal beneficiary;

    event Deposited(address indexed who, uint256 amount);

    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function contribute() external payable {
        stakes[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function ownerWithdraw(uint256 amount) external onlyOwner {
        (bool ok, ) = payable(owner).call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function quoteFee(uint256 amount) public view returns (uint256) {
        return amount * rateBps / 10000;
    }

    function vestStep() external onlyOwner {
        require(block.timestamp >= releaseTime, "locked");
        releaseTime = block.timestamp + 1 days;
        (bool ok, ) = payable(owner).call{value: address(this).balance / 10}("");
        require(ok, "release failed");
    }

    function transferControl(address newOwner) external {
        require(msg.sender == owner, "not owner");
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function useCode(string calldata campaign, string calldata code) external {
        bytes32 id = keccak256(abi.encode(campaign, code));
        require(!redeemed[id], "used");
        redeemed[id] = true;
        stakes[msg.sender] += 1;
    }

    function setBeneficiary(address payable _b) external onlyOwner {
        require(_b != address(0), "zero");
        beneficiary = _b;
    }

    function moveToTreasury() external onlyOwner {
        require(beneficiary != address(0), "beneficiary not set");
        beneficiary.transfer(address(this).balance / 2);
    }

    // slither-disable-next-line incorrect-equality
    function zeroBalance() external view returns (bool) {
        return address(this).balance == 0;
    }
}
