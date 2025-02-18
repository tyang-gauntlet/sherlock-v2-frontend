// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    bool private locked;
    uint256 private constant MINIMUM_DEPOSIT = 0.1 ether;

    constructor() {
        owner = msg.sender;
    }

    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: state update after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    // Timestamp dependency vulnerability
    function lockFunds() public payable {
        require(msg.value >= MINIMUM_DEPOSIT, "Deposit too small");
        // Vulnerable: using block.timestamp for randomness
        if (block.timestamp % 2 == 0) {
            balances[msg.sender] += msg.value * 2;
        } else {
            balances[msg.sender] += msg.value;
        }
    }

    // Unprotected function with self-destruct
    function emergencyWithdraw() public {
        // Vulnerable: no access control
        selfdestruct(payable(msg.sender));
    }

    // Integer overflow (less relevant in ^0.8.0 due to built-in overflow checks)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Delegatecall vulnerability
    receive() external payable {
        // Vulnerable: delegatecall to user-supplied address
        (bool success,) = msg.sender.delegatecall("");
        require(success, "Delegatecall failed");
    }

    // Unprotected setter function
    function setOwner(address newOwner) public {
        // Vulnerable: no access control
        owner = newOwner;
    }
} 