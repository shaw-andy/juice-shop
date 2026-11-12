// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "ETHWalletBank.sol";

// Calls withdraw again from receive. A failed reentrant call is ignored so a
// withdrawal that debits before the external call can still pay the credited amount.
contract ReentrancyAttacker {
    ETHWalletBank bank;
    uint public reentered;
    uint attackAmount;
    bool armed;
    bool unlimited;

    constructor (ETHWalletBank _bank) public {
        bank = _bank;
    }

    function attackOnce (uint amount) external {
        _attack(amount, false);
    }

    function attackUnlimited (uint amount) external {
        _attack(amount, true);
    }

    function withdrawOnce (uint amount) external {
        armed = false;
        _withdraw(amount);
    }

    function _attack (uint amount, bool keepReentering) internal {
        attackAmount = amount;
        armed = true;
        unlimited = keepReentering;
        reentered = 0;
        _withdraw(amount);
        armed = false;
    }

    function _withdraw (uint amount) internal {
        (bool ok, bytes memory data) = address(bank).call(abi.encodeWithSignature("withdraw(uint256)", amount));
        if (!ok) {
            assembly {
                revert(add(data, 0x20), mload(data))
            }
        }
    }

    receive () external payable {
        if (armed && (unlimited || reentered < 1)) {
            reentered += 1;
            (bool ignored,) = address(bank).call(abi.encodeWithSignature("withdraw(uint256)", attackAmount));
            ignored;
        }
    }
}

contract EthWalletBankReentrancyTest {
    function testSingleReentrantWithdrawCannotExceedCredit () external payable returns (uint attackerBal, uint recorded, uint bankBal, uint victimRecorded) {
        (ETHWalletBank bank, ReentrancyAttacker attacker, address victim) = _fundedBank();
        (bool ignored,) = address(attacker).call(abi.encodeWithSignature("attackOnce(uint256)", uint(0.1 ether)));
        ignored;
        return _balances(bank, attacker, victim);
    }

    function testUnlimitedReentrantWithdrawThenDrainCannotTakeVictimEther () external payable returns (uint attackerBal, uint recorded, uint bankBal, uint victimRecorded) {
        (ETHWalletBank bank, ReentrancyAttacker attacker, address victim) = _fundedBank();
        (bool ignored,) = address(attacker).call(abi.encodeWithSignature("attackUnlimited(uint256)", uint(0.1 ether)));
        ignored;
        (bool ignoredDrain,) = address(attacker).call(abi.encodeWithSignature("withdrawOnce(uint256)", uint(0.1 ether)));
        ignoredDrain;
        return _balances(bank, attacker, victim);
    }

    function testHonestWithdrawPaysCreditOnce () external payable {
        require(msg.value == 0.1 ether, "fund the honest withdrawal");
        ETHWalletBank bank = new ETHWalletBank();
        bank.ethdeposit{value: 0.1 ether}(address(this));
        uint before = address(this).balance;
        bank.withdraw(0.1 ether);
        require(address(this).balance == before + 0.1 ether, "honest withdraw paid a different amount than the credit");
        require(bank.balanceOf(address(this)) == 0, "honest withdraw did not debit the account that was paid");
        require(address(bank).balance == 0, "honest withdraw left the credited ether in the bank");
    }

    function _fundedBank () internal returns (ETHWalletBank bank, ReentrancyAttacker attacker, address victim) {
        require(msg.value == 1.6 ether, "fund the bank");
        bank = new ETHWalletBank();
        attacker = new ReentrancyAttacker(bank);
        victim = address(0xBEEF);
        (bool accepted,) = address(bank).call{value: 0.5 ether}("");
        require(accepted, "bank rejected ether sent to receive");
        bank.ethdeposit{value: 1 ether}(victim);
        bank.ethdeposit{value: 0.1 ether}(address(attacker));
        require(bank.balanceOf(address(attacker)) == 0.1 ether, "ethdeposit did not credit the attacker contract");
        require(bank.balanceOf(victim) == 1 ether, "ethdeposit did not credit the victim");
        require(address(bank).balance == 1.6 ether, "bank did not hold the ether it was sent");
    }

    function _balances (ETHWalletBank bank, ReentrancyAttacker attacker, address victim) internal view returns (uint attackerBal, uint recorded, uint bankBal, uint victimRecorded) {
        attackerBal = address(attacker).balance;
        recorded = bank.balanceOf(address(attacker));
        bankBal = address(bank).balance;
        victimRecorded = bank.balanceOf(victim);
    }

    receive () external payable {}
}
