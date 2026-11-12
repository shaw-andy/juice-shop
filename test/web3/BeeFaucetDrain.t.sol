// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import "../../data/static/web3-snippets/BeeFaucet.sol";
import "../../data/static/web3-snippets/BEEToken.sol";

/// Spec for BeeFaucet. These tests fail until the contract matches it.
///
/// withdraw(uint8) is the call the bee-haven page encodes. It may pay the caller
/// `amount * 10^18` Bee tokens and debit this faucet's shared counter by `amount`.
/// One address may receive at most 10 whole tokens in total. withdraw reverts when
/// `amount >=` the counter, so the counter cannot reach 0. A reverted withdraw
/// leaves the counter and every token balance unchanged.
///
/// restore(uint8) adds to this faucet's counter. Only the address that deployed
/// this faucet may call it. It reverts instead of wrapping past 255, and it does
/// not move tokens. adminWithdraw(uint8) may debit the whole remaining counter and
/// pay that same deployer. Nobody else may call it, and it must not move another
/// faucet's counter or tokens.
interface Vm {
    function prank(address msgSender) external;
    function cloneAccount(address source, address target) external;
}

interface IBeeFaucet {
    function balance() external view returns (uint8);
    function getBalance() external view returns (uint8);
    function token() external view returns (address);
}

contract DeployerProbe {
    address public deployer;

    constructor() {
        deployer = msg.sender;
    }
}

contract BeeFaucetDrainTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal constant BEE = 0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13;
    uint8 internal constant CAP = 10;
    uint256 internal constant WHOLE = 1000000000000000000;

    // ethers 5.7.2 / @ethersproject/abi 5.7.0 encodeFunctionData("withdraw", [200])
    // for the BeeFaucetABI uint8 argument. 0xc8 is 200.
    bytes internal constant FRONTEND_WITHDRAW_FULL =
        hex"c6ab5d9000000000000000000000000000000000000000000000000000000000000000c8";

    BeeToken internal bee;
    address internal faucetOwner = address(0xF0A0CE7);
    address internal stranger = address(0x57A06E2);

    function setUp() public {
        vm.prank(faucetOwner);
        DeployerProbe probe = new DeployerProbe();
        require(probe.deployer() == faucetOwner, "deploy prank did not set msg.sender");

        BeeToken live = new BeeToken();
        vm.cloneAccount(address(live), BEE);
        bee = BeeToken(BEE);
        require(
            bee.balanceOf(address(this)) == live.balanceOf(address(this)),
            "cloned BeeToken balance does not match the deployed token"
        );
        require(bee.balanceOf(address(this)) == 1000000000 * WHOLE, "BeeToken supply was not minted to the deployer");
        require(
            keccak256(FRONTEND_WITHDRAW_FULL) == keccak256(abi.encodeWithSignature("withdraw(uint8)", uint8(200))),
            "frontend withdraw calldata is not withdraw(uint8, 200)"
        );
        require(bytes4(FRONTEND_WITHDRAW_FULL) == bytes4(keccak256("withdraw(uint8)")), "withdraw selector mismatch");
    }

    function test_callerCannotWithdrawTheFullSharedCounter() public {
        IBeeFaucet faucet = _freshFaucet();
        address caller = address(0xA11CE);
        uint256 callerBefore = bee.balanceOf(caller);
        uint256 faucetBefore = bee.balanceOf(address(_asContract(faucet)));

        (bool readOk, bytes memory readData) = address(_asContract(faucet)).staticcall(hex"b69ef8a8");
        require(readOk, "balance() read failed");
        uint8 reported = abi.decode(readData, (uint8));
        require(reported == 200, "balance() is not the initial counter");
        require(faucet.getBalance() == reported, "getBalance diverges from balance()");
        require(faucet.token() == BEE, "faucet token is not the Bee token");

        (bool overOk,) = _call(faucet, caller, abi.encodeWithSignature("withdraw(uint8)", uint8(201)));
        require(!overOk, "withdraw above the counter succeeded");
        _assertUntouched(faucet, caller, callerBefore, faucetBefore, 200);

        (bool fullOk,) = _call(faucet, caller, FRONTEND_WITHDRAW_FULL);
        if (fullOk) {
            revert(string.concat(
                "full withdraw succeeded, counter=",
                _dec(faucet.balance()),
                ", paidWhole=",
                _dec(bee.balanceOf(caller) / WHOLE)
            ));
        }
        _assertUntouched(faucet, caller, callerBefore, faucetBefore, 200);

        address later = address(0xB0B);
        (bool laterOk,) = _call(faucet, later, abi.encodeWithSignature("withdraw(uint8)", CAP));
        require(laterOk, "later visitor could not take a capped share");
        require(faucet.balance() == 190, "capped share did not debit the counter by 10");
        require(bee.balanceOf(later) == uint256(CAP) * WHOLE, "capped share paid the wrong number of tokens");
        require(
            bee.balanceOf(address(_asContract(faucet))) == faucetBefore - (uint256(CAP) * WHOLE),
            "capped share did not debit the faucet token balance"
        );
    }

    function test_addressCapIsTenAndIsCumulative() public {
        IBeeFaucet faucet = _freshFaucet();
        IBeeFaucet other = _freshFaucet();
        address alice = address(0xA11CE);
        address bob = address(0xB0B);

        require(_take(faucet, alice, 6), "first share reverted");
        require(_take(faucet, alice, 4), "second share within the cap reverted");
        require(faucet.balance() == 190, "two shares did not debit 10");
        require(bee.balanceOf(alice) == uint256(CAP) * WHOLE, "alice was not paid 10 whole tokens");
        require(other.balance() == 200, "another faucet's counter changed");

        uint8 counter = faucet.balance();
        uint256 aliceTokens = bee.balanceOf(alice);
        uint256 faucetTokens = bee.balanceOf(address(_asContract(faucet)));
        require(!_take(faucet, alice, 1), "withdraw past the per-address cap succeeded");
        _assertUntouched(faucet, alice, aliceTokens, faucetTokens, counter);

        require(_take(faucet, bob, CAP), "a second address could not take its own cap");
        require(faucet.balance() == 180, "second address was not debited");
        require(bee.balanceOf(bob) == uint256(CAP) * WHOLE, "second address was paid the wrong amount");
        require(!_take(faucet, bob, 1), "second address exceeded its cap");
    }

    function test_withdrawCannotTakeTheLastRemainingToken() public {
        IBeeFaucet faucet = _freshFaucet();
        for (uint256 i = 0; i < 19; i++) {
            address visitor = address(uint160(0x1000 + i));
            require(_take(faucet, visitor, CAP), "visitor share reverted");
        }
        require(faucet.balance() == 10, "counter after 19 capped shares is not 10");

        address last = address(0x1A57);
        uint256 lastBefore = bee.balanceOf(last);
        uint256 faucetBefore = bee.balanceOf(address(_asContract(faucet)));
        require(!_take(faucet, last, CAP), "withdraw of the entire remaining counter succeeded");
        _assertUntouched(faucet, last, lastBefore, faucetBefore, 10);

        require(_take(faucet, last, 9), "withdraw that leaves one token reverted");
        require(faucet.balance() == 1, "leaving one token did not debit 9");
        require(bee.balanceOf(last) == 9 * WHOLE, "partial last share paid the wrong amount");

        address nextVisitor = address(0xA47E2);
        uint256 nextBefore = bee.balanceOf(nextVisitor);
        uint256 faucetLeft = bee.balanceOf(address(_asContract(faucet)));
        require(!_take(faucet, nextVisitor, 1), "withdraw of the last token succeeded");
        _assertUntouched(faucet, nextVisitor, nextBefore, faucetLeft, 1);
    }

    function test_restoreIsOnlyTheDeployerOfThatFaucet() public {
        IBeeFaucet faucet = _freshFaucet();
        IBeeFaucet other = _freshFaucet();
        uint256 faucetTokens = bee.balanceOf(address(_asContract(faucet)));
        uint256 otherTokens = bee.balanceOf(address(_asContract(other)));
        uint256 ownerTokens = bee.balanceOf(faucetOwner);
        uint256 strangerTokens = bee.balanceOf(stranger);
        uint256 holderTokens = bee.balanceOf(address(this));

        require(!_as(faucet, address(this), "restore(uint8)", 1), "token holder restored the faucet");
        require(!_as(faucet, stranger, "restore(uint8)", 1), "stranger restored the faucet");
        _assertCounters(faucet, 200, other, 200);
        _assertTokenGroup(faucet, other, faucetTokens, otherTokens, ownerTokens, strangerTokens, holderTokens);

        require(_as(faucet, faucetOwner, "restore(uint8)", 55), "deployer restore reverted");
        require(faucet.balance() == 255, "restore did not add 55 to this faucet");
        require(faucet.getBalance() == 255, "getBalance did not follow restore");
        require(other.balance() == 200, "restore changed the other faucet");
        _assertTokenGroup(faucet, other, faucetTokens, otherTokens, ownerTokens, strangerTokens, holderTokens);

        require(!_as(faucet, faucetOwner, "restore(uint8)", 1), "restore wrapped or accepted an overflow");
        require(faucet.balance() == 255, "overflowing restore changed the counter");
        require(other.balance() == 200, "overflowing restore changed the other faucet");
        _assertTokenGroup(faucet, other, faucetTokens, otherTokens, ownerTokens, strangerTokens, holderTokens);
    }

    function test_adminWithdrawEmptiesOnlyTheAuthorizedFaucet() public {
        IBeeFaucet faucet = _freshFaucet();
        IBeeFaucet other = _freshFaucet();
        uint256 otherTokens = bee.balanceOf(address(_asContract(other)));
        uint256 strangerTokens = bee.balanceOf(stranger);
        uint256 holderTokens = bee.balanceOf(address(this));

        require(!_as(faucet, stranger, "adminWithdraw(uint8)", 200), "stranger emptied the faucet");
        require(!_as(faucet, address(this), "adminWithdraw(uint8)", 200), "token holder emptied the faucet");
        require(faucet.balance() == 200, "unauthorized admin withdraw changed the counter");
        require(bee.balanceOf(stranger) == strangerTokens, "unauthorized admin withdraw paid a stranger");
        require(bee.balanceOf(address(this)) == holderTokens, "unauthorized admin withdraw paid the token holder");
        require(other.balance() == 200, "unauthorized admin withdraw changed the other faucet");
        require(bee.balanceOf(address(_asContract(other))) == otherTokens, "unauthorized admin withdraw moved the other faucet's tokens");

        uint256 ownerBefore = bee.balanceOf(faucetOwner);
        uint256 faucetBefore = bee.balanceOf(address(_asContract(faucet)));
        require(_as(faucet, faucetOwner, "adminWithdraw(uint8)", 200), "deployer admin withdraw reverted");
        require(faucet.balance() == 0, "admin withdraw did not empty this counter");
        require(bee.balanceOf(faucetOwner) == ownerBefore + (200 * WHOLE), "admin withdraw paid the wrong amount");
        require(bee.balanceOf(address(_asContract(faucet))) == faucetBefore - (200 * WHOLE), "admin withdraw debited the wrong faucet balance");
        require(other.balance() == 200, "admin withdraw changed the other faucet's counter");
        require(bee.balanceOf(address(_asContract(other))) == otherTokens, "admin withdraw moved the other faucet's tokens");

        address later = address(0xBEE);
        require(!_take(faucet, later, 1), "visitor withdrew after the counter was emptied");

        require(_as(faucet, faucetOwner, "restore(uint8)", 11), "deployer could not restore the emptied counter");
        require(faucet.balance() == 11, "restore after an admin withdraw did not refill this counter");
        require(other.balance() == 200, "restore after an admin withdraw changed the other faucet");
        require(_take(faucet, later, CAP), "visitor could not withdraw after restore");
        require(faucet.balance() == 1, "post-restore withdraw did not leave the last token");
        require(!_take(faucet, address(0xBEE2), 1), "post-restore withdraw took the last token");
    }

    function _freshFaucet() internal returns (IBeeFaucet faucet) {
        vm.prank(faucetOwner);
        BeeFaucet deployed = new BeeFaucet();
        faucet = IBeeFaucet(address(deployed));
        require(faucet.balance() == 200, "new faucet counter is not 200");
        require(faucet.getBalance() == 200, "new faucet getBalance is not 200");
        require(faucet.token() == BEE, "new faucet does not point at the Bee token");
        require(bee.transfer(address(deployed), 1000 * WHOLE), "funding the faucet failed");
        require(bee.balanceOf(address(deployed)) == 1000 * WHOLE, "faucet was not funded");
    }

    function _take(IBeeFaucet faucet, address from, uint8 amount) internal returns (bool ok) {
        (ok,) = _call(faucet, from, abi.encodeWithSignature("withdraw(uint8)", amount));
    }

    function _call(IBeeFaucet faucet, address from, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(from);
        (ok, ret) = address(_asContract(faucet)).call(data);
    }

    function _as(IBeeFaucet faucet, address from, string memory signature, uint8 amount) internal returns (bool ok) {
        (ok,) = _call(faucet, from, abi.encodeWithSignature(signature, amount));
    }

    function _asContract(IBeeFaucet faucet) internal pure returns (BeeFaucet) {
        return BeeFaucet(address(uint160(address(faucet))));
    }

    function _assertUntouched(
        IBeeFaucet faucet,
        address caller,
        uint256 callerBefore,
        uint256 faucetBefore,
        uint8 counter
    ) internal view {
        require(faucet.balance() == counter, "rejected call changed balance()");
        require(faucet.getBalance() == counter, "rejected call changed getBalance()");
        require(bee.balanceOf(caller) == callerBefore, "rejected call paid the caller");
        require(bee.balanceOf(address(_asContract(faucet))) == faucetBefore, "rejected call moved faucet tokens");
    }

    function _assertCounters(IBeeFaucet faucet, uint8 want, IBeeFaucet other, uint8 otherWant) internal view {
        require(faucet.balance() == want && faucet.getBalance() == want, "this faucet counter is wrong");
        require(other.balance() == otherWant && other.getBalance() == otherWant, "other faucet counter is wrong");
    }

    function _assertTokenGroup(
        IBeeFaucet faucet,
        IBeeFaucet other,
        uint256 faucetTokens,
        uint256 otherTokens,
        uint256 ownerTokens,
        uint256 strangerTokens,
        uint256 holderTokens
    ) internal view {
        require(bee.balanceOf(address(_asContract(faucet))) == faucetTokens, "restore moved this faucet's tokens");
        require(bee.balanceOf(address(_asContract(other))) == otherTokens, "restore moved the other faucet's tokens");
        require(bee.balanceOf(faucetOwner) == ownerTokens, "restore paid the deployer");
        require(bee.balanceOf(stranger) == strangerTokens, "restore paid a stranger");
        require(bee.balanceOf(address(this)) == holderTokens, "restore paid the token holder");
    }

    function _dec(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + (value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
