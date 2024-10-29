// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";

// Cheat code address, 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D.
address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
Vm constant VM = Vm(VM_ADDRESS);
