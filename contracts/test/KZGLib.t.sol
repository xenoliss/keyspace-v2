// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {KZGLib} from "../src/libs/KZGLib.sol";

contract KZGLiTest is Test {
    function test_verify() public view {
        bytes memory com =
            hex"8e1ecc5eb459120eb3aa4cada6d437a323b35ceb935f60a8f9bd77e863456fbf9a11ce4ebe642f5cad93a4302aed723c";

        bytes memory proof =
            hex"a6e228d5ce2459947e2656bb861c4ca67fe61d8856f32b9c903fbe404b792e26d06cdaa829ad37dd888e6f09e2e61203";

        bytes32 z = 0x0000000000000000000000000000000000000000000000000000000000000003;
        bytes32 y = 0x2d2a7e4fa6d4ec2d3b95b18fefcd550c87636779818142e2deef930193ae083a;

        (bool success, bytes memory res) = KZGLib.verify({com: com, proof: proof, z: z, y: y});
        console.logBool(success);
        console.logBytes(res);
    }
}
