// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {G1Point, G2Point, KZGLib} from "../src/libs/kzg/KZGLib.sol";

contract KZGLibTest is Test {
    function test_verify() public view {
        G2Point memory tau = G2Point({
            xs: [
                0x116da8c89a0d090f3d8644ada33a5f1c8013ba7204aeca62d66d931b99afe6e7,
                0x12740934ba9615b77b6a49b06fcce83ce90d67b1d0e2a530069e3a7306569a91
            ],
            ys: [
                0x076441042e77b6309644b56251f059cf14befc72ac8a6157d30924e58dc4c172,
                0x25222d9816e5f86b4a7dedd00d04acc5c979c18bd22b834ea8c6d07c0ba441db
            ]
        });

        G1Point memory com = G1Point({
            x: 0x1ffe64ab2a77b2d7c9c2a07585e328a2952aabd3b6a71b6ea73f1883cd9318ab,
            y: 0x26d26e1556f3065f0a4212e2217e270237ca54abded1571db1e3872f7f61de1c
        });

        G1Point memory proof = G1Point({
            x: 0x01033af6313a6b1d211473409857fe9e202cacd420c141f434b25ef02c8e9e94,
            y: 0x2aaa17f74acf21170eef89274178b260508fcd4cece0eed17d0c3c580c01f7d4
        });

        uint256 z = 0x30644e72e131a029048b6e193fd841045cea24f6fd736bec231204708f703636;
        uint256 y = 0x0000000000000000000000000000000000000000000000000000000000000002;

        KZGLib.verify({z: z, y: y, com: com, proof: proof, tau: tau});
    }
}
