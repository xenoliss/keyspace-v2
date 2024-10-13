// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

struct G1Point {
    uint256 x;
    uint256 y;
}

struct G2Point {
    uint256[2] xs;
    uint256[2] ys;
}

uint256 constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
uint256 constant G1_X = 1;
uint256 constant G1_Y = 2;
uint256 constant G2_X1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
uint256 constant G2_X2 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
uint256 constant G2_Y1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
uint256 constant G2_Y2 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;

library KZGLib {
    struct Pairing {
        uint256 aG1x;
        uint256 aG1y;
        uint256 bG2x2;
        uint256 bG2x1;
        uint256 bG2y2;
        uint256 bG2y1;
    }

    function verify(uint256 z, uint256 y, G1Point memory com, G1Point memory proof, G2Point memory tau) internal view {
        // e(C − [y]1, H) = e(π, [𝝉 − z]2)
        // e(C − [y]1, H) * e(π, [𝝉 − z]2)^-1 = 1
        // e(C − [y]1, H) * e(-π, [𝝉 − z]2) = 1

        // TODO: Check if adding 1 more pairing is effectively cheaper than implementing point addition in G2.
        // We avoid having to compute [𝝉 − z]2 by doing the following changes:
        // e(C − [y]1, H) * e(-π, [𝝉 − z]2) = 1
        // e(C − [y]1, H) * e(-π, [𝝉]2) * e(-π, -[z]2) = 1
        // e(C − [y]1, H) * e(-π, [𝝉]2) * e(π, [z]2) = 1
        // e(C − [y]1, H) * e(-π, [𝝉]2) * e(z * π, [G]2) = 1

        // 1. Compute −[y]1
        (uint256 yG1X, uint256 yG1Y) = _scalarMul({x: G1_X, y: G1_Y, s: y});
        uint256 negYG1Y = _neg({x: yG1X, y: yG1Y});

        // 2. Negate -π.
        uint256 negProofG1Y = _neg({x: proof.x, y: proof.y});

        // 3. Compute z * π.
        (uint256 zPiX, uint256 zPiy) = _scalarMul({x: proof.x, y: proof.y, s: z});

        // 4. Compute comSub = C − [y]1.
        (uint256 comSubX, uint256 comSubY) = _add({aX: com.x, aY: com.y, bX: yG1X, bY: negYG1Y});

        // 5. Prepare args for e(C − [y]1, H).
        Pairing memory p1 =
            Pairing({aG1x: comSubX, aG1y: comSubY, bG2x2: G2_X2, bG2x1: G2_X1, bG2y2: G2_Y2, bG2y1: G2_Y1});

        // 6. Prepare args for e(-π, [s]2).
        Pairing memory p2 = Pairing({
            aG1x: proof.x,
            aG1y: negProofG1Y,
            bG2x2: tau.xs[1],
            bG2x1: tau.xs[0],
            bG2y2: tau.ys[1],
            bG2y1: tau.ys[0]
        });

        // 6. Prepare args for e(z * π, [G]2).
        Pairing memory p3 = Pairing({aG1x: zPiX, aG1y: zPiy, bG2x2: G2_X2, bG2x1: G2_X1, bG2y2: G2_Y2, bG2y1: G2_Y1});

        (bool success,) = address(0x8).staticcall(abi.encode(p1, p2, p3));
        if (!success) {
            revert("pairing failed");
        }
    }

    function _neg(uint256 x, uint256 y) private pure returns (uint256 y_) {
        if (x == 0 && y == 0) {
            return 0;
        } else {
            return Q - (y % Q);
        }
    }

    function _add(uint256 aX, uint256 aY, uint256 bX, uint256 bY) private view returns (uint256 x, uint256 y) {
        (bool success, bytes memory res_) = address(0x6).staticcall(abi.encodePacked(aX, aY, bX, bY));
        if (!success) {
            revert("add failed");
        }

        (x, y) = abi.decode(res_, (uint256, uint256));
    }

    function _scalarMul(uint256 x, uint256 y, uint256 s) private view returns (uint256 x_, uint256 y_) {
        (bool success, bytes memory res_) = address(0x7).staticcall(abi.encodePacked(x, y, s));
        if (!success) {
            revert("scalar mul failed");
        }

        (x_, y_) = abi.decode(res_, (uint256, uint256));
    }
}
