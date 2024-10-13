package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

func main() {
	// 1. Setup KZG.
	size := uint64(3)
	alpha := big.NewInt(42)
	fmt.Printf("alpha: %v\n", alpha)

	srs, err := kzg.NewSRS(size, alpha)
	if err != nil {
		panic("KZG setup failed")
	}

	// 2. Build a polynomial from a set of values.
	// 0x2 + x + 1 => f(0) = 1; f(1) = 2; f(2) = 3
	poly := make([]fr.Element, size)
	poly[0].SetInt64(1)
	poly[1].SetInt64(1)
	poly[2].SetInt64(0)

	initialCom, err := kzg.Commit(poly, srs.Pk)
	if err != nil {
		panic("commit failed")
	}
	fmt.Printf("initialCom: %v\n", initialCom)

	initialProof, err := kzg.Open(poly, fr.One(), srs.Pk)
	if err != nil {
		panic("proof failed")
	}
	fmt.Printf("initialProof: %v\n", initialProof)

	err = kzg.Verify(&initialCom, &initialProof, fr.One(), srs.Vk)
	if err != nil {
		panic("verify failed")
	}

	// 2. Update the polynomial in place.
	// -40x2 + 161x - 120 => f(0) = 1; f(1) = 42; f(2) = 3
	poly[0].SetInt64(-120)
	poly[1].SetInt64(161)
	poly[2].SetInt64(-40)

	updatedCom, err := kzg.Commit(poly, srs.Pk)
	if err != nil {
		panic("commit failed")
	}
	fmt.Printf("updatedCom: %v\n", updatedCom)

	updatedProof, err := kzg.Open(poly, fr.One(), srs.Pk)
	if err != nil {
		panic("proof failed")
	}
	fmt.Printf("updatedProof: %v\n", updatedProof)

	err = kzg.Verify(&updatedCom, &updatedProof, fr.One(), srs.Vk)
	if err != nil {
		panic("verify failed")
	}

	err = kzg.Verify(&updatedCom, &initialProof, fr.One(), srs.Vk)
	if err != nil {
		panic("verify failed")
	}

	// // 2. Create an evaluation domain.
	// domain := fft.NewDomain(uint64(degree))

	// // 3. Compute the vector of com(Li(x)) from the SRS G1 points.
	// comLis := IfftG1(domain, srs.Pk.G1)
	// // srs.Pk.G1 = comLis
	// fmt.Printf("comLis[0].X %v\n", comLis[0].X.BigInt(&bn))
	// fmt.Printf("comLis[0].Y %v\n", comLis[0].Y.BigInt(&bn))
	// fmt.Printf("comLis[1].X %v\n", comLis[1].X.BigInt(&bn))
	// fmt.Printf("comLis[1].Y %v\n", comLis[1].Y.BigInt(&bn))
	// fmt.Printf("comLis[2].X %v\n", comLis[2].X.BigInt(&bn))
	// fmt.Printf("comLis[2].Y %v\n", comLis[2].Y.BigInt(&bn))
	// fmt.Printf("comLis[3].X %v\n", comLis[3].X.BigInt(&bn))
	// fmt.Printf("comLis[3].Y %v\n", comLis[3].Y.BigInt(&bn))

	// // 4. Build a polynomial from a set of values.
	// poly := make([]fr.Element, degree)
	// for i := range poly {
	// 	poly[i].SetInt64(0)
	// }

	// // domain.FFTInverse(poly, fft.DIT)

	// // 5. Commit to the initial state.
	// initialCom, err := kzg.Commit(poly, srs.Pk)
	// if err != nil {
	// 	panic("commit failed")
	// }
	// fmt.Printf("initialCom: %v\n", initialCom)

	// //  6. Update the commitment in place (change index 1 from 0 to 42).
	// //     updatedCom = com + (new - old) * com(Li(x))
	// index := 1
	// var a bn254.G1Affine
	// a.ScalarMultiplication(&srs.Pk.G1[index], big.NewInt(42-0))
	// updatedCom := initialCom.Add(&initialCom, &a)
	// fmt.Printf("updatedCom: %v\n", *updatedCom)

	// // 7. Compare against the expected commitment.
	// for i := range poly {
	// 	poly[i].SetInt64(0)
	// }
	// poly[index].SetInt64(42)

	// // domain.FFTInverse(poly, fft.DIT)
	// expectedCom, err := kzg.Commit(poly, srs.Pk)
	// if err != nil {
	// 	panic("commit failed")
	// }
	// fmt.Printf("expectedCom: %v\n", expectedCom)

}
