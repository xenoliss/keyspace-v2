use alloy::primitives::keccak256;
use bls12_381::Scalar;
use math::{
    kzg::{trusted_setup, Kzg},
    poly::{lagrange_polynomial_coefficients, LagrangePoly},
};

mod bindings;
mod bridged_keystore_test_input;
mod math;

#[tokio::main]

async fn main() {
    // 1. Perform the trusted setup.
    let trusted_setup = trusted_setup(10);
    println!("Trusted setup done");

    // 2. Instanciate a KZG.
    let kzg = Kzg::new(trusted_setup);

    // 3. Compute the basis Lagrange polynimials for a random degre (10 - 1) polynomial.
    //    NOTE: we don't actually care about the y_point values, all we need is a polynimial that commits to 10 elements.
    let x_points = (1..=10).map(Scalar::from).collect::<Vec<_>>();
    let y_points = vec![Scalar::from(1); 10];
    let LagrangePoly { basis, .. } = lagrange_polynomial_coefficients(&x_points, &y_points);
    println!("Lagrange basis computed");

    // 4. Commit to each lagrange basis.
    let basis_coms = basis
        .iter()
        .map(|basis| {
            let mut h = keccak256(kzg.commit_poly(basis));
            h[31] >>= 2;
            Scalar::from_bytes(&h).unwrap()
        })
        .collect::<Vec<_>>();
    println!("Lagrange basis commitments: {basis_coms:?}");

    // 5. Commit to the set of com(Li).
    let (lis_poly, lis_com) = kzg.commit_set(&basis_coms);
    let basis_coms_com = keccak256(lis_com);
    println!("Lagrange basis commitments commitment: {basis_coms_com:?}");

    // 6. Generate a proof for the 3rd com(Li).
    let z: Scalar = Scalar::from(3);
    let y = basis_coms.get(2).unwrap();
    let proof = kzg.generate_proof(&lis_poly, &z, y);
    println!("Lagrange basis 3rd commitments proof: {proof:?}");

    // 7. Verify the proof.
    println!("Proof valid: {}", kzg.verify(&lis_com, &proof, &z, y,));
}
