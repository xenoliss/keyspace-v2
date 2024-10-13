use ark_bn254::{Bn254, Fr};
use ark_ec::{pairing::Pairing, short_weierstrass::Projective, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain,
};
use ark_poly_commit::kzg10::{Commitment, Powers, KZG10};
use ark_std::test_rng;
use hex::ToHex;

type UniPoly254 = DensePolynomial<<Bn254 as Pairing>::ScalarField>;

fn main() {
    let rng = &mut test_rng();
    let degree = 4;

    // 1. Setup
    let setup = KZG10::<Bn254, UniPoly254>::setup(degree, false, rng).expect("Setup failed");
    let powers_of_g = setup.powers_of_g[..=degree].to_vec();
    println!("powers_of_g[0] {:?}", powers_of_g[0]);

    let powers_of_gamma_g = (0..=degree).map(|i| setup.powers_of_gamma_g[&i]).collect();
    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    // println!("srs_g2: {:?}", setup.beta_h);

    let srs_g1s = setup
        .powers_of_g
        .into_iter()
        .map(Into::into)
        .collect::<Vec<Projective<_>>>();

    // 2. Create evaluation domain and get back the com(Li)s.
    let domain = Radix2EvaluationDomain::<Fr>::new(degree).unwrap();
    // println!("domain: {:?}", domain.elements().collect::<Vec<_>>());
    let srs_g1s_ifft = domain.ifft(&srs_g1s);
    println!("srs_g1s_ifft: {:?}", srs_g1s_ifft);

    // 3. Build the polynomial to commit to and commit to it.
    let values = vec![Fr::from(0); degree];
    let coeffs = domain.ifft(&values);
    let poly = UniPoly254::from_coefficients_slice(&coeffs);
    // println!("poly: {poly:?}");

    let (comm, _) =
        KZG10::<Bn254, UniPoly254>::commit(&powers, &poly, None, None).expect("Commitment failed");
    // println!("Initial state comm: {comm:?}");

    // 4. Update the commitment in place (change index 1 from 3 to 10).
    let index = 1;
    println!(
        "domain[index]: {:?}",
        domain
            .element(index)
            .into_bigint()
            .to_bytes_be()
            .encode_hex::<String>()
    );

    let new_value = Fr::from(10);
    println!("new_value: {:?}", new_value);
    let comm: Projective<_> = comm.0.into();
    let comm = comm + srs_g1s_ifft[index] * (new_value - values[index]);
    let comm = Commitment::<Bn254>(comm.into_affine());
    // println!("Updated state comm: {:?}", comm);

    // 5. Compare against the expected commitment.
    let mut values = vec![Fr::from(0); degree];
    values[index] = new_value;
    let coeffs = domain.ifft(&values);
    let poly = UniPoly254::from_coefficients_slice(&coeffs);
    let (expected_comm, _) =
        KZG10::<Bn254, UniPoly254>::commit(&powers, &poly, None, None).expect("Commitment failed");
    println!("Expected state comm: {expected_comm:?}");

    assert!(expected_comm == comm);
}
