use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;

use crate::math::poly::{lagrange_polynomial_coefficients, Poly};

pub struct TrustedSetup {
    powers_of_tau: Vec<G1Projective>,
    tau_g2: G2Projective,
}

// Trusted setup for N elements
pub fn trusted_setup(n: usize) -> TrustedSetup {
    // Generate a random secret τ
    let tau = Scalar::from(42);

    // Use a generator of the elliptic curve
    let g = G1Projective::generator();

    // Generate powers of τ: {τ^0 * G, τ^1 * G, ..., τ^(N-1) * G}
    let mut powers_of_tau = Vec::with_capacity(n);
    let mut current_power_of_tau = Scalar::one(); // Start with τ^0 = 1

    for _ in 0..n {
        powers_of_tau.push(g * current_power_of_tau); // τ^i * G
        current_power_of_tau *= tau; // Move to τ^(i+1)
    }

    // Return the public setup elements
    TrustedSetup {
        powers_of_tau,
        tau_g2: G2Projective::generator() * tau,
    }
}

pub struct Kzg {
    trusted_setup: TrustedSetup,
}

impl Kzg {
    /// Create a new KZG context.
    pub fn new(trusted_setup: TrustedSetup) -> Self {
        Self { trusted_setup }
    }

    /// Commit to the given set of elements.
    pub fn commit_set(&self, elements: &[Scalar]) -> (Poly, [u8; 48]) {
        assert!(elements.len() <= self.trusted_setup.powers_of_tau.len());

        let x_points = (1..=elements.len() as u64)
            .map(Scalar::from)
            .collect::<Vec<_>>();

        let lagrange_poly = lagrange_polynomial_coefficients(&x_points, elements);
        let com = self.commit_poly(&lagrange_poly.poly);

        (lagrange_poly.poly, com)
    }

    /// Commit to the given polynomial.
    pub fn commit_poly(&self, poly: &Poly) -> [u8; 48] {
        assert!(poly.coeffs.len() <= self.trusted_setup.powers_of_tau.len());

        poly.encrypted_evaluation(&self.trusted_setup.powers_of_tau)
            .to_affine()
            .to_compressed()
    }

    /// Generate a ZK proof for p(z) = y.
    pub fn generate_proof(&self, poly: &Poly, z: &Scalar, y: &Scalar) -> [u8; 48] {
        // q(x) = (P(x) - y) / (x - z)
        let (quotient, remainder) = poly
            .add(&Poly::new(vec![y.neg()]))
            .divide(&Poly::new(vec![z.neg(), Scalar::one()]));

        assert!(remainder.is_none());

        self.commit_poly(&quotient)
    }

    /// Verify the KZG proof.
    pub fn verify(&self, com: &[u8; 48], proof: &[u8; 48], z: &Scalar, y: &Scalar) -> bool {
        let p1 = G1Affine::from_compressed(proof).unwrap();
        let p2 = (self.trusted_setup.tau_g2 - (G2Projective::generator() * z)).to_affine();
        let gt_left = pairing(&p1, &p2);

        let p1 =
            (G1Affine::from_compressed(com).unwrap() - (G1Projective::generator() * y)).to_affine();
        let p2 = G2Affine::generator();
        let gt_right = pairing(&p1, &p2);

        gt_left == gt_right
    }
}
