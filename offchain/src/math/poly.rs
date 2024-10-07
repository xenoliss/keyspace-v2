use bls12_381::{G1Projective, Scalar};

#[derive(Debug, Clone)]
pub struct Poly {
    pub coeffs: Vec<Scalar>,
}

impl Poly {
    pub fn new(coeffs: Vec<Scalar>) -> Self {
        Self { coeffs }
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
    }

    pub fn is_null(&self) -> bool {
        self.coeffs.iter().all(|c| *c == Scalar::zero())
    }

    /// Function to perform polynomial evaluation.
    pub fn eval(&self, point: impl Into<Scalar>) -> Scalar {
        // Initialize the result.
        let mut result = Scalar::zero();

        // Perform the summation c_i * point^i
        let point = point.into();
        let mut current_power = Scalar::one(); // Start with point^0 = 1
        for coeff in self.coeffs.iter() {
            result += current_power * coeff;
            current_power *= point;
        }

        result
    }

    /// Function to perform encrypted polynomial evaluation.
    pub fn encrypted_evaluation(&self, point_powers: &[G1Projective]) -> G1Projective {
        // Initialize the result as the identity element (point at infinity)
        let mut result = G1Projective::identity();

        // Perform the summation c_i * (point^i * G)
        for (i, coeff) in self.coeffs.iter().enumerate() {
            let term = point_powers[i] * coeff;
            result += term;
        }

        result
    }

    /// Sum up two polynomials represented as coefficient vectors
    pub fn add(&self, other: &Poly) -> Poly {
        let mut coeffs = vec![Scalar::zero(); std::cmp::max(self.coeffs.len(), other.coeffs.len())];

        for i in 0..self.coeffs.len() {
            coeffs[i] += self.coeffs[i];
        }

        for i in 0..other.coeffs.len() {
            coeffs[i] += other.coeffs[i];
        }

        let mut p = Poly { coeffs };
        p.clean();
        p
    }

    /// Function to multiply two polynomials represented as vectors of coefficients
    pub fn multiply(&self, other: &Poly) -> Poly {
        let mut coeffs = vec![Scalar::zero(); self.coeffs.len() + other.coeffs.len() - 1];

        for i in 0..self.coeffs.len() {
            for j in 0..other.coeffs.len() {
                coeffs[i + j] += self.coeffs[i] * other.coeffs[j];
            }
        }

        let mut p = Poly { coeffs };
        p.clean();
        p
    }

    /// Multiply polynomial by a scalar (for the y_i * l_i(x) operation)
    pub fn multiply_scalar(&self, scalar: &Scalar) -> Poly {
        let mut p = Poly {
            coeffs: self.coeffs.iter().map(|&c| c * scalar).collect(),
        };

        p.clean();
        p
    }

    /// Perform synthetic division to divide `self` by (x - z).
    pub fn divide(&self, divisor: &Poly) -> (Poly, Option<Poly>) {
        let minus_one = Scalar::one().neg();

        // Will store the quotient polynomial coefficients.
        // Those will need to be reversed before being used to build a Poly.
        let mut quotient_coeffs_rev = vec![];

        let mut remainder = None;
        let mut dividend = Poly::new(self.coeffs.clone());
        loop {
            // Exit the loop once we're done.
            if dividend.degree() < divisor.degree() {
                if !dividend.is_null() {
                    remainder = Some(dividend);
                }

                break;
            }

            // Get the leading dividend coeff.
            let dividend_leading_coeff = dividend.coeffs.last().unwrap();

            // Set the next term of the quotient.
            quotient_coeffs_rev.push(*dividend_leading_coeff);

            // Simulate a division by x by moving the dividend_leading_coeff one back.
            let mut coeffs = vec![Scalar::zero(); dividend.coeffs.len() - 1];
            *coeffs.last_mut().unwrap() = *dividend_leading_coeff;

            // Multiply the divisor (x - z) by this term.
            let to_sub = divisor.multiply(&Poly::new(coeffs));

            // Substract that from the dividend.
            dividend = dividend.add(&to_sub.multiply_scalar(&minus_one));
        }

        quotient_coeffs_rev.reverse();
        (Poly::new(quotient_coeffs_rev), remainder)
    }

    fn clean(&mut self) {
        while self.coeffs[1..].last() == Some(&Scalar::zero()) {
            self.coeffs.pop();
        }
    }
}

#[derive(Debug, Clone)]
pub struct LagrangePoly {
    pub poly: Poly,
    pub basis: Vec<Poly>,
}

/// Compute the coefficients of the Lagrange polynomial
pub fn lagrange_polynomial_coefficients(x_points: &[Scalar], y_points: &[Scalar]) -> LagrangePoly {
    let mut poly = Poly::new(vec![Scalar::zero()]); // Start with the zero polynomial

    let mut basis = Vec::with_capacity(x_points.len());
    for (i, y_point) in y_points.iter().enumerate().take(x_points.len()) {
        // Compute the basis polynomial l_i(x) in coefficient form
        let basis_poly = lagrange_basis_coefficients(x_points, i);

        // Multiply the basis polynomial by y_i
        let weighted_basis_poly = basis_poly.multiply_scalar(y_point);

        // Add to the result polynomial
        poly = poly.add(&weighted_basis_poly);

        // Add the basis polynomial.
        basis.push(basis_poly);
    }

    LagrangePoly { poly, basis }
}

/// Compute the Lagrange basis polynomial l_i(x) in coefficient form
fn lagrange_basis_coefficients(x_points: &[Scalar], i: usize) -> Poly {
    let mut basis_poly = Poly::new(vec![Scalar::one()]); // Start with the polynomial 1 (constant)

    let x_point_i = x_points[i];
    for (j, x_point_j) in x_points.iter().enumerate() {
        if j == i {
            continue;
        }

        // The linear factor (x - x_j) / (x_i - x_j)
        let denom = (x_point_i - x_point_j).invert().unwrap(); // (x_i - x_j)^(-1)
        let factor = Poly::new(vec![-x_point_j * denom, denom]);
        basis_poly = basis_poly.multiply(&factor);
    }

    basis_poly
}
