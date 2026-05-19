//! R1CS constraint system for Bulletproofs (Bulletproofs §5, BCC+16 Appendix A).
//!
//! A constraint system over `F_p` is built from:
//! * **multiplication gates** `a_L[i] · a_R[i] = a_O[i]` (`i = 0..n`),
//! * **committed values** `v[j]` with Pedersen commitments `V[j]` (`j = 0..m`),
//! * **linear constraints** `<W_L[q], a_L> + <W_R[q], a_R> + <W_O[q], a_O> + <W_V[q], v> + c[q] = 0`
//!   for each `q = 0..Q`.
//!
//! The constraints are expressed as `LinearCombination`s over [`Variable`]s.
//! Both prover and verifier build the *same* circuit (so the verifier knows
//! `W_*`), but only the prover assigns values.

use crate::curves::Fp;
use ark_ff::{One, Zero};
use std::ops::{Add, Mul, Neg, Sub};

/// A wire in the constraint system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variable {
    /// Committed value `v[j]`.
    Committed(usize),
    /// Left input of multiplication gate `i`.
    MultiplierLeft(usize),
    /// Right input of multiplication gate `i`.
    MultiplierRight(usize),
    /// Output of multiplication gate `i`.
    MultiplierOutput(usize),
    /// The constant `1`.
    One,
}

/// A linear combination `∑ c_i · x_i + c_0`.
///
/// Stored as a flat `(variable, coefficient)` list rather than a map: every
/// downstream consumer (`flatten`, `Assignments::eval`) treats repeated
/// variables additively, so the dedup a map would buy is dead work — and the
/// gadgets the `R_eVRF` circuit uses never produce repeats anyway.  This keeps
/// circuit construction a `Vec::push` rather than a `BTreeMap` insert.
#[derive(Clone, Debug, Default)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, Fp)>,
}

impl LinearCombination {
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }
    pub fn constant(c: Fp) -> Self {
        if c.is_zero() {
            Self::zero()
        } else {
            Self {
                terms: vec![(Variable::One, c)],
            }
        }
    }
    pub fn add_term(&mut self, v: Variable, c: Fp) {
        if !c.is_zero() {
            self.terms.push((v, c));
        }
    }
}

impl From<Variable> for LinearCombination {
    fn from(v: Variable) -> Self {
        Self {
            terms: vec![(v, Fp::one())],
        }
    }
}
impl From<Fp> for LinearCombination {
    fn from(c: Fp) -> Self {
        Self::constant(c)
    }
}

impl Add<LinearCombination> for LinearCombination {
    type Output = Self;
    fn add(mut self, rhs: LinearCombination) -> Self {
        self.terms.extend(rhs.terms);
        self
    }
}
impl Sub<LinearCombination> for LinearCombination {
    type Output = Self;
    fn sub(self, rhs: LinearCombination) -> Self {
        self + (-rhs)
    }
}
impl Neg for LinearCombination {
    type Output = Self;
    fn neg(mut self) -> Self {
        for (_, c) in &mut self.terms {
            *c = -*c;
        }
        self
    }
}
impl Mul<Fp> for LinearCombination {
    type Output = Self;
    fn mul(mut self, s: Fp) -> Self {
        if s.is_zero() {
            return Self::zero();
        }
        for (_, c) in &mut self.terms {
            *c *= s;
        }
        self
    }
}
impl Add<Variable> for LinearCombination {
    type Output = Self;
    fn add(mut self, rhs: Variable) -> Self {
        self.add_term(rhs, Fp::one());
        self
    }
}
impl Sub<Variable> for LinearCombination {
    type Output = Self;
    fn sub(mut self, rhs: Variable) -> Self {
        self.add_term(rhs, -Fp::one());
        self
    }
}
impl Add<Fp> for LinearCombination {
    type Output = Self;
    fn add(mut self, rhs: Fp) -> Self {
        self.add_term(Variable::One, rhs);
        self
    }
}
impl Sub<Fp> for LinearCombination {
    type Output = Self;
    fn sub(mut self, rhs: Fp) -> Self {
        self.add_term(Variable::One, -rhs);
        self
    }
}

/// Common circuit-building interface for the prover and verifier.
pub trait ConstraintSystem {
    /// Allocate a multiplication gate.  The prover supplies `(left, right)`
    /// values; the verifier passes `None`.  Returns the three wires.
    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable);

    /// Allocate a multiplication gate whose inputs are unconstrained
    /// (i.e., free witness wires).  Returns `(L, R, O)`.
    fn allocate_multiplier(
        &mut self,
        assignment: Option<(Fp, Fp)>,
    ) -> Result<(Variable, Variable, Variable), String>;

    /// Add the linear constraint `lc == 0`.
    fn constrain(&mut self, lc: LinearCombination);

    /// Number of multiplication gates so far.
    fn num_multipliers(&self) -> usize;

    /// Evaluate a linear combination.  Only meaningful for the prover; returns
    /// `None` on the verifier.
    fn eval(&self, lc: &LinearCombination) -> Option<Fp>;
}

/// Witness assignments for the prover.
#[derive(Clone, Debug, Default)]
pub struct Assignments {
    pub a_l: Vec<Fp>,
    pub a_r: Vec<Fp>,
    pub a_o: Vec<Fp>,
    pub v: Vec<Fp>,
}

impl Assignments {
    pub fn eval(&self, lc: &LinearCombination) -> Fp {
        let mut acc = Fp::zero();
        for (var, c) in &lc.terms {
            acc += *c
                * match var {
                    Variable::Committed(j) => self.v[*j],
                    Variable::MultiplierLeft(i) => self.a_l[*i],
                    Variable::MultiplierRight(i) => self.a_r[*i],
                    Variable::MultiplierOutput(i) => self.a_o[*i],
                    Variable::One => Fp::one(),
                };
        }
        acc
    }
}

/// Flattened linear-constraint matrices `W_L, W_R, W_O, W_V, c` evaluated at
/// the verifier's challenge `z` (i.e. `z^q`-weighted sums of the rows).
///
/// `W_L^T z, W_R^T z, W_O^T z, W_V^T z, <z, c>`.
#[derive(Clone, Debug)]
pub struct FlattenedConstraints {
    pub w_l: Vec<Fp>,
    pub w_r: Vec<Fp>,
    pub w_o: Vec<Fp>,
    pub w_v: Vec<Fp>,
    pub w_c: Fp,
}

/// Flatten a list of `LinearCombination` constraints by `z^1, z^2, …, z^Q`
/// (Bulletproofs §5.2).
///
/// Each constraint is `⟨W_L, a_L⟩ + ⟨W_R, a_R⟩ + ⟨W_O, a_O⟩ − ⟨W_V, v⟩ − c·1 = 0`,
/// i.e. the standard R1CS row form `⟨W_L, a_L⟩ + ⟨W_R, a_R⟩ + ⟨W_O, a_O⟩ = ⟨W_V, v⟩ + c`.
/// Committed-variable and constant coefficients are therefore *negated* when
/// collected into `w_v` and `w_c`.
pub fn flatten(
    constraints: &[LinearCombination],
    n: usize,
    m: usize,
    z: Fp,
) -> FlattenedConstraints {
    let mut w_l = vec![Fp::zero(); n];
    let mut w_r = vec![Fp::zero(); n];
    let mut w_o = vec![Fp::zero(); n];
    let mut w_v = vec![Fp::zero(); m];
    let mut w_c = Fp::zero();
    let mut zq = z;
    for lc in constraints {
        for (var, c) in &lc.terms {
            let coeff = *c * zq;
            match var {
                Variable::MultiplierLeft(i) => w_l[*i] += coeff,
                Variable::MultiplierRight(i) => w_r[*i] += coeff,
                Variable::MultiplierOutput(i) => w_o[*i] += coeff,
                Variable::Committed(j) => w_v[*j] -= coeff,
                Variable::One => w_c -= coeff,
            }
        }
        zq *= z;
    }
    FlattenedConstraints {
        w_l,
        w_r,
        w_o,
        w_v,
        w_c,
    }
}
