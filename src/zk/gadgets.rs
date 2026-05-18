//! Circuit gadgets for the `R_eVRF` circuit.
//!
//! The constraint field is `F_p` (BLS12-381 scalar field), which is also the
//! base field of the embedded curve `G_in` (Jubjub).  This makes Jubjub point
//! arithmetic *native* in the circuit.
//!
//! ## Witness handling
//!
//! Every gadget keeps a *parallel witness*: the prover threads `Some(value)`
//! through; the verifier passes `None`.  The constraint system itself only
//! sees `LinearCombination`s and multiplier wires, so both sides build the
//! same circuit shape.  The shapes must be *exactly* identical or the
//! Fiat-Shamir transcripts diverge.
//!
//! ## Cost summary (number of multiplication gates)
//!
//! | gadget                   | muls         |
//! |--------------------------|--------------|
//! | `bit_decompose(λ)`       | `λ`          |
//! | `add_const`              | 3            |
//! | `add_var`                | 8            |
//! | `cond_add_const`         | 5 (= 3 + 2)  |
//! | `scalar_mul_const(λ)`    | `5λ + 3`     |
//! | `r_eVRF` total ≈ 4·sm + 2·bd ≈ `22λ + …` (we don't try to hit the
//!   paper's `14λ + 14`; that figure assumes more aggressive windowing/sharing.) |

use crate::curves::{Fp, Fs, GinAffine, GinProj};
use crate::zk::r1cs::{ConstraintSystem, LinearCombination};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ed_on_bls12_381::JubjubConfig;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

/// Number of bits used for scalar decompositions in the `R_eVRF` circuit.
/// `int(S.x)` is an `F_p` element of up to 255 bits; `sk_1` is an `F_s`
/// element of up to 252 bits.  We use 255 to cover both.
pub const LAMBDA: usize = 255;

/// A scalar in the circuit: an LC plus the prover's value.
#[derive(Clone, Debug)]
pub struct ScalarVar {
    pub lc: LinearCombination,
    pub w: Option<Fp>,
}
impl ScalarVar {
    pub fn constant(v: Fp) -> Self {
        Self {
            lc: LinearCombination::constant(v),
            w: Some(v),
        }
    }
    pub fn from_committed<CS: ConstraintSystem>(
        cs: &CS,
        v: crate::zk::r1cs::Variable,
        witness: Option<Fp>,
    ) -> Self {
        let lc = LinearCombination::from(v);
        Self {
            lc: lc.clone(),
            w: cs.eval(&lc).or(witness),
        }
    }
    pub fn add(&self, other: &Self) -> Self {
        Self {
            lc: self.lc.clone() + other.lc.clone(),
            w: self.w.zip(other.w).map(|(a, b)| a + b),
        }
    }
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            lc: self.lc.clone() - other.lc.clone(),
            w: self.w.zip(other.w).map(|(a, b)| a - b),
        }
    }
    pub fn scale(&self, c: Fp) -> Self {
        Self {
            lc: self.lc.clone() * c,
            w: self.w.map(|v| v * c),
        }
    }
    pub fn shift(&self, c: Fp) -> Self {
        Self {
            lc: self.lc.clone() + c,
            w: self.w.map(|v| v + c),
        }
    }
}

/// A point in the circuit (affine Edwards coordinates).
#[derive(Clone, Debug)]
pub struct PointVar {
    pub x: ScalarVar,
    pub y: ScalarVar,
    pub w: Option<GinAffine>,
}
impl PointVar {
    pub fn constant(p: &GinAffine) -> Self {
        Self {
            x: ScalarVar::constant(p.x),
            y: ScalarVar::constant(p.y),
            w: Some(*p),
        }
    }
    pub fn from_xy(x: ScalarVar, y: ScalarVar) -> Self {
        let w = x.w.zip(y.w).map(|(x, y)| GinAffine::new_unchecked(x, y));
        Self { x, y, w }
    }
}

/// `c = a * b` — both inputs constrained.  1 mul gate.
fn mul<CS: ConstraintSystem>(cs: &mut CS, a: &ScalarVar, b: &ScalarVar) -> ScalarVar {
    let (vl, vr, vo) = cs.allocate_multiplier(a.w.zip(b.w)).unwrap();
    cs.constrain(a.lc.clone() - vl);
    cs.constrain(b.lc.clone() - vr);
    ScalarVar {
        lc: LinearCombination::from(vo),
        w: a.w.zip(b.w).map(|(a, b)| a * b),
    }
}

/// `q = num / den` — allocate `q` as a free witness wire and constrain
/// `q · den = num`.  1 mul gate + 2 linear constraints.  Caller must ensure
/// `den ≠ 0` (always true for Jubjub's complete Edwards formulas).
fn div<CS: ConstraintSystem>(cs: &mut CS, num: &ScalarVar, den: &ScalarVar) -> ScalarVar {
    let q_w = num
        .w
        .zip(den.w)
        .map(|(n, d)| n * d.inverse().expect("nonzero denominator"));
    let (vl, vr, vo) = cs.allocate_multiplier(q_w.zip(den.w)).unwrap();
    cs.constrain(den.lc.clone() - vr);
    cs.constrain(num.lc.clone() - vo);
    ScalarVar {
        lc: LinearCombination::from(vl),
        w: q_w,
    }
}

/// `out = c + b·(a − c)` for boolean `b`.  1 mul gate.
fn cond_select<CS: ConstraintSystem>(
    cs: &mut CS,
    b: &ScalarVar,
    a: &ScalarVar,
    c: &ScalarVar,
) -> ScalarVar {
    let diff = a.sub(c);
    let prod = mul(cs, b, &diff);
    c.add(&prod)
}

/// Decompose a `ScalarVar` into `n_bits` little-endian boolean `ScalarVar`s.
/// `n_bits` mul gates.  Caller must ensure `value < 2^n_bits`.
pub fn bit_decompose<CS: ConstraintSystem>(
    cs: &mut CS,
    value: &ScalarVar,
    n_bits: usize,
) -> Vec<ScalarVar> {
    let bits_w: Option<Vec<bool>> = value.w.map(|v| fp_to_bits_le(&v, n_bits));
    let mut out = Vec::with_capacity(n_bits);
    let mut sum = LinearCombination::zero();
    let mut pow = Fp::one();
    for i in 0..n_bits {
        let bw = bits_w.as_ref().map(|b| b[i]);
        // `b·(1−b) = 0`: allocate (l = b, r = 1−b), constrain l + r = 1, o = 0.
        let assignment = bw.map(|b| {
            let bf = Fp::from(b as u64);
            (bf, Fp::one() - bf)
        });
        let (vl, vr, vo) = cs.allocate_multiplier(assignment).unwrap();
        cs.constrain(LinearCombination::from(vl) + vr - Fp::one());
        cs.constrain(LinearCombination::from(vo));
        sum.add_term(vl, pow);
        pow.double_in_place();
        out.push(ScalarVar {
            lc: LinearCombination::from(vl),
            w: bw.map(|b| Fp::from(b as u64)),
        });
    }
    cs.constrain(sum - value.lc.clone());
    out
}

/// `out = P + Q` with `Q` a circuit constant.  3 mul gates.
///
/// ```text
///   x3 = (cy·x1 + cx·y1) / (1 + d·cx·cy·x1·y1)
///   y3 = (cy·y1 − a·cx·x1) / (1 − d·cx·cy·x1·y1)
/// ```
pub fn add_const<CS: ConstraintSystem>(cs: &mut CS, p: &PointVar, q: &GinAffine) -> PointVar {
    let a = JubjubConfig::COEFF_A;
    let d = JubjubConfig::COEFF_D;
    let (cx, cy) = (q.x, q.y);
    // u = x1 y1.
    let u = mul(cs, &p.x, &p.y);
    let dccu = u.scale(d * cx * cy);
    let den_x = dccu.shift(Fp::one());
    let den_y = dccu.scale(-Fp::one()).shift(Fp::one());
    let num_x = p.x.scale(cy).add(&p.y.scale(cx));
    let num_y = p.y.scale(cy).sub(&p.x.scale(a * cx));
    let x3 = div(cs, &num_x, &den_x);
    let y3 = div(cs, &num_y, &den_y);
    let pq_w =
        p.w.map(|pw| (GinProj::from(pw) + GinProj::from(*q)).into_affine());
    PointVar {
        x: x3,
        y: y3,
        w: pq_w,
    }
}

/// `out = P + Q` for a variable `Q`.  8 mul gates.
pub fn add_var<CS: ConstraintSystem>(cs: &mut CS, p: &PointVar, q: &PointVar) -> PointVar {
    let a = JubjubConfig::COEFF_A;
    let d = JubjubConfig::COEFF_D;
    let x1x2 = mul(cs, &p.x, &q.x);
    let y1y2 = mul(cs, &p.y, &q.y);
    let x1y2 = mul(cs, &p.x, &q.y);
    let y1x2 = mul(cs, &p.y, &q.x);
    let t = mul(cs, &x1x2, &y1y2);
    let dt = t.scale(d);
    let den_x = dt.shift(Fp::one());
    let den_y = dt.scale(-Fp::one()).shift(Fp::one());
    let num_x = x1y2.add(&y1x2);
    let num_y = y1y2.sub(&x1x2.scale(a));
    let x3 = div(cs, &num_x, &den_x);
    let y3 = div(cs, &num_y, &den_y);
    let pq_w =
        p.w.zip(q.w)
            .map(|(pw, qw)| (GinProj::from(pw) + GinProj::from(qw)).into_affine());
    PointVar {
        x: x3,
        y: y3,
        w: pq_w,
    }
}

/// `out = P + b·Q` with `Q` a circuit constant.  5 mul gates.
fn cond_add_const<CS: ConstraintSystem>(
    cs: &mut CS,
    p: &PointVar,
    bit: &ScalarVar,
    q: &GinAffine,
) -> PointVar {
    let s = add_const(cs, p, q);
    let out_x = cond_select(cs, bit, &s.x, &p.x);
    let out_y = cond_select(cs, bit, &s.y, &p.y);
    let bw = bit.w.map(|b| !b.is_zero());
    let out_w = bw
        .zip(p.w.zip(s.w))
        .map(|(b, (pw, sw))| if b { sw } else { pw });
    PointVar {
        x: out_x,
        y: out_y,
        w: out_w,
    }
}

/// Constrain a point to be on Jubjub: `a x² + y² = 1 + d x² y²`.  3 mul gates.
pub fn on_curve<CS: ConstraintSystem>(cs: &mut CS, p: &PointVar) {
    let a = JubjubConfig::COEFF_A;
    let d = JubjubConfig::COEFF_D;
    let xx = mul(cs, &p.x, &p.x);
    let yy = mul(cs, &p.y, &p.y);
    let xxyy = mul(cs, &xx, &yy);
    cs.constrain(xx.lc * a + yy.lc - xxyy.lc * d - Fp::one());
}

/// Constrain `p == q` (same coordinates).
pub fn assert_eq_point<CS: ConstraintSystem>(cs: &mut CS, p: &PointVar, q: &GinAffine) {
    cs.constrain(p.x.lc.clone() - q.x);
    cs.constrain(p.y.lc.clone() - q.y);
}

/// `out = ⟨bits, [B, 2B, 4B, …]⟩` — fixed-base scalar multiplication.
/// `5·n_bits + 3` mul gates.  The base `B` is a circuit constant.
///
/// Uses the offset trick: `acc₀ = O`, `acc_{i+1} = acc_i + b_i·(2^i B)`,
/// `out = acc_λ − O`.  (Twisted Edwards complete addition tolerates the
/// identity, but an offset gives a clean accumulator and one consistent code
/// path; the cost is a single extra `add_const` at the end.)
pub fn scalar_mul_const<CS: ConstraintSystem>(
    cs: &mut CS,
    bits: &[ScalarVar],
    base: &GinAffine,
) -> PointVar {
    let offset = offset_point();
    let mut acc = PointVar::constant(&offset);
    let mut q = *base;
    for bit in bits {
        acc = cond_add_const(cs, &acc, bit, &q);
        q = (GinProj::from(q).double()).into_affine();
    }
    add_const(cs, &acc, &(-offset))
}

/// Fixed offset point — an arbitrary non-identity prime-order Jubjub point.
fn offset_point() -> GinAffine {
    crate::hash_to_curve::hash_to_gin(b"gadget-offset", b"v1")
}

/// Decompose an `Fp` element into `n_bits` little-endian bits.
pub fn fp_to_bits_le(v: &Fp, n_bits: usize) -> Vec<bool> {
    let mut bits = v.into_bigint().to_bits_le();
    bits.resize(n_bits, false);
    bits.truncate(n_bits);
    bits
}

/// Decompose an `Fs` element into `n_bits` little-endian bits.
pub fn fs_to_bits_le(v: &Fs, n_bits: usize) -> Vec<bool> {
    let mut bits = v.into_bigint().to_bits_le();
    bits.resize(n_bits, false);
    bits.truncate(n_bits);
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::bp_r1cs::{Prover, Verifier};
    use crate::zk::generators::BpGens;
    use crate::zk::r1cs::Variable;
    use ark_ec::{AffineRepr, PrimeGroup};
    use ark_std::UniformRand;
    use merlin::Transcript;

    fn alloc_bit<CS: ConstraintSystem>(cs: &mut CS, b: Option<bool>) -> ScalarVar {
        let assignment = b.map(|b| {
            let bf = Fp::from(b as u64);
            (bf, Fp::one() - bf)
        });
        let (vl, vr, vo) = cs.allocate_multiplier(assignment).unwrap();
        cs.constrain(LinearCombination::from(vl) + vr - Fp::one());
        cs.constrain(LinearCombination::from(vo));
        ScalarVar {
            lc: LinearCombination::from(vl),
            w: b.map(|b| Fp::from(b as u64)),
        }
    }

    #[test]
    fn fp_bits_roundtrip() {
        let v = Fp::from(12345u64);
        let bits = fp_to_bits_le(&v, 64);
        let mut acc = Fp::zero();
        let mut p = Fp::one();
        for b in &bits {
            if *b {
                acc += p;
            }
            p.double_in_place();
        }
        assert_eq!(acc, v);
    }

    #[test]
    fn bit_decompose_gadget() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(64);
        let v = Fp::from(42u64);

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let (vc, vv) = prover.commit(v, Fp::rand(&mut rng));
        let svar = ScalarVar {
            lc: LinearCombination::from(vv),
            w: Some(v),
        };
        bit_decompose(&mut prover, &svar, 8);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let vv = verifier.commit(vc);
        let svar = ScalarVar {
            lc: LinearCombination::from(vv),
            w: None,
        };
        bit_decompose(&mut verifier, &svar, 8);
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn add_const_gadget() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(8);
        let p = (GinProj::generator() * Fs::from(7u64)).into_affine();
        let q = (GinProj::generator() * Fs::from(11u64)).into_affine();
        let expected = (GinProj::from(p) + GinProj::from(q)).into_affine();

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let out = add_const(&mut prover, &PointVar::constant(&p), &q);
        assert_eq!(out.w.unwrap(), expected);
        assert_eq!(out.x.w.unwrap(), expected.x);
        assert_eq!(out.y.w.unwrap(), expected.y);
        assert_eq_point(&mut prover, &out, &expected);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let out = add_const(&mut verifier, &PointVar::constant(&p), &q);
        assert_eq_point(&mut verifier, &out, &expected);
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn add_var_gadget() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(16);
        let p = (GinProj::generator() * Fs::from(7u64)).into_affine();
        let q = (GinProj::generator() * Fs::from(11u64)).into_affine();
        let expected = (GinProj::from(p) + GinProj::from(q)).into_affine();

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let out = add_var(
            &mut prover,
            &PointVar::constant(&p),
            &PointVar::constant(&q),
        );
        assert_eq!(out.w.unwrap(), expected);
        assert_eq_point(&mut prover, &out, &expected);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let out = add_var(
            &mut verifier,
            &PointVar::constant(&p),
            &PointVar::constant(&q),
        );
        assert_eq_point(&mut verifier, &out, &expected);
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn on_curve_gadget() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(8);
        let p = (GinProj::generator() * Fs::from(99u64)).into_affine();
        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        on_curve(&mut prover, &PointVar::constant(&p));
        let proof = prover.prove(&mut rng).unwrap();
        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        on_curve(&mut verifier, &PointVar::constant(&p));
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn scalar_mul_const_gadget() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(64);
        let base = GinAffine::generator();
        let scalar = Fs::from(7u64);
        let bits_w = fs_to_bits_le(&scalar, 8);
        let expected = (GinProj::from(base) * scalar).into_affine();

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let bits: Vec<ScalarVar> = bits_w
            .iter()
            .map(|&b| alloc_bit(&mut prover, Some(b)))
            .collect();
        let out = scalar_mul_const(&mut prover, &bits, &base);
        assert_eq!(out.w.unwrap(), expected);
        assert_eq_point(&mut prover, &out, &expected);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let bits: Vec<ScalarVar> = (0..8).map(|_| alloc_bit(&mut verifier, None)).collect();
        let out = scalar_mul_const(&mut verifier, &bits, &base);
        assert_eq_point(&mut verifier, &out, &expected);
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn scalar_mul_zero_works() {
        // 0·B = identity (0, 1).  This used to be the offset trick's job.
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(64);
        let base = GinAffine::generator();
        let bits_w = [false; 8];
        let expected = GinAffine::zero(); // identity

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let bits: Vec<ScalarVar> = bits_w
            .iter()
            .map(|&b| alloc_bit(&mut prover, Some(b)))
            .collect();
        let out = scalar_mul_const(&mut prover, &bits, &base);
        assert_eq!(out.w.unwrap(), expected);
        assert_eq_point(&mut prover, &out, &expected);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let bits: Vec<ScalarVar> = (0..8).map(|_| alloc_bit(&mut verifier, None)).collect();
        let out = scalar_mul_const(&mut verifier, &bits, &base);
        assert_eq_point(&mut verifier, &out, &expected);
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn linked_committed_variable() {
        // Verify that a committed value with γ=0 produces the linking
        // commitment `V = B^v` and the circuit can reference it.
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(64);
        let v = Fp::rand(&mut rng);
        let two_v = v + v;

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let (vc, vv) = prover.commit(v, Fp::zero());
        // Constrain `2v == two_v` (a public constant).
        let svar = ScalarVar {
            lc: LinearCombination::from(vv),
            w: Some(v),
        };
        let two = svar.add(&svar);
        prover.constrain(two.lc - two_v);
        // Need ≥1 multiplier.
        prover
            .allocate_multiplier(Some((Fp::zero(), Fp::zero())))
            .unwrap();
        let proof = prover.prove(&mut rng).unwrap();

        // V = B^v exactly.
        assert_eq!(vc, crate::curves::gout_mul(&v));

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let vv = verifier.commit(vc);
        let svar = ScalarVar {
            lc: LinearCombination::from(vv),
            w: None,
        };
        let two = svar.add(&svar);
        verifier.constrain(two.lc - two_v);
        verifier.allocate_multiplier(None).unwrap();
        verifier.verify(&proof).unwrap();
        let _ = Variable::One;
    }
}
