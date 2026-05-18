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
//! | gadget                                | muls               |
//! |---------------------------------------|--------------------|
//! | `bit_decompose(λ)`                    | `λ`                |
//! | `add_const`                           | 3                  |
//! | `add_var` (Karatsuba cross-products)  | 6                  |
//! | `cond_add_const`                      | 5 (= 3 + 2)        |
//! | `scalar_mul_const_naive(λ)`           | `5λ + 3`           |
//! | `scalar_mul_const(λ)` (3-bit window)  | `≈ 10⌈λ/3⌉ + 3`    |
//!
//! The 3-bit window's per-chunk cost is `4` monomial pre-products + `6`
//! `add_var` muls = `10` per `3` bits, ≈ `3.4` per bit.  This matches the
//! paper's `3λ + 2` exponentiation gadget budget within a small constant.
//! `R_eVRF` per-recipient is `≈ 3·(3.4λ) + λ ≈ 11λ`; the dealer's shared
//! `g_in^{sk}` and `sk` decomposition adds `≈ 4.4λ` once.

use crate::curves::{Fp, Fs, GinAffine, GinProj};
use crate::zk::r1cs::{ConstraintSystem, LinearCombination};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ed_on_bls12_381::JubjubConfig;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

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

/// `out = P + Q` for a variable `Q`.  6 mul gates (Karatsuba on the
/// cross-products: `x1·y2 + y1·x2 = (x1+y1)(x2+y2) − x1x2 − y1y2`).
pub fn add_var<CS: ConstraintSystem>(cs: &mut CS, p: &PointVar, q: &PointVar) -> PointVar {
    let a = JubjubConfig::COEFF_A;
    let d = JubjubConfig::COEFF_D;
    let x1x2 = mul(cs, &p.x, &q.x);
    let y1y2 = mul(cs, &p.y, &q.y);
    let xy12 = mul(cs, &p.x.add(&p.y), &q.x.add(&q.y));
    // x1·y2 + y1·x2 = (x1 + y1)(x2 + y2) − x1·x2 − y1·y2.
    let cross = xy12.sub(&x1x2).sub(&y1y2);
    let t = mul(cs, &x1x2, &y1y2);
    let dt = t.scale(d);
    let den_x = dt.shift(Fp::one());
    let den_y = dt.scale(-Fp::one()).shift(Fp::one());
    let num_y = y1y2.sub(&x1x2.scale(a));
    let x3 = div(cs, &cross, &den_x);
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
pub fn scalar_mul_const_naive<CS: ConstraintSystem>(
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

/// Window size in bits for [`scalar_mul_const`].  `3` is the sweet spot for
/// Jubjub (≈3.3 mul gates per bit).
pub const WINDOW: usize = 3;

/// `out = ⟨bits, [B, 2B, 4B, …]⟩` via 3-bit windows + 8-entry lookup table.
/// `≈ ⌈n/3⌉ · (4 + 6) + 3 ≈ 3.4·n` mul gates.
///
/// Each chunk of 3 bits selects one of `{0, 2^{3i}B, 2·2^{3i}B, …, 7·2^{3i}B}`
/// via multilinear interpolation, then adds it to the accumulator with the
/// 6-mul Karatsuba `add_var`.  Twisted-Edwards complete addition handles the
/// identity (when all 3 bits are 0) without a special case.
pub fn scalar_mul_const<CS: ConstraintSystem>(
    cs: &mut CS,
    bits: &[ScalarVar],
    base: &GinAffine,
) -> PointVar {
    let offset = offset_point();
    let mut acc = PointVar::constant(&offset);
    // Window base for chunk `i` is `2^{WINDOW·i}·B`.
    let mut chunk_base = GinProj::from(*base);
    for chunk in bits.chunks(WINDOW) {
        let table = build_table(&chunk_base, chunk.len());
        let q = lookup(cs, chunk, &table);
        acc = add_var(cs, &acc, &q);
        for _ in 0..chunk.len() {
            chunk_base.double_in_place();
        }
    }
    add_const(cs, &acc, &(-offset))
}

/// 2^k-entry table `{0·B, 1·B, …, (2^k-1)·B}`.
fn build_table(base: &GinProj, k: usize) -> Vec<GinAffine> {
    let n = 1usize << k;
    let mut out = Vec::with_capacity(n);
    let mut acc = GinProj::default();
    for _ in 0..n {
        out.push(acc.into_affine());
        acc += base;
    }
    out
}

/// Multilinear lookup of `table[∑ b_i 2^i]`.  Cost `2^k − k − 1` mul gates
/// for the monomial pre-products (`2^k = table.len()`); the lookup itself is
/// linear in those monomials.
fn lookup<CS: ConstraintSystem>(cs: &mut CS, bits: &[ScalarVar], table: &[GinAffine]) -> PointVar {
    let k = bits.len();
    debug_assert_eq!(table.len(), 1usize << k);
    // Build monomial products `m[S] = ∏_{j ∈ S} b_j`, `S ⊆ {0..k}`, indexed
    // by the bitmask of `S`.  `m[0] = 1`, `m[2^j] = b_j`, others by 1 mul.
    let mut mono: Vec<ScalarVar> = Vec::with_capacity(1 << k);
    mono.push(ScalarVar::constant(Fp::one()));
    for s in 1usize..(1 << k) {
        if s.is_power_of_two() {
            mono.push(bits[s.trailing_zeros() as usize].clone());
        } else {
            // Split off the low bit: m[S] = b_lo · m[S \ {lo}].
            let lo = s.trailing_zeros() as usize;
            let rest = s & (s - 1);
            mono.push(mul(cs, &bits[lo], &mono[rest]));
        }
    }
    // Multilinear interpolation coefficients α_S = Σ_{T ⊆ S} (−1)^{|S|−|T|} table[T].coord.
    let coeff = |coord: &dyn Fn(&GinAffine) -> Fp| -> Vec<Fp> {
        let mut alpha = vec![Fp::zero(); 1 << k];
        for s in 0usize..(1 << k) {
            // Subset-sum / Möbius: α_S = Σ_{T ⊆ S} (−1)^{|S \ T|} f(T).
            let mut t = s;
            loop {
                let sign = if ((s ^ t).count_ones()) % 2 == 0 {
                    Fp::one()
                } else {
                    -Fp::one()
                };
                alpha[s] += sign * coord(&table[t]);
                if t == 0 {
                    break;
                }
                t = (t - 1) & s;
            }
        }
        alpha
    };
    // The identity `(0, 1)` has y-coordinate `1`, and `table[0] = identity`.
    let alpha_x = coeff(&|p: &GinAffine| if p.is_zero() { Fp::zero() } else { p.x });
    let alpha_y = coeff(&|p: &GinAffine| if p.is_zero() { Fp::one() } else { p.y });
    // q.x = Σ alpha_x[S] · mono[S], q.y = Σ alpha_y[S] · mono[S].
    let mut x_lc = LinearCombination::zero();
    let mut y_lc = LinearCombination::zero();
    let mut x_w = Some(Fp::zero());
    let mut y_w = Some(Fp::zero());
    for s in 0usize..(1 << k) {
        x_lc = x_lc + mono[s].lc.clone() * alpha_x[s];
        y_lc = y_lc + mono[s].lc.clone() * alpha_y[s];
        x_w = x_w.zip(mono[s].w).map(|(a, b)| a + alpha_x[s] * b);
        y_w = y_w.zip(mono[s].w).map(|(a, b)| a + alpha_y[s] * b);
    }
    let q_w = x_w.zip(y_w).map(|(x, y)| {
        if x == Fp::zero() && y == Fp::one() {
            GinAffine::zero()
        } else {
            GinAffine::new_unchecked(x, y)
        }
    });
    PointVar {
        x: ScalarVar { lc: x_lc, w: x_w },
        y: ScalarVar { lc: y_lc, w: y_w },
        w: q_w,
    }
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
    fn scalar_mul_witness_correct_for_random_inputs() {
        // Sanity: the *witness* threading of `scalar_mul_const` must match
        // arkworks for many random scalars and bases — including inputs with
        // boundary chunks (`λ` not a multiple of `WINDOW`).  This exercises
        // the multilinear lookup arithmetic without paying for a full proof.
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(8);
        for nbits in [1usize, 2, 3, 4, 7, 9, 15, 24] {
            for _ in 0..10 {
                let base = (GinProj::generator() * Fs::rand(&mut rng)).into_affine();
                let raw = Fs::rand(&mut rng);
                let scalar = Fs::from_le_bytes_mod_order(
                    &raw.into_bigint().to_bytes_le()[..nbits.div_ceil(8).max(1)],
                );
                // Truncate to `nbits` bits.
                let mut bits_w = fs_to_bits_le(&scalar, nbits);
                bits_w.truncate(nbits);
                let scalar_truncated: Fs = {
                    let mut acc = Fs::from(0u64);
                    let mut p = Fs::from(1u64);
                    for &b in &bits_w {
                        if b {
                            acc += p;
                        }
                        p += p;
                    }
                    acc
                };
                let expected = (GinProj::from(base) * scalar_truncated).into_affine();
                // Build a *prover* (with witness) just to run the gadget.
                let mut cs = Prover::new(&gens, Transcript::new(b"witness-test"));
                let bits: Vec<ScalarVar> = bits_w
                    .iter()
                    .map(|&b| alloc_bit(&mut cs, Some(b)))
                    .collect();
                let out = scalar_mul_const(&mut cs, &bits, &base);
                assert_eq!(out.w.unwrap(), expected, "nbits={nbits}, scalar={scalar:?}");
                // The naive (5-mul-per-bit) gadget must agree.
                let mut cs2 = Prover::new(&gens, Transcript::new(b"witness-test-2"));
                let bits2: Vec<ScalarVar> = bits_w
                    .iter()
                    .map(|&b| alloc_bit(&mut cs2, Some(b)))
                    .collect();
                let out2 = scalar_mul_const_naive(&mut cs2, &bits2, &base);
                assert_eq!(out2.w.unwrap(), expected);
            }
        }
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
