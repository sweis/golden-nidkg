//! Bulletproofs over R1CS — prover and verifier.
//!
//! This is a faithful port of the dalek-cryptography `bulletproofs`
//! R1CS protocol to arkworks/BLS12-381, restricted to the *non-randomised*
//! single-phase protocol (no second-phase challenge gates), which is enough
//! for Golden's `R_eVRF` circuit.
//!
//! References:
//! * Bulletproofs (Bünz et al., S&P 2018), §5.
//! * BCC+16, "Efficient Zero-Knowledge Arguments for Arithmetic Circuits in
//!   the Discrete Log Setting", Appendix A.
//! * <https://doc-internal.dalek.rs/bulletproofs/notes/r1cs_proof/index.html>
//!
//! Variable layout / naming follows the dalek notes.

use crate::curves::{Fp, GoutAffine, GoutProj};
use crate::transcript::TranscriptExt;
use crate::zk::generators::BpGens;
use crate::zk::ipa::{inner_product, powers, InnerProductProof};
use crate::zk::r1cs::{flatten, Assignments, ConstraintSystem, LinearCombination, Variable};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, Zero};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use merlin::Transcript;

const PROTO_LABEL: &[u8] = b"golden-nidkg/bp-r1cs/v1";

/// The proof.
#[derive(Clone, Debug)]
pub struct R1CSProof {
    /// Commitment to `a_L, a_R`.
    pub a_i: GoutAffine,
    /// Commitment to `a_O`.
    pub a_o: GoutAffine,
    /// Commitment to the blinding vectors `s_L, s_R`.
    pub s: GoutAffine,
    /// `t(x)` polynomial coefficient commitments (degrees 1, 3, 4, 5, 6).
    pub t_1: GoutAffine,
    pub t_3: GoutAffine,
    pub t_4: GoutAffine,
    pub t_5: GoutAffine,
    pub t_6: GoutAffine,
    /// `t(x)` evaluated at `x` and its blinding.
    pub t_x: Fp,
    pub t_x_blinding: Fp,
    /// Synthetic blinding factor for `l(x), r(x)`.
    pub e_blinding: Fp,
    /// IPA over `l(x), r(x)`.
    pub ipp: InnerProductProof,
}

fn msm(bases: &[GoutAffine], scalars: &[Fp]) -> GoutProj {
    GoutProj::msm(bases, scalars).expect("msm")
}

/// ─── Prover ─────────────────────────────────────────────────────────────────

pub struct Prover<'g> {
    gens: &'g BpGens,
    transcript: Transcript,
    constraints: Vec<LinearCombination>,
    assignments: Assignments,
    /// Blinding factors `γ_j` for each `V_j = B^{v_j} · B_b^{γ_j}`.
    v_blindings: Vec<Fp>,
}

impl<'g> Prover<'g> {
    pub fn new(gens: &'g BpGens, mut transcript: Transcript) -> Self {
        transcript.append_bytes(b"dom-sep", PROTO_LABEL);
        Self {
            gens,
            transcript,
            constraints: Vec::new(),
            assignments: Assignments::default(),
            v_blindings: Vec::new(),
        }
    }

    /// Commit to a value `v` with blinding `γ`.  The Pedersen commitment is
    /// appended to the transcript (so the prover and verifier agree).  Use
    /// `γ = 0` to open the committed value to a public group element
    /// `V = B^v` (Golden's `R = g_out^r` linking).
    pub fn commit(&mut self, v: Fp, gamma: Fp) -> (GoutAffine, Variable) {
        let i = self.assignments.v.len();
        self.assignments.v.push(v);
        self.v_blindings.push(gamma);
        let vp = (GoutProj::from(self.gens.b) * v + GoutProj::from(self.gens.b_blinding) * gamma)
            .into_affine();
        self.transcript.append_gout(b"V", &vp);
        (vp, Variable::Committed(i))
    }

    fn alloc_mul(&mut self, l: Fp, r: Fp) -> (Variable, Variable, Variable) {
        let i = self.assignments.a_l.len();
        self.assignments.a_l.push(l);
        self.assignments.a_r.push(r);
        self.assignments.a_o.push(l * r);
        (
            Variable::MultiplierLeft(i),
            Variable::MultiplierRight(i),
            Variable::MultiplierOutput(i),
        )
    }

    /// Produce the proof from the accumulated circuit.
    pub fn prove(mut self, rng: &mut impl Rng) -> Result<R1CSProof, String> {
        // 1. Pad the multiplication-gate vectors to a power of two.
        let n0 = self.assignments.a_l.len();
        let n = n0.next_power_of_two().max(1);
        if n > self.gens.gens_capacity {
            return Err(format!(
                "circuit too large: {} > {}",
                n, self.gens.gens_capacity
            ));
        }
        let pad = n - n0;
        let m = self.assignments.v.len();

        let i_blinding = Fp::rand(rng);
        let o_blinding = Fp::rand(rng);
        let s_blinding = Fp::rand(rng);
        let s_l: Vec<Fp> = (0..n).map(|_| Fp::rand(rng)).collect();
        let s_r: Vec<Fp> = (0..n).map(|_| Fp::rand(rng)).collect();

        // 2. Commit to a_L, a_R, a_O, s_L, s_R.
        let (g_vec, h_vec) = self.gens.share(n);
        let a_l = pad_vec(&self.assignments.a_l, n);
        let a_r = pad_vec(&self.assignments.a_r, n);
        let a_o = pad_vec(&self.assignments.a_o, n);
        // A_I = B_b^α G^{a_L} H^{a_R}
        let a_i_pt = {
            let mut bases = vec![self.gens.b_blinding];
            let mut scalars = vec![i_blinding];
            bases.extend_from_slice(g_vec);
            scalars.extend(&a_l);
            bases.extend_from_slice(h_vec);
            scalars.extend(&a_r);
            msm(&bases, &scalars).into_affine()
        };
        // A_O = B_b^β G^{a_O}
        let a_o_pt = {
            let mut bases = vec![self.gens.b_blinding];
            let mut scalars = vec![o_blinding];
            bases.extend_from_slice(g_vec);
            scalars.extend(&a_o);
            msm(&bases, &scalars).into_affine()
        };
        // S = B_b^ρ G^{s_L} H^{s_R}
        let s_pt = {
            let mut bases = vec![self.gens.b_blinding];
            let mut scalars = vec![s_blinding];
            bases.extend_from_slice(g_vec);
            scalars.extend(&s_l);
            bases.extend_from_slice(h_vec);
            scalars.extend(&s_r);
            msm(&bases, &scalars).into_affine()
        };

        self.transcript.append_u64(b"m", m as u64);
        self.transcript.append_gout(b"A_I", &a_i_pt);
        self.transcript.append_gout(b"A_O", &a_o_pt);
        self.transcript.append_gout(b"S", &s_pt);
        let y = self.transcript.challenge_fp(b"y");
        let z = self.transcript.challenge_fp(b"z");

        // 3. Flatten linear constraints by z^q.
        let fl = flatten(&self.constraints, n, m, z);

        // 4. Build l(x), r(x) polynomials.
        //    Following the dalek notes (single-phase, "left" vectors only):
        //    l(x) = a_L·x + a_O·x² + y^{-n}·z_W_R·x + s_L·x³
        //    r(x) = y^n∘a_R·x − y^n + z_W_L·x + z_W_O + y^n∘s_R·x³
        //    where z_W_L = W_L^T z, etc.
        let y_pows = powers(y, n);
        let mut y_inv_pows = powers(y.inverse().unwrap(), n);

        let mut l_poly = VecPoly3::zero(n);
        let mut r_poly = VecPoly3::zero(n);
        for i in 0..n {
            l_poly.t1[i] = a_l[i] + y_inv_pows[i] * fl.w_r[i];
            l_poly.t2[i] = a_o[i];
            l_poly.t3[i] = s_l[i];
            r_poly.t0[i] = fl.w_o[i] - y_pows[i];
            r_poly.t1[i] = y_pows[i] * a_r[i] + fl.w_l[i];
            r_poly.t3[i] = y_pows[i] * s_r[i];
        }
        let t_poly = l_poly.inner_product(&r_poly);

        // 5. Commit to t(x) coefficients (skipping t_2 which the verifier
        //    reconstructs from the commitments V).
        let t_1_blinding = Fp::rand(rng);
        let t_3_blinding = Fp::rand(rng);
        let t_4_blinding = Fp::rand(rng);
        let t_5_blinding = Fp::rand(rng);
        let t_6_blinding = Fp::rand(rng);
        let pc = |v: &Fp, b: &Fp| {
            (GoutProj::from(self.gens.b) * v + GoutProj::from(self.gens.b_blinding) * b)
                .into_affine()
        };
        let t_1 = pc(&t_poly.t1, &t_1_blinding);
        let t_3 = pc(&t_poly.t3, &t_3_blinding);
        let t_4 = pc(&t_poly.t4, &t_4_blinding);
        let t_5 = pc(&t_poly.t5, &t_5_blinding);
        let t_6 = pc(&t_poly.t6, &t_6_blinding);
        self.transcript.append_gout(b"T_1", &t_1);
        self.transcript.append_gout(b"T_3", &t_3);
        self.transcript.append_gout(b"T_4", &t_4);
        self.transcript.append_gout(b"T_5", &t_5);
        self.transcript.append_gout(b"T_6", &t_6);
        let u = self.transcript.challenge_fp(b"u"); // unused in single-phase but kept for parity
        let _ = u;
        let x = self.transcript.challenge_fp(b"x");

        // 6. Evaluate l(x), r(x), t(x) and synthetic blindings.
        let t_2_blinding: Fp = inner_product(&fl.w_v, &self.v_blindings);
        let t_blinding_poly = Poly6 {
            t1: t_1_blinding,
            t2: t_2_blinding,
            t3: t_3_blinding,
            t4: t_4_blinding,
            t5: t_5_blinding,
            t6: t_6_blinding,
        };
        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);
        let l_vec = l_poly.eval(x);
        let r_vec = r_poly.eval(x);
        let e_blinding = x * (i_blinding + x * (o_blinding + x * s_blinding));

        self.transcript.append_fp(b"t_x", &t_x);
        self.transcript.append_fp(b"t_x_blinding", &t_x_blinding);
        self.transcript.append_fp(b"e_blinding", &e_blinding);

        // 7. Inner product argument for `l(x), r(x)`.
        let w = self.transcript.challenge_fp(b"w");
        let q = (GoutProj::from(self.gens.b) * w).into_affine();
        let g_factors = vec![Fp::one(); n];
        // Note: H_i are scaled by y^{-i} so the inner product is ⟨l, r⟩ in F_p.
        let ipp = InnerProductProof::create(
            &mut self.transcript,
            &q,
            &g_factors,
            &y_inv_pows,
            g_vec,
            h_vec,
            &l_vec,
            &r_vec,
        );
        // Throw away the borrow.
        let _ = &mut y_inv_pows;
        let _ = pad;

        Ok(R1CSProof {
            a_i: a_i_pt,
            a_o: a_o_pt,
            s: s_pt,
            t_1,
            t_3,
            t_4,
            t_5,
            t_6,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp,
        })
    }
}

impl ConstraintSystem for Prover<'_> {
    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        let l = self.assignments.eval(&left);
        let r = self.assignments.eval(&right);
        let (vl, vr, vo) = self.alloc_mul(l, r);
        // Constrain the multiplier inputs to equal the requested LCs.
        self.constrain(left - vl);
        self.constrain(right - vr);
        (vl, vr, vo)
    }
    fn allocate_multiplier(
        &mut self,
        assignment: Option<(Fp, Fp)>,
    ) -> Result<(Variable, Variable, Variable), String> {
        let (l, r) = assignment.ok_or("prover requires assignment")?;
        Ok(self.alloc_mul(l, r))
    }
    fn constrain(&mut self, lc: LinearCombination) {
        debug_assert!(
            self.assignments.eval(&lc).is_zero(),
            "constraint not satisfied: {lc:?}"
        );
        self.constraints.push(lc);
    }
    fn num_multipliers(&self) -> usize {
        self.assignments.a_l.len()
    }
    fn eval(&self, lc: &LinearCombination) -> Option<Fp> {
        Some(self.assignments.eval(lc))
    }
}

/// ─── Verifier ───────────────────────────────────────────────────────────────

pub struct Verifier<'g> {
    gens: &'g BpGens,
    transcript: Transcript,
    constraints: Vec<LinearCombination>,
    n_mul: usize,
    n_committed: usize,
    v_commitments: Vec<GoutAffine>,
}

impl<'g> Verifier<'g> {
    pub fn new(gens: &'g BpGens, mut transcript: Transcript) -> Self {
        transcript.append_bytes(b"dom-sep", PROTO_LABEL);
        Self {
            gens,
            transcript,
            constraints: Vec::new(),
            n_mul: 0,
            n_committed: 0,
            v_commitments: Vec::new(),
        }
    }

    /// Register a Pedersen commitment to a high-level witness value.  Must be
    /// called in the same order as `Prover::commit`.
    pub fn commit(&mut self, v: GoutAffine) -> Variable {
        let i = self.n_committed;
        self.n_committed += 1;
        self.v_commitments.push(v);
        self.transcript.append_gout(b"V", &v);
        Variable::Committed(i)
    }

    pub fn verify(mut self, proof: &R1CSProof) -> Result<(), String> {
        let n0 = self.n_mul;
        let n = n0.next_power_of_two().max(1);
        if n > self.gens.gens_capacity {
            return Err(format!(
                "circuit too large: {} > {}",
                n, self.gens.gens_capacity
            ));
        }
        let m = self.n_committed;
        let (g_vec, h_vec) = self.gens.share(n);

        self.transcript.append_u64(b"m", m as u64);
        self.transcript.append_gout(b"A_I", &proof.a_i);
        self.transcript.append_gout(b"A_O", &proof.a_o);
        self.transcript.append_gout(b"S", &proof.s);
        let y = self.transcript.challenge_fp(b"y");
        let z = self.transcript.challenge_fp(b"z");
        let fl = flatten(&self.constraints, n, m, z);

        self.transcript.append_gout(b"T_1", &proof.t_1);
        self.transcript.append_gout(b"T_3", &proof.t_3);
        self.transcript.append_gout(b"T_4", &proof.t_4);
        self.transcript.append_gout(b"T_5", &proof.t_5);
        self.transcript.append_gout(b"T_6", &proof.t_6);
        let _u = self.transcript.challenge_fp(b"u");
        let x = self.transcript.challenge_fp(b"x");

        self.transcript.append_fp(b"t_x", &proof.t_x);
        self.transcript
            .append_fp(b"t_x_blinding", &proof.t_x_blinding);
        self.transcript.append_fp(b"e_blinding", &proof.e_blinding);
        let w = self.transcript.challenge_fp(b"w");

        let y_pows = powers(y, n);
        let y_inv = y.inverse().unwrap();
        let y_inv_pows = powers(y_inv, n);

        // Reconstruct the IPA verification scalars.
        let (u_sq, u_inv_sq, s) = proof.ipp.verification_scalars(n, &mut self.transcript)?;
        let mut s_inv = s.clone();
        s_inv.reverse();
        let a = proof.ipp.a;
        let b = proof.ipp.b;

        // Constants.
        let xx = x.square();
        let xxx = xx * x;
        // δ(y, z) = ⟨y^{-n}∘z_W_R, z_W_L⟩
        let delta: Fp = (0..n).map(|i| y_inv_pows[i] * fl.w_r[i] * fl.w_l[i]).sum();

        // First check: t(x) consistency.
        //   B^{t_x} B_b^{t_x_blinding}
        //   == V^{x²·z_W_V} · B^{x²·(δ + w_c)} · T_1^x · T_3^{x³} · T_4^{x⁴} · T_5^{x⁵} · T_6^{x⁶}
        // We instead fold this into a single combined MSM with the second
        // check using a random linear combiner `r_chal`.
        let r_chal = self.transcript.challenge_fp(b"r");

        // Second check: P (the IPA target).
        //   P = A_I·x + A_O·x² + S·x³
        //       + ⟨z_W_L, H'⟩ + ⟨y^{-n}∘z_W_R, G⟩·x + ⟨z_W_O, H'⟩
        //       − G^{1ⁿ}·0 − H'^{y^n}
        //       − B_b^{e_blinding} − Q^{t_x}
        //       == ∑(a·s_i)G_i + ∑(b·s_inv_i·y^{-i})H_i + a·b·Q − ∑u²L − ∑u^{-2}R
        // This is the single-phase analogue of the dalek combined check.

        // We assemble a single MSM with all the bases.
        //   coefficient_on_base · base, summed; should equal identity.
        let mut bases: Vec<GoutAffine> = Vec::new();
        let mut scalars: Vec<Fp> = Vec::new();

        // ── second check (P) terms ──
        // A_I, A_O, S
        bases.push(proof.a_i);
        scalars.push(x);
        bases.push(proof.a_o);
        scalars.push(xx);
        bases.push(proof.s);
        scalars.push(xxx);
        // V_j: only enter the t(x) check (handled below)

        // G_i: x·y^{-i}·z_W_R_i  −  a·s_i
        for i in 0..n {
            bases.push(g_vec[i]);
            scalars.push(x * y_inv_pows[i] * fl.w_r[i] - a * s[i]);
        }
        // H_i: y^{-i}·(x·z_W_L_i + z_W_O_i − y^i)  −  b·s_inv_i·y^{-i}
        for i in 0..n {
            bases.push(h_vec[i]);
            scalars.push(y_inv_pows[i] * (x * fl.w_l[i] + fl.w_o[i] - y_pows[i] - b * s_inv[i]));
        }
        // L, R from the IPA
        for i in 0..proof.ipp.l_vec.len() {
            bases.push(proof.ipp.l_vec[i]);
            scalars.push(u_sq[i]);
            bases.push(proof.ipp.r_vec[i]);
            scalars.push(u_inv_sq[i]);
        }
        // B_b: −e_blinding (from P) − r·t_x_blinding (from the t(x) check)
        bases.push(self.gens.b_blinding);
        scalars.push(-proof.e_blinding - r_chal * proof.t_x_blinding);
        // B: w·(t_x − a·b) (from Q^{t_x}, Q^{a·b})  +  r·(x²(δ + w_c) − t_x)
        bases.push(self.gens.b);
        scalars.push(w * (proof.t_x - a * b) + r_chal * (xx * (delta + fl.w_c) - proof.t_x));

        // ── t(x) check terms (scaled by r_chal) ──
        for j in 0..m {
            bases.push(self.v_commitments[j]);
            scalars.push(r_chal * xx * fl.w_v[j]);
        }
        bases.push(proof.t_1);
        scalars.push(r_chal * x);
        bases.push(proof.t_3);
        scalars.push(r_chal * xxx);
        bases.push(proof.t_4);
        scalars.push(r_chal * xxx * x);
        bases.push(proof.t_5);
        scalars.push(r_chal * xxx * xx);
        bases.push(proof.t_6);
        scalars.push(r_chal * xxx * xxx);

        let combined = msm(&bases, &scalars);
        if combined.is_zero() {
            Ok(())
        } else {
            Err("R1CS verification failed".into())
        }
    }
}

impl ConstraintSystem for Verifier<'_> {
    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        let i = self.n_mul;
        self.n_mul += 1;
        let (vl, vr, vo) = (
            Variable::MultiplierLeft(i),
            Variable::MultiplierRight(i),
            Variable::MultiplierOutput(i),
        );
        self.constrain(left - vl);
        self.constrain(right - vr);
        (vl, vr, vo)
    }
    fn allocate_multiplier(
        &mut self,
        _assignment: Option<(Fp, Fp)>,
    ) -> Result<(Variable, Variable, Variable), String> {
        let i = self.n_mul;
        self.n_mul += 1;
        Ok((
            Variable::MultiplierLeft(i),
            Variable::MultiplierRight(i),
            Variable::MultiplierOutput(i),
        ))
    }
    fn constrain(&mut self, lc: LinearCombination) {
        self.constraints.push(lc);
    }
    fn num_multipliers(&self) -> usize {
        self.n_mul
    }
    fn eval(&self, _lc: &LinearCombination) -> Option<Fp> {
        None
    }
}

/// ─── Polynomials over `F_p^n` ───────────────────────────────────────────────

/// Vector polynomial of degree 3: `p(x) = t0 + t1 x + t2 x² + t3 x³`, each
/// coefficient an `F_p^n` vector.
struct VecPoly3 {
    t0: Vec<Fp>,
    t1: Vec<Fp>,
    t2: Vec<Fp>,
    t3: Vec<Fp>,
}
impl VecPoly3 {
    fn zero(n: usize) -> Self {
        Self {
            t0: vec![Fp::zero(); n],
            t1: vec![Fp::zero(); n],
            t2: vec![Fp::zero(); n],
            t3: vec![Fp::zero(); n],
        }
    }
    fn eval(&self, x: Fp) -> Vec<Fp> {
        let n = self.t0.len();
        let mut out = vec![Fp::zero(); n];
        for i in 0..n {
            out[i] = self.t0[i] + x * (self.t1[i] + x * (self.t2[i] + x * self.t3[i]));
        }
        out
    }
    /// Inner product `⟨l(x), r(x)⟩` as a degree-6 scalar polynomial.
    /// Special case (Karatsuba-free): `l.t0 = 0` and `r.t2 = 0` here, so
    /// `t0` is trivially 0 and `t2` doesn't appear in `r`.
    fn inner_product(&self, r: &VecPoly3) -> Poly6 {
        let ip = |a: &[Fp], b: &[Fp]| inner_product(a, b);
        let t1 = ip(&self.t1, &r.t0) + ip(&self.t0, &r.t1);
        let t2 = ip(&self.t2, &r.t0) + ip(&self.t1, &r.t1) + ip(&self.t0, &r.t2);
        let t3 =
            ip(&self.t3, &r.t0) + ip(&self.t2, &r.t1) + ip(&self.t1, &r.t2) + ip(&self.t0, &r.t3);
        let t4 = ip(&self.t3, &r.t1) + ip(&self.t2, &r.t2) + ip(&self.t1, &r.t3);
        let t5 = ip(&self.t3, &r.t2) + ip(&self.t2, &r.t3);
        let t6 = ip(&self.t3, &r.t3);
        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }
}

/// Degree-6 scalar polynomial with no constant term.
struct Poly6 {
    t1: Fp,
    t2: Fp,
    t3: Fp,
    t4: Fp,
    t5: Fp,
    t6: Fp,
}
impl Poly6 {
    fn eval(&self, x: Fp) -> Fp {
        x * (self.t1 + x * (self.t2 + x * (self.t3 + x * (self.t4 + x * (self.t5 + x * self.t6)))))
    }
}

fn pad_vec(v: &[Fp], n: usize) -> Vec<Fp> {
    let mut out = v.to_vec();
    out.resize(n, Fp::zero());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Toy gadget: prove `(a + b) * (c + d) = e` for committed values.
    fn toy_gadget<CS: ConstraintSystem>(
        cs: &mut CS,
        a: Variable,
        b: Variable,
        c: Variable,
        d: Variable,
        e: Variable,
    ) {
        let (_, _, out) = cs.multiply(
            LinearCombination::from(a) + b,
            LinearCombination::from(c) + d,
        );
        cs.constrain(LinearCombination::from(e) - out);
    }

    #[test]
    fn bp_r1cs_toy() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(8);

        let (a, b, c, d) = (
            Fp::from(3u64),
            Fp::from(4u64),
            Fp::from(5u64),
            Fp::from(6u64),
        );
        let e = (a + b) * (c + d);
        let blindings: Vec<Fp> = (0..5).map(|_| Fp::rand(&mut rng)).collect();

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let (va_c, va) = prover.commit(a, blindings[0]);
        let (vb_c, vb) = prover.commit(b, blindings[1]);
        let (vc_c, vc) = prover.commit(c, blindings[2]);
        let (vd_c, vd) = prover.commit(d, blindings[3]);
        let (ve_c, ve) = prover.commit(e, blindings[4]);
        toy_gadget(&mut prover, va, vb, vc, vd, ve);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let va = verifier.commit(va_c);
        let vb = verifier.commit(vb_c);
        let vc = verifier.commit(vc_c);
        let vd = verifier.commit(vd_c);
        let ve = verifier.commit(ve_c);
        toy_gadget(&mut verifier, va, vb, vc, vd, ve);
        verifier.verify(&proof).unwrap();
    }

    #[test]
    fn bp_r1cs_toy_wrong() {
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(8);

        let (a, b, c, d) = (
            Fp::from(3u64),
            Fp::from(4u64),
            Fp::from(5u64),
            Fp::from(6u64),
        );
        let e_wrong = (a + b) * (c + d) + Fp::one();
        let blindings: Vec<Fp> = (0..5).map(|_| Fp::rand(&mut rng)).collect();

        let mut prover = Prover::new(&gens, Transcript::new(b"test"));
        let (va_c, va) = prover.commit(a, blindings[0]);
        let (vb_c, vb) = prover.commit(b, blindings[1]);
        let (vc_c, vc) = prover.commit(c, blindings[2]);
        let (vd_c, vd) = prover.commit(d, blindings[3]);
        let (ve_c, ve) = prover.commit(e_wrong, blindings[4]);
        // Prove a constraint that's actually wrong — for the test we DON'T
        // build the toy_gadget on the prover (which would `debug_assert!`
        // fail).  Instead we just build a trivially-satisfied prover circuit
        // and a constraining verifier circuit to make sure the proof fails.
        let _ = (va, vb, vc, vd, ve);
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"test"));
        let va = verifier.commit(va_c);
        let vb = verifier.commit(vb_c);
        let vc = verifier.commit(vc_c);
        let vd = verifier.commit(vd_c);
        let ve = verifier.commit(ve_c);
        toy_gadget(&mut verifier, va, vb, vc, vd, ve);
        assert!(verifier.verify(&proof).is_err());
    }

    #[test]
    fn bp_r1cs_zero_blinding_links() {
        // Commit with γ=0 ⇒ V = B^v.  This is the linking trick for `R = g_out^r`.
        let mut rng = ark_std::test_rng();
        let gens = BpGens::new(8);
        let v = Fp::from(42u64);

        let mut prover = Prover::new(&gens, Transcript::new(b"link"));
        let (vc, vv) = prover.commit(v, Fp::zero());
        // V should be exactly B^v.
        assert_eq!(vc, (GoutProj::from(gens.b) * v).into_affine());
        // Trivial constraint v - 42 == 0
        prover.constrain(LinearCombination::from(vv) - Fp::from(42u64));
        // Add a dummy multiplier so n >= 1.
        prover
            .allocate_multiplier(Some((Fp::zero(), Fp::zero())))
            .unwrap();
        let proof = prover.prove(&mut rng).unwrap();

        let mut verifier = Verifier::new(&gens, Transcript::new(b"link"));
        let vv = verifier.commit(vc);
        verifier.constrain(LinearCombination::from(vv) - Fp::from(42u64));
        verifier.allocate_multiplier(None).unwrap();
        verifier.verify(&proof).unwrap();
    }
}
