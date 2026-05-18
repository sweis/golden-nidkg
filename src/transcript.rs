//! Merlin transcript helpers for Fiat-Shamir over arkworks types.

use crate::curves::{Fp, Fs, GinAffine, GoutAffine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub trait TranscriptExt {
    fn append_u64(&mut self, label: &'static [u8], v: u64);
    fn append_bytes(&mut self, label: &'static [u8], v: &[u8]);
    fn append_fp(&mut self, label: &'static [u8], v: &Fp);
    fn append_fs(&mut self, label: &'static [u8], v: &Fs);
    fn append_gin(&mut self, label: &'static [u8], v: &GinAffine);
    fn append_gout(&mut self, label: &'static [u8], v: &GoutAffine);
    fn challenge_fp(&mut self, label: &'static [u8]) -> Fp;
    fn challenge_fs(&mut self, label: &'static [u8]) -> Fs;
}

fn ser<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    v.serialize_compressed(&mut buf).expect("serialize");
    buf
}

impl TranscriptExt for Transcript {
    fn append_u64(&mut self, label: &'static [u8], v: u64) {
        self.append_message(label, &v.to_le_bytes());
    }
    fn append_bytes(&mut self, label: &'static [u8], v: &[u8]) {
        self.append_message(label, v);
    }
    fn append_fp(&mut self, label: &'static [u8], v: &Fp) {
        self.append_message(label, &ser(v));
    }
    fn append_fs(&mut self, label: &'static [u8], v: &Fs) {
        self.append_message(label, &ser(v));
    }
    fn append_gin(&mut self, label: &'static [u8], v: &GinAffine) {
        self.append_message(label, &ser(v));
    }
    fn append_gout(&mut self, label: &'static [u8], v: &GoutAffine) {
        self.append_message(label, &ser(v));
    }
    fn challenge_fp(&mut self, label: &'static [u8]) -> Fp {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Fp::from_le_bytes_mod_order(&buf)
    }
    fn challenge_fs(&mut self, label: &'static [u8]) -> Fs {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Fs::from_le_bytes_mod_order(&buf)
    }
}
