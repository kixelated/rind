// Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
// Copyright (c) 2022-2023 HACL* Contributors
// Copyright 2023 Cryspen Sarl
// SPDX-License-Identifier: Apache-2.0
//
// HChaCha20, for XChaCha20, over HACL*'s verified `Hacl_Chacha20` as
// libcrux-chacha20poly1305 0.0.10 ships it (`src/hacl/chacha20.rs`): the state
// setup and rounds, less the module paths, since libcrux does not export them.
// HChaCha20 runs the rounds as draft-irtf-cfrg-xchacha-03 specifies. The
// keystream itself is aws-lc's, in `chacha_armv4`.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(unreachable_patterns)]

use libcrux_hacl_rs::prelude::*;
use libcrux_macros as krml;

pub(crate) use super::chacha_armv4::ChaCha20;

pub(crate) const chacha20_constants: [u32; 4] =
    [0x61707865u32, 0x3320646eu32, 0x79622d32u32, 0x6b206574u32];

#[inline]
fn quarter_round(st: &mut [u32], a: u32, b: u32, c: u32, d: u32) {
    let sta: u32 = st[a as usize];
    let stb: u32 = st[b as usize];
    let std: u32 = st[d as usize];
    let sta1: u32 = sta.wrapping_add(stb);
    let std1: u32 = std ^ sta1;
    let std2: u32 = std1.wrapping_shl(16u32) | std1.wrapping_shr(16u32);
    st[a as usize] = sta1;
    st[d as usize] = std2;
    let sta0: u32 = st[c as usize];
    let stb0: u32 = st[d as usize];
    let std0: u32 = st[b as usize];
    let sta10: u32 = sta0.wrapping_add(stb0);
    let std10: u32 = std0 ^ sta10;
    let std20: u32 = std10.wrapping_shl(12u32) | std10.wrapping_shr(20u32);
    st[c as usize] = sta10;
    st[b as usize] = std20;
    let sta2: u32 = st[a as usize];
    let stb1: u32 = st[b as usize];
    let std3: u32 = st[d as usize];
    let sta11: u32 = sta2.wrapping_add(stb1);
    let std11: u32 = std3 ^ sta11;
    let std21: u32 = std11.wrapping_shl(8u32) | std11.wrapping_shr(24u32);
    st[a as usize] = sta11;
    st[d as usize] = std21;
    let sta3: u32 = st[c as usize];
    let stb2: u32 = st[d as usize];
    let std4: u32 = st[b as usize];
    let sta12: u32 = sta3.wrapping_add(stb2);
    let std12: u32 = std4 ^ sta12;
    let std22: u32 = std12.wrapping_shl(7u32) | std12.wrapping_shr(25u32);
    st[c as usize] = sta12;
    st[b as usize] = std22
}

#[inline]
fn double_round(st: &mut [u32]) {
    quarter_round(st, 0u32, 4u32, 8u32, 12u32);
    quarter_round(st, 1u32, 5u32, 9u32, 13u32);
    quarter_round(st, 2u32, 6u32, 10u32, 14u32);
    quarter_round(st, 3u32, 7u32, 11u32, 15u32);
    quarter_round(st, 0u32, 5u32, 10u32, 15u32);
    quarter_round(st, 1u32, 6u32, 11u32, 12u32);
    quarter_round(st, 2u32, 7u32, 8u32, 13u32);
    quarter_round(st, 3u32, 4u32, 9u32, 14u32)
}

#[inline]
pub(crate) fn rounds(st: &mut [u32]) {
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st);
    double_round(st)
}

fn chacha20_init(ctx: &mut [u32], k: &[u8], n: &[u8], ctr: u32) {
    krml::unroll_for!(4, "i", 0u32, 1u32, {
        let x: u32 = (&chacha20_constants)[i as usize];
        let os: &mut [u32] = &mut (&mut ctx[0usize..])[0usize..];
        os[i as usize] = x
    });
    let uu____0: (&mut [u32], &mut [u32]) = ctx.split_at_mut(4usize);
    krml::unroll_for!(8, "i", 0u32, 1u32, {
        let bj: (&[u8], &[u8]) = k.split_at(i.wrapping_mul(4u32) as usize);
        let u: u32 = lowstar::endianness::load32_le(bj.1);
        let r: u32 = u;
        let x: u32 = r;
        let os: (&mut [u32], &mut [u32]) = uu____0.1.split_at_mut(0usize);
        os.1[i as usize] = x
    });
    ctx[12usize] = ctr;
    let uu____1: (&mut [u32], &mut [u32]) = ctx.split_at_mut(13usize);
    krml::unroll_for!(3, "i", 0u32, 1u32, {
        let bj: (&[u8], &[u8]) = n.split_at(i.wrapping_mul(4u32) as usize);
        let u: u32 = lowstar::endianness::load32_le(bj.1);
        let r: u32 = u;
        let x: u32 = r;
        let os: (&mut [u32], &mut [u32]) = uu____1.1.split_at_mut(0usize);
        os.1[i as usize] = x
    })
}

pub(crate) struct XChaCha20(ChaCha20);

impl XChaCha20 {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let mut chacha_nonce = [0u8; 16];
        chacha_nonce[8..].copy_from_slice(&nonce[16..]);
        Self(ChaCha20::new(&hchacha20(key, nonce), &chacha_nonce))
    }

    pub(crate) fn cipher(&mut self, buffer: &mut [u8]) {
        self.0.cipher(buffer)
    }
}

/// HChaCha20 of `key` and the first 16 bytes of `nonce`: the ChaCha20 rounds
/// without the final addition, keeping words 0-3 and 12-15.
fn hchacha20(key: &[u8; 32], nonce: &[u8; 24]) -> [u8; 32] {
    let mut st = [0u32; 16];
    let counter = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    chacha20_init(&mut st, key, &nonce[4..16], counter);
    rounds(&mut st);
    let mut out = [0u8; 32];
    for (o, w) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(st[..4].iter().chain(&st[12..]))
    {
        *o = w.to_le_bytes();
    }
    out
}
