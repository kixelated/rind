// Copyright the HACL* and libcrux authors.
// SPDX-License-Identifier: Apache-2.0
//
// ChaCha20, from HACL*'s verified `Hacl_Chacha20` as libcrux-chacha20poly1305
// 0.0.10 ships it (`src/hacl/chacha20.rs`): the state setup and block function,
// less the module paths. armv7's ChaCha20-Poly1305 runs the same code inside
// libcrux, which does not export it.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(unreachable_patterns)]

use libcrux_hacl_rs::prelude::*;
use libcrux_macros as krml;

use crate::low::zeroise;

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

#[inline]
fn chacha20_core(k: &mut [u32], ctx: &[u32], ctr: u32) {
    (k[0usize..16usize]).copy_from_slice(&ctx[0usize..16usize]);
    let ctr_u32: u32 = ctr;
    k[12usize] = (k[12usize]).wrapping_add(ctr_u32);
    rounds(k);
    krml::unroll_for!(16, "i", 0u32, 1u32, {
        let x: u32 = (k[i as usize]).wrapping_add(ctx[i as usize]);
        let os: (&mut [u32], &mut [u32]) = k.split_at_mut(0usize);
        os.1[i as usize] = x
    });
    k[12usize] = (k[12usize]).wrapping_add(ctr_u32)
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

pub(crate) struct ChaCha20 {
    ctx: [u32; 16],
}

impl ChaCha20 {
    /// `nonce` is the little-endian block counter followed by the 96-bit nonce.
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let mut ctx = [0u32; 16];
        let (counter, nonce) = nonce.split_at(4);
        chacha20_init(
            &mut ctx,
            key,
            nonce,
            u32::from_le_bytes(counter.try_into().unwrap()),
        );
        Self { ctx }
    }

    pub(crate) fn cipher(&mut self, buffer: &mut [u8]) {
        let mut keystream = [0u32; 16];
        for block in buffer.chunks_mut(64) {
            chacha20_core(&mut keystream, &self.ctx, 0);
            for (b, k) in block
                .iter_mut()
                .zip(keystream.iter().flat_map(|w| w.to_le_bytes()))
            {
                *b ^= k;
            }
            self.ctx[12] = self.ctx[12].wrapping_add(1);
        }
        zeroise(&mut keystream);
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        zeroise(&mut self.ctx);
    }
}
