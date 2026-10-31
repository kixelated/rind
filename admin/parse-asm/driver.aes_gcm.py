from driver import (
    Architecture_aarch64,
    RustDriver,
)
from parse import assemble_and_disassemble, parse_file

if __name__ == "__main__":
    for bits, rounds in ((128, 10), (256, 14)):
        for op in ("enc", "dec"):
            name = "aes%d_gcm_%s" % (bits, op)
            with (
                open("../../thirdparty/s2n-bignum/arm/aes_gcm/%s.S" % name) as input,
                open("../../rind/src/low/aarch64/%s.rs" % name, "w") as output,
            ):
                d = RustDriver(output, Architecture_aarch64)
                d.emit_rust_function(
                    name,
                    parameter_map=[
                        ("inout", "inout => _"),
                        ("inout", "blocks * 128 => _"),
                        ("inout", "inout => _"),
                        ("inout", "tag.as_mut_ptr() => _"),
                        ("inout", "ivec.as_mut_ptr() => _"),
                        ("inout", "key.as_ptr() => _"),
                        ("inout", "htable.as_ptr() => _"),
                    ],
                    func_attrs='#[target_feature(enable = "aes")]\n',
                    # In place: the proofs exclude it, but each block is loaded
                    # before its output is stored (see `low::aarch64::aes_gcm`).
                    rust_decl="unsafe fn %s(inout: *mut [u8; 16], blocks: usize, tag: &mut [u8; 16], ivec: &mut [u8; 16], key: &[core::arch::aarch64::uint8x16_t; %d], htable: &[core::arch::aarch64::uint64x2_t; 6])"
                    % (name, rounds + 1),
                )
                # A BTI landing pad means nothing inside inline assembly.
                input = assemble_and_disassemble(
                    input, tool_prefix="aarch64-linux-gnu-", defines=["NO_IBT=1"]
                )
                parse_file(input, d)
