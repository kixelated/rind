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
                        ("inout", "input.as_ptr() => _"),
                        ("inout", "input.len() * 128 => _"),
                        ("inout", "output.as_mut_ptr() => _"),
                        ("inout", "tag.as_mut_ptr() => _"),
                        ("inout", "ivec.as_mut_ptr() => _"),
                        ("inout", "key.as_ptr() => _"),
                        ("inout", "htable.as_ptr() => _"),
                    ],
                    assertions=["input.len() == output.len()"],
                    func_attrs='#[target_feature(enable = "aes")]\n',
                    rust_decl="fn %s(input: &[[u8; 16]], output: &mut [[u8; 16]], tag: &mut [u8; 16], ivec: &mut [u8; 16], key: &[core::arch::aarch64::uint8x16_t; %d], htable: &[core::arch::aarch64::uint64x2_t; 6])"
                    % (name, rounds + 1),
                )
                # A BTI landing pad means nothing inside inline assembly.
                input = assemble_and_disassemble(
                    input, tool_prefix="aarch64-linux-gnu-", defines=["NO_IBT=1"]
                )
                parse_file(input, d)
