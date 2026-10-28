# CAVP SHA-1 sample files

NIST [CAVP][cavp] sample responses for SHA-1, which the `thirdparty/cavp`
mirror omits. The files are unmodified.

Source (retrieved 2026-10-27):
<https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip>

`SHA1LongMsg.rsp` is left out; differential tests against aws-lc-rs cover
long messages.

[cavp]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
