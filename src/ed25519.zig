const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub fn derivePublic(seed: [32]u8) [32]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    return kp.public_key.bytes;
}

pub fn sign(msg: []const u8, seed: [32]u8) [64]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const sig = kp.sign(msg, null) catch unreachable;
    return sig.toBytes();
}

/// Strict RFC 8032 cofactorless Ed25519 verification matching Go `sshlib.EdVerify`:
/// rejects non-canonical public key encodings, non-canonical R encodings, and S >= L.
pub fn verify(msg: []const u8, sig_bytes: [64]u8, pub_bytes: [32]u8) bool {
    const pk = Ed25519.PublicKey.fromBytes(pub_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verifyStrict(msg, pk) catch return false;
    return true;
}

test "RFC 8032 test vector 1" {
    const store = @import("store.zig");
    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const want_pub = store.decodeLowerHexFixed(32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").?;
    const got_pub = derivePublic(seed);
    try std.testing.expectEqualSlices(u8, &want_pub, &got_pub);

    const sig = sign("", seed);
    try std.testing.expect(verify("", sig, got_pub));

    var bad_sig = sig;
    bad_sig[63] ^= 0x01;
    try std.testing.expect(!verify("", bad_sig, got_pub));
}
