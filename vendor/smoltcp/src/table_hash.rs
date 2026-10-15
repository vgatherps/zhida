// Constants are hexadecimal pi digits; foldhash uses the same table.
pub(crate) const C1: u64 = 0x243f6a8885a308d3;
pub(crate) const C2: u64 = 0x452821e638d01377;

#[inline]
pub(crate) fn fold_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128) * (b as u128);
    (product >> 64) as u64 ^ product as u64
}

#[inline]
pub(crate) fn mix(hash: u64, word: u64) -> u64 {
    fold_mul(hash ^ word, C2)
}

#[inline]
pub(crate) fn finish(h: u64) -> u64 {
    fold_mul(h, C1)
}
