use crate::wire::icmpv4;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Repr<'a> {
    Ipv4(icmpv4::Repr<'a>),
}
impl<'a> From<icmpv4::Repr<'a>> for Repr<'a> {
    fn from(s: icmpv4::Repr<'a>) -> Self {
        Repr::Ipv4(s)
    }
}
