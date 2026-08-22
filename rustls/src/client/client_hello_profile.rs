//! Shaping the `ClientHello` to resemble another TLS implementation.
//!
//! rustls sends the `ClientHello` rustls needs, and that hello is recognisably
//! rustls: a censor or a CDN can tell it apart from a browser by the set of
//! extensions alone, before a single byte of application data is exchanged.
//! For a plain HTTPS client that is nobody's problem. For a client whose whole
//! job is to be indistinguishable from a browser - anything built on Reality,
//! ShadowTLS or similar - it is the problem.
//!
//! This module carries the parts of that job which belong in the TLS stack,
//! and only those: GREASE (RFC 8701), and room for extensions rustls has no
//! reason to model. Which extensions a given browser sends, in what order,
//! with what bodies, is not knowledge rustls should hold - that lives in the
//! caller, expressed through [`RawExtension`].

use alloc::vec::Vec;

use crate::Error;
use crate::crypto::SecureRandom;
use crate::msgs::handshake::RawExtension;

/// The sixteen values RFC 8701 reserves for GREASE.
///
/// They are spread across the codepoint space on purpose: a peer that special
/// cases one of them, or that chokes on an unknown value, is caught early
/// rather than years later when a real extension takes that number.
pub(crate) const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// How the `ClientHello` should look on the wire.
///
/// The default sends what rustls has always sent. Every field below moves the
/// hello towards resembling something else, and none of them change what is
/// negotiated: GREASE values are ignored by any correct peer, and verbatim
/// extensions are the caller's business.
#[derive(Clone, Debug, Default)]
pub struct ClientHelloProfile {
    /// Advertise GREASE values (RFC 8701).
    ///
    /// When set, a reserved value is added to the cipher suite list, the
    /// supported groups list, the key share list and the supported versions
    /// list, and two more appear as extensions of their own - one first in the
    /// extension list, one just before the trailing extensions. That is what
    /// browsers built on BoringSSL do, down to the bodies of the two: the
    /// first empty, the second a single zero byte.
    pub grease: bool,

    /// Extensions written before everything rustls generates.
    pub prepend_extensions: Vec<RawExtension>,

    /// Extensions written after everything rustls generates.
    ///
    /// They still precede the extensions the standard pins to the end of the
    /// list - encrypted client hello and the pre-shared key offer.
    pub append_extensions: Vec<RawExtension>,

    /// Pad the hello out with a `padding` extension (RFC 7685).
    pub padding: Option<Padding>,

    /// The cipher suite list to put on the wire, in this order.
    ///
    /// By default rustls advertises the suites its provider holds, which is
    /// also the set it can negotiate. Those two are the same thing right up
    /// until the hello has to resemble an implementation that supports suites
    /// rustls does not - and every browser does, static RSA key exchange being
    /// the obvious case. The suite count and their order both feed the common
    /// fingerprints, so leaving them at what rustls happens to support gives
    /// the game away on its own.
    ///
    /// # This is a loaded gun
    ///
    /// Suites listed here are advertised and nothing more. If the peer selects
    /// one that the provider cannot actually do, the handshake fails - late,
    /// after the server has already committed to it. Two consequences:
    ///
    /// - keep every suite the provider supports in the list, or connections
    ///   will fail against perfectly ordinary servers;
    /// - only advertise suites rustls lacks where the peer cannot pick them,
    ///   which in practice means a peer pinned to TLS 1.3.
    ///
    /// Nothing else in the hello is derived from this field: the versions and
    /// key shares offered are still rustls own.
    pub cipher_suites: Option<Vec<u16>>,
}

/// When and how far to pad the `ClientHello`.
///
/// Padding exists because some middleboxes mishandle a hello whose length
/// lands in a particular range; browsers therefore pad out of that range
/// unconditionally. Its side effect is that hello length stops being a
/// distinguishing feature, which is why it belongs here.
#[derive(Clone, Copy, Debug)]
pub struct Padding {
    /// Pad only if the hello has reached this length. Shorter helloes are left
    /// alone: padding a small hello would itself stand out.
    pub only_above: usize,

    /// Length to pad up to.
    pub up_to: usize,
}

impl Default for Padding {
    /// The rule BoringSSL applies, and so every browser built on it.
    fn default() -> Self {
        Self {
            only_above: 0x100,
            up_to: 0x200,
        }
    }
}

impl Padding {
    /// How many zero bytes the padding extension body needs, given the length
    /// the hello has reached without it.
    ///
    /// `None` when no padding extension should be sent at all - which is not
    /// the same as an empty one, that being a visible difference on the wire.
    pub(crate) fn body_len(&self, hello_len: usize) -> Option<usize> {
        if hello_len < self.only_above || hello_len >= self.up_to {
            return None;
        }

        // The extension header is four bytes and is itself part of what we are
        // padding. If those four alone overshoot the target there is nothing
        // sensible left to add, so send an empty body rather than a negative
        // one.
        Some(
            self.up_to
                .saturating_sub(hello_len)
                .saturating_sub(4),
        )
    }
}

/// GREASE values chosen for one connection.
///
/// Picked once and kept, because a `HelloRetryRequest` makes us send a second
/// hello which has to agree with the first.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Grease {
    pub(crate) cipher_suite: u16,
    pub(crate) named_group: u16,
    pub(crate) version: u16,
    pub(crate) first_extension: u16,
    pub(crate) last_extension: u16,
}

impl Grease {
    /// The single byte browsers put in the GREASE key share.
    ///
    /// The content is meaningless by definition; the length is not, so it is
    /// fixed here rather than left to chance.
    pub(crate) const KEY_SHARE_PAYLOAD: [u8; 1] = [0x00];

    /// The body of the trailing GREASE extension.
    ///
    /// The leading one is empty and this one is a single zero byte. There is
    /// no reason for the asymmetry beyond BoringSSL doing it that way, and
    /// that is reason enough: matching it is the entire point.
    pub(crate) const LAST_EXTENSION_PAYLOAD: [u8; 1] = [0x00];

    pub(crate) fn new(random: &'static dyn SecureRandom) -> Result<Self, Error> {
        let mut seed = [0u8; 5];
        random.fill(&mut seed)?;

        let pick = |byte: u8| GREASE_VALUES[usize::from(byte & 0x0f)];

        // The two extension placeholders must differ: two extensions of the
        // same type in one hello is a protocol error, and a peer rejecting it
        // would be right to.
        let first_extension = pick(seed[3]);
        let mut last_extension = pick(seed[4]);
        if last_extension == first_extension {
            last_extension = GREASE_VALUES[usize::from(seed[4].wrapping_add(1) & 0x0f)];
        }

        Ok(Self {
            cipher_suite: pick(seed[0]),
            named_group: pick(seed[1]),
            version: pick(seed[2]),
            first_extension,
            last_extension,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_follows_the_boringssl_rule() {
        let padding = Padding::default();

        // Below the window: left alone.
        assert_eq!(padding.body_len(0xff), None);
        // At the bottom edge: padded up to the target, header included.
        assert_eq!(padding.body_len(0x100), Some(0x200 - 0x100 - 4));
        // Room for a body.
        assert_eq!(padding.body_len(0x1f0), Some(0x200 - 0x1f0 - 4));
        // Too close to the target for the four byte header to fit: an empty
        // extension goes out anyway, overshooting by those four bytes. That is
        // what BoringSSL does, and matching it is the point.
        assert_eq!(padding.body_len(0x1ff), Some(0));
        // At and above the target: nothing to do.
        assert_eq!(padding.body_len(0x200), None);
        assert_eq!(padding.body_len(0x400), None);
    }

    #[test]
    fn padding_never_asks_for_a_negative_body() {
        // Four bytes short of the target there is no room for a body, but the
        // extension is still sent - an absent extension and an empty one look
        // different on the wire.
        let padding = Padding {
            only_above: 0,
            up_to: 10,
        };
        assert_eq!(padding.body_len(8), Some(0));
        assert_eq!(padding.body_len(7), Some(0));
        assert_eq!(padding.body_len(6), Some(0));
        assert_eq!(padding.body_len(5), Some(1));
    }

    #[test]
    fn grease_values_are_the_reserved_ones() {
        // Every value is 0xNaNa, which is what makes them recognisable.
        for value in GREASE_VALUES {
            let [high, low] = value.to_be_bytes();
            assert_eq!(high, low);
            assert_eq!(low & 0x0f, 0x0a);
        }
    }
}
