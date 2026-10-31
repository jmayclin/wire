use crate::codec::DecodeByteSource;
use crate::codec::DecodeValue;
use crate::codec::EncodeBytesSink;
use crate::codec::EncodeValue;

pub mod server_key_exchange {
    use super::*;

    use brass_aphid_wire_macros::{DecodeEnum, DecodeStruct, EncodeEnum, EncodeStruct};

    use crate::{
        codec::DecodeValueWithContext,
        discriminant::impl_byte_value,
        iana::{self},
        prefixed_list::PrefixedBlob,
        protocol::DigitallySignedElement,
    };

    /// The ECCCurveType is used in the server KeyExchange message to indicate the
    /// type of group.
    ///
    /// Generally everything should be using `NamedCurve`.
    ///
    /// [RFC reference](https://datatracker.ietf.org/doc/html/rfc4492#section-5.4)
    #[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
    #[repr(u8)]
    pub enum ECCurveType {
        /// Indicates the elliptic curve domain parameters are conveyed verbosely,
        /// and the underlying finite field is a prime field.
        ExplicitPrime = 1,
        /// Indicates the elliptic curve domain parameters are conveyed verbosely,
        /// and the underlying finite field is a characteristic-2 field.
        ExplicitChar2 = 2,
        /// Indicates that a named curve is used.  This option SHOULD be used when
        /// applicable.
        NamedCurve = 3,
        Unknown(u8),
    }
    impl_byte_value!(ECCurveType, u8);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum EcCurveValue<'a> {
        ExplicitPrime(ExplicitPrimeValue<'a>),
        ExplicitChar2(ExplicitChar2Value<'a>),
        NamedCurve(iana::Group),
    }

    #[derive(Debug, Clone, PartialEq, Eq, EncodeStruct, DecodeStruct)]
    pub struct ServerEcdhParams<'a> {
        pub curve_params: EcParameters<'a>,
        pub public: EcPoint<'a>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, EncodeStruct, DecodeStruct)]
    pub struct EcPoint<'a> {
        pub point: PrefixedBlob<'a, u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
    pub struct ExplicitPrimeValue<'a> {
        pub prime_p: PrefixedBlob<'a, u8>,
        pub curve: EcCurve<'a>,
        pub base: EcPoint<'a>,
        pub order: PrefixedBlob<'a, u8>,
        pub cofactor: PrefixedBlob<'a, u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
    pub struct ExplicitChar2Value<'a> {
        pub m: u16,
        // note, we replace the basis and basis_value types with a single unified
        // struct to minimize the amount of manual Encode/Decode logic we have to
        // write.
        pub basis: EcBasis<'a>,
        pub curve: EcCurve<'a>,
        pub base: EcPoint<'a>,
        pub order: PrefixedBlob<'a, u8>,
        pub cofactor: PrefixedBlob<'a, u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
    pub struct EcCurve<'a> {
        pub a: PrefixedBlob<'a, u8>,
        pub b: PrefixedBlob<'a, u8>,
    }

    /// This type isn't defined in the RFC, but we bundle them together so that
    /// we can minimize the manual encode/decode implementation that we have to
    /// write.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EcBasis<'a> {
        basis_type: EcBasisType,
        basis_value: EcBasisValue<'a>,
    }

    impl<'a> DecodeValue<'a> for EcBasis<'a> {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            let (basis_type, buffer) = buffer.decode_value()?;
            let (basis_value, buffer) = match basis_type {
                EcBasisType::Trinomial => {
                    let (value, buffer) = buffer.decode_value()?;
                    (EcBasisValue::Trinomial(value), buffer)
                }
                EcBasisType::Pentanomial => {
                    let (value, buffer) = buffer.decode_value()?;
                    (EcBasisValue::Pentanomial(value), buffer)
                }
                EcBasisType::Unknown(v) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unrecognized EC basis type {v}"),
                    ));
                }
            };
            let value = Self {
                basis_type,
                basis_value,
            };
            Ok((value, buffer))
        }
    }

    impl EncodeValue for EcBasis<'_> {
        fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
            self.basis_type.encode_to(buffer)?;
            match &self.basis_value {
                EcBasisValue::Trinomial(value) => value.encode_to(buffer),
                EcBasisValue::Pentanomial(value) => value.encode_to(buffer),
            }?;
            Ok(())
        }
    }

    /// You need to look at the errata to figure out that value for this
    /// https://mailarchive.ietf.org/arch/msg/tls/azwTmtiFRoWz9uJYd_tVanBDgYI/
    #[derive(Debug, Clone, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
    #[repr(u8)]
    pub enum EcBasisType {
        Trinomial = 1,
        Pentanomial = 2,
        Unknown(u8),
    }
    impl_byte_value!(EcBasisType, u8);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum EcBasisValue<'a> {
        Trinomial(TrinomialValue<'a>),
        Pentanomial(PentanomialValue<'a>),
    }

    #[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
    pub struct TrinomialValue<'a> {
        pub k: PrefixedBlob<'a, u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
    pub struct PentanomialValue<'a> {
        pub k1: PrefixedBlob<'a, u8>,
        pub k2: PrefixedBlob<'a, u8>,
        pub k3: PrefixedBlob<'a, u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EcParameters<'a> {
        pub curve_type: ECCurveType,
        pub curve_value: EcCurveValue<'a>,
    }

    impl<'a> DecodeValue<'a> for EcParameters<'a> {
        fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
            let (curve_type, buffer) = ECCurveType::decode_from(buffer)?;
            let (named_curve_value, buffer) = match curve_type {
                ECCurveType::ExplicitPrime => {
                    let (value, buffer) = buffer.decode_value()?;
                    (EcCurveValue::ExplicitPrime(value), buffer)
                }
                ECCurveType::ExplicitChar2 => {
                    let (value, buffer) = buffer.decode_value()?;
                    (EcCurveValue::ExplicitChar2(value), buffer)
                }
                ECCurveType::NamedCurve => {
                    let (value, buffer) = buffer.decode_value()?;
                    (EcCurveValue::NamedCurve(value), buffer)
                }
                ECCurveType::Unknown(v) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unrecognized EC curve type {v}"),
                    ));
                }
            };
            let value = Self {
                curve_type,
                curve_value: named_curve_value,
            };
            Ok((value, buffer))
        }
    }

    impl EncodeValue for EcParameters<'_> {
        fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
            self.curve_type.encode_to(buffer)?;
            match &self.curve_value {
                EcCurveValue::ExplicitPrime(value) => value.encode_to(buffer),
                EcCurveValue::ExplicitChar2(value) => value.encode_to(buffer),
                EcCurveValue::NamedCurve(value) => value.encode_to(buffer),
            }?;
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Signature<'a> {
        pub signature: Option<DigitallySignedElement<'a>>,
    }

    impl<'a> DecodeValueWithContext<'a> for Signature<'a> {
        /// if the selected cipher uses anonymous key exchange, then no signature
        /// is included.
        type Context = iana::Cipher;

        fn decode_from_with_context(
        buffer: &'a [u8],
        context: Self::Context,
    ) -> std::io::Result<(Self, &'a [u8])> {
            if context.anonymous_kx() {
                Ok((Self { signature: None }, buffer))
            } else {
                let (signature, buffer) = DigitallySignedElement::decode_from(buffer)?;
                let value = Self {
                    signature: Some(signature),
                };
                Ok((value, buffer))
            }
        }
    }

    //    struct {
    //        opaque dh_p<1..2^16-1>;
    //        opaque dh_g<1..2^16-1>;
    //        opaque dh_Ys<1..2^16-1>;
    //    } ServerDHParams;     /* Ephemeral DH parameters */
    #[derive(Debug, Clone, PartialEq, Eq, DecodeStruct, EncodeStruct)]
    pub struct ServerDhParams<'a> {
        pub dh_p: PrefixedBlob<'a, u16>,
        pub dh_g: PrefixedBlob<'a, u16>,
        pub dh_ys: PrefixedBlob<'a, u16>,
    }
}
