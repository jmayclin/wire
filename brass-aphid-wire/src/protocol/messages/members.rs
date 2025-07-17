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
    #[derive(Debug, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
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
    }
    impl_byte_value!(ECCurveType, u8);

    #[derive(Debug)]
    pub enum EcCurveValue {
        ExplicitPrime(ExplicitPrimeValue),
        ExplicitChar2(ExplicitChar2Value),
        NamedCurve(iana::Group),
    }

    #[derive(Debug, EncodeStruct, DecodeStruct)]
    pub struct ServerEcdhParams {
        pub curve_params: EcParameters,
        pub public: EcPoint,
    }

    #[derive(Debug, EncodeStruct, DecodeStruct)]
    pub struct EcPoint {
        pub point: PrefixedBlob<u8>,
    }

    #[derive(Debug, DecodeStruct, EncodeStruct)]
    pub struct ExplicitPrimeValue {
        pub prime_p: PrefixedBlob<u8>,
        pub curve: EcCurve,
        pub base: EcPoint,
        pub order: PrefixedBlob<u8>,
        pub cofactor: PrefixedBlob<u8>,
    }

    #[derive(Debug, DecodeStruct, EncodeStruct)]
    pub struct ExplicitChar2Value {
        pub m: u16,
        // note, we replace the basis and basis_value types with a single unified
        // struct to minimize the amount of manual Encode/Decode logic we have to
        // write.
        pub basis: EcBasis,
        pub curve: EcCurve,
        pub base: EcPoint,
        pub order: PrefixedBlob<u8>,
        pub cofactor: PrefixedBlob<u8>,
    }

    #[derive(Debug, DecodeStruct, EncodeStruct)]
    pub struct EcCurve {
        pub a: PrefixedBlob<u8>,
        pub b: PrefixedBlob<u8>,
    }

    /// This type isn't defined in the RFC, but we bundle them together so that
    /// we can minimize the manual encode/decode implementation that we have to
    /// write.
    #[derive(Debug)]
    pub struct EcBasis {
        basis_type: EcBasisType,
        basis_value: EcBasisValue,
    }

    impl DecodeValue for EcBasis {
        fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
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
            };
            let value = Self {
                basis_type,
                basis_value,
            };
            Ok((value, buffer))
        }
    }

    impl EncodeValue for EcBasis {
        fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
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
    #[derive(Debug, PartialEq, Eq, strum::EnumIter, EncodeEnum, DecodeEnum)]
    #[repr(u8)]
    pub enum EcBasisType {
        Trinomial = 1,
        Pentanomial = 2,
    }
    impl_byte_value!(EcBasisType, u8);

    #[derive(Debug)]
    pub enum EcBasisValue {
        Trinomial(TrinomialValue),
        Pentanomial(PentanomialValue),
    }

    #[derive(Debug, DecodeStruct, EncodeStruct)]
    pub struct TrinomialValue {
        pub k: PrefixedBlob<u8>,
    }

    #[derive(Debug, DecodeStruct, EncodeStruct)]
    pub struct PentanomialValue {
        pub k1: PrefixedBlob<u8>,
        pub k2: PrefixedBlob<u8>,
        pub k3: PrefixedBlob<u8>,
    }

    #[derive(Debug)]
    pub struct EcParameters {
        pub curve_type: ECCurveType,
        pub curve_value: EcCurveValue,
    }

    impl DecodeValue for EcParameters {
        fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
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
            };
            let value = Self {
                curve_type,
                curve_value: named_curve_value,
            };
            Ok((value, buffer))
        }
    }

    impl EncodeValue for EcParameters {
        fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
            self.curve_type.encode_to(buffer)?;
            match &self.curve_value {
                EcCurveValue::ExplicitPrime(value) => value.encode_to(buffer),
                EcCurveValue::ExplicitChar2(value) => value.encode_to(buffer),
                EcCurveValue::NamedCurve(value) => value.encode_to(buffer),
            }?;
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct Signature {
        pub signature: Option<DigitallySignedElement>,
    }

    impl DecodeValueWithContext for Signature {
        /// if the selected cipher uses anonymous key exchange, then no signature
        /// is included.
        type Context = iana::Cipher;

        fn decode_from_with_context(
            buffer: &[u8],
            context: Self::Context,
        ) -> std::io::Result<(Self, &[u8])> {
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
    #[derive(Debug, DecodeStruct, EncodeStruct)]
    pub struct ServerDhParams {
        pub dh_p: PrefixedBlob<u16>,
        pub dh_g: PrefixedBlob<u16>,
        pub dh_ys: PrefixedBlob<u16>,
    }
}
