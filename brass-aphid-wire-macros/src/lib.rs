extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Implement `EncodeValue` for an enum.
///
/// The enum must have a `byte_value` method which returns the appropriate sized
/// primitive for each variant.
///
/// The generated implementation looks like the following.
/// ```ignore
/// impl EncodeValue for ContentType {
///     fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
///         self.byte_value().encode_to(buffer)
///     }
/// }
/// ```
#[proc_macro_derive(EncodeEnum)]
pub fn derive_encode_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = input.ident.clone();

    let Data::Enum(_) = input.data else {
        return syn::Error::new_spanned(input.ident, "EncodeEnum only supports enums")
            .to_compile_error()
            .into();
    };

    let output = quote! {
        impl EncodeValue for #enum_name {
            fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
                self.byte_value().encode_to(buffer)
            }
        }
    };

    output.into()
}

/// Implement `DecodeValue` for an enum
///
/// The enum must have defined a `byte_value()` method. The actual implementation
/// looks like the following:
/// ```ignore
/// impl DecodeValue for ContentType {
///     fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
///         let (value, buffer) = buffer.decode_value()?;
///         match Self::iter().find(|e| e.byte_value() == value) {
///             Some(valid) => Ok((valid, buffer)),
///             None => Err(io::Error::new(
///                 ErrorKind::InvalidInput,
///                 format!("{} is not a valid {}", value, type_name::<Self>()),
///             )),
///         }
///     }
/// }
/// ```
#[proc_macro_derive(DecodeEnum)]
pub fn derive_decode_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = input.ident.clone();

    let Data::Enum(_) = input.data else {
        return syn::Error::new_spanned(input.ident, "DecodeEnum only supports enums")
            .to_compile_error()
            .into();
    };

    let output = quote! {
        impl DecodeValue for #enum_name {
            fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
                let (value, buffer) = buffer.decode_value()?;
                match <Self as strum::IntoEnumIterator>::iter().find(|e| e.byte_value() == value) {
                    Some(valid) => Ok((valid, buffer)),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("{} is not a valid {}", value, std::any::type_name::<Self>()),
                    )),
                }
            }
        }
    };

    output.into()
}

/// Derive `DecodeValue` for a struct.
///
/// All of the members of the struct must also implement DecodeValue.
///
/// The resulting derivation looks like the following:
/// ```ignore
/// impl DecodeValue for HandshakeMessageHeader {
///     fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
///         let (handshake_type, buffer) = buffer.decode_value()?;
///         let (handshake_message_length, buffer) = buffer.decode_value()?;
///
///         let header = Self {
///             handshake_type,
///             handshake_message_length,
///         };
///
///         Ok((header, buffer))
///     }
/// }
/// ```
#[proc_macro_derive(DecodeStruct)]
pub fn derive_decode_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident;

    let Data::Struct(data_struct) = input.data else {
        return syn::Error::new_spanned(&struct_name, "DecodeStruct only supports structs")
            .to_compile_error()
            .into();
    };

    let Fields::Named(fields_named) = data_struct.fields else {
        return syn::Error::new_spanned(&struct_name, "DecodeStruct requires named fields")
            .to_compile_error()
            .into();
    };

    let mut decode_stmts = Vec::new();
    let mut field_bindings = Vec::new();

    for field in &fields_named.named {
        if let Some(ident) = &field.ident {
            let field_str = ident.to_string();
            decode_stmts.push(quote! {
                let (#ident, buffer) = buffer.decode_value()
                    .map_err(|e| std::io::Error::new(e.kind(), format!("{} while decoding field `{}`", e, #field_str)))?;
            });
            field_bindings.push(quote! { #ident });
        }
    }

    let output = quote! {
        impl DecodeValue for #struct_name {
            fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
                #(#decode_stmts)*

                let result = Self {
                    #(#field_bindings),*
                };

                Ok((result, buffer))
            }
        }
    };

    output.into()
}

/// Derive `EncodeValue` for a struct.
///
/// All of the members of the struct must also implement EncodeValue.
///
/// The resulting derivation looks like the following:
/// ```ignore
/// impl EncodeValue for HandshakeMessageHeader {
///     fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
///         buffer.encode_value(&self.handshake_type)?;
///         buffer.encode_value(&self.handshake_message_length)?;
///         Ok(())
///     }
/// }
/// ```
#[proc_macro_derive(EncodeStruct)]
pub fn derive_encode_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident;

    let Data::Struct(data_struct) = input.data else {
        return syn::Error::new_spanned(&struct_name, "EncodeStruct only supports structs")
            .to_compile_error()
            .into();
    };

    let Fields::Named(fields_named) = data_struct.fields else {
        return syn::Error::new_spanned(&struct_name, "EncodeStruct requires named fields")
            .to_compile_error()
            .into();
    };

    let encode_stmts: Vec<_> = fields_named
        .named
        .iter()
        .map(|f| {
            let ident = f.ident.as_ref().unwrap();
            quote! {
                buffer.encode_value(&self.#ident)?;
            }
        })
        .collect();

    let output = quote! {
        impl EncodeValue for #struct_name {
            fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
                #(#encode_stmts)*
                Ok(())
            }
        }
    };

    output.into()
}
