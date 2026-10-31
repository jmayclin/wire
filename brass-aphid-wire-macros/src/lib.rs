extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::visit_mut::VisitMut;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Returns true if the enum has a variant named "Unknown" with exactly one unnamed field.
fn has_unknown_variant(data: &syn::DataEnum) -> bool {
    data.variants.iter().any(|v| {
        v.ident == "Unknown" && matches!(&v.fields, Fields::Unnamed(f) if f.unnamed.len() == 1)
    })
}

/// Implement `EncodeValue` for an enum.
///
/// The enum must have a `byte_value` method which returns the appropriate sized
/// primitive for each variant.
///
/// If the enum has an `Unknown(T)` variant, the inner value is encoded directly
/// for that variant.
#[proc_macro_derive(EncodeEnum)]
pub fn derive_encode_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = input.ident.clone();

    let Data::Enum(data_enum) = &input.data else {
        return syn::Error::new_spanned(input.ident, "EncodeEnum only supports enums")
            .to_compile_error()
            .into();
    };

    let output = if has_unknown_variant(data_enum) {
        quote! {
            impl EncodeValue for #enum_name {
                fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
                    if let Self::Unknown(v) = self {
                        v.encode_to(buffer)
                    } else {
                        self.byte_value().encode_to(buffer)
                    }
                }
            }
        }
    } else {
        quote! {
            impl EncodeValue for #enum_name {
                fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
                    self.byte_value().encode_to(buffer)
                }
            }
        }
    };

    output.into()
}

/// Implement `DecodeValue` for an enum.
///
/// The enum must have defined a `byte_value()` method and implement `strum::IntoEnumIterator`.
///
/// If the enum has an `Unknown(T)` variant, unrecognized values are stored in that
/// variant instead of returning an error.
#[proc_macro_derive(DecodeEnum)]
pub fn derive_decode_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = input.ident.clone();

    let Data::Enum(data_enum) = &input.data else {
        return syn::Error::new_spanned(input.ident, "DecodeEnum only supports enums")
            .to_compile_error()
            .into();
    };

    // Enums never borrow from the buffer, so they implement `DecodeValue<'a>`
    // for every `'a`.
    let output = if has_unknown_variant(data_enum) {
        quote! {
            impl<'a> DecodeValue<'a> for #enum_name {
                fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
                    fn __decode_repr<'b, E, R: DecodeValue<'b>>(
                        buffer: &'b [u8],
                        _byte_value: fn(&E) -> R,
                    ) -> std::io::Result<(R, &'b [u8])> {
                        R::decode_from(buffer)
                    }
                    let (value, buffer) = __decode_repr(buffer, Self::byte_value)?;
                    let result = <Self as strum::IntoEnumIterator>::iter()
                        .find(|e| {
                            !matches!(e, Self::Unknown(_)) && e.byte_value() == value
                        })
                        .unwrap_or(Self::Unknown(value));
                    Ok((result, buffer))
                }
            }
        }
    } else {
        quote! {
            impl<'a> DecodeValue<'a> for #enum_name {
                fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
                    fn __decode_repr<'b, E, R: DecodeValue<'b>>(
                        buffer: &'b [u8],
                        _byte_value: fn(&E) -> R,
                    ) -> std::io::Result<(R, &'b [u8])> {
                        R::decode_from(buffer)
                    }
                    let (value, buffer) = __decode_repr(buffer, Self::byte_value)?;
                    match <Self as strum::IntoEnumIterator>::iter().find(|e| e.byte_value() == value) {
                        Some(valid) => Ok((valid, buffer)),
                        None => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("{} is not a valid {}", value, std::any::type_name::<Self>()),
                        )),
                    }
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
/// impl<'a> DecodeValue<'a> for HandshakeMessageHeader {
///     fn decode_from(buffer: &'a [u8]) -> std::io::Result<(Self, &'a [u8])> {
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
    let struct_name = input.ident.clone();

    let Data::Struct(data_struct) = input.data.clone() else {
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

    // If the struct already has a lifetime parameter (because it holds borrowed
    // data like `PrefixedBlob<'a, L>`), reuse it. Otherwise introduce a fresh
    // `'a` that the struct doesn't mention.
    let (impl_generics, ty_generics, lifetime) = match input.generics.lifetimes().next() {
        Some(lt) => {
            let lt = lt.lifetime.clone();
            (quote! { <#lt> }, quote! { <#lt> }, quote! { #lt })
        }
        None => (quote! { <'a> }, quote! {}, quote! { 'a }),
    };

    let output = quote! {
        impl #impl_generics DecodeValue<#lifetime> for #struct_name #ty_generics {
            fn decode_from(buffer: &#lifetime [u8]) -> std::io::Result<(Self, &#lifetime [u8])> {
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
///     fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
///         buffer.encode_value(&self.handshake_type)?;
///         buffer.encode_value(&self.handshake_message_length)?;
///         Ok(())
///     }
/// }
/// ```
#[proc_macro_derive(EncodeStruct)]
pub fn derive_encode_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident.clone();

    let Data::Struct(data_struct) = input.data.clone() else {
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

    let (impl_generics, ty_generics) = match input.generics.lifetimes().next() {
        Some(lt) => {
            let lt = lt.lifetime.clone();
            (quote! { <#lt> }, quote! { <#lt> })
        }
        None => (quote! {}, quote! {}),
    };

    let output = quote! {
        impl #impl_generics EncodeValue for #struct_name #ty_generics {
            fn encode_to(&self, buffer: &mut std::io::Cursor<&mut [u8]>) -> std::io::Result<()> {
                #(#encode_stmts)*
                Ok(())
            }
        }
    };

    output.into()
}


//////////////////////////////// Writers ///////////////////////////////////////

/// Rewrites every lifetime in a type to `'static`.
///
/// The type is only used as the `T` in a `Writer<T>` bound, where it names a
/// decoded type. The lifetime is never used for anything, and the `Writer` impls
/// leave it free, so any lifetime would do and `'static` needs no declaration.
struct ToStatic;

impl VisitMut for ToStatic {
    fn visit_lifetime_mut(&mut self, lifetime: &mut syn::Lifetime) {
        *lifetime = syn::Lifetime::new("'static", lifetime.span());
    }
}

/// If `ty` is `Option<X>`, return `X`.
///
/// This matches on the name, so a type alias for `Option` is not recognized.
fn option_inner(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match args.args.first()? {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

/// Shared implementation of `WriterStruct` and `Writer`.
fn expand_writer(
    input: &DeriveInput,
    derive_name: &str,
    with_encode: bool,
) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let vis = &input.vis;
    let writer_name = format_ident!("{}Writer", name);

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            format!("{derive_name} only supports structs"),
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            name,
            format!("{derive_name} requires named fields"),
        ));
    };
    if input.generics.type_params().next().is_some()
        || input.generics.const_params().next().is_some()
        || input.generics.lifetimes().count() > 1
    {
        return Err(syn::Error::new_spanned(
            &input.generics,
            format!("{derive_name} supports at most one lifetime parameter and no type parameters"),
        ));
    }

    let mut tparams = Vec::new();
    let mut bounds = Vec::new();
    let mut writer_fields = Vec::new();
    let mut encode_stmts = Vec::new();

    for (index, field) in fields.named.iter().enumerate() {
        let ident = field.ident.as_ref().expect("named fields have identifiers");
        let field_vis = &field.vis;
        let tparam = format_ident!("T{}", index + 1);

        // an `Option<X>` field is written as `Option<T>` where `T: Writer<X>`
        let (decoded, is_option) = match option_inner(&field.ty) {
            Some(inner) => (inner, true),
            None => (&field.ty, false),
        };
        let mut marker = decoded.clone();
        ToStatic.visit_type_mut(&mut marker);

        bounds.push(quote! { #tparam: Writer<#marker> });
        if is_option {
            writer_fields.push(quote! { #field_vis #ident: Option<#tparam> });
            encode_stmts.push(quote! {
                if let Some(value) = &self.#ident {
                    <#tparam as Writer<#marker>>::encode_transform(value, buffer)?;
                }
            });
        } else {
            writer_fields.push(quote! { #field_vis #ident: #tparam });
            encode_stmts.push(quote! {
                <#tparam as Writer<#marker>>::encode_transform(&self.#ident, buffer)?;
            });
        }
        tparams.push(tparam);
    }

    // the decoded type borrows with `'a` if it has a lifetime. The writer never
    // does: all of its borrows are inside its type parameters.
    let (lifetime_generics, decoded_ty) = match input.generics.lifetimes().next() {
        Some(lifetime) => {
            let lifetime = &lifetime.lifetime;
            (quote! { #lifetime, }, quote! { #name<#lifetime> })
        }
        None => (quote! {}, quote! { #name }),
    };

    let doc = format!(
        "The write side of [`{name}`], generated by `#[derive({derive_name})]`.\n\n\
         Each field is a type parameter that can write itself out as the \
         corresponding field of `{name}`."
    );

    let encode_impl = if with_encode {
        quote! {
            impl<#(#tparams),*> EncodeValue for #writer_name<#(#tparams),*>
            where
                #(#bounds),*
            {
                fn encode_to(
                    &self,
                    buffer: &mut std::io::Cursor<&mut [u8]>,
                ) -> std::io::Result<()> {
                    #(#encode_stmts)*
                    Ok(())
                }
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        #[doc = #doc]
        #vis struct #writer_name<#(#tparams),*>
        where
            #(#bounds),*
        {
            #(#writer_fields),*
        }

        #encode_impl

        // lets the writer be used as a field of another writer. It needs an
        // `EncodeValue` impl, which `Writer` derives, and `WriterStruct` leaves
        // to the caller.
        impl<#lifetime_generics #(#tparams),*> Writer<#decoded_ty> for #writer_name<#(#tparams),*>
        where
            #(#bounds,)*
            Self: EncodeValue,
        {
            fn encode_transform(
                &self,
                buffer: &mut std::io::Cursor<&mut [u8]>,
            ) -> std::io::Result<()> {
                <Self as EncodeValue>::encode_to(self, buffer)
            }
        }
    })
}

/// Derive only the writer struct.
///
/// For a struct `Foo` this generates `FooWriter<T1, .., Tn>`, with one type
/// parameter per field. Field `f: F` becomes `f: Ti` where `Ti: Writer<F>`, and
/// `f: Option<F>` becomes `f: Option<Ti>`. It also generates
/// `impl Writer<Foo> for FooWriter<..>`, so writers nest.
///
/// It does *not* generate `EncodeValue for FooWriter`. Write that by hand when
/// the encoding needs validation or logic that the fields alone can't express,
/// and use `#[derive(Writer)]` when it doesn't.
///
/// `Writer` and `EncodeValue` must be in scope where this is used.
#[proc_macro_derive(WriterStruct)]
pub fn derive_writer_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_writer(&input, "WriterStruct", false) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Derive the writer struct and its `EncodeValue` impl.
///
/// This is `WriterStruct` plus `impl EncodeValue for FooWriter`, which encodes
/// the fields in declaration order, skipping `None` for `Option` fields.
#[proc_macro_derive(Writer)]
pub fn derive_writer(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_writer(&input, "Writer", true) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
