use proc_macro::TokenStream;
use quote::quote;
use syn::{AttributeArgs, DeriveInput, Ident, Lit, Meta, NestedMeta, parse_macro_input};

#[proc_macro_attribute]
pub fn select_enum(args: TokenStream, input: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(args as AttributeArgs);
    let input_struct = parse_macro_input!(input as DeriveInput);

    let selector_ident = match attr_args.get(0) {
        Some(NestedMeta::Meta(Meta::Path(path))) => path.get_ident().cloned(),
        _ => panic!("Expected a single identifier as the selector argument"),
    }
    .expect("Expected a valid identifier");

    let enum_name = input_struct.ident;

    if let syn::Data::Enum(enum_data) = input_struct.data {
        let variant_parsers = enum_data.variants.iter().map(|variant| {
            let variant_ident = &variant.ident;
            let condition = match variant
                .attrs
                .iter()
                .find(|attr| attr.path.is_ident("select_case"))
            {
                Some(attr) => {
                    if let Ok(Meta::List(meta_list)) = attr.parse_meta() {
                        if let Some(NestedMeta::Lit(Lit::Int(lit_int))) =
                            meta_list.nested.first()
                        {
                            let int_val = lit_int
                                .base10_parse::<u8>()
                                .expect("Expected an integer literal");
                            quote! {
                                if #selector_ident == #int_val {
                                    return Ok((input, #enum_name::#variant_ident));
                                }
                            }
                        } else {
                            panic!("Expected an integer literal in select_case");
                        }
                    } else {
                        panic!("Expected a select_case attribute list");
                    }
                }
                None => quote! {}, // No condition, skip variant
            };

            condition
        });

        let expanded = quote! {
            #input_struct

            impl #enum_name {
                fn parse<'a>(input: &'a [u8], #selector_ident: u8) -> nom::IResult<&'a [u8], #enum_name> {
                    #(#variant_parsers)*
                    Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
                }
            }
        };

        TokenStream::from(expanded)
    } else {
        panic!("select_enum can only be used on enums");
    }
}
