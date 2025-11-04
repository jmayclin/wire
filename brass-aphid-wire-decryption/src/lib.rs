pub mod decryption;

pub mod key_log;
pub mod offline;
pub mod prefixed_list;
#[cfg(test)]
pub mod testing;

mod discriminant {
    macro_rules! impl_byte_value {
        ($enum:ident, $repr:ty) => {
            impl $enum {
                #[allow(dead_code)]
                pub fn byte_value(&self) -> $repr {
                    // SAFETY: Because the enum is marked #[repr($repr)], we can read
                    // the discriminant directly from the memory representation.
                    // https://doc.rust-lang.org/std/mem/fn.discriminant.html#accessing-the-numeric-value-of-the-discriminant
                    unsafe { *<*const _>::from(self).cast::<$repr>() }
                }
            }
        };
    }

    
}
