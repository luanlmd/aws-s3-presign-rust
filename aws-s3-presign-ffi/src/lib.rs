use std::ffi::CStr;
use aws_s3_presign::GetSignedUrlOptions;

#[no_mangle]
pub extern "C" fn add(a: f64, b:f64) -> f64
{
   return a + b;
}

#[no_mangle]
pub extern "C" fn ffi_get_signature_key(secret_access_key_ptr: *const i8) -> *const u8
{
    unsafe
    {
        let secret_access_key = CStr::from_ptr(secret_access_key_ptr).to_str().unwrap();
        println!("Rust String Received: {}", &secret_access_key);

        let options: GetSignedUrlOptions = GetSignedUrlOptions {
            secret_access_key: String::from(secret_access_key),
            ..GetSignedUrlOptions::default()
        };

        let signature_vec = aws_s3_presign::get_signature_key(&options);
        println!("Rust Signature: {:?}", signature_vec);
        return signature_vec.as_ptr();
    }
}

#[no_mangle]
pub extern "C" fn ffi_get_signed_url(_options: *const i8, signature_key_ptr: *const i8) ->  *const u8
{
    unsafe
    {
        let signature_key = signature_key_ptr.as_ref().unwrap();
        println!("Rust Signature: {:?}", signature_key);

        return "qwerty\0".as_bytes().as_ptr();
    }
}
