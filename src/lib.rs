use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use url_search_params::build_url_search_params;

#[derive(Debug)]
pub struct GetSignedUrlOptions {
    pub key: String,
    pub method: String,
    pub region: String,
    pub expires_in: i32,
    pub date: DateTime<Utc>,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint: String,
    pub pre_signature: Option<Vec<u8>>
}

impl Default for GetSignedUrlOptions {
    fn default() -> GetSignedUrlOptions {
        GetSignedUrlOptions {
            key: String::from("key"),
            method: String::from("GET"),
            region: String::from("auto"),
            expires_in: 84600,
            date: Utc::now(),
            bucket: String::from("bucket"),
            access_key_id: String::from("key_id"),
            secret_access_key: String::from("key_secret"),
            endpoint: String::from("endpoint"),
            pre_signature: None,
        }
    }
}

fn sha256(data: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    return format!("{:x}",hasher.finalize());
}

fn hmac_sha_256(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data);
    return hasher.finalize().into_bytes().to_vec();
}

fn hmac_sha_256_hex(key: &Vec<u8>, data: &String) -> String {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data.as_bytes());
    return format!("{:x}", hasher.finalize().into_bytes());
}

fn get_query_parameters(options: &GetSignedUrlOptions) -> String
{
    let mut url_params: HashMap<String, String>= HashMap::new();
    url_params.insert("X-Amz-Algorithm".to_string(), "AWS4-HMAC-SHA256".to_string());
    url_params.insert("X-Amz-Credential".to_string(), options.access_key_id.to_string() + "/" + &options.date.format("%Y%m%d").to_string() + "/" + &options.region + "/s3/aws4_request");
    url_params.insert("X-Amz-Date".to_string(), options.date.format("%Y%m%dT%H%M%SZ").to_string());
    url_params.insert("X-Amz-Expires".to_string(), options.expires_in.to_string());
    url_params.insert("X-Amz-SignedHeaders".to_string(), "host".to_string());
    return build_url_search_params(url_params);
}

fn get_canonical_request(options: &GetSignedUrlOptions, query_parameters: &String) -> String
{
    let key = &("/".to_string() + &options.key);
    let host = &("host:".to_string() + &options.bucket + "." + &options.endpoint);

    let canonical_request: Vec<&str> = vec![&options.method, key, query_parameters, host, "", "host", "UNSIGNED-PAYLOAD"];
    return canonical_request.join("\n");
}

fn get_signature_payload(options: &GetSignedUrlOptions, payload: String) -> String
{
    let payload_hash = &sha256(&payload)[..];
    let date1 = &options.date.format("%Y%m%dT%H%M%SZ").to_string()[..];
    let date2 = &options.date.format("%Y%m%d").to_string()[..];
    let third = &(date2.to_owned() + "/" + &options.region + "/s3/aws4_request");

    let signature_payload: Vec<&str> = vec!["AWS4-HMAC-SHA256", &date1, &third, payload_hash];
    return signature_payload.join("\n");
}

pub fn get_signature_key(options: &GetSignedUrlOptions) -> Vec<u8>
{
    let parts: Vec<String> = vec![
        "AWS4".to_string() + &options.secret_access_key,
        options.date.format("%Y%m%d").to_string(),
        options.region.to_string(),
        "s3".to_string(),
        "aws4_request".to_string(),
    ];  

    let bytes_vec: Vec<Vec<u8>> = parts.into_iter().map(|s| s.into_bytes()).collect::<Vec<Vec<u8>>>();

    let vec_key: Vec<u8> = bytes_vec.into_iter().reduce(|a, b| hmac_sha_256(&a, &b)).unwrap();
    return vec_key;
}

fn get_url(options: &GetSignedUrlOptions, query_parameters: String, signature: String) -> String
{
    let url: Vec<&str> = vec!["https://", &options.bucket, ".", &options.endpoint, "/", &options.key, "?", &query_parameters, "&X-Amz-Signature=", &signature];
    return url.join("");
}

pub fn get_signed_url(options: &GetSignedUrlOptions) -> String
{
    let signature_key = match options.pre_signature.clone() {
        Some(pre_signature) => pre_signature,
        None => get_signature_key(&options),
    };

    let query_parameters = get_query_parameters(&options);
    let canonical_request = get_canonical_request(&options, &query_parameters);
    let signature_payload = get_signature_payload(&options, canonical_request);
    let signature = hmac_sha_256_hex(&signature_key, &signature_payload);
    let url = get_url(&options, query_parameters, signature);
    return url;
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn define_options() {
        let options = GetSignedUrlOptions{
            ..Default::default()
        };
        assert_eq!(options.method, "GET".to_string());
    }

    #[test]
    fn generate_signature_key()
    {
        let options = GetSignedUrlOptions{
            secret_access_key: "secret".to_string(),
            ..Default::default()
        };

        let signature_key = get_signature_key(&options);
        println!("signature_key {:?}", signature_key);
    }

    #[test]
    fn generate_signed_url()
    {
        let options = GetSignedUrlOptions {
            key: "file.mp4".to_string(),
            secret_access_key: "secret".to_string(),
            access_key_id: "key".to_string(),
            endpoint: "123.r2.cloudflarestorage.com".to_string(),
            bucket: "bucket".to_string(),
            ..Default::default()
        };

        let signed_url = get_signed_url(&options);
        println!("Signed url {}", signed_url);
    }

    #[test]
    fn generate_signed_url_with_presigned_key()
    {
        let mut options = GetSignedUrlOptions {
            key: "file.mp4".to_string(),
            date: chrono::Utc::now(),
            method: "GET".to_string(),
            secret_access_key: "secret".to_string(),
            access_key_id: "key".to_string(),
            endpoint: "123.r2.cloudflarestorage.com".to_string(),
            bucket: "bucket".to_string(),
            ..Default::default()
        };

        let signature_key = get_signature_key(&options);
        options.pre_signature = Some(signature_key.clone());

        let signed_url = get_signed_url(&options);
        println!("Signed url {}", signed_url);
    }
}
