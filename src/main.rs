use aws_nitro_enclaves_nsm_api::{
    api::{AttestationDoc, Digest, ErrorCode},
    driver::nsm_init,
};
use ciborium::{de::from_reader, value::Value};
use coset::{AsCborValue, CoseSign1};
use nsm_lib::nsm_get_attestation_doc;
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    stack::Stack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509StoreContext, X509,
    },
};
use std::{
    str,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MAX_DOC_DATA_LEN: usize = 5120;
const AWS_ROOT_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"#;

#[derive(Error, Debug)]
pub enum UtilErr {
    #[error("nsm error: `{0}`")]
    NsmErr(String),
    #[error("cert error: `{0}`")]
    CertErr(String),
}
impl UtilErr {
    pub fn nsm_from<E>(prefix_msg: &str, e: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::NsmErr(format!("{}: {}", prefix_msg, e))
    }
}

type Result<T = ()> = std::result::Result<T, UtilErr>;

/// request a new attestation document
fn get_attestation_doc(
    fd: i32,
    pk: Option<&[u8]>,
    data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<String> {
    let ret = [0u8; MAX_DOC_DATA_LEN];
    let mut ret_len = MAX_DOC_DATA_LEN as u32;
    unsafe {
        let (pk_ptr, pk_len) = pk.map_or(([0u8; 0].as_ptr() as *const u8, 0u32), |d| {
            (d.as_ptr() as *const u8, d.len() as u32)
        });
        let (user_data_ptr, user_data_len) = data
            .map_or(([0u8; 0].as_ptr() as *const u8, 0u32), |d| {
                (d.as_ptr() as *const u8, d.len() as u32)
            });
        let (nonce_data_ptr, nonce_data_len) = nonce
            .map_or(([0u8; 0].as_ptr() as *const u8, 0u32), |d| {
                (d.as_ptr() as *const u8, d.len() as u32)
            });
        match nsm_get_attestation_doc(
            fd,
            user_data_ptr,  // user data
            user_data_len,  // user data len
            nonce_data_ptr, // user nonce data
            nonce_data_len, // user nonce len
            pk_ptr,
            pk_len,
            ret.as_ptr() as *mut u8,
            &mut ret_len,
        ) {
            ErrorCode::Success => Ok(base64::encode(&ret[0..ret_len as usize])),
            _ => Err(UtilErr::NsmErr("nsm att doc failed".to_owned())),
        }
    }
}

/// verify whether the attestation document is valid or not
fn verify_attest_doc(attest_doc: &str) -> Result<()> {
    let att_doc_cbor =
        base64::decode(attest_doc).map_err(|e| UtilErr::nsm_from("b64 decode", e))?;
    let cbor_value: Value = from_reader(att_doc_cbor.as_slice())
        .map_err(|e| UtilErr::nsm_from("cbor value from reader", e))?;
    let cose_doc =
        CoseSign1::from_cbor_value(cbor_value).map_err(|e| UtilErr::nsm_from("cosesign1", e))?;
    let cose_doc_payload = cose_doc
        .payload
        .as_ref()
        .ok_or_else(|| UtilErr::NsmErr("attestation doc format invalid".to_owned()))?;

    let att_doc = AttestationDoc::from_binary(cose_doc_payload)
        .map_err(|_| UtilErr::NsmErr("attestation doc from binary failed".to_owned()))?;

    if att_doc.module_id.is_empty() {
        return Err(UtilErr::NsmErr("module_id empty".to_owned()));
    }
    if !matches!(att_doc.digest, Digest::SHA384) {
        return Err(UtilErr::NsmErr("digest not sha384".to_owned()));
    }
    if att_doc.pcrs.is_empty() || att_doc.pcrs.len() > 32 {
        return Err(UtilErr::NsmErr("pcr len not in [0, 31]".to_owned()));
    }
    if att_doc.cabundle.is_empty() {
        return Err(UtilErr::NsmErr("cabundle invalid".to_owned()));
    }

    // verify cert chain
    let cabundle = att_doc
        .cabundle
        .iter()
        .map(|ca| X509::from_der(ca).map_err(|e| UtilErr::NsmErr(format!("x509 from_der: {}", e))))
        .filter(|c| c.is_ok())
        .map(|c| c.unwrap())
        .collect::<Vec<_>>();
    if cabundle.len() != att_doc.cabundle.len() {
        return Err(UtilErr::NsmErr(
            "some of cert in cabundle is invalid".to_owned(),
        ));
    }
    let root_cert = X509::from_pem(AWS_ROOT_CERT.as_bytes()).unwrap();
    let root_cert_valid = {
        let first_cert = cabundle.first().unwrap();
        first_cert
            .digest(MessageDigest::from_nid(Nid::SHA256).unwrap())
            .unwrap()
            .as_ref()
            == root_cert
                .digest(MessageDigest::from_nid(Nid::SHA256).unwrap())
                .unwrap()
                .as_ref()
    };
    if !root_cert_valid {
        return Err(UtilErr::NsmErr("root cert not match".to_owned()));
    }
    let cert = X509::from_der(&att_doc.certificate)
        .map_err(|e| UtilErr::NsmErr(format!("x509 my cert from_der: {}", e)))?;

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // !!! the cert chain verification failed below for an enclave running 2 days
    if let Err(err) = verify_cert_chain(&root_cert, &cert, &cabundle) {
        if matches!(err, UtilErr::NsmErr(err_msg) if err_msg == "certificate is not yet valid") {
            println!(
                "cert not before: {}, not after: {}, now: {}",
                cert.not_before().to_string(),
                cert.not_after().to_string(),
                now_ts,
            );
        }
        return Err(UtilErr::NsmErr("cert chain invalid".to_owned()));
    }
    Ok(())
}

/// verify the cert chain in attestation document by using openssl
fn verify_cert_chain(root_cert: &X509, cert: &X509, cabundle: &[X509]) -> Result<()> {
    let mut cert_stack = Stack::new().map_err(|e| UtilErr::NsmErr(e.to_string()))?;
    for (i, ca) in cabundle.iter().enumerate() {
        if i > 0 {
            cert_stack
                .push(ca.clone())
                .map_err(|e| UtilErr::NsmErr(e.to_string()))?;
        }
    }

    let mut cert_store_ctx =
        X509StoreContext::new().map_err(|e| UtilErr::NsmErr(format!("new x509store: {}", e)))?;

    // trust store, store the trusted ca
    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root_cert.clone()).unwrap();
    let trust: X509Store = builder.build();

    let verify_res = cert_store_ctx
        .init(&trust, cert, &cert_stack, |ctx| {
            ctx.verify_cert().map(|_| ctx.error())
        })
        .map_err(|e| UtilErr::NsmErr(format!("cert store init: {}", e)))?;

    if verify_res.as_raw() != 0 {
        return Err(UtilErr::NsmErr(verify_res.to_string()));
    }
    Ok(())
}

fn main() {
    // init the nsm module and get the file descriptor
    println!("start running...");
    let fd = match nsm_init() {
        fd if fd > 0 => fd,
        _ => {
            panic!("init nsm failed");
        }
    };

    // get attestation document
    let doc = get_attestation_doc(fd, None, None, None).expect("get doc failed");
    // verify the document
    verify_attest_doc(&doc).expect("verify doc failed");

    println!("verify ok for the first time");

    let mut try_times = 0;
    loop {
        if try_times > 10 {
            println!("try out, eveything seems ok.");
            break;
        }
        // sleep 0.5 days
        println!("now sleep 0.5 days...");
        sleep(Duration::from_secs(12 * 3600));
        // get attestation document again
        let doc = get_attestation_doc(fd, None, None, None).expect("get doc failed");
        // !!!! this time document verify failed
        verify_attest_doc(&doc).expect("verify doc failed");

        // this log will never success
        println!("verify ok for the {} time", try_times + 2);
        try_times += 1;
    }
}
