use aranya_runtime::{ClientState, linear::{LinearStorageProvider, libc::FileManager}};

use crate::common::C2PolicyStore;

pub const CERTIFICATE: &str = r"
-----BEGIN CERTIFICATE-----
MIIBXjCCAQSgAwIBAgIUUPdWqg2k+pI1DAUFPi+iickl5rEwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAw
MDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWdu
ZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJuQlKfyXCzyRbvxm0ve
3qyak7CLvuabQ8CmR+63iO32Nv7N012nFWzqoEowohsABqe+MDcAVVzDm6TDgQzN
GXejGDAWMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiBn
TMfCkuGOHP5ZqArbG1Po3PlUlghBtHkfWOquf2oYiAIhAIeq/Ox6LsjowYlAzN2r
oSWUX87FKXPU6udE3iyxENvb
-----END CERTIFICATE-----
";

pub const KEY: &str = r"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO6g4eIsIPxd5dJTc
QU8FZ/qbgL++/Nxkadto6cSOGsqhRANCAASbkJSn8lws8kW78ZtL3t6smpOwi77m
m0PApkfut4jt9jb+zdNdpxVs6qBKMKIbAAanvjA3AFVcw5ukw4EMzRl3
-----END PRIVATE KEY-----
";

pub const POLICY: &str = include_str!("policy.md");

pub const GRAPH: &str = "9cfBkPsoQ2NPHYPi7b69bcQG8FKfNc33k2UfRxiPFyd9";

pub const PORT: u16 = 4445;

pub const DOMAIN: &str = "test.slin.ie";

// File storage for now
pub type C2StorageProvider = LinearStorageProvider<FileManager>;

pub type C2ClientState = ClientState<C2PolicyStore, C2StorageProvider>;
