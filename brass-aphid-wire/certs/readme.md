This folder actually just contains symlinks to the files in s2n-tls/test/pems/permutations

```
mkdir ecdsa256
mkdir ecdsa384
mkdir ecdsa521
mkdir rsa2048
mkdir rsa3072
mkdir rsa4096
mkdir rsapss2048
cp ~/workplace/s2n-tls/tests/pems/permutations/ec_ecdsa_p256_sha256/* ecdsa256
cp ~/workplace/s2n-tls/tests/pems/permutations/ec_ecdsa_p384_sha384/* ecdsa384
cp ~/workplace/s2n-tls/tests/pems/permutations/ec_ecdsa_p521_sha512/* ecdsa521
cp ~/workplace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/* rsa2048
cp ~/workplace/s2n-tls/tests/pems/permutations/rsae_pkcs_3072_sha384/* rsa3072
cp ~/workplace/s2n-tls/tests/pems/permutations/rsae_pkcs_4096_sha384/* rsa4096
cp ~/workplace/s2n-tls/tests/pems/permutations/rsapss_pss_2048_sha256/* rsapss2048
```
