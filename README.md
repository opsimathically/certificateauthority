# certificateauthority

Create a CA, issue keys/certs from that CA. Decrypt/mitm data using CA/keys certs. Useful for proxies, etc.

This code is a modernization/cleaning of [this](https://github.com/joeferner/node-http-mitm-proxy/blob/master/lib/ca.ts) mitm proxy code. It's been updated to use async/await instead of callbacks.
It now uses a sqlite certificate store instead of storing certs/keys on the filesystem directly. This will
remove the possibility of large numbers of dangling files, as well as make it easier to search for created
cert sets.

The main usecase of this code for me personally, is as a certificate authority for a HTTP mitm proxy, although
I'm certain it could be useful in other places as well. For example, dynamically authorizing hosts/content on your own
networks, behaving as the crypto authority for your own assets.

## Install

```bash
npm install @opsimathically/certificateauthority
```

## Building from source

This package is intended to be run via npm, but if you'd like to build from source,
clone this repo, enter directory, and run `npm install` for dev dependencies, then run
`npm run build`.

## Usage

[See API Reference for documentation](https://github.com/opsimathically/certificateauthority/blob/main/docs/)

[See unit tests for more direct usage examples](https://github.com/opsimathically/certificateauthority/blob/main/test/certificateauthority.test.ts)

```typescript
import { CertificateAuthority } from '@opsimathically/certificateauthority';

(async function () {
  const db_file_path = path.join(__dirname, './test_certs/test.sqlitedb');

  // create and initialize the CA
  const certificate_authority = new CertificateAuthority();
  await certificate_authority.init({
    name: 'name_of_your_ca_whatever_you_want',
    description: 'Any description of your CA.',
    file: path.join(__dirname, './path_to/your.sqlite.db'),
    ca_attrs: [
      {
        name: 'commonName',
        value: 'any_name'
      },
      {
        name: 'countryName',
        value: 'Internet'
      },
      {
        shortName: 'ST',
        value: 'Internet'
      },
      {
        name: 'localityName',
        value: 'Internet'
      },
      {
        name: 'organizationName',
        value: 'any_organizational_name'
      },
      {
        shortName: 'OU',
        value: 'CA'
      }
    ]
  });

  // Note: the reason we use hosts here is because our use case
  //       has a client give us hosts, to which we need to generate
  //       certs for to mitm.

  // generate keys/pems/etc for hosts
  let keys_and_pems_for_mitm_hosts =
    await certificate_authority.generateServerCertificateAndKeysPEMSet([
      'hello.com',
      '0.0.0.0',
      '255.255.255.255'
    ]);

  // you can also lookup items using hosts after generation
  keys_and_pems_for_mitm_hosts =
    await certificate_authority.getSignedPEMSetByHosts([
      'hello.com',
      '0.0.0.0',
      '255.255.255.255'
    ]);

  /*
  // keys_and_pems_for_mitm_hosts is returned as ca_signed_https_pems_t, looking similar to:
  {
    ca_pems_sha1: ca_ref.ca_loaded_ctx.ca_pems_sha1,
    pems_sha1: pems_sha1,
    hosts: hosts,
    hosts_unique_sha1: hosts_unique_sha1,
    loaded: {
      cert: cert_for_server,
      keys: keys_for_server
    },
    cert_pem: Forge.pki.certificateToPem(cert_for_server),
    private_key_pem: Forge.pki.privateKeyToPem(keys_for_server.privateKey),
    public_key_pem: Forge.pki.publicKeyToPem(keys_for_server.publicKey)
  };
  */

  // you can also remove them by hosts
  await certificate_authority.removeSignedPEMSetByHosts([
    'hello.com',
    '0.0.0.0',
    '255.255.255.255'
  ]);

  // to remove/get by other criteria, or to lookup by other criteria check
  // certificate_authority.ca_store methods.
})();
```
