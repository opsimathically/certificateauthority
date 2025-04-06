import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { deepEqual } from 'fast-equals';

import { CertificateAuthority } from '@src/CertificateAuthority.class';
import { CertificateStore } from '@src/CertificateStore.class';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

(async function () {
  test('Create CertificateAuthority.', async function () {
    const certificate_authority = new CertificateAuthority({
      ca_folder: path.resolve(__dirname, 'test_certs')
    });

    // initialize the ca
    await certificate_authority.init();

    // generate keys
    const certkeys =
      await certificate_authority.generateServerCertificateAndKeysPEMSet([
        'hello.com',
        '0.0.0.0',
        '255.255.255.255'
      ]);
    debugger;

    const certificate_store = new CertificateStore();

    await certificate_store.open({ file: './blah.db' });

    // generate keys
    /*
     opsiproxy_ref.ca.generateServerCertificateKeys(
        hosts,
        (certPEM: any, privateKeyPEM: any) => {
          cert_pem = certPEM;
          private_key_pem = privateKeyPEM;
          cert_deferred.resolve(true);
        }
      );
    */
  });
})();
