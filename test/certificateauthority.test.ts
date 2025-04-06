/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { deepEqual } from 'fast-equals';
import { SqliteError } from 'better-sqlite3';
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
    await certificate_authority.init({
      name: 'ca_unit_test',
      description: 'Used for testing.',
      file: path.join(__dirname, './test_certs/test.db'),
      ca_attrs: [
        {
          name: 'commonName',
          value: 'ca_unit_test'
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
          value: 'ca_unit_test'
        },
        {
          shortName: 'OU',
          value: 'CA'
        }
      ]
    });

    // generate keys
    const certkeys =
      await certificate_authority.generateServerCertificateAndKeysPEMSet([
        'hello.com',
        '0.0.0.0',
        '255.255.255.255'
      ]);

    debugger;
    /*
    // generate keys
    const certkeys =
      await certificate_authority.generateServerCertificateAndKeysPEMSet([
        'hello.com',
        '0.0.0.0',
        '255.255.255.255'
      ]);

    const certificate_store = new CertificateStore({
      file: path.join(__dirname, './test_certs/test.db')
    });

    certificate_store.insert(certkeys);
    */
    debugger;

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
