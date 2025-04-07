import fs_promises from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { CertificateAuthority } from '@src/CertificateAuthority.class';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

(async function () {
  test('Create CertificateAuthority, initialize with new context, create a pemset, delete context, delete pemset, verify.', async function () {
    const db_file_path = path.join(__dirname, './test_certs/test.sqlitedb');

    // create and initialize the CA
    const certificate_authority = new CertificateAuthority();
    await certificate_authority.init({
      name: 'ca_unit_test',
      description: 'Used for testing.',
      file: db_file_path,
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

    // ensure the ctx was loaded from a db record (should always be a positive integer)
    assert(certificate_authority.ca_loaded_ctx.loaded_from_record.id);

    // create certs for these hosts
    const host_set = ['hello.com', '0.0.0.0', '255.255.255.255'];

    // generate keys
    const certkeys =
      await certificate_authority.generateServerCertificateAndKeysPEMSet(
        host_set
      );

    // ensure we have a loaded cert
    assert(certkeys?.loaded?.cert);

    // ensure we have a database handle
    assert(certificate_authority.ca_store.db);

    // attempt to get/load a signed pem set from the sqlite db
    const looked_up_cert_keys =
      await certificate_authority.getSignedPEMSetByHosts(host_set);
    assert(looked_up_cert_keys?.loaded?.cert);

    // pull all ca_data records
    let ca_data_records = certificate_authority.ca_store.db
      .prepare(`SELECT * from ca_data;`)
      .all();

    // ensure database has exactly one record for the ca_data table
    assert(Array.isArray(ca_data_records));
    assert(ca_data_records.length === 1);

    // pull all ca_signed_pem_sets records
    let ca_signed_pem_sets_records = certificate_authority.ca_store.db
      .prepare(`SELECT * from ca_signed_pem_sets;`)
      .all();

    // ensure database has exactly one record for the ca_signed_pem_sets table
    assert(Array.isArray(ca_signed_pem_sets_records));
    assert(ca_signed_pem_sets_records.length === 1);

    // remove ca record
    await certificate_authority.ca_store.removeCAPems({
      name: certificate_authority.ca_loaded_ctx.name
    });

    // remove signed pem set record
    await certificate_authority.ca_store.removeCASignedPEMSets({
      ca_pems_sha1: certkeys.ca_pems_sha1,
      pems_sha1: certkeys.pems_sha1,
      hosts_unique_sha1: certkeys.hosts_unique_sha1
    });

    // pull all ca_data records
    ca_data_records = certificate_authority.ca_store.db
      .prepare(`SELECT * from ca_data;`)
      .all();

    // record set should be empty array now
    assert(Array.isArray(ca_data_records));
    assert(ca_data_records.length === 0);

    // pull all ca_signed_pem_sets records
    ca_signed_pem_sets_records = certificate_authority.ca_store.db
      .prepare(`SELECT * from ca_signed_pem_sets;`)
      .all();

    // record set should be empty array now
    assert(Array.isArray(ca_signed_pem_sets_records));
    assert(ca_signed_pem_sets_records.length === 0);

    // remove the test database
    await fs_promises.unlink(db_file_path);
  });
})();
