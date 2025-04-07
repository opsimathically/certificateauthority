/* eslint-disable no-empty */
/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-unsafe-function-type */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable @typescript-eslint/no-explicit-any */

/*
Attribution:
This code is a modernization/cleaning of this MIT code.  I've updated it to use
async/await rather than callbacks, etc.
https://github.com/joeferner/node-http-mitm-proxy/blob/master/lib/ca.ts

Understanding This Code:
This code primarily deals with X.509 generation using node-forge.  It is recommended
that you read the X.509 section of the following URL for better understanding of what
and why things are happening.
https://www.npmjs.com/package/node-forge
*/

// import fs promises api
import crypto from 'crypto';

// old imports
import path from 'node:path';
import Forge from 'node-forge';
import { Deferred } from '@opsimathically/deferred';

import {
  CertificateStore,
  ca_pems_record_t,
  ca_signed_https_pems_record_t
} from '@src/CertificateStore.class';

type ca_loaded_context_t = {
  name: string;
  description: string;
  ca_cert: ReturnType<typeof Forge.pki.createCertificate>;
  ca_keys: ReturnType<typeof Forge.pki.rsa.generateKeyPair>;
  ca_pems_sha1: string;
  ca_attrs: string;
  ca_cert_pem: string;
  ca_private_key_pem: string;
  ca_public_key_pem: string;
  loaded_from_record: ca_pems_record_t;
};

// these values are returned to the https server for use
type ca_signed_https_pems_t = {
  ca_pems_sha1: string;
  pems_sha1: string;
  hosts: string[];
  hosts_unique_sha1: string;
  loaded: {
    cert: any;
    keys: any;
  };
  cert_pem: string;
  private_key_pem: string;
  public_key_pem: string;
};

class CertificateAuthority {
  // certificate datastore
  ca_store!: CertificateStore;

  // loaded context
  ca_loaded_ctx!: ca_loaded_context_t;

  constructor() {}

  // Initialize the CA
  async init(params: {
    name: string;
    description: string;
    file: string;
    ca_attrs?: Forge.pki.CertificateField[];
  }): Promise<boolean> {
    // set self reference
    const ca_ref = this;

    // open the ca store
    ca_ref.ca_store = new CertificateStore({
      file: params.file
    });

    // attempt to lookup ca pems if we have any, if we have none, create new ones.
    let ca_pems = await ca_ref.ca_store.getCAPems({ name: params.name });

    if (ca_pems) {
      // set the loaded context from pems
      ca_ref.ca_loaded_ctx = {
        name: ca_pems.name,
        description: ca_pems.description,
        ca_cert: Forge.pki.certificateFromPem(ca_pems.ca_cert_pem),
        ca_keys: {
          privateKey: Forge.pki.privateKeyFromPem(ca_pems.ca_private_key_pem),
          publicKey: Forge.pki.publicKeyFromPem(ca_pems.ca_public_key_pem)
        },
        ca_pems_sha1: ca_pems.ca_pems_sha1,
        ca_attrs: JSON.parse(ca_pems.ca_attrs),
        ca_cert_pem: ca_pems.ca_cert_pem,
        ca_private_key_pem: ca_pems.ca_private_key_pem,
        ca_public_key_pem: ca_pems.ca_public_key_pem,
        loaded_from_record: ca_pems
      };

      return true;
    }

    // generate a keypair and set keypair from generation callback result
    const key_gen_deferred: Deferred<Forge.pki.rsa.KeyPair, string> =
      new Deferred<Forge.pki.rsa.KeyPair, string>();
    Forge.pki.rsa.generateKeyPair(
      { bits: 2048 },
      (err: Error, keys: Forge.pki.rsa.KeyPair) => {
        key_gen_deferred.resolve(keys);
      }
    );
    const keypair: Forge.pki.rsa.KeyPair = await key_gen_deferred.promise;
    if (!keypair) return false;

    // create a new certificate
    const cert = Forge.pki.createCertificate();
    if (!cert) return false;

    // set public key
    cert.publicKey = keypair.publicKey;

    // set serial number
    cert.serialNumber = ca_ref.randomSerialNumber();

    // set validity
    cert.validity.notBefore = new Date();
    cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );

    // set attrs
    let CAattrs: Forge.pki.CertificateField[] | undefined = params.ca_attrs;
    if (!CAattrs)
      CAattrs = [
        {
          name: 'commonName',
          value: 'DefaultCACommonName'
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
          value: 'Default Organizational Name'
        },
        {
          shortName: 'OU',
          value: 'CA'
        }
      ];

    // set subject/issuer
    cert.setSubject(CAattrs);
    cert.setIssuer(CAattrs);

    const CAextensions = [
      {
        name: 'basicConstraints',
        cA: true
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true
      },
      {
        name: 'nsCertType',
        client: true,
        server: true,
        email: true,
        objsign: true,
        sslCA: true,
        emailCA: true,
        objCA: true
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ];

    // set extensions
    cert.setExtensions(CAextensions);

    // sign certificate
    cert.sign(keypair.privateKey, Forge.md.sha256.create());

    // generate pems
    const ca_cert_pem = Forge.pki.certificateToPem(cert);
    const ca_private_key_pem = Forge.pki.privateKeyToPem(keypair.privateKey);
    const ca_public_key_pem = Forge.pki.publicKeyToPem(keypair.publicKey);

    // create pems sha1
    const ca_pems_sha1 = crypto
      .createHash('sha1')
      .update(ca_cert_pem + ca_private_key_pem + ca_public_key_pem)
      .digest('hex');

    // try to add to the ca store
    try {
      await ca_ref.ca_store.addCAPems({
        name: params.name,
        description: params.description,
        ca_pems_sha1: ca_pems_sha1,
        ca_attrs: CAattrs,
        ca_cert: ca_cert_pem,
        ca_private_key: ca_private_key_pem,
        ca_public_key: ca_public_key_pem
      });
    } catch (err) {
      return false;
    }

    // --- load and parse new record

    // attempt to lookup ca pems if we have any, if we have none, create new ones.
    ca_pems = await ca_ref.ca_store.getCAPems({ name: params.name });
    if (!ca_pems) return false;

    // set the loaded context from pems
    ca_ref.ca_loaded_ctx = {
      name: ca_pems.name,
      description: ca_pems.description,
      ca_cert: Forge.pki.certificateFromPem(ca_pems.ca_cert_pem),
      ca_keys: {
        privateKey: Forge.pki.privateKeyFromPem(ca_pems.ca_private_key_pem),
        publicKey: Forge.pki.publicKeyFromPem(ca_pems.ca_public_key_pem)
      },
      ca_pems_sha1: ca_pems.ca_pems_sha1,
      ca_attrs: JSON.parse(ca_pems.ca_attrs),
      ca_cert_pem: ca_pems.ca_cert_pem,
      ca_private_key_pem: ca_pems.ca_private_key_pem,
      ca_public_key_pem: ca_pems.ca_public_key_pem,
      loaded_from_record: ca_pems
    };
    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% HTTP MITM Cert/Key Generators %%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /**
   * This method is used to generate cert/priv/public key usable for a
   * nodejs https server (MITM server)
   */
  async generateServerCertificateAndKeysPEMSet(
    hosts: string[]
  ): Promise<ca_signed_https_pems_t> {
    // set self reference
    const ca_ref = this;

    // create a unique hash of the hosts
    const hosts_unique_sha1 = crypto
      .createHash('sha1')
      .update(hosts.join(','))
      .digest('hex');

    // lookup pem set record if available
    let pem_set_record: ca_signed_https_pems_record_t =
      await ca_ref.ca_store.getCASignedPEMSet({
        ca_pems_sha1: ca_ref?.ca_loaded_ctx?.ca_pems_sha1,
        hosts_unique_sha1: hosts_unique_sha1
      });

    // if we have a record, just parse and return it
    if (pem_set_record) {
      // generate pem set
      return {
        ca_pems_sha1: ca_ref.ca_loaded_ctx.ca_pems_sha1,
        pems_sha1: pem_set_record.pems_sha1,
        hosts: JSON.parse(pem_set_record.hosts),
        hosts_unique_sha1: pem_set_record.hosts_unique_sha1,
        loaded: {
          cert: Forge.pki.certificateFromPem(pem_set_record.cert_pem),
          keys: {
            publicKey: Forge.pki.publicKeyFromPem(
              pem_set_record.public_key_pem
            ),
            privateKey: Forge.pki.privateKeyFromPem(
              pem_set_record.private_key_pem
            )
          }
        },
        cert_pem: pem_set_record.cert_pem,
        private_key_pem: pem_set_record.private_key_pem,
        public_key_pem: pem_set_record.public_key_pem
      };
    }

    // set main host
    const main_host = hosts[0];

    const keys_for_server = Forge.pki.rsa.generateKeyPair(2048);
    const cert_for_server = Forge.pki.createCertificate();

    cert_for_server.publicKey = keys_for_server.publicKey;
    cert_for_server.serialNumber = this.randomSerialNumber();
    cert_for_server.validity.notBefore = new Date();
    cert_for_server.validity.notBefore.setDate(
      cert_for_server.validity.notBefore.getDate() - 1
    );
    cert_for_server.validity.notAfter = new Date();

    // Changed this from 1, to 20 years, because why not.
    cert_for_server.validity.notAfter.setFullYear(
      cert_for_server.validity.notBefore.getFullYear() + 20
    );

    const ServerAttrs = [
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
        value: 'Node MITM Proxy CA'
      },
      {
        shortName: 'OU',
        value: 'Node MITM Proxy Server Certificate'
      }
    ];
    const attrsServer = ServerAttrs.slice(0);
    attrsServer.unshift({
      name: 'commonName',
      value: main_host
    });

    cert_for_server.setSubject(attrsServer);

    cert_for_server.setIssuer(ca_ref.ca_loaded_ctx.ca_cert.issuer.attributes);

    const ServerExtensions = [
      {
        name: 'basicConstraints',
        cA: false
      },
      {
        name: 'keyUsage',
        keyCertSign: false,
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: true,
        dataEncipherment: true
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        codeSigning: false,
        emailProtection: false,
        timeStamping: false
      },
      {
        name: 'nsCertType',
        client: true,
        server: true,
        email: false,
        objsign: false,
        sslCA: false,
        emailCA: false,
        objCA: false
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ] as any[];

    /*
    Determine Subject Alt Names For Host

    type	Description	          Field name in altNames object
    1	    RFC822 Name (Email)	  value
    2	    DNS Name	          value
    6	    URI	                  value
    7	    IP Address	          ip
    8	    Registered ID (OID)	  oid

    */
    const alt_names_array = hosts.map((host) => {
      if (host.match(/^[\d.]+$/)) {
        return { type: 7, ip: host };
      }
      return { type: 2, value: host };
    });

    const server_extensions = ServerExtensions.concat([
      {
        name: 'subjectAltName',
        altNames: alt_names_array
      }
    ]);

    // set server extensions
    cert_for_server.setExtensions(server_extensions);

    // sign the cert with the certificate authorities private key
    cert_for_server.sign(
      ca_ref.ca_loaded_ctx.ca_keys.privateKey,
      Forge.md.sha256.create()
    );

    // convert bins to pems
    const cert_pem = Forge.pki.certificateToPem(cert_for_server);
    const private_key_pem = Forge.pki.privateKeyToPem(
      keys_for_server.privateKey
    );
    const public_key_pem = Forge.pki.publicKeyToPem(keys_for_server.publicKey);

    // hash the pems to create a unique identifier
    const pems_sha1 = crypto
      .createHash('sha1')
      .update(cert_pem + private_key_pem + public_key_pem)
      .digest('hex');

    // generate pem set
    const pem_set: ca_signed_https_pems_t = {
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

    // add to ca store
    await ca_ref.ca_store.addCASignedPEMSet(pem_set);

    // lookup record
    pem_set_record = await ca_ref.ca_store.getCASignedPEMSet({
      ca_pems_sha1: ca_ref.ca_loaded_ctx.ca_pems_sha1,
      hosts_unique_sha1: pem_set.hosts_unique_sha1
    });
    if (!pem_set_record) return null as unknown as ca_signed_https_pems_t;

    // return the pem set
    return pem_set;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // generate random 16 bytes hex string
  randomSerialNumber() {
    let sn = '';
    for (let i = 0; i < 4; i++) {
      sn += `00000000${Math.floor(Math.random() * 256 ** 4).toString(
        16
      )}`.slice(-8);
    }
    return sn;
  }
}

export { CertificateAuthority, ca_signed_https_pems_t };
