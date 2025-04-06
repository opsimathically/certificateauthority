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
import * as fs_promises from 'node:fs/promises';
import crypto from 'crypto';

// old imports
import path from 'node:path';
import Forge from 'node-forge';
import { Deferred } from '@opsimathically/deferred';

// these values are returned to the https server for use
type ca_mitm_https_server_pems_t = {
  hosts_unique_sha1: string;
  cert_pem: string;
  private_key_pem: string;
  public_key_pem: string;
};

type ca_options_t = {
  ca_folder: string;
};

class CertificateAuthority {
  // base folder for the CA
  base_ca_folder!: string;

  // cert folder (where certs are stored)
  certs_folder!: string;

  // keys folder (where keys are stored)
  keys_folder!: string;

  // certificate authority cert and keys
  ca_cert!: ReturnType<typeof Forge.pki.createCertificate>;
  ca_keys!: ReturnType<typeof Forge.pki.rsa.generateKeyPair>;

  ca_pems!: {
    cert: string;
    private_key: string;
    public_key: string;
  };

  // certificate authority file paths
  ca_file_paths: {
    ca_cert?: string;
    ca_private_key?: string;
    ca_public_key?: string;
  } = {};

  constructor(options: ca_options_t) {
    this.base_ca_folder = options.ca_folder;
    this.certs_folder = path.join(this.base_ca_folder, 'certs');
    this.keys_folder = path.join(this.base_ca_folder, 'keys');
  }

  // Initialize the CA
  async init() {
    // set self reference
    const ca_ref = this;

    // create base_ca_folder
    if (!(await ca_ref.directoryExistsAndIsReadable(ca_ref.base_ca_folder)))
      if (!(await ca_ref.mkdirp(ca_ref.base_ca_folder)))
        throw new Error(
          'certificate_authority__init_failed__could_not_create_base_ca_folder'
        );

    // create certs_folder
    if (!(await ca_ref.directoryExistsAndIsReadable(ca_ref.certs_folder)))
      if (!(await ca_ref.mkdirp(ca_ref.certs_folder)))
        throw new Error(
          'certificate_authority__init_failed__could_not_create_certs_folder'
        );

    // keys_folder
    if (!(await ca_ref.directoryExistsAndIsReadable(ca_ref.keys_folder)))
      if (!(await ca_ref.mkdirp(ca_ref.keys_folder)))
        throw new Error(
          'certificate_authority__init_failed__could_not_create_keys_folder'
        );

    ca_ref.ca_file_paths.ca_cert = path.join(ca_ref.certs_folder, 'ca.pem');

    ca_ref.ca_file_paths.ca_private_key = path.join(
      ca_ref.keys_folder,
      'ca.private.key'
    );

    ca_ref.ca_file_paths.ca_public_key = path.join(
      ca_ref.keys_folder,
      'ca.public.key'
    );

    // load or generate files
    if (!(await ca_ref.loadCertificateAuthorityFiles())) {
      await ca_ref.generateCertificateAuthorityFiles();
    }
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Load or Generate CA Files %%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // These methods load or generate the cert/keys for the CA itself,
  // eg. "ca.pem" | "ca.public.key" | "ca.private.key"

  // Attempt to load certificate authority files from the filesystem.
  async loadCertificateAuthorityFiles(): Promise<boolean> {
    // set self reference
    const ca_ref = this;

    // ensure mandatory files are set
    if (!ca_ref.ca_file_paths.ca_cert) return false;
    if (!ca_ref.ca_file_paths.ca_private_key) return false;
    if (!ca_ref.ca_file_paths.ca_public_key) return false;

    // check that all necessary ca parts exist
    const ca_cert_exists = await ca_ref.fileExistsAndIsReadable(
      ca_ref.ca_file_paths.ca_cert
    );
    const ca_private_key_exists = await ca_ref.fileExistsAndIsReadable(
      ca_ref.ca_file_paths.ca_private_key
    );
    const ca_public_key_exists = await ca_ref.fileExistsAndIsReadable(
      ca_ref.ca_file_paths.ca_public_key
    );

    // iof the files don't exist, we can't load anything
    if (!ca_cert_exists || !ca_private_key_exists || !ca_public_key_exists)
      return false;

    // read ca cert
    const ca_cert_content = await fs_promises.readFile(
      ca_ref.ca_file_paths.ca_cert
    );

    // read ca priv key
    const ca_private_key_content = await fs_promises.readFile(
      ca_ref.ca_file_paths.ca_private_key
    );

    // read ca pub key
    const ca_public_key_content = await fs_promises.readFile(
      ca_ref.ca_file_paths.ca_public_key
    );

    // store ca pems for future reference
    ca_ref.ca_pems = {
      cert: ca_cert_content.toString(),
      private_key: ca_private_key_content.toString(),
      public_key: ca_public_key_content.toString()
    };

    // set cert
    ca_ref.ca_cert = Forge.pki.certificateFromPem(ca_ref.ca_pems.cert);

    // set keys
    ca_ref.ca_keys = {
      privateKey: Forge.pki.privateKeyFromPem(ca_ref.ca_pems.private_key),
      publicKey: Forge.pki.publicKeyFromPem(ca_ref.ca_pems.public_key)
    };

    // return indicating success
    return true;
  }

  // If certificate authority files are missing, we use this to generate thrm
  async generateCertificateAuthorityFiles() {
    // set self reference
    const ca_ref = this;

    // generate the keypair
    const key_gen_deferred: Deferred<Forge.pki.rsa.KeyPair, string> =
      new Deferred<Forge.pki.rsa.KeyPair, string>();
    Forge.pki.rsa.generateKeyPair(
      { bits: 2048 },
      (err: Error, keys: Forge.pki.rsa.KeyPair) => {
        key_gen_deferred.resolve(keys);
      }
    );

    // set keypair from generation callback result
    const keypair: Forge.pki.rsa.KeyPair = await key_gen_deferred.promise;

    // create a new certificate
    const cert: Forge.pki.Certificate = Forge.pki.createCertificate();

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

    const CAattrs = [
      {
        name: 'commonName',
        value: 'NodeMITMProxyCA'
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
        value: 'Node MITM Proxy CA'
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

    // sign
    cert.sign(keypair.privateKey, Forge.md.sha256.create());

    // set cert/keypair in class
    ca_ref.ca_cert = cert;
    ca_ref.ca_keys = keypair;

    // write ca cert pem
    const ca_cert_path = path.join(ca_ref.certs_folder, 'ca.pem');
    const ca_cert_pem = Forge.pki.certificateToPem(cert);
    await fs_promises.writeFile(ca_cert_path, ca_cert_pem);
    ca_ref.ca_file_paths.ca_cert = ca_cert_path;

    // write ca private key
    const ca_private_key_path = path.join(ca_ref.keys_folder, 'ca.private.key');
    const ca_private_key_pem = Forge.pki.privateKeyToPem(keypair.privateKey);
    await fs_promises.writeFile(ca_private_key_path, ca_private_key_pem);
    ca_ref.ca_file_paths.ca_private_key = ca_private_key_path;

    // write ca public key
    const ca_public_key_path = path.join(ca_ref.keys_folder, 'ca.public.key');
    const ca_public_key_pem = Forge.pki.publicKeyToPem(keypair.publicKey);
    await fs_promises.writeFile(ca_public_key_path, ca_public_key_pem);
    ca_ref.ca_file_paths.ca_public_key = ca_public_key_path;

    // return indicating success
    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Cert/Key Generators %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /**
   * This method is used to generate cert/priv/public key usable for a
   * nodejs https server (MITM server)
   */
  async generateServerCertificateAndKeysPEMSet(
    hosts: string[]
  ): Promise<ca_mitm_https_server_pems_t> {
    // set self reference
    const ca_ref = this;

    // create a unique hash of the hosts
    const hosts_unique_sha1 = crypto
      .createHash('sha1')
      .update(hosts.join(','))
      .digest('hex');

    // set main host
    const main_host = hosts[0];

    const key_for_server = Forge.pki.rsa.generateKeyPair(2048);
    const cert_for_server = Forge.pki.createCertificate();

    cert_for_server.publicKey = key_for_server.publicKey;
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
    cert_for_server.setIssuer(this.ca_cert.issuer.attributes);

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
    cert_for_server.sign(ca_ref.ca_keys.privateKey, Forge.md.sha256.create());

    // generate pem set
    const pem_set: ca_mitm_https_server_pems_t = {
      hosts_unique_sha1: hosts_unique_sha1,
      cert_pem: Forge.pki.certificateToPem(cert_for_server),
      private_key_pem: Forge.pki.privateKeyToPem(key_for_server.privateKey),
      public_key_pem: Forge.pki.publicKeyToPem(key_for_server.publicKey)
    };

    // return the pem set
    return pem_set;
  }

  async storeServerCertficiateAndKeysPEMSet(
    hosts_unique_sha1: string
  ): Promise<ca_mitm_https_server_pems_t> {
    return null as unknown as ca_mitm_https_server_pems_t;
  }

  async loadServerCertficiateAndKeysPEMSet(
    hosts_unique_sha1: string
  ): Promise<ca_mitm_https_server_pems_t> {
    return null as unknown as ca_mitm_https_server_pems_t;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% File/Directory Utilities %%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async directoryExistsAndIsReadable(dirPath: string): Promise<boolean> {
    try {
      await fs_promises.access(
        dirPath,
        fs_promises.constants.F_OK | fs_promises.constants.R_OK
      );
      const stats = await fs_promises.stat(dirPath);
      return stats.isDirectory();
    } catch {
      return false;
    }
  }

  async fileExistsAndIsReadable(filePath: string): Promise<boolean> {
    try {
      await fs_promises.access(
        filePath,
        fs_promises.constants.F_OK | fs_promises.constants.R_OK
      );
      // File exists and is readable
      return true;
    } catch {
      // Either doesn't exist or not readable
      return false;
    }
  }

  // mkdir -p
  async mkdirp(dirPath: string): Promise<boolean> {
    const fullPath = path.resolve(dirPath);
    try {
      await fs_promises.mkdir(fullPath, { recursive: true });
      return true;
    } catch (err) {
      return false;
    }
  }

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

  getPem() {
    return Forge.pki.certificateToPem(this.ca_cert);
  }
}

export { CertificateAuthority, ca_options_t, ca_mitm_https_server_pems_t };
