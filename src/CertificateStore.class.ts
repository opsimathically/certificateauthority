/* eslint-disable @typescript-eslint/no-this-alias */
import Database from 'better-sqlite3';
import crypto from 'crypto';
import { ca_signed_https_pems_t } from '@src/CertificateAuthority.class';

import Forge from 'node-forge';

type ca_pems_record_t = {
  id: number;
  name: string;
  description: string;
  ca_pems_sha1: string;
  ca_attrs: string;
  ca_cert_pem: string;
  ca_private_key_pem: string;
  ca_public_key_pem: string;
  timestamp: number;
};

type ca_signed_https_pems_record_t = {
  id: number;
  ca_pems_sha1: string;
  pems_sha1: string;
  hosts: string;
  hosts_unique_sha1: string;
  cert_pem: string;
  private_key_pem: string;
  public_key_pem: string;
  timestamp: number;
};

type ca_pems_params_t = {
  name: string;
  description: string;
  ca_pems_sha1: string;
  ca_attrs: Forge.pki.CertificateField[];
  ca_cert: string;
  ca_private_key: string;
  ca_public_key: string;
};

/**
 * Simple sqlite based certificate store.  We use this instead of the filesystem to prevent
 * the potentially overwhelming glut of individual dangling files in the filesystem.
 */
class CertificateStore {
  db: InstanceType<typeof Database>;
  constructor(params: { file: string }) {
    // open database/create tables (if not already present)
    this.db = new Database(params.file);
    const db_table_creation_query = `

    CREATE TABLE IF NOT EXISTS ca_data 
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL,
        ca_pems_sha1 TEXT NOT NULL UNIQUE,
        ca_attrs TEXT NOT NULL,
        ca_cert_pem TEXT NOT NULL,
        ca_private_key_pem TEXT NOT NULL,
        ca_public_key_pem TEXT NOT NULL,
        timestamp INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE INDEX IF NOT EXISTS ca_data__name         ON ca_data(name);
    CREATE INDEX IF NOT EXISTS ca_data__ca_pems_sha1 ON ca_data(ca_pems_sha1);

    CREATE TABLE IF NOT EXISTS ca_signed_pem_sets 
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ca_pems_sha1 TEXT NOT NULL,
        pems_sha1 TEXT NOT NULL,
        hosts TEXT NOT NULL,
        hosts_unique_sha1 TEXT NOT NULL,
        cert_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        timestamp INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE INDEX IF NOT EXISTS ca_signed_pem_sets__pems_sha1         ON ca_signed_pem_sets(pems_sha1);
    CREATE INDEX IF NOT EXISTS ca_signed_pem_sets__ca_pems_sha1      ON ca_signed_pem_sets(ca_pems_sha1);
    CREATE INDEX IF NOT EXISTS ca_signed_pem_sets__hosts_unique_sha1 ON ca_signed_pem_sets(hosts_unique_sha1);

    `;
    this.db.exec(db_table_creation_query);
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Add/Remove %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /**
   * Add CA pems.
   */
  async addCAPems(params: ca_pems_params_t) {
    const cs_ref = this;

    // prepare and run the query
    cs_ref.db
      .prepare(
        `
        INSERT INTO ca_data(
            name,
            description,
            ca_pems_sha1,
            ca_attrs,
            ca_cert_pem,
            ca_private_key_pem,
            ca_public_key_pem
        )
        VALUES
        (
            @name,
            @description,
            @ca_pems_sha1,
            @ca_attrs,
            @ca_cert_pem,
            @ca_private_key_pem,
            @ca_public_key_pem
        );
    `
      )
      .run({
        name: params.name,
        description: params.description,
        ca_pems_sha1: params.ca_pems_sha1,
        ca_attrs: JSON.stringify(params.ca_attrs),
        ca_cert_pem: params.ca_cert,
        ca_private_key_pem: params.ca_private_key,
        ca_public_key_pem: params.ca_public_key
      });
  }

  /**
   * Get CA pems.
   */
  async getCAPems(params: { name: string }): Promise<ca_pems_record_t> {
    const cs_ref = this;

    // prepare and run the query
    const raw_record = cs_ref.db
      .prepare(`SELECT * from ca_data where name = @name LIMIT 0,1;`)
      .get({
        name: params.name
      });
    return raw_record as unknown as ca_pems_record_t;
  }

  /**
   * Remove CA pems.
   */
  async removeCAPems(params: { name: string }): Promise<boolean> {
    const cs_ref = this;

    // prepare and run the query
    cs_ref.db.prepare(`DELETE FROM ca_data where name = @name LIMIT 0,1;`).run({
      name: params.name
    });
    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Add/Remove %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /**
   * Add a signed PEM set into the database.
   */
  async addCASignedPEMSet(signed_pems: ca_signed_https_pems_t) {
    const cs_ref = this;

    // prepare and run the query
    cs_ref.db
      .prepare(
        `
        INSERT INTO ca_signed_pem_sets
        (
            ca_pems_sha1,
            pems_sha1,
            hosts,
            hosts_unique_sha1,
            cert_pem,
            private_key_pem,
            public_key_pem
        )
        VALUES
        (
            @ca_pems_sha1,
            @pems_sha1,
            @hosts,
            @hosts_unique_sha1,
            @cert_pem,
            @private_key_pem,
            @public_key_pem
        );
    `
      )
      .run({
        ca_pems_sha1: signed_pems.ca_pems_sha1,
        pems_sha1: signed_pems.pems_sha1,
        hosts: JSON.stringify(signed_pems.hosts),
        hosts_unique_sha1: signed_pems.hosts_unique_sha1,
        cert_pem: signed_pems.cert_pem,
        private_key_pem: signed_pems.private_key_pem,
        public_key_pem: signed_pems.public_key_pem
      });
  }

  /**
   * Lookup a signed PEM set.
   */
  async getCASignedPEMSet(params: {
    ca_pems_sha1: string;
    hosts_unique_sha1?: string;
    hosts?: string[];
  }): Promise<ca_signed_https_pems_record_t> {
    const cs_ref = this;

    // ensure we have a ca pems set
    if (!params.ca_pems_sha1)
      return null as unknown as ca_signed_https_pems_record_t;

    if (!params?.hosts_unique_sha1) {
      // must have either unique sha, or host set
      if (!params.hosts)
        return null as unknown as ca_signed_https_pems_record_t;

      params.hosts_unique_sha1 = crypto
        .createHash('sha1')
        .update(params.hosts?.join(','))
        .digest('hex');
    }

    // we must always have a unique sha1 by this point
    if (!params.hosts_unique_sha1)
      return null as unknown as ca_signed_https_pems_record_t;

    // prepare and run the query
    const raw_record = cs_ref.db
      .prepare(
        `SELECT * from ca_signed_pem_sets 
        WHERE 
            ca_pems_sha1 = @ca_pems_sha1 AND 
            hosts_unique_sha1 = @hosts_unique_sha1 
        LIMIT 0,1;`
      )
      .get({
        ca_pems_sha1: params.ca_pems_sha1,
        hosts_unique_sha1: params.hosts_unique_sha1
      });
    return raw_record as unknown as ca_signed_https_pems_record_t;
  }

  /**
   * Requires one or more unique sha1 constraint to be set.
   */
  async removeCASignedPEMSets(params: {
    ca_pems_sha1: string;
    pems_sha1?: string;
    hosts_unique_sha1?: string;
  }) {
    const cs_ref = this;

    // build prepared query based on available parameters; must have at
    // least one constraint.
    let query_str = `DELETE FROM ca_signed_pem_sets WHERE`;
    const query_tail: { str: string; val: string }[] = [];
    if (params.ca_pems_sha1) {
      query_tail.push({ str: ` ca_pems_sha1 = ? `, val: params.ca_pems_sha1 });
    }
    if (params.pems_sha1) {
      query_tail.push({ str: ` pems_sha1 = ? `, val: params.pems_sha1 });
    }
    if (params.hosts_unique_sha1) {
      query_tail.push({
        str: ` hosts_unique_sha1 = ? `,
        val: params.hosts_unique_sha1
      });
    }

    // ensure we have some constraints
    if (!query_tail.length) return false;

    const query_params: string[] = [];
    for (let idx = 0; idx < query_tail.length; idx++) {
      query_str += query_tail[idx].str;
      query_params.push(query_tail[idx].val);
      if (idx !== query_tail.length - 1) query_str += ' AND ';
    }

    // debugger;
    // prepare and run the query
    cs_ref.db.prepare(query_str).run(query_params);
    return true;
  }
}

export { CertificateStore, ca_pems_record_t, ca_signed_https_pems_record_t };
