/* eslint-disable @typescript-eslint/no-this-alias */
import Database from 'better-sqlite3';

/**
 * Simple sqlite based certificate store.  We use this instead of the filesystem to prevent
 * the overwhelming glut of individual dangling files in the filesystem that could be generated
 * by something like a crawler that's using the proxy.  You could very easily wind up with
 * hundreds of thousands of files rather than just one indexed sqlite db.
 */
class CertificateStore {
  db: InstanceType<typeof Database>;
  constructor(params: { file: string }) {
    this.db = new Database(params.file, { fileMustExist: false });

    /*
    .exec(`
  CREATE TABLE IF NOT EXISTS data_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    data BLOB NOT NULL,
    timestamp INTEGER DEFAULT (strftime('%s','now'))
  );
`);
    */
  }
}

export { CertificateStore };
