import { readFileSync } from 'node:fs';
import { createPostgresPool } from '../dist/postgres.js';
export function testPool() {
  const env = process.env;
  return createPostgresPool({ host: env.PGHOST, port: Number(env.PGPORT), user: env.PGUSER, password: env.PGPASSWORD, database: env.PGDATABASE,
    ssl: env.D1_LOCAL === '1' ? false : { rejectUnauthorized: true, ca: readFileSync(env.PGSSLROOTCERT!, 'utf8') },
    max: 2, maxUses: 1, application_name: 'poppykit-d1-contract', connectionTimeoutMillis: 3000, idleTimeoutMillis: 1000 });
}
