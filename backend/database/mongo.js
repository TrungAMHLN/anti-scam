const { MongoClient } = require('mongodb');

let client = null;
let db = null;
let connectingPromise = null;

const getMongoUri = () => process.env.MONGODB_URI || '';
const getMongoDbName = () => process.env.MONGODB_DB || 'antiscam';

async function getDb() {
  if (db) return db;
  const uri = getMongoUri();
  if (!uri) throw new Error('MONGODB_URI is not configured');
  if (!connectingPromise) {
    client = new MongoClient(uri, {
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: parseInt(process.env.MONGODB_TIMEOUT_MS || '5000', 10),
      connectTimeoutMS: parseInt(process.env.MONGODB_TIMEOUT_MS || '5000', 10),
      maxPoolSize: parseInt(process.env.MONGODB_MAX_POOL_SIZE || '10', 10),
    });
    connectingPromise = client.connect().then(() => {
      db = client.db(getMongoDbName());
      return db;
    }).catch((err) => {
      connectingPromise = null;
      client = null;
      db = null;
      throw err;
    });
  }
  return connectingPromise;
}

async function getDbOrNull() {
  try {
    return await getDb();
  } catch (err) {
    console.warn('[MongoDB] unavailable:', err.message || err);
    return null;
  }
}

module.exports = { getDb, getDbOrNull };
