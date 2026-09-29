/**
 * A small key-value store for what the console remembers between visits.
 * IndexedDB where it exists; memory otherwise (private windows, tests), so the
 * console still opens — it just forgets on reload.
 */
export type KeyValue = {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
};

export function memoryKeyValue(seed: Record<string, unknown> = {}): KeyValue {
  const map = new Map(Object.entries(seed));
  return {
    get: async <T>(key: string) => map.get(key) as T | undefined,
    set: async (key, value) => {
      map.set(key, value);
    },
  };
}

const DB = 'tilder';
const STORE = 'kv';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function indexedDbKeyValue(): Promise<KeyValue> {
  if (typeof indexedDB === 'undefined') return memoryKeyValue();
  try {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    const db = await request(open);
    const store = (mode: IDBTransactionMode) => db.transaction(STORE, mode).objectStore(STORE);
    return {
      get: async <T>(key: string) => (await request(store('readonly').get(key))) as T | undefined,
      set: async (key, value) => {
        await request(store('readwrite').put(value, key));
      },
    };
  } catch {
    return memoryKeyValue();
  }
}
