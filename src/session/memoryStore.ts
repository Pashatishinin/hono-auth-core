import { randomString } from '../pkce.js'
import type { SessionMeta, SessionStore } from '../types.js'

interface Entry {
  id: string
  userId: string
  meta?: SessionMeta
}

/**
 * In-memory SessionStore. Fine for local dev or a single-process server —
 * it does not survive restarts and isn't shared across instances. For
 * production with more than one process/region, implement `SessionStore`
 * against your own database (Postgres, Redis, etc).
 */
export function createMemorySessionStore(): SessionStore {
  const tokens = new Map<string, Entry>()

  return {
    async create(userId, meta) {
      const token = randomString(48)
      const id = randomString(16)
      tokens.set(token, { id, userId, meta })
      return { token, id }
    },

    async rotate(presentedToken, meta) {
      const entry = tokens.get(presentedToken)
      if (!entry) return null

      tokens.delete(presentedToken)
      const newToken = randomString(48)
      tokens.set(newToken, { id: entry.id, userId: entry.userId, meta })
      return { newToken, userId: entry.userId }
    },

    async revoke(token) {
      tokens.delete(token)
    },

    async revokeAll(userId) {
      for (const [token, entry] of tokens) {
        if (entry.userId === userId) tokens.delete(token)
      }
    },
  }
}
