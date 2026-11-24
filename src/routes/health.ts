import { createFileRoute } from '@tanstack/react-router'
import { handleHealth, notFoundJson } from '~/server/pipe'

// GET /health -- 200 { ok: true }, no auth, no other data.
export const Route = createFileRoute('/health')({
  server: {
    handlers: {
      GET: async () => handleHealth(),
      HEAD: async () => notFoundJson(),
      POST: async () => notFoundJson(),
      PUT: async () => notFoundJson(),
      PATCH: async () => notFoundJson(),
      DELETE: async () => notFoundJson(),
      OPTIONS: async () => notFoundJson(),
    },
  },
})
