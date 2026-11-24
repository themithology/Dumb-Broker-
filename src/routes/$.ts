import { createFileRoute } from '@tanstack/react-router'
import { notFoundJson } from '~/server/pipe'

// Catch-all: anything that is not /fetch or /health is a JSON 404.
// The service has exactly two endpoints and nothing else.
export const Route = createFileRoute('/$')({
  server: {
    handlers: {
      GET: async () => notFoundJson(),
      HEAD: async () => notFoundJson(),
      POST: async () => notFoundJson(),
      PUT: async () => notFoundJson(),
      PATCH: async () => notFoundJson(),
      DELETE: async () => notFoundJson(),
      OPTIONS: async () => notFoundJson(),
    },
  },
})
