import { createFileRoute } from '@tanstack/react-router'
import { handleFetch, notFoundJson } from '~/server/pipe'

// POST /fetch -- the one job. Any other method is a 404: this service has
// exactly two endpoints and no opinion about anything else.
export const Route = createFileRoute('/fetch')({
  server: {
    handlers: {
      POST: async ({ request }: { request: Request }) => handleFetch(request),
      GET: async () => notFoundJson(),
      HEAD: async () => notFoundJson(),
      PUT: async () => notFoundJson(),
      PATCH: async () => notFoundJson(),
      DELETE: async () => notFoundJson(),
      OPTIONS: async () => notFoundJson(),
    },
  },
})
