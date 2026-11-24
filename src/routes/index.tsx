import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/')({
  component: Home,
})

function Home() {
  return (
    <main
      style={{
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        maxWidth: '42rem',
        margin: '4rem auto',
        padding: '0 1.5rem',
        lineHeight: 1.6,
      }}
    >
      <h1 style={{ fontSize: '1.5rem' }}>Dumb Broker</h1>
      <p>
        A dumb fetch pipe. It fetches a URL it is told to fetch and returns the
        raw result. It does not parse, interpret, cache, or retry. The caller
        decides what the body means. This service never does.
      </p>
      <ul>
        <li>
          <code>POST /fetch</code> &mdash; fetch a URL, return the raw result.
          Requires an <code>x-key</code> header.
        </li>
        <li>
          <code>GET /health</code> &mdash; <code>{'{ "ok": true }'}</code>
        </li>
      </ul>
      <p style={{ opacity: 0.6 }}>Nothing else.</p>
    </main>
  )
}
