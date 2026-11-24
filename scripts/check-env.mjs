// Refuses to start when FETCH_KEY is unset (see README).
if (!process.env.FETCH_KEY) {
  console.error('refusing to start: FETCH_KEY is not set')
  process.exit(1)
}
