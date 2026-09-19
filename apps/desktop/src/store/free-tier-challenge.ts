import type { FreeTierChallenge } from '@/types/hermes'

/**
 * The free tier's browser challenge, renderer half: a relay. The backend
 * (`hermes_cli/anon_challenge.py`) announces a challenge and polls the account
 * service for the result itself; the Electron main process
 * (`electron/challenge-window.ts`) loads the page hidden and decides when to
 * reveal it. This only carries the URL from one to the other, once per URL —
 * the event and a status read can both name the same challenge.
 */

export type FreeTierChallengeOutcome = 'done' | 'failed' | 'closed' | 'timeout' | 'refused' | 'error' | 'unsupported'

const inFlight = new Map<string, Promise<FreeTierChallengeOutcome>>()

function isBrowserChallenge(value: unknown): value is FreeTierChallenge {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  const candidate = value as Partial<FreeTierChallenge>

  return candidate.type === 'browser' && typeof candidate.url === 'string' && candidate.url.length > 0
}

export function runFreeTierChallenge(challenge: unknown): Promise<FreeTierChallengeOutcome> | null {
  if (!isBrowserChallenge(challenge)) {
    return null
  }

  const existing = inFlight.get(challenge.url)

  if (existing) {
    return existing
  }

  const bridge = window.hermesDesktop?.freeTierChallenge

  if (!bridge) {
    // A web build, or a desktop shell older than this renderer: nothing can
    // host the page. The backend's wait times out into its own error copy.
    return Promise.resolve('unsupported')
  }

  const run = bridge
    .run({ url: challenge.url, required: challenge.required !== false, expiresIn: challenge.expires_in })
    .catch((): FreeTierChallengeOutcome => 'error')
    .finally(() => inFlight.delete(challenge.url))

  inFlight.set(challenge.url, run)

  return run
}
