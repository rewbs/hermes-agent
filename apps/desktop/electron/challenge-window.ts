import type { BrowserWindow, BrowserWindowConstructorOptions, Session } from 'electron'

/**
 * The free tier's browser challenge, desktop half.
 *
 * The Nous account service can ask an anonymous install to clear a challenge
 * before it mints a token (`hermes_cli/anon_challenge.py`). The challenge is a
 * portal page; everything it does (bot detection, an in-browser proof of work,
 * an interactive fallback) belongs to the portal and changes without a Desktop
 * release. Desktop's whole job is this file: load that page in a HIDDEN
 * window, reveal the window only if the page asks for the human, and close it
 * when the page says it is finished. The backend polls the account service on
 * its own and re-mints; nothing here holds a credential.
 *
 * The page talks to us through its URL fragment, which we can read with no
 * bridge into the page:
 *
 *   #working      nothing to show; stay hidden
 *   #interactive  needs the human: reveal
 *   #done         passed: close
 *   #failed       ended without a pass: close (the backend's next mint says why)
 *
 * The page is remote content, so the window is hardened the way the link-title
 * window is: sandboxed, isolated, its own partition, no popups, no downloads,
 * no permissions, and no navigation off the portal origin. Only
 * `<portal>/challenge…` URLs are ever loaded — the URL arrives from the
 * network by way of the backend and the renderer, and "open this URL" must not
 * become "open any URL".
 */

export type ChallengePhase = 'working' | 'interactive' | 'done' | 'failed'

export type ChallengeOutcome = 'done' | 'failed' | 'closed' | 'timeout' | 'refused' | 'error'

export interface ChallengeRequest {
  url: string
  /** False for a challenge the service is only measuring with: never revealed. */
  required: boolean
  /** Seconds the ticket has left, as the service reported it. */
  expiresIn?: number
}

interface ChallengeWindowDependencies {
  isReady: () => boolean
  getSession: () => Session | null
  resolvePortalBaseUrl: () => string
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow
  rememberLog: (message: string) => void
  now?: () => number
}

export const CHALLENGE_PARTITION = 'persist:hermes-challenge'
export const CHALLENGE_PATH = '/challenge'

// While hidden nobody can see it hang: BotID plus a CPU-fallback proof of work
// fits well inside this. Once revealed, the human has the ticket's own life.
const HIDDEN_DEADLINE_MS = 90_000
const DEFAULT_TICKET_LIFE_MS = 10 * 60_000
// Long enough to read "You're all set" when the window was revealed.
const REVEALED_DONE_LINGER_MS = 1_500
const REVEALED_FAILED_LINGER_MS = 20_000

const PHASES: readonly ChallengePhase[] = ['working', 'interactive', 'done', 'failed']

export function challengeUrlAllowed(url: string, portalBaseUrl: string): boolean {
  try {
    const target = new URL(url)
    const portal = new URL(portalBaseUrl)

    return (
      (target.protocol === 'https:' || target.protocol === 'http:') &&
      target.origin === portal.origin &&
      (target.pathname === CHALLENGE_PATH || target.pathname.startsWith(`${CHALLENGE_PATH}/`))
    )
  } catch {
    return false
  }
}

export function challengePhase(url: string): ChallengePhase | null {
  try {
    const fragment = new URL(url).hash.replace(/^#/, '')

    return PHASES.find(phase => phase === fragment) ?? null
  } catch {
    return null
  }
}

export function challengeWindowOptions(session: Session): BrowserWindowConstructorOptions {
  return {
    width: 520,
    height: 720,
    show: false,
    title: 'Hermes — quick check',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      session,
      // An unshown window is not composited; without this its timers are
      // clamped and the page's work can stall while nobody is watching it.
      backgroundThrottling: false
    }
  }
}

/** Remote content in its own jar: no permissions, no downloads. Idempotent per session. */
const guardedSessions = new WeakSet<Session>()

export function guardChallengeSession(session: Session): void {
  if (guardedSessions.has(session)) {
    return
  }

  guardedSessions.add(session)
  session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false))
  session.setPermissionCheckHandler(() => false)
  session.on('will-download', event => event.preventDefault())
}

export function createChallengeWindows({
  isReady,
  getSession,
  resolvePortalBaseUrl,
  createWindow,
  rememberLog
}: ChallengeWindowDependencies) {
  // One window per challenge URL: the backend's event and the renderer's
  // status read can both ask for the same one.
  const running = new Map<string, Promise<ChallengeOutcome>>()

  function drive(request: ChallengeRequest, session: Session): Promise<ChallengeOutcome> {
    const portalOrigin = new URL(resolvePortalBaseUrl()).origin

    return new Promise<ChallengeOutcome>(resolve => {
      let settled = false
      let revealed = false
      let win: BrowserWindow | null = null
      let deadline: ReturnType<typeof setTimeout> | null = null
      let linger: ReturnType<typeof setTimeout> | null = null

      const finish = (outcome: ChallengeOutcome) => {
        if (settled) {
          return
        }

        settled = true

        for (const timer of [deadline, linger]) {
          if (timer) {
            clearTimeout(timer)
          }
        }

        rememberLog(`[free-tier] challenge window ${outcome}${revealed ? ' (revealed)' : ''}`)
        // Settle first: a destroy() that throws must not leave the caller hanging.
        resolve(outcome)

        if (win && !win.isDestroyed()) {
          win.destroy()
        }
      }

      const armDeadline = (ms: number) => {
        if (deadline) {
          clearTimeout(deadline)
        }

        deadline = setTimeout(() => finish('timeout'), ms)
      }

      const finishAfter = (outcome: ChallengeOutcome, ms: number) => {
        if (!settled && !linger) {
          linger = setTimeout(() => finish(outcome), ms)
        }
      }

      const onPhase = (url: string) => {
        const phase = challengePhase(url)

        if (settled || phase === null || phase === 'working') {
          return
        }

        if (phase === 'interactive') {
          // An optional challenge runs where nobody is looking; it has nothing
          // to ask a person for.
          if (!request.required) {
            finish('failed')

            return
          }

          if (!revealed && win && !win.isDestroyed()) {
            revealed = true
            armDeadline(Math.max(HIDDEN_DEADLINE_MS, (request.expiresIn ?? 0) * 1000 || DEFAULT_TICKET_LIFE_MS))
            win.show()
            win.focus()
          }

          return
        }

        if (revealed) {
          finishAfter(phase, phase === 'done' ? REVEALED_DONE_LINGER_MS : REVEALED_FAILED_LINGER_MS)
        } else {
          finish(phase)
        }
      }

      try {
        guardChallengeSession(session)
        win = createWindow(challengeWindowOptions(session))
      } catch (error) {
        rememberLog(`[free-tier] challenge window could not be created: ${String(error)}`)
        finish('error')

        return
      }

      const contents = win.webContents

      contents.setAudioMuted(true)
      contents.setWindowOpenHandler(() => ({ action: 'deny' }))
      // The page may move within the portal (a fragment, a reload); it may not
      // take this window anywhere else.
      contents.on('will-navigate', (event, url) => {
        try {
          if (new URL(url).origin === portalOrigin) {
            return
          }
        } catch {
          // fall through to the refusal
        }

        event.preventDefault()
      })
      contents.on('did-navigate-in-page', (_event, url) => onPhase(url))
      contents.on('did-navigate', (_event, url) => onPhase(url))
      contents.on('render-process-gone', () => finish('error'))
      win.on('closed', () => finish('closed'))

      armDeadline(HIDDEN_DEADLINE_MS)
      win.loadURL(request.url).catch(() => finish('error'))
    })
  }

  function run(request: ChallengeRequest): Promise<ChallengeOutcome> {
    const session = isReady() ? getSession() : null

    if (!session || !challengeUrlAllowed(request.url, resolvePortalBaseUrl())) {
      rememberLog('[free-tier] challenge window refused (not ready, or URL is not a portal challenge)')

      return Promise.resolve('refused')
    }

    const existing = running.get(request.url)

    if (existing) {
      return existing
    }

    const outcome = drive(request, session).finally(() => running.delete(request.url))

    running.set(request.url, outcome)

    return outcome
  }

  return { run }
}

/** IPC payloads are untrusted: accept only the documented shape. */
export function parseChallengeRequest(value: unknown): ChallengeRequest | null {
  if (typeof value !== 'object' || value === null) {
    return null
  }

  const { url, required, expiresIn } = value as Record<string, unknown>

  if (typeof url !== 'string' || url.length === 0 || url.length > 2048) {
    return null
  }

  return {
    url,
    required: required !== false,
    expiresIn: typeof expiresIn === 'number' && Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : undefined
  }
}
