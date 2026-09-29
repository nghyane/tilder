/**
 * What this browser keeps for its account (ADR 0042), every piece of it
 * forgotten on "Start over", as Bitwarden's state declares clearOn: logout
 * for each per-user key. A new account inherited the old one's held wraps
 * (ADR 0037 merges them into its own list, and dropped its own recovery
 * code for the old one's), workspaces, machines and folders. What is the
 * device's own (theme, sizes, how the editor shows) stays.
 */
export const ACCOUNT_KV = [
  'identity',
  'pending-root-wraps',
  'held-root-wraps',
  'join-secrets',
  'directory',
  'directory-adopted',
  'machines',
  'workspace-layout',
] as const;

export const ACCOUNT_LOCAL = [
  'tilder:workspace-roots',
  'tilder:workspace-current',
  'tilder:recent-folders',
  'tilder:recent-places',
  'tilder:pinned-machines',
] as const;

/** The device's own: kept across accounts. */
export const DEVICE_LOCAL = [
  'tilder:theme',
  'tilder:density',
  'tilder:right-click',
  'tilder:terminal-font-size',
  'tilder:terminal-scheme',
  'tilder:editor-font-size',
  'tilder:line-numbers',
  'tilder:word-wrap',
] as const;
