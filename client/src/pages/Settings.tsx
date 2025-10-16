import { CogIcon } from '@heroicons/react/24/outline'
import { Disclosure } from '@headlessui/react'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { getServerSqlmapProfiles, getUserScanSettings, listUserProfiles, updateUserScanSettings, validateSqlmap, createUserProfile, getQuickVerifyPreference, updateQuickVerifyPreference, clearQuickVerifyPreference } from '../utils/api'
import type { QuickVerifyConsentPreference } from '../utils/api'

type FormDefaults = {
  level?: number
  risk?: number
  threads?: number
  delay?: number
  timeout?: number
  tamper?: string[]
  userAgent?: string
  headers?: Record<string, string>
  proxy?: string
}

export default function Settings() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [serverProfiles, setServerProfiles] = useState<Array<{ key: string, name: string, description: string, flags: string[] }>>([])
  const [userProfiles, setUserProfiles] = useState<Array<{ id: string, name: string, description: string, flags: string[] }>>([])
  const [defaultProfile, setDefaultProfile] = useState('basic')
  const [lastUsedProfile, setLastUsedProfile] = useState<string | null>(null)
  const [defaults, setDefaults] = useState<FormDefaults>({})
  const [quickVerifyPreference, setQuickVerifyPreference] = useState<QuickVerifyConsentPreference | null>(null)
  const [quickVerifyPrefLoading, setQuickVerifyPrefLoading] = useState(true)
  const [quickVerifyPrefSaving, setQuickVerifyPrefSaving] = useState(false)
  const [quickVerifyPrefError, setQuickVerifyPrefError] = useState<string | null>(null)

  // Builder state
  const [target, setTarget] = useState('http://example.com')
  const [builderProfile, setBuilderProfile] = useState('basic')
  const [customFlags, setCustomFlags] = useState('')
  const [validation, setValidation] = useState<{ ok: boolean; disallowed: string[]; warnings: string[]; commandPreview: string; description: string; impact?: any; normalizedArgs?: string[] } | null>(null)
  const [creatingProfile, setCreatingProfile] = useState<{ name: string; description: string; flagToggles?: Record<string, boolean> } | null>(null)

  useEffect(() => {
    let mounted = true
    ;(async () => {
      try {
        const [profiles, settings, myProfiles] = await Promise.all([
          getServerSqlmapProfiles(),
          getUserScanSettings(),
          listUserProfiles()
        ])
        if (!mounted) return
        setServerProfiles(profiles)
        setDefaultProfile(settings.default_profile || 'basic')
        setLastUsedProfile(settings.last_used_profile || null)
        setDefaults(settings.defaults || {})
        setUserProfiles(myProfiles.map(p => ({ id: p.id, name: p.name, description: p.description, flags: p.flags })))
        setBuilderProfile(settings.last_used_profile || settings.default_profile || 'basic')
      } catch {
        // ignore
      } finally {
        if (mounted) setLoading(false)
      }
    })()
    return () => { mounted = false }
  }, [])

  useEffect(() => {
    let mounted = true
    ;(async () => {
      try {
        const pref = await getQuickVerifyPreference()
        if (!mounted) return
        setQuickVerifyPreference(pref)
      } catch (e: any) {
        if (mounted) setQuickVerifyPrefError(e?.message || 'Failed to load preference')
      } finally {
        if (mounted) setQuickVerifyPrefLoading(false)
      }
    })()
    return () => { mounted = false }
  }, [])

  // Debounced server validation
  useEffect(() => {
    const h = setTimeout(async () => {
      try {
        const res = await validateSqlmap({ target, profile: builderProfile, customFlags })
        setValidation(res)
      } catch (e: any) {
        setValidation({ ok: false, disallowed: [], warnings: [e?.message || 'Validation failed'], commandPreview: '', description: '' })
      }
    }, 300)
    return () => clearTimeout(h)
  }, [target, builderProfile, customFlags])

  const onSaveSettings = async () => {
    setSaving(true)
    try {
      const payload = { default_profile: defaultProfile, defaults }
      const fresh = await updateUserScanSettings(payload)
      setDefaultProfile(fresh.default_profile || 'basic')
      setDefaults(fresh.defaults || {})
    } catch (e) {
      // surface toast elsewhere if available
      console.error(e)
    } finally {
      setSaving(false)
    }
  }

  const flagsCsv = useMemo(() => (defaults.tamper || []).join(','), [defaults.tamper])

  const quickVerifyMode: 'store' | 'skip' | 'ask' = useMemo(() => {
    if (!quickVerifyPreference) return 'ask'
    if (quickVerifyPreference.rememberChoice && quickVerifyPreference.storeEvidence === true) return 'store'
    if (quickVerifyPreference.rememberChoice && quickVerifyPreference.storeEvidence === false) return 'skip'
    return 'ask'
  }, [quickVerifyPreference])

  const updateQuickVerifyMode = async (mode: 'store' | 'skip' | 'ask') => {
    if (quickVerifyPrefSaving || mode === quickVerifyMode) return
    setQuickVerifyPrefSaving(true)
    setQuickVerifyPrefError(null)
    try {
      if (mode === 'ask') {
        await clearQuickVerifyPreference()
        const fresh = await getQuickVerifyPreference()
        setQuickVerifyPreference(fresh)
      } else {
        const fresh = await updateQuickVerifyPreference({
          storeEvidence: mode === 'store',
          rememberChoice: true,
          promptSuppressed: true,
          source: 'settings'
        })
        setQuickVerifyPreference(fresh)
      }
    } catch (e: any) {
      setQuickVerifyPrefError(e?.message || 'Failed to update preference')
    } finally {
      setQuickVerifyPrefSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="h-full overflow-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-gray-300">Loading settings…</div>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white flex items-center">
            <CogIcon className="h-8 w-8 mr-3 text-blue-400" />
            Settings
          </h1>
          <p className="mt-2 text-gray-400">Personal defaults, custom validation, and reusable profiles.</p>
        </div>

        {/* Personal Variables */}
        <Disclosure defaultOpen>
          {({ open }) => (
            <div className="mb-6 bg-gray-800 rounded-lg border border-gray-700">
              <Disclosure.Button className="w-full text-left p-4 flex items-center justify-between">
                <div className="text-white font-semibold">My Defaults (Personal Variables)</div>
                <span className="text-gray-400 text-sm">{open ? 'Hide' : 'Show'}</span>
              </Disclosure.Button>
              <Disclosure.Panel className="px-4 pb-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="defaultProfile" className="block text-sm text-gray-300 mb-1">Default Profile</label>
                    <select id="defaultProfile" value={defaultProfile} onChange={e => setDefaultProfile(e.target.value)} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2">
                      {serverProfiles.map(p => (
                        <option key={p.key} value={p.key}>{p.name} ({p.key})</option>
                      ))}
                    </select>
                    {lastUsedProfile && <div className="mt-1 text-xs text-gray-500">Last used: {lastUsedProfile}</div>}
                  </div>

                  <div>
                    <label htmlFor="level" className="block text-sm text-gray-300 mb-1">Level (1–5)</label>
                    <input id="level" type="number" min={1} max={5} placeholder="1-5" value={defaults.level ?? ''} onChange={e => setDefaults(d => ({ ...d, level: Number(e.target.value) }))} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                  <div>
                    <label htmlFor="risk" className="block text-sm text-gray-300 mb-1">Risk (1–3)</label>
                    <input id="risk" type="number" min={1} max={3} placeholder="1-3" value={defaults.risk ?? ''} onChange={e => setDefaults(d => ({ ...d, risk: Number(e.target.value) }))} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                  <div>
                    <label htmlFor="threads" className="block text-sm text-gray-300 mb-1">Threads</label>
                    <input id="threads" type="number" min={1} max={10} placeholder="e.g. 1" value={defaults.threads ?? ''} onChange={e => setDefaults(d => ({ ...d, threads: Number(e.target.value) }))} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                  <div>
                    <label htmlFor="delay" className="block text-sm text-gray-300 mb-1">Delay (seconds)</label>
                    <input id="delay" type="number" min={0} placeholder="e.g. 1" value={defaults.delay ?? ''} onChange={e => setDefaults(d => ({ ...d, delay: Number(e.target.value) }))} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                  <div>
                    <label htmlFor="timeout" className="block text-sm text-gray-300 mb-1">Timeout (seconds)</label>
                    <input id="timeout" type="number" min={0} placeholder="e.g. 30" value={defaults.timeout ?? ''} onChange={e => setDefaults(d => ({ ...d, timeout: Number(e.target.value) }))} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                  <div className="md:col-span-2">
                    <label htmlFor="tamper" className="block text-sm text-gray-300 mb-1">Tamper (comma separated)</label>
                    <input id="tamper" type="text" placeholder="space2comment,charencode" value={flagsCsv} onChange={e => setDefaults(d => ({ ...d, tamper: e.target.value.split(',').map(s => s.trim()).filter(Boolean) }))} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                </div>
                <div className="mt-4 flex gap-3">
                  <button onClick={onSaveSettings} disabled={saving} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded disabled:opacity-50">{saving ? 'Saving…' : 'Save Defaults'}</button>
                </div>
              </Disclosure.Panel>
            </div>
          )}
        </Disclosure>

        {/* Quick Verify Evidence Retention */}
        <Disclosure defaultOpen>
          {({ open }) => (
            <div className="mb-6 bg-gray-800 rounded-lg border border-gray-700">
              <Disclosure.Button className="w-full text-left p-4 flex items-center justify-between">
                <div className="text-white font-semibold">Quick Verify Evidence Retention</div>
                <span className="text-gray-400 text-sm">{open ? 'Hide' : 'Show'}</span>
              </Disclosure.Button>
              <Disclosure.Panel className="px-4 pb-4 space-y-4">
                {quickVerifyPrefLoading ? (
                  <div className="text-sm text-gray-400">Loading preference…</div>
                ) : (
                  <>
                    {quickVerifyPrefError && (
                      <div className="text-sm text-red-400">{quickVerifyPrefError}</div>
                    )}
                    <fieldset className="space-y-3">
                      <legend className="text-xs uppercase tracking-wide text-gray-400">Storage preference</legend>
                      <label className={`flex items-start gap-3 border rounded-lg p-3 cursor-pointer transition ${quickVerifyMode === 'store' ? 'border-emerald-500/60 bg-emerald-900/20' : 'border-gray-700 hover:border-emerald-600/40'}`}>
                        <input
                          type="radio"
                          name="qv-pref"
                          className="mt-1"
                          value="store"
                          checked={quickVerifyMode === 'store'}
                          onChange={() => updateQuickVerifyMode('store')}
                          disabled={quickVerifyPrefSaving}
                        />
                        <div className="space-y-1">
                          <div className="text-sm font-semibold text-emerald-200">Always store responses</div>
                          <p className="text-xs text-emerald-100/80">Automatically keeps raw quick-verify evidence with integrity hashes for every run without prompting.</p>
                        </div>
                      </label>
                      <label className={`flex items-start gap-3 border rounded-lg p-3 cursor-pointer transition ${quickVerifyMode === 'skip' ? 'border-slate-400/60 bg-slate-900/40' : 'border-gray-700 hover:border-slate-500/40'}`}>
                        <input
                          type="radio"
                          name="qv-pref"
                          className="mt-1"
                          value="skip"
                          checked={quickVerifyMode === 'skip'}
                          onChange={() => updateQuickVerifyMode('skip')}
                          disabled={quickVerifyPrefSaving}
                        />
                        <div className="space-y-1">
                          <div className="text-sm font-semibold text-gray-200">Never store responses</div>
                          <p className="text-xs text-gray-300/80">Discards raw payloads after scoring. Keeps verification lightweight while suppressing future prompts.</p>
                        </div>
                      </label>
                      <label className={`flex items-start gap-3 border rounded-lg p-3 cursor-pointer transition ${quickVerifyMode === 'ask' ? 'border-blue-400/60 bg-blue-900/20' : 'border-gray-700 hover:border-blue-500/40'}`}>
                        <input
                          type="radio"
                          name="qv-pref"
                          className="mt-1"
                          value="ask"
                          checked={quickVerifyMode === 'ask'}
                          onChange={() => updateQuickVerifyMode('ask')}
                          disabled={quickVerifyPrefSaving}
                        />
                        <div className="space-y-1">
                          <div className="text-sm font-semibold text-blue-200">Ask me each time</div>
                          <p className="text-xs text-blue-100/80">Clears the remembered decision so verifications prompt for consent on the next run.</p>
                        </div>
                      </label>
                    </fieldset>
                    {quickVerifyPreference && (
                      <div className="text-xs text-gray-400 space-y-1">
                        <div>
                          Prompts {quickVerifyPreference.promptSuppressed ? 'are suppressed—verifications will not ask again.' : 'will appear the next time you run quick verify.'}
                        </div>
                        {quickVerifyPreference.updatedAt && (
                          <div>Last updated: {new Date(quickVerifyPreference.updatedAt).toLocaleString()}</div>
                        )}
                      </div>
                    )}
                    <div className="flex flex-wrap items-center gap-3">
                      <button
                        type="button"
                        className="px-3 py-1.5 rounded border border-gray-600 bg-gray-800 hover:bg-gray-700 text-sm text-gray-200 disabled:opacity-60"
                        onClick={() => updateQuickVerifyMode('ask')}
                        disabled={quickVerifyPrefSaving || quickVerifyMode === 'ask'}
                      >
                        Restore prompts
                      </button>
                      <span className="text-xs text-gray-500">Changes apply immediately for your account.</span>
                    </div>
                  </>
                )}
              </Disclosure.Panel>
            </div>
          )}
        </Disclosure>

        {/* Custom Command Builder */}
        <Disclosure defaultOpen>
          {({ open }) => (
            <div className="mb-6 bg-gray-800 rounded-lg border border-gray-700">
              <Disclosure.Button className="w-full text-left p-4 flex items-center justify-between">
                <div className="text-white font-semibold">Custom Command Builder</div>
                <span className="text-gray-400 text-sm">{open ? 'Hide' : 'Show'}</span>
              </Disclosure.Button>
              <Disclosure.Panel className="px-4 pb-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="md:col-span-1">
                    <label htmlFor="builderProfile" className="block text-sm text-gray-300 mb-1">Profile</label>
                    <select id="builderProfile" value={builderProfile} onChange={e => setBuilderProfile(e.target.value)} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2">
                      {serverProfiles.map(p => (
                        <option key={p.key} value={p.key}>{p.name} ({p.key})</option>
                      ))}
                    </select>
                  </div>
                  <div className="md:col-span-1">
                    <label htmlFor="builderTarget" className="block text-sm text-gray-300 mb-1">Target</label>
                    <input id="builderTarget" placeholder="http://example.com" value={target} onChange={e => setTarget(e.target.value)} className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                  <div className="md:col-span-1">
                    <label htmlFor="customFlags" className="block text-sm text-gray-300 mb-1">Custom Flags</label>
                    <input id="customFlags" value={customFlags} onChange={e => setCustomFlags(e.target.value)} placeholder="--level=3 --risk=2 --tamper=space2comment" className="w-full bg-gray-900 border border-gray-700 text-white rounded p-2" />
                  </div>
                </div>
                <div className="mt-3 p-3 bg-gray-900 border border-gray-700 rounded text-gray-200">
                  <div className="text-sm text-gray-400">Validation</div>
                  {validation ? (
                    <div className="mt-1 text-sm">
                      <div className={`font-mono text-xs break-all ${validation.ok ? 'text-green-400' : 'text-yellow-300'}`}>{validation.commandPreview || '—'}</div>
                      {!validation.ok && validation.disallowed.length > 0 && (
                        <div className="mt-1 text-xs text-red-300">Disallowed: {validation.disallowed.join(', ')}</div>
                      )}
                      {validation.warnings.length > 0 && (
                        <ul className="mt-1 list-disc list-inside text-yellow-300 text-xs">
                          {validation.warnings.map((w, i) => <li key={i}>{w}</li>)}
                        </ul>
                      )}
                      {validation.description && (
                        <div className="mt-2 text-xs text-gray-300">{validation.description}</div>
                      )}
                    </div>
                  ) : (
                    <div className="text-sm text-gray-400">Type flags to see validation…</div>
                  )}
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-gray-400">
                  <span>Need to confirm what the platform adds automatically?</span>
                  <Link to="/terminal#base-flags" className="inline-flex items-center rounded border border-blue-500/40 bg-blue-900/20 px-2 py-1 text-[11px] text-blue-200 hover:bg-blue-900/40">
                    View base scan defaults
                  </Link>
                </div>
                <div className="mt-3 flex gap-2 items-center">
                  <button onClick={() => setCreatingProfile({ name: '', description: '', flagToggles: {} })} className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded">Save as New Profile</button>
                </div>

                {creatingProfile && (
                  <div className="mt-3 p-3 bg-gray-900 border border-gray-700 rounded">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <label htmlFor="newProfileName" className="block text-sm text-gray-300 mb-1">Profile Name</label>
                        <input id="newProfileName" placeholder="My WAF bypass" value={creatingProfile.name} onChange={e => setCreatingProfile({ ...creatingProfile, name: e.target.value })} className="w-full bg-gray-950 border border-gray-700 text-white rounded p-2" />
                      </div>
                      <div>
                        <label htmlFor="newProfileDescription" className="block text-sm text-gray-300 mb-1">Description</label>
                        <input id="newProfileDescription" placeholder="Explain the tradeoffs" value={creatingProfile.description} onChange={e => setCreatingProfile({ ...creatingProfile, description: e.target.value })} className="w-full bg-gray-950 border border-gray-700 text-white rounded p-2" />
                      </div>
                    </div>
                    {validation?.normalizedArgs && (
                      <div className="mt-3">
                        <p className="text-sm text-gray-300 mb-2"><strong>Configure which flags to use:</strong></p>
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                          {validation.normalizedArgs
                            .filter((flag: string) => flag.startsWith('--'))
                            .map((flag: string) => {
                              const flagName = flag.split('=')[0]
                              const isEnabled = creatingProfile.flagToggles?.[flagName] !== false
                              return (
                                <div key={flagName} className="flex items-center gap-2 p-2 bg-gray-800 rounded">
                                  <input
                                    type="checkbox"
                                    checked={isEnabled}
                                    onChange={e => {
                                      const newToggles = { ...creatingProfile.flagToggles || {} }
                                      newToggles[flagName] = e.target.checked
                                      setCreatingProfile({ ...creatingProfile, flagToggles: newToggles })
                                    }}
                                    className="w-4 h-4"
                                    id={`flag-${flagName}`}
                                  />
                                  <label htmlFor={`flag-${flagName}`} className="text-xs text-gray-300 cursor-pointer flex-1">
                                    {flag}
                                  </label>
                                </div>
                              )
                            })}
                        </div>
                      </div>
                    )}
                    <div className="mt-3 flex gap-2 flex-col">
                      <div className="flex gap-2">
                        <button onClick={async () => {
                          try {
                            const flags = (validation?.normalizedArgs || []).filter((x: string) => x.startsWith('--'))
                            const saved = await createUserProfile({ name: creatingProfile.name, description: creatingProfile.description, flags, flagToggles: creatingProfile.flagToggles })
                            setUserProfiles(prev => [{ id: saved.id, name: saved.name, description: saved.description, flags: saved.flags }, ...prev])
                            setCreatingProfile(null)
                          } catch (e: any) {
                            console.error(e)
                            alert(`Failed to create profile: ${e.message || e.toString()}`)
                          }
                        }} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">Create Profile</button>
                        <button onClick={() => setCreatingProfile(null)} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded">Cancel</button>
                      </div>
                    </div>
                  </div>
                )}
              </Disclosure.Panel>
            </div>
          )}
        </Disclosure>

        {/* Preconfigured Scan Types */}
        <Disclosure>
          {({ open }) => (
            <div className="mb-6 bg-gray-800 rounded-lg border border-gray-700">
              <Disclosure.Button className="w-full text-left p-4 flex items-center justify-between">
                <div className="text-white font-semibold">Preconfigured Scan Types</div>
                <span className="text-gray-400 text-sm">{open ? 'Hide' : 'Show'}</span>
              </Disclosure.Button>
              <Disclosure.Panel className="px-4 pb-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {serverProfiles.map(p => (
                    <div key={p.key} className="p-3 bg-gray-900 border border-gray-700 rounded">
                      <div className="text-white font-medium">{p.name}</div>
                      <div className="text-xs text-gray-400">{p.description}</div>
                      <div className="mt-2 text-xs text-gray-300">
                        <span className="text-gray-400">Flags:</span> {p.flags.join(' ')}
                      </div>
                      <div className="mt-2 flex gap-2">
                        <button onClick={() => setDefaultProfile(p.key)} className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded text-sm">Set as Default</button>
                        <button onClick={() => { setBuilderProfile(p.key); setCustomFlags(''); }} className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded text-sm">Load in Builder</button>
                      </div>
                    </div>
                  ))}
                </div>
              </Disclosure.Panel>
            </div>
          )}
        </Disclosure>

        {/* Saved Profiles */}
        <Disclosure>
          {({ open }) => (
            <div className="mb-6 bg-gray-800 rounded-lg border border-gray-700">
              <Disclosure.Button className="w-full text-left p-4 flex items-center justify-between">
                <div className="text-white font-semibold">Saved Profiles</div>
                <span className="text-gray-400 text-sm">{open ? 'Hide' : 'Show'}</span>
              </Disclosure.Button>
              <Disclosure.Panel className="px-4 pb-4">
                {userProfiles.length === 0 ? (
                  <div className="text-sm text-gray-400">No saved profiles yet.</div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {userProfiles.map(p => (
                      <div key={p.id} className="p-3 bg-gray-900 border border-gray-700 rounded">
                        <div className="text-white font-medium">{p.name}</div>
                        {p.description && <div className="text-xs text-gray-400">{p.description}</div>}
                        <div className="mt-2 text-xs text-gray-300 break-all">
                          <span className="text-gray-400">Flags:</span> {p.flags.join(' ')}
                        </div>
                        <div className="mt-2 flex gap-2">
                          <button onClick={() => { setBuilderProfile('custom'); setCustomFlags(p.flags.join(' ')); }} className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded text-sm">Load in Builder</button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Disclosure.Panel>
            </div>
          )}
        </Disclosure>
      </div>
    </div>
  )
}