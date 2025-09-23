import { CogIcon } from '@heroicons/react/24/outline'
import { Disclosure } from '@headlessui/react'
import { useEffect, useMemo, useState } from 'react'
import { getServerSqlmapProfiles, getUserScanSettings, listUserProfiles, updateUserScanSettings, validateSqlmap, createUserProfile } from '../utils/api'

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

  // Builder state
  const [target, setTarget] = useState('http://example.com')
  const [builderProfile, setBuilderProfile] = useState('basic')
  const [customFlags, setCustomFlags] = useState('')
  const [validation, setValidation] = useState<{ ok: boolean; disallowed: string[]; warnings: string[]; commandPreview: string; description: string; impact?: any; normalizedArgs?: string[] } | null>(null)
  const [creatingProfile, setCreatingProfile] = useState<{ name: string; description: string } | null>(null)

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
                <div className="mt-3 flex gap-2 items-center">
                  <button onClick={() => setCreatingProfile({ name: '', description: '' })} className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded">Save as New Profile</button>
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
                    <div className="mt-2 flex gap-2">
                      <button onClick={async () => {
                        try {
                          const flags = (validation?.normalizedArgs || []).filter((x: string) => x.startsWith('--'))
                          const saved = await createUserProfile({ name: creatingProfile.name, description: creatingProfile.description, flags })
                          setUserProfiles(prev => [{ id: saved.id, name: saved.name, description: saved.description, flags: saved.flags }, ...prev])
                          setCreatingProfile(null)
                        } catch (e) {
                          console.error(e)
                        }
                      }} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">Create Profile</button>
                      <button onClick={() => setCreatingProfile(null)} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded">Cancel</button>
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