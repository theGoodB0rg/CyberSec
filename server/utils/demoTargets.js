const DEMO_HOSTNAMES = [
  'testphp.vulnweb.com',
  'juice-shop.herokuapp.com',
  'demo.testfire.net',
  'zero.webappsecurity.com',
  'www.webscantest.com',
  'testasp.vulnweb.com',
  'bwapp.honeybot.io'
]

const parseSafeHostnames = (raw = '') => {
  return String(raw || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
}

const matchesHostname = (hostname, candidate) => {
  if (!hostname || !candidate) return false
  if (hostname === candidate) return true
  return hostname.endsWith(`.${candidate}`)
}

const isDemoHostname = (hostname = '') => {
  const normalized = String(hostname || '').trim().toLowerCase()
  if (!normalized) return false
  return DEMO_HOSTNAMES.some((demoHost) => matchesHostname(normalized, demoHost))
}

const getAdditionalSafeHostnames = () => {
  return parseSafeHostnames(process.env.SAFE_PUBLIC_TARGETS)
}

const getAllSafeHostnames = () => {
  const builtin = [...DEMO_HOSTNAMES]
  const additional = getAdditionalSafeHostnames()
  const seen = new Set(builtin.map((host) => host.toLowerCase()))
  const merged = [...builtin]

  for (const host of additional) {
    const normalized = host.toLowerCase()
    if (seen.has(normalized)) continue
    seen.add(normalized)
    merged.push(host)
  }

  return merged
}

const isSafeTargetHostname = (hostname = '') => {
  const normalized = String(hostname || '').trim().toLowerCase()
  if (!normalized) return false
  if (isDemoHostname(normalized)) return true
  const additional = getAdditionalSafeHostnames()
  return additional.some((candidate) => matchesHostname(normalized, candidate))
}

module.exports = {
  DEMO_HOSTNAMES,
  isDemoHostname,
  getAdditionalSafeHostnames,
  getAllSafeHostnames,
  isSafeTargetHostname
}
