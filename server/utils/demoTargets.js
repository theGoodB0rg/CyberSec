const DEMO_HOSTNAMES = [
  'testphp.vulnweb.com',
  'juice-shop.herokuapp.com',
  'demo.testfire.net',
  'zero.webappsecurity.com',
  'www.webscantest.com',
  'testasp.vulnweb.com',
  'bwapp.honeybot.io'
]

module.exports = {
  DEMO_HOSTNAMES,
  isDemoHostname(hostname = '') {
    const normalized = String(hostname || '').trim().toLowerCase()
    if (!normalized) return false
    return DEMO_HOSTNAMES.some((demoHost) => normalized === demoHost || normalized.endsWith(`.${demoHost}`))
  }
}
