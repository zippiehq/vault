var HDKey = require('hdkey')
var secp256k1 = require('secp256k1')
var shajs = require('sha.js')
var store = require('store')
const crypto = require('crypto');

var sessionStoreEngine = require('store/storages/sessionStorage')
var sessionStore = store.createStore(sessionStoreEngine)

// vault per-session state
var inited = false
var apphash = null
var pubex = null
var pubex_hdkey = null

// vault database (currently localstorage, should be indexeddb) contains:
// cache of app hash -> app-pubex
// device local private key
// device authentication private key
// seed piece 1 out of 2 (2of2) encrypted with device local private key
// forgetme server url if non-standard

// an app-pubex is calculated by taking private extended key of root + some derivation, always hardened +
//   [for every 32 bit of the 256-bit hash, take the hardended child of index (value integer divided with 2^31) and then the hardened child of index (value integer mod 2^31)
function deriveWithHash(hdkey, hash) {
  for (var i = 0; i < 32; i += 4) {
    var value = hash.readUInt32LE(i)
    var upper = Math.trunc(value / HDKey.HARDENED_OFFSET)
    var lower = value - Math.trunc(value / HDKey.HARDENED_OFFSET) * HDKey.HARDENED_OFFSET
    hdkey = hdkey.deriveChild(upper + HDKey.HARDENED_OFFSET)
    hdkey = hdkey.deriveChild(lower + HDKey.HARDENED_OFFSET)
  }
  return hdkey
}

function vaultInit(event) {
  var callback = event.data.callback

  // if we aren't set up, ask to sign-in, give optional launch url
  if (store.get('vaultSetup') == null) {
    // request to sign in
    parent.postMessage({'callback' : callback, 'error' : 'signin', 'launch' : location.href.split('#')[0]}, event.origin)
    return
  }
  
  if ('trustOrigin' in event.data.init) {
    // is this origin on our blacklist such as IPFS gateway, if so reject it and ask to be launched instead
    // but for now we just trust our browser
    // TODO: do we actually need a re-launch; does changing top level URI always cause a reload, when done from iframe?
    apphash = shajs('sha256').update(event.origin).digest()
    pubex = store.get('pubex-' + apphash.toString('hex'))
    if (pubex == null) {
      // balk and ask to re-launch, we need launcher to set pubex for us first time for now
      parent.postMessage({'callback' : callback, 'error' : 'launch', 'launch' : location.href.split('#')[0], reason: 'trust origin but no pubex'}, event.origin)
      return
    }
  }
  else {
    // okay so we aren't asked to trust origin but instead trust a hash cookie. make sure there's one
    if (location.hash.length > 0) {
      var magiccookie = location.hash.slice(1)
      apphash = sessionStore.get('vault-cookie-' + magiccookie)
      sessionStore.remove('vault-cookie-' + magiccookie)
      if (apphash) {
        pubex = store.get('pubex-' + apphash.toString('hex'))
        // redirection should have given a pubex already, else balk and send 'please re-launch' back
        if (pubex == null) {
          // balk and send 'please re-launch' back
          parent.postMessage({'callback' : callback, 'error' : 'launch', 'launch' : location.href.split('#')[0], reason: 'valid cookie but no pubex'}, event.origin)
          return
        }
      } else {
        // balk and send 'please re-launch' back
        parent.postMessage({'callback' : callback, 'error' : 'launch', 'launch' : location.href.split('#')[0], reason: 'no cookie'}, event.origin)
        return
      }
    } else {
      parent.postMessage({'callback' : callback, 'error' : 'launch', 'launch' : location.href.split('#')[0], reason: 'not trusted nor cookie'}, event.origin)
      return
    }
  }
  // okay, now we have apphash and pubex
  pubex_hdkey = HDKey.fromExtendedKey(pubex)
  inited = true
  parent.postMessage({'callback' : callback, 'result' : 'inited'}, event.origin)
}

async function getSeed() {
  // in real case this gets the other slice from the server and grabs seed for a moment
  return new Promise(resolve => {
    // simulate terrible network
    setTimeout(() => {
      resolve(Buffer.from(store.get('masterseed-NOPRODUCTION'), 'hex'))
    }, 2000);
  })
}

async function getAppPrivEx() {
  let seed = await getSeed()
  let hdkey = HDKey.fromMasterSeed(buf)
  let privex_hdkey = HDKey.fromExtendedKey(deriveWithHash(hdkey, apphash).privateExtendedKey)
  return privex_hdkey
}

async function setup() {
  // we either:
  // - launch a uri w/ a cookie for authentication towards an app-pubex
  // - start a signup process and afterwards launch a uri as linked
  if (location.hash.startsWith('#launch=')) {
    // TODO: slice off the # in the end of target uri to allow deep returns but same context
    var uri = location.hash.slice('#launch='.length)
    if (store.get('vaultSetup') == null) {
      window.location = location.href.split('#')[0] + '#signup=' + uri
      window.location.reload()
      return
    }
    document.getElementById('content').innerHTML = 'signing in with Zipper...'
    apphash = shajs('sha256').update(uri).digest()
    pubex = store.get('pubex-' + apphash.toString('hex'))
    if (pubex == null) {
       let seed = await getSeed()
       var hdkey = HDKey.fromMasterSeed(seed)
       pubex_hdkey = HDKey.fromExtendedKey(deriveWithHash(hdkey, apphash).publicExtendedKey)
       pubex = pubex_hdkey.publicExtendedKey
       store.set('pubex-' + apphash.toString('hex'), pubex)
    }
    // we're now ready to launch
    // generate a one time cookie and redirect to the new uri + cookie
    crypto.randomBytes(32, (err, buf) => {
      if (err) {
        throw err
      }
      var vaultcookie = buf.toString('hex')
      sessionStore.set('vault-cookie-' + vaultcookie, apphash.toString('hex'))
      // TODO: add deep return possible
      window.location = uri + '#zipper-vault=' + location.href.split('#')[0] + '#' + vaultcookie
      return
    })
  } else if (location.hash.startsWith('#signup=')) {
    if (store.get('vaultSetup') != null) {
      alert('already setup')
      return
    }
    alert('signup ux')
    // XXX ask if you have another device
    crypto.randomBytes(64, (err, buf) => {
      if (err) {
        throw err
      }
      var hdkey = HDKey.fromMasterSeed(buf)
      store.set('masterseed-NOPRODUCTION', buf.toString('hex'))
      store.set('vaultSetup', 1)

      // we're now done, now launching
      var uri = location.hash.slice('#signup='.length)
      window.location = location.href.split('#')[0] + '#launch=' + uri
      window.location.reload()
    })
    // show signup UX, generate keys
  } else {
    alert('launched plainly, what now?')
  }
}

function handleVaultMessage(event) {
  if (event.source == parent)
  {
    // are we inited? if so, only accept one message, init
    if ('init' in event.data && !inited) {
      vaultInit(event);
      return;
    }
    if (!inited) {
      return
    }
    // this doesn't give hardened keys for now
    if ('secp256k1KeyInfo' in event.data) {
      // key { derive: 'm/0' } 
      var callback = event.data.callback
      var ahdkey = pubex_hdkey.derive(event.data.secp256k1KeyInfo.key.derive)
      var pubkey = secp256k1.publicKeyConvert(ahdkey.publicKey, false)
      // SEC1 form return
      parent.postMessage({'callback' : callback, 'result' : { 'pubkey' : pubkey.toString('hex'), 'pubex' : ahdkey.publicExtendedKey }}, event.origin)
    } else if ('secp256k1Sign' in event.data) {
      // key { derive 'm/0' }
      var callback = event.data.callback;
      
      // we need to grab a private key for this
      getAppPrivEx().then((privex_hdkey) => {
        var from = privex.hdkey.derive(event.data.secp256k1Sign.key.derive)
        var sig = secp256k1.sign(Buffer.from(event.data.secp256k1Sign.hash, 'hex'), from.privateKey)
        parent.postMessage({'callback' : callback, 'result' : { signature: sig.signature.toString('hex'), recovery: sig.recovery, hash: event.data.secp256k1Sign.hash } }, event.origin)
      })
    } else {
      parent.postMessage({'callback' : callback, 'error' : 'unknown method'}, event.origin)
      return
    }
  }
  return
}
 
if (window.top == window.self) {
  setup().then(() => {
    console.log('Setup done')
  })
} else {
  // we're in an iframe, time to listen for commands
  console.log('Zipper Vault listening')
  window.addEventListener('message', handleVaultMessage)
  parent.postMessage({'ready' : true}, '*')
}
