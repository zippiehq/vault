var HDKey = require('hdkey')
var secrets = require('secrets.js-grempe')
var secp256k1 = require('secp256k1')
var shajs = require('sha.js')
var store = require('store')
const crypto = require('crypto');
const eccrypto = require('eccrypto');
const XMLHttpRequestPromise = require('xhr-promise')

var sessionStoreEngine = require('store/storages/sessionStorage')
var sessionStore = store.createStore(sessionStoreEngine)

// vault per-session state
var inited = false
var apphash = null
var pubex = null
var pubex_hdkey = null

var rootWindow = null

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
      var apph = store.get('vault-cookie-' + magiccookie)
      console.log('looked up ' + magiccookie + ' got ' + apph)
      store.remove('vault-cookie-' + magiccookie)
      if (apph) {
        apphash = Buffer.from(apph, 'hex')
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
  let timestamp = Date.now()
  let hash = shajs('sha256').update(timestamp.toString()).digest()
  let sig = secp256k1.sign(hash, Buffer.from(store.get('authkey'), 'hex'))
  // XXX error handling
  var fms_bundle = { 'hash': hash.toString('hex'), 'timestamp' : timestamp.toString(), 'sig' : sig.signature.toString('hex'), 'recovery' : sig.recovery }
  var url = 'https://fms.zippie.org/fetch'
  var xhrPromise = new XMLHttpRequestPromise()
  let response = await xhrPromise.send({
    'method': 'POST',
    'url': url,
    'headers': {
      'Content-Type': 'application/json;charset=UTF-8'
    },
    'data': JSON.stringify(fms_bundle)
  })
  let ciphertext2_dict = JSON.parse(response.responseText).data
  console.log(ciphertext2_dict)
  let ciphertext2 = {
    iv: Buffer.from(ciphertext2_dict.iv, 'hex'),
    ephemPublicKey: Buffer.from(ciphertext2_dict.ephemPublicKey, 'hex'),
    ciphertext: Buffer.from(ciphertext2_dict.ciphertext, 'hex'),
    mac: Buffer.from(ciphertext2_dict.mac, 'hex')
  }
  let localkey = Buffer.from(store.get('localkey'), 'hex')
  let remoteslice_e = await eccrypto.decrypt(localkey, ciphertext2)
  let remoteslice = remoteslice_e.toString('utf8')

  let ciphertext1_dict = JSON.parse(store.get('localslice_e'))
  let ciphertext1 = {
    iv: Buffer.from(ciphertext1_dict.iv, 'hex'),
    ephemPublicKey: Buffer.from(ciphertext1_dict.ephemPublicKey, 'hex'),
    ciphertext: Buffer.from(ciphertext1_dict.ciphertext, 'hex'),
    mac: Buffer.from(ciphertext1_dict.mac, 'hex')
  }
  let localslice_e = await eccrypto.decrypt(localkey, ciphertext1)
  let localslice = localslice_e.toString('utf8')
  var masterseed = Buffer.from(secrets.combine([localslice, remoteslice]), 'hex')
  // XXX some kind of checksum?
  return masterseed
}

async function getAppPrivEx() {
  let seed = await getSeed()
  let hdkey = HDKey.fromMasterSeed(seed)
  let privex_hdkey = HDKey.fromExtendedKey(deriveWithHash(hdkey, apphash).privateExtendedKey)
  return privex_hdkey
}

function pbkdf2promisify(password, salt, iterations, keylen, digest) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, buf) => {
      if (err) {
        reject(err)
      } else {
        resolve(buf)
      }
    })
  })
}

function randomBuf(length = 32) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(length, (err, buf) => {
      if (err) {
        reject(err)
      } else {
        resolve(buf)
      }
    })  
  })
}

async function handleRootMessage(event) {
  if (event.source != rootWindow) {
    return
  }
  if ('checkenrollment' in event.data) {
    let salt = Buffer.from('3949edd685c135ed6599432db9bba8c433ca8ca99fcfca4504e80aa83d15f3c4', 'hex')
    let derivedKey = await pbkdf2promisify(event.data.checkenrollment.email, salt, 100000, 32, 'sha512')

    let timestamp = Date.now()
    let hash = shajs('sha256').update(timestamp.toString()).digest()
    let sig = secp256k1.sign(hash, derivedKey)
    // XXX error handling
    var fms_bundle = { 'hash': hash.toString('hex'), 'timestamp' : timestamp.toString(), 'sig' : sig.signature.toString('hex'), 'recovery' : sig.recovery }
    var url = 'https://fms.zippie.org/fetch'
    var xhrPromise = new XMLHttpRequestPromise()
    try {
      let response = await xhrPromise.send({
        'method': 'POST',
        'url': url,
        'headers': {
          'Content-Type': 'application/json;charset=UTF-8'
        },
        'data': JSON.stringify(fms_bundle)
      })
      if ('error' in JSON.parse(response.responseText)) {
        event.source.postMessage({'enrollmentresult': 'no'}, event.origin)
      } else {
        event.source.postMessage({'enrollmentresult': 'yes'}, event.origin)
      }
    } catch (e) {
      event.source.postMessage({'enrollmentresult': 'unknown'}, event.origin)
    }
  } else if ('newidentity' in event.data) {
    let masterseed = await randomBuf(64)

    // generate localkey as a outside-JS key ideally
    let localkey = await randomBuf(32)
    let authkey = await randomBuf(32)
    let localpubkey = secp256k1.publicKeyCreate(localkey, false)

    let authpubkey = secp256k1.publicKeyCreate(authkey, false)

    let hash = shajs('sha256').update('zippie-devices/initial').digest()
    
    var revokepubkey = secp256k1.publicKeyConvert(deriveWithHash(HDKey.fromMasterSeed(masterseed), hash).derive('m/0').publicKey, false)
    
    store.set('localkey', localkey.toString('hex'))
    store.set('authkey', authkey.toString('hex'))
    var shares = secrets.share(masterseed.toString('hex'), 2, 2)
    let ciphertext1 = await eccrypto.encrypt(localpubkey, Buffer.from(shares[0], 'utf8'))
    let ciphertext2 = await eccrypto.encrypt(localpubkey, Buffer.from(shares[1], 'utf8'))
    let ciphertext1_json = JSON.stringify({
      iv: ciphertext1.iv.toString('hex'), 
      ephemPublicKey: ciphertext1.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext1.ciphertext.toString('hex'),
      mac: ciphertext1.mac.toString('hex')
    })
    store.set('localslice_e', ciphertext1_json)

    let ciphertext2_dict = {
      iv: ciphertext2.iv.toString('hex'), 
      ephemPublicKey: ciphertext2.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext2.ciphertext.toString('hex'),
      mac: ciphertext2.mac.toString('hex')
    }
    
    // contact forgetme server and upload {authpubkey, ciphertext2_json, revokepubkey}
    let forgetme_upload = JSON.stringify({'authpubkey' : authpubkey.toString('hex'), 'data': ciphertext2_dict, 'revokepubkey' : revokepubkey.toString('hex')})

    var url = 'https://fms.zippie.org/store'
    store.set('fms', 'https://fms.zippie.org')
    
    var xhrPromise = new XMLHttpRequestPromise()
    let response = await xhrPromise.send({
       'method': 'POST',
       'url': url,
       'headers': {
         'Content-Type': 'application/json;charset=UTF-8'
       },
       'data' : forgetme_upload
    })

    var salt = Buffer.from('3949edd685c135ed6599432db9bba8c433ca8ca99fcfca4504e80aa83d15f3c4', 'hex')
    var derivedKey = await pbkdf2promisify(event.data.newidentity.email, salt, 100000, 32, 'sha512')
    var randomKey = await randomBuf(32)
    let derivedPubKey = secp256k1.publicKeyCreate(derivedKey, false)
    store.set('useremail', event.data.newidentity.email)
    forgetme_upload = JSON.stringify({'authpubkey' : derivedPubKey.toString('hex'), 'data': {}, 'revokepubkey': randomKey.toString('hex')})
    var url = 'https://fms.zippie.org/store'
    var xhrPromise = new XMLHttpRequestPromise()
    let response2 = await xhrPromise.send({
      'method': 'POST',
      'url': url,
      'headers': {
        'Content-Type': 'application/json;charset=UTF-8'
      },
      'data': forgetme_upload
    })
    // XXX error handling

    store.set('vaultSetup', 1)
    // we're now done, now launching
    var uri = location.hash.slice('#signup='.length)
    window.location = location.href.split('#')[0] + '#launch=' + uri
    window.location.reload()
    // XXX add error handling
  }
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
    document.getElementById('content').innerHTML = 'signing in with Zippie...'
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
    let cookie = await randomBuf(32)
    var vaultcookie = cookie.toString('hex')
    console.log('set vault cookie ' + vaultcookie + ' to ' + apphash.toString('hex'))
    store.set('vault-cookie-' + vaultcookie, apphash.toString('hex'))
    // TODO: add deep return possible
    window.location = uri.split('#')[0] + '#zippie-vault=' + location.href.split('#')[0] + '#' + vaultcookie
    return
  } else if (location.hash.startsWith('#signup=')) {
    if (store.get('vaultSetup') != null) {
      alert('already setup')
      return
    }
    // insert a iframe that can postmessage to us in a privileged manner
    var iframe = document.createElement('iframe')
    iframe.style.cssText = 'border: 0; position:fixed; top:0; left:0; right:0; bottom:0; width:100%; height:100%'
    iframe.src = 'https://signup.zippie.org/' // XXX switch to IPFS
    document.body.appendChild(iframe)
    rootWindow = iframe.contentWindow
    window.addEventListener('message', handleRootMessage)
  } else {
      alert('launched v8 plainly, what now?')
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
        var from = privex_hdkey.derive(event.data.secp256k1Sign.key.derive)
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
  console.log('Zippie Vault listening')
  window.addEventListener('message', handleVaultMessage)
  parent.postMessage({'ready' : true}, '*')
}
