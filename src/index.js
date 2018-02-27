var HDKey = require('hdkey')
var secp256k1 = require('secp256k1')
var shajs = require('sha.js')
var store = require('store')

var inited = false
var apphash = null
var origin = null
var pubex = null

// vault contains:
// cache of app hash -> app-pubex
// device local private key
// device authentication private key
// seed piece 1 out of 2 (2of2) encrypted with device local private key
// forgetme server url if non-standard

// app-pubex is calculated by taking private extended key of root + some derivation, always hardened +
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

  if (store.get('vaultSetup') == null) {
    // request to sign in
    parent.postMessage({'callback' : callback, 'result' : 'signin'}, event.origin)
    return
  }
  
  if ('trustOrigin' in event.data.init) {
    // is this origin on our blacklist such as IPFS gateway, if so reject it and ask to be launched instead
    // but for now we just trust our browser
    apphash = shajs('sha256').update(origin).digest()
    pubex = store.get('pubex-' + apphash.toString('hex'))
    if (pubex == null) {
      // balk and ask to re-launch, we need launcher to set pubex for us first time for now
      parent.postMessage({'callback' : callback, 'result' : 'launch', launch : location.href, reason: 'trust origin but no pubex'}, event.origin)
      return
    }
  }
  else {
    // okay so we aren't asked to trust origin but instead trust a cookie. make sure there's one
    if ('originCookie' in event.data.init) {
      var magiccookie = event.data.init.originCookie
      apphash = store.get('vault-cookie-' + magiccookie)
      store.remove('vault-cookie-' + magiccookie)
      if (apphash) {
        pubex = store.get('pubex-' + apphash.toString('hex')){
        // redirection should have given a pubex already, else balk and send 'please re-launch' back
        if (pubex == null) {
          // balk and send 'please re-launch' back
          parent.postMessage({'callback' : callback, 'result' : 'launch', launch : location.href, reason: 'valid cookie but no pubex'}, event.origin)
          return
        }
      } else {
        // balk and send 'please re-launch' back
        parent.postMessage({'callback' : callback, 'result' : 'launch', launch : location.href, reason: 'no cookie'}, event.origin)
        return
      }
    } else {
      parent.postMessage({'callback' : callback, 'result' : 'launch', launch : location.href, reason: 'not trusted nor cookie'}, event.origin)
    }    
}



// vault is initially started with device local key which enables it to decrypt it's local pieces
/* 
var seed = 'a0c42a9c3ac6abf2ba6a9946ae83af18f51bf1c9fa7dacc4c92513cc4dd015834341c775dcd4c0fac73547c5662d81a9e9361a0aac604a73a321bd9103bce8af'
var hdkey = HDKey.fromMasterSeed(new Buffer(seed, 'hex'))

var hash = shajs('sha256').update('notshit').digest().toString('hex')

console.log(deriveWithHash(hdkey, hash).publicExtendedKey)

function handleVaultMessage(event) {
  if (event.source == parent) {
    if ('init' in event.data && !inited)
    {
      vaultInit(event);
      inited = true
      return;
    }

    if (!inited)
      return;
    
  }
}
*/

if (window.top == window.self) {
  // we either:
  // - launch a uri w/ a cookie for authentication towards an app-pubex
  // - start a signup process and afterwards launch a uri as linked
  // XXX don't bother to allow anything if not initialised, show up signup?
  
  if (location.hash.startsWith('#launch=')) {
    // TODO: slice off the # in the end
    var uri = location.hash.slice('#launch='.length)
    apphash = shajs('sha256').update(uri).digest()
    pubex = store.get('pubex-' + apphash.toString('hex'))
    if (pubex != null)
    {
      // we're ready to launch
      // generate a one time cookie and redirect to the new uri + cookie
    } else {
      // we need to generate public extended key for this particular apphash
    }
  } else if (location.hash.startsWith('#signup=')) {
    
  }
} else {
  // we're in an iframe, time to listen for commands
  console.log('Zipper Vault listening')
  window.addEventListener('message', handleVaultMessage)
  parent.postMessage({'ready' : true}, '*')
}
