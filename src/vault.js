/*
 * Copyright (c) 2018 Zippie Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/
const Cookie = require('js-cookie')

var HDKey = require('hdkey')
var secrets = require('secrets.js-grempe')
var secp256k1 = require('secp256k1')
var shajs = require('sha.js')
const crypto = require('crypto');
const eccrypto = require('eccrypto');
const XMLHttpRequestPromise = require('xhr-promise')
const storeplain = require('store')

// vault database contains:
// cache of app hash -> app-pubex
// device local private key
// device authentication private key
// seed piece 1 out of 2 (2of2) encrypted with device local private key
// forgetme server url if non-standard


// Configuration
var iframe_style = 'border: none; position: absolute; width: 100%; height: 100%'

var fms_uri = 'https://fms.zippie.org'
var signup_uri = 'https://signup.zippie.org'
var my_uri = 'https://my.zippie.org'

// If we're running in dev environment, use dev signup aswell.
if (window.location.host === 'vault.dev.zippie.org') {
  signup_uri = 'https://signup.dev.zippie.org'
  my_uri = 'https://my.dev.zippie.org'
} else if (window.location.host === 'vault.testing.zippie.org') {
  signup_uri = 'https://signup.testing.zippie.org'
  my_uri = 'https://my.testing.zippie.org'
}

// vault per-session state
var inited = false
var apphash = null
var pubex = null
var pubex_hdkey = null

var params = {}
var iframed = false

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
  var magiccookie

  if ('cookie' in event.data.init) {
    console.log('Using cookie in init message.')
    magiccookie = Buffer.from(event.data.init.cookie, 'hex')

  } else if (location.hash.length > 0) {
    console.log('Using cookie in URI hash')
    magiccookie = Buffer.from(location.hash.slice(1), 'hex')
  }

  // Decode cookie
  let vdata = Cookie.get('v-data')
  console.log("Vault Data:", vdata)

  if (vdata === undefined) {
      console.error('No vault data cookie.')
      return event.source.postMessage({
        'callback': callback,
        'error': 'launch',
        'launch': location.href.split('#')[0],
        'reason': 'No vault data cookie.'
      }, '*')
  }

  if (vdata !== undefined) {
    if (magiccookie === undefined) {
      console.error('No magiccookie supplied!')
      return event.source.postMessage({
        'callback': callback,
        'error': 'launch',
        'launch': location.href.split('#')[0],
        'reason': 'No magic cookie.'
      }, '*')
    }

    vdata = JSON.parse(vdata)
    console.log('VV Key', magiccookie)
    // Decrypt vdata, populate local storage and continue.
    let cipher = crypto.createDecipheriv('aes-256-cbc', magiccookie, Buffer.from(vdata.iv, 'hex'))
    let b1 = cipher.update(Buffer.from(vdata.text, 'hex'))
    let b2 = cipher.final()

    vdata = JSON.parse(Buffer.concat([b1, b2]).toString('utf8'))
    console.log('VV DECRYPTED:', vdata)

    store.set('localkey', vdata.localkey),
    store.set('authkey', vdata.authkey),
    store.set('localslice_e', vdata.localslice_e),
    store.set('vaultSetup', 1)    
  }

  // Read vault identity setup flag
  store.get('vaultSetup')
    .then(function(r) {
      // Error with signup if no identity setup
      if ((r.result === undefined || r.result.value !== 1)) {
        return Promise.reject({error: 'signin', reason: 'signin'})
      }
    })
    .then(function() {
      apphash = shajs('sha256').update(event.origin).digest()

      return getSeed()
        .then(seed => {
          let hdkey = HDKey.fromMasterSeed(seed)
          pubex_hdkey = HDKey.fromExtendedKey(
            deriveWithHash(hdkey, apphash).publicExtendedKey
          )

          pubex = pubex_hdkey.publicExtendedKey
        })

      // Read magic cookie from message parameters or location hash
      var magiccookie;

      if ('cookie' in event.data.init) {
        console.log('Using cookie in init message.')
        magiccookie = event.data.init.cookie
        iframed = true

      } else if (location.hash.length > 0) {
        console.log('Using cookie in URI hash')
        magiccookie = location.hash.slice(1)
      }

      // Get magic cookie from vault storage and validate.
      return store.get('vault-cookie-' + magiccookie)
        .then(function(r) {
          if (r.result === undefined || r.result.value === undefined) {
            return Promise.reject({error: 'launch', reason: 'no magic cookie'})
          }

          var apph = r.result.value

          console.log('looked up ' + magiccookie +  ' got ' + apph)
          store.remove('vault-cookie-' + magiccookie)

          return store.get('pubex-' + apph)
            .then(function(r) {
              if (r.result === undefined || r.result.value === undefined) {
                return Promise.reject({
                  error: 'launch',
                  reason: 'Valid cookie but no pubex'
                })
              }

              apphash = Buffer.from(apph, 'hex')
              pubex = r.result.value

              return Promise.resolve()
            })
        })
    })
    .then(_ => {
      // okay, now we have apphash and pubex
      pubex_hdkey = HDKey.fromExtendedKey(pubex)

      event.source.postMessage({
        'callback' : callback,
        'result' : 'inited'
      }, event.origin)

      inited = true
    })
    .catch(e => {
      console.error('Vault init error:', e)
      event.source.postMessage({
        'callback': callback,
        'error': e.error,
        'launch': e.launch || location.href.split('#')[0],
        'reason': e.reason
      }, event.origin)
    })
}

function getSeed() {
  // in real case this gets the other slice from the server and grabs seed for a moment
  let timestamp = Date.now()
  var hash = shajs('sha256').update(timestamp.toString()).digest()

  return store.get('authkey')
    .then(function(r) {
      if (r.result === undefined || r.result.value === undefined) {
        return Promise.reject('Failed to get authkey')
      }

      // XXX error handling
      let sig = secp256k1.sign(hash, Buffer.from(r.result.value, 'hex'))
      let fms_bundle = {
        'hash': hash.toString('hex'),
        'timestamp': timestamp.toString(),
        'sig': sig.signature.toString('hex'),
        'recovery': sig.recovery
      }

      let xhr = new XMLHttpRequestPromise()
      return xhr.send({
        'method': 'POST',
        'url': fms_uri + '/fetch',
        'headers': {
          'Content-Type': 'application/json;charset=UTF-8'
        },
        'data': JSON.stringify(fms_bundle)
      })
    })
    .then(function(response) {
      if (response.status != 200) {
        return Promise.reject(JSON.stringify(response))
      }

      if ('error' in JSON.parse(response.responseText)) {
        return Promise.reject('Got error fetching from FMS')
      }

      let localkey
      let ciphertext2
      let remoteslice

      return store.get('localkey')
        .then(async function (r) {
          if (r.result === undefined || r.result.value === undefined) {
            return Promise.reject('Failed to get localkey')
          }

          localkey = Buffer.from(r.result.value, 'hex')

          let ciphertext2_dict = JSON.parse(response.responseText).data
          ciphertext2 = {
            iv: Buffer.from(ciphertext2_dict.iv, 'hex'),
            ephemPublicKey: Buffer.from(ciphertext2_dict.ephemPublicKey, 'hex'),
            ciphertext: Buffer.from(ciphertext2_dict.ciphertext, 'hex'),
            mac: Buffer.from(ciphertext2_dict.mac, 'hex')
          }

          let remoteslice_e = await eccrypto.decrypt(localkey, ciphertext2)
          remoteslice = remoteslice_e.toString('utf8')

          return store.get('localslice_e')
        })
        .then(async function (r) {
          if (r.result === undefined || r.result.value === undefined) {
            return Promise.reject('Failed to get localslice')
          }

          let ciphertext1_dict = JSON.parse(r.result.value)
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
        })
    })
}

async function getAppPrivEx() {
  let seed = await getSeed()
  let hdkey = HDKey.fromMasterSeed(seed)
  let privex_hdkey = HDKey.fromExtendedKey(deriveWithHash(hdkey, apphash).privateExtendedKey)
  return privex_hdkey
}

export function setup() {
  if (location.hash.startsWith('#wipe=') && confirm('Do you really want to wipe Zippie Vault? May cause data loss or money lost') === true) {
    return store.clearAll()
      .then(_ => {
        alert('Vault wiped')
      })
      .catch(e => {
        alert(e)
      })
  }

  // Variables for parameter processing
  let hash = window.location.hash

  // Process URI fragment part for vault params
  if (hash.indexOf('?') !== -1) {
    let p = hash.split('?')[1].split(';')

    for (var i = 0; i < p.length; i++) {
      var kv = p[i].split('=')
      params[kv[0]] = kv[1]
    }

    // Strip params from URI fragment part
    //window.location.hash = hash.slice(0, hash.indexOf('?'))
  }

  console.log('Vault Parameters:', params)

  // we either:
  // - launch a uri w/ a cookie for authentication towards an app-pubex
  // - start a signup process and afterwards launch a uri as linked
  if (params['iframe'] !== undefined) {
    let uri = params['iframe']

    return store.get('vaultSetup')
      .then(function(r) {
        if (r.result === undefined || r.result.value === undefined) {
          window.location = location.href.split('/#')[0] + '/#?signup=' + uri
          window.location.reload()
        }

        // TODO: Implement a nicer loading page.
        document.getElementById('content').innerHTML = 'Signing in with Zippie...'
        apphash = shajs('sha256').update(uri.split('/#')[0]).digest()

        return store.get('pubex-' + apphash.toString('hex'))
      })
      .then(function(r) {
        if (r.result === undefined || r.result.value === undefined) {
          return getSeed()
            .then(seed => {
              let hdkey = HDKey.fromMasterSeed(seed)
              pubex_hdkey = HDKey.fromExtendedKey(
                deriveWithHash(hdkey, apphash).publicExtendedKey
              )

              pubex = pubex_hdkey.publicExtendedKey
              return store.set('pubex-' + apphash.toString('hex'), pubex)
            })
        }

        pubex = r.result.value
      })
      .then(async function() {
        let cookie = crypto.randomBytes(32)
        let vaultcookie = cookie.toString('hex')

        return store.set('vault-cookie-' + vaultcookie, apphash.toString('hex'))
          .then(function() {
            var iframe = document.createElement('iframe')

            iframe.allow = 'camera'
            iframe.style.cssText = iframe_style

            if (uri.indexOf('#') === -1) uri += '#'
            iframe.src = uri + '?iframe=' + vaultcookie

            document.body.innerHTML = ''
            document.body.appendChild(iframe)
            return
          })
      })

  } else if (params['launch'] !== undefined) {
    // TODO: slice off the # in the end of target uri to allow deep returns but same context
    let uri = params['launch']
    console.log('Launching:', uri)

    return store.get('vaultSetup')
      .then(function(r) {
        if (r.result === undefined || r.result.value === undefined) {
          window.location.hash = '#?signup=' + uri
          window.location.reload()
          return
        }

        document.getElementById('content').innerHTML = 'Signing in with Zippie...'
        apphash = shajs('sha256').update(uri.split('/#')[0]).digest()
        return store.get('pubex-' + apphash.toString('hex'))
      })
      .then(function(r) {
        if (r.result === undefined || r.result.value === undefined) {
          return getSeed()
            .then(seed => {
              let hdkey = HDKey.fromMasterSeed(seed)
              pubex_hdkey = HDKey.fromExtendedKey(
                deriveWithHash(hdkey, apphash).publicExtendedKey
              )
              pubex = pubex_hdkey.publicExtendedKey

              return store.set('pubex-' + apphash.toString('hex'), pubex)
            })
        }

        pubex = r.result.value
      })
      .then(function () {
        let localkey
        let authkey
        let localslice

        console.log('VV: Setting up cookie data')
        return Promise.all([
            store.get('localkey').then(r => { localkey = r.result.value }),
            store.get('authkey').then(r => { authkey = r.result.value }),
            store.get('localslice_e').then(r => {localslice = r.result.value })
          ])
          .then(function() {
            return Promise.resolve({
              localkey: localkey,
              authkey: authkey,
              localslice_e: localslice
            })
          })
          .catch(e => {
            console.error('VV', e)
          })
      })
      .then(async function(vdata) {
        let iv = crypto.randomBytes(16)
        let cookie = crypto.randomBytes(32)
        let vaultcookie = cookie.toString('hex')

        console.log('Encrypting identity cookie.')
        let cipher = crypto.createCipheriv('aes-256-cbc', cookie, iv)
        let b1 = cipher.update(Buffer.from(JSON.stringify(vdata), 'utf8'))
        let b2 = cipher.final()

        console.log('Setting identity cookie.')
        Cookie.set(
          'v-data',
          JSON.stringify({
            iv: iv.toString('hex'),
            text: Buffer.concat([b1, b2]).toString('hex')
          }),
          {secure: true}
        )

        return store.set('vault-cookie-' + vaultcookie, apphash.toString('hex'))
          .then(_ => {
            if (uri.indexOf('#') === -1) uri += '#'
            window.location = uri + '?zippie-vault=' + location.href.split('#')[0] + '#' + vaultcookie
          })
      })

  } else if (params['signup'] !== undefined) {
    return store.get('vaultSetup')
      .then(function(r) {
        if (r.result != undefined && r.result.value === 1) {
          alert('already setup')
          return
        }

        var iframe = document.createElement('iframe')
        iframe.style.cssText = iframe_style
        iframe.src = signup_uri // XXX switch to IPFS
        document.body.innerHTML = ''
        document.body.appendChild(iframe)
      })

  } else if (params['enroll'] !== undefined) {
    // insert a iframe that can postmessage to us in a privileged manner
    var iframe = document.createElement('iframe')
    iframe.style.cssText = iframe_style

    // XXX switch to IPFS
    iframe.src = signup_uri + '/#/enroll/' + params['enroll']

    document.body.innerHTML = ''
    document.body.appendChild(iframe)

  } else {
      alert('launched v9 plainly, what now?')      
  }
}

//
// Local storage adapter
//
const store = {
  get: function (key) {
    return Promise.resolve({ result: { value: storeplain.get(key)}})
  },

  set: function (key, value) {
    return Promise.resolve(storeplain.set(key, value))
  },

  remove: function (key) {
    return Promise.resolve(storeplain.remove(key))
  },

  clearAll: function () {
    return Promise.resolve(storeplain.clearAll())
  }
}

//
// Vault storage adapter
//
/*
const store = {
  get: function (key) {
    return window.VaultChannel.request({'store.get': {key: key}})
  },

  set: function (key, value) {
    return window.VaultChannel.request({'store.set': {key: key, value: value}})
  },

  remove: function (key) {
    return window.VaultChannel.request({'store.set': {key: key, value: undefined}})
  },

  clearAll: function () {
    return window.VaultChannel.request({'store.clearAll': null})
  }
}
*/

//
// Generate secp256k1 key helper
//
async function secp256k1GenerateKey () {
  let key = crypto.randomBytes(32)
  let pub = secp256k1.publicKeyCreate(key, false)
  return {privateKey: key, publicKey: pub}
}

//
// Message processing for root level apps, like onboarding.
//
export class RootMessageHandler {
  // Open qrscan.io for scanning qr codes.
  //
  qrscan (event) {
    window.location = 'https://qrscan.io'
    window.reload()
  }

  // enroleeinfo
  //
  async enroleeinfo (event) {
    let local = await secp256k1GenerateKey()
    let auth = await secp256k1GenerateKey()

    Promise.all([
      store.set('localkey', local.privateKey.toString('hex')),
      store.set('authkey', auth.privateKey.toString('hex')),
      store.set('devicePartiallySetup', 1)
    ]).then(_ => {
      event.source.postMessage({
        'deviceenroleeinfo' : {
          'localpubkey' : local.publicKey.toString('hex'),
          'authpubkey' : auth.publicKey.toString('hex')
        }
      }, event.origin)
    }).catch(e => {
      console.error('Failed to store enroleeinfo:', e)
      event.source.postMessage({
        'deviceneroleeinfo': {success: false}
      })
    })
  }

  // enrolldevice
  //
  async enrolldevice (event) {
    // we get: 
    // - devicepubkey
    // - authpubkey
    // - device name
    let devicepubkey = Buffer.from(event.data.enrolldevice.devicepubkey, 'hex')
    let authpubkey = Buffer.from(event.data.enrolldevice.authpubkey, 'hex')

    let devicename = event.data.enrolldevice.devicename
    let hash = shajs('sha256').update('zippie-devices/' + devicename).digest()

    var masterseed = await getSeed()
    var revokepubkey = secp256k1.publicKeyConvert(deriveWithHash(HDKey.fromMasterSeed(masterseed), hash).derive('m/0').publicKey, false)

    var shares = secrets.share(masterseed.toString('hex'), 2, 2)
    let ciphertext1 = await eccrypto.encrypt(devicepubkey, Buffer.from(shares[0], 'utf8'))
    let ciphertext2 = await eccrypto.encrypt(devicepubkey, Buffer.from(shares[1], 'utf8'))

    // Sent to enrolee
    let ciphertext1_json = {
      iv: ciphertext1.iv.toString('hex'), 
      ephemPublicKey: ciphertext1.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext1.ciphertext.toString('hex'),
      mac: ciphertext1.mac.toString('hex')
    }

    // Stored in FMS
    let ciphertext2_dict = {
      iv: ciphertext2.iv.toString('hex'), 
      ephemPublicKey: ciphertext2.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext2.ciphertext.toString('hex'),
      mac: ciphertext2.mac.toString('hex')
    }

    // contact forgetme server and upload {authpubkey, ciphertext2_json, revokepubkey}
    let forgetme_upload = JSON.stringify({
      'authpubkey' : authpubkey.toString('hex'),
      'data': ciphertext2_dict,
      'revokepubkey' : revokepubkey.toString('hex')
    })

    var url = fms_uri + '/store'
    var xhrPromise = new XMLHttpRequestPromise()
    try {
      let response = await xhrPromise.send({
         'method': 'POST',
         'url': url,
         'headers': {
           'Content-Type': 'application/json;charset=UTF-8'
         },
         'data' : forgetme_upload
      })
      if (response.status != 200)
         throw 'Got error ' + JSON.stringify(response)
      let responsejson = JSON.parse(response.responseText)
      if ('error' in responsejson)
        throw error
    } catch (err) {
      alert('FMS store 1 (enroll) failed, balking: ' + err)
      return
    }

    event.source.postMessage({
      'deviceenrollmentresponse' : ciphertext1_json
    }, event.origin)
  }

  // finishenrollment
  //
  finishenrollment (event) {
    // we get slice
    store.get('devicePartiallySetup')
      .then(r => {
        if (r.result != undefined && r.result.value !== 1) {
          return
        }

        let params = event.data.finishenrollment

        return Promise.all([
          store.set('localslice_e', JSON.stringify(params)),
          store.set('vaultSetup', 1)
        ]).then(_ => {
          // we're now done, launch home
          window.location = my_uri
        })
        .catch(e => {
          console.error('Error in finishenrollment storing vault data:', e)
        })
      })
  }

  // checkenrollment
  //
  async checkenrollment (event) {
    let salt = Buffer.from('3949edd685c135ed6599432db9bba8c433ca8ca99fcfca4504e80aa83d15f3c4', 'hex')
    let derivedKey = crypto.pbkdf2Sync(event.data.checkenrollment.email, salt, 100000, 32, 'sha512')

    let timestamp = Date.now()
    let hash = shajs('sha256').update(timestamp.toString()).digest()
    let sig = secp256k1.sign(hash, derivedKey)
    // XXX error handling
    var fms_bundle = { 'hash': hash.toString('hex'), 'timestamp' : timestamp.toString(), 'sig' : sig.signature.toString('hex'), 'recovery' : sig.recovery }
    var url = fms_uri + '/fetch'
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
      if (response.status != 200)
        throw JSON.stringify(response)
      if ('error' in JSON.parse(response.responseText)) {
        event.source.postMessage({'enrollmentresult': 'no'}, event.origin)
      } else {
        event.source.postMessage({'enrollmentresult': 'yes'}, event.origin)
      }
    } catch (e) {
      event.source.postMessage({'enrollmentresult': 'unknown'}, event.origin)
    }
  }

  // newidentity
  //
  async newidentity (event) {
    let masterseed = crypto.randomBytes(32)

    // generate localkey as a outside-JS key ideally
    console.log('Generating local and auth key.')
    let local = await secp256k1GenerateKey()
    let auth = await secp256k1GenerateKey()

    let hash = shajs('sha256').update('zippie-devices/initial').digest()

    console.log('Generating revoke key.')
    var revokepubkey = secp256k1.publicKeyConvert(deriveWithHash(HDKey.fromMasterSeed(masterseed), hash).derive('m/0').publicKey, false)

    console.log('Encrypting remote and local slices.')
    var shares = secrets.share(masterseed.toString('hex'), 2, 2)
    let ciphertext1 = await eccrypto.encrypt(local.publicKey, Buffer.from(shares[0], 'utf8'))
    let ciphertext2 = await eccrypto.encrypt(local.publicKey, Buffer.from(shares[1], 'utf8'))

    let ciphertext1_json = JSON.stringify({
      iv: ciphertext1.iv.toString('hex'), 
      ephemPublicKey: ciphertext1.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext1.ciphertext.toString('hex'),
      mac: ciphertext1.mac.toString('hex')
    })

    let ciphertext2_dict = {
      iv: ciphertext2.iv.toString('hex'), 
      ephemPublicKey: ciphertext2.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext2.ciphertext.toString('hex'),
      mac: ciphertext2.mac.toString('hex')
    }
    
    // contact forgetme server and upload {authpubkey, ciphertext2_json, revokepubkey}
    let forgetme_upload = JSON.stringify({
      'authpubkey' : auth.publicKey.toString('hex'),
      'data': ciphertext2_dict,
      'revokepubkey': revokepubkey.toString('hex')
    })

    var url = fms_uri + '/store'
    
    var xhrPromise = new XMLHttpRequestPromise()
    try {
      console.log('Storing remote slice')
      let response = await xhrPromise.send({
         'method': 'POST',
         'url': url,
         'headers': {
           'Content-Type': 'application/json;charset=UTF-8'
         },
         'data': forgetme_upload
      })
      if (response.status != 200)
         throw 'Got error ' + JSON.stringify(response2)
      let responsejson = JSON.parse(response.responseText)
      if ('error' in responsejson)
        throw error
    } catch (err) {
      alert('FMS store 1 failed, balking: ' + err)
      return
    }

    /*
    var salt = Buffer.from('3949edd685c135ed6599432db9bba8c433ca8ca99fcfca4504e80aa83d15f3c4', 'hex')
    console.log('Generating revoke authkey')
    var derivedKey = crypto.pbkdf2Sync(event.data.newidentity.email, salt, 10000, 32, 'sha512')
    console.log('Generating revoke key')
    var randomKey = crypto.randomBytes(32)

    let derivedPubKey = secp256k1.publicKeyCreate(derivedKey, false)
    forgetme_upload = JSON.stringify({
      'authpubkey' : derivedPubKey.toString('hex'),
      'data': {},
      'revokepubkey': randomKey.toString('hex')
    })

    var url = fms_uri + '/store'
    var xhrPromise = new XMLHttpRequestPromise()
    try {
      console.log('Storing revokation key')
      let response2 = await xhrPromise.send({
        'method': 'POST',
        'url': url,
        'headers': {
          'Content-Type': 'application/json;charset=UTF-8'
        },
        'data': forgetme_upload
      })
      if (response2.status != 200)
         throw 'Got error ' + JSON.stringify(response2)
      let response2json = JSON.parse(response2.responseText)
      if ('error' in response2json)
        throw error

    } catch (err) {
      alert('FMS upload 2 failed, balking: ' + JSON.stringify(err))
      return
    }*/

    console.log('Storing local identity into vault')
    return Promise.all([
        store.set('localkey', local.privateKey.toString('hex')),
        store.set('authkey', auth.privateKey.toString('hex')),
        store.set('localslice_e', ciphertext1_json),
        store.set('fms', fms_uri),
        store.set('useremail', event.data.newidentity.email),
        store.set('vaultSetup', 1)
      ])
      .then(_ => {
        // we're now done, launching
        console.log('Identity created, redirecting...')
        let uri = params['signup']
        window.location = location.href.split('#')[0] + '#?launch=' + uri
        window.location.reload()
      })
      .catch(e => {
        console.error('Error storing identity locally:', e)
      })
  }

  respondsTo (event) {
    // Check we're root window, otherwise we don't respond.
    if (window.top !== window) return false

    return ('qrscan' in event.data) ||
           ('enroleeinfo' in event.data) ||
           ('enrolldevice' in event.data) ||
           ('finishenrollment' in event.data) ||
           ('checkenrollment' in event.data) ||
           ('newidentity' in event.data)
  }

  process (event) {
    if ('qrscan' in event.data) {
      return this.qrscan(event)
    }

    if ('enroleeinfo' in event.data) {
      return this.enroleeinfo(event)
    }

    if ('enrolldevice' in event.data) {
      return this.enrolldevice(event)
    }

    if ('finishenrollment' in event.data) {
      return this.finishenrollment(event)
    }

    if ('checkenrollment' in event.data) {
      return this.checkenrollment(event)
    }

    if ('newidentity' in event.data) {
      return this.newidentity(event)
    }
  }
}

//
// Normal vault message processing
//
export class VaultMessageHandler {
  init (event) {
    if (inited) return
    vaultInit(event)
  }

  qrscan (event) {
    window.location = 'https://qrscan.io/'
    window.reload()
  }

  secp256k1KeyInfo (event) {
    // this doesn't give hardened keys for now
    // key { derive: 'm/0' }
    var ahdkey = pubex_hdkey.derive(event.data.secp256k1KeyInfo.key.derive)
    var pubkey = secp256k1.publicKeyConvert(ahdkey.publicKey, false)
    // SEC1 form return
    event.source.postMessage({'callback' : event.data.callback, 'result' : { 'pubkey' : pubkey.toString('hex'), 'pubex' : ahdkey.publicExtendedKey }}, event.origin)
  }

  secp256k1Sign (event) {
    // key { derive 'm/0' }

    // we need to grab a private key for this
    getAppPrivEx().then((privex_hdkey) => {
      var from = privex_hdkey.derive(event.data.secp256k1Sign.key.derive)
      var sig = secp256k1.sign(Buffer.from(event.data.secp256k1Sign.hash, 'hex'), from.privateKey)
      event.source.postMessage({'callback' : event.data.callback, 'result' : { signature: sig.signature.toString('hex'), recovery: sig.recovery, hash: event.data.secp256k1Sign.hash } }, event.origin)
    })
  }

  secp256k1Encrypt (event) {
    var ecpub = Buffer.from(event.data.secp256k1Encrypt.pubkey, 'hex');
    var plaintext = Buffer.from(event.data.secp256k1Encrypt.plaintext, 'hex');
    eccrypto.encrypt(ecpub, plaintext)
      .then(function (response) {
        var rep = {
          iv: response.iv.toString('hex'),
          ephemPublicKey: response.ephemPublicKey.toString('hex'),
          ciphertext: response.ciphertext.toString('hex'),
          mac: response.mac.toString('hex')
        }
        event.source.postMessage({'callback' : event.data.callback, 'result' : rep }, event.origin)
      })
  }

  secp256k1Decrypt (event) {
    getAppPrivEx().then(privex_hdkey => {
      var to = privex_hdkey.derive(event.data.secp256k1Decrypt.key.derive)
      var ecpriv = to.privateKey
      var response = {
        iv: Buffer.from(event.data.secp256k1Decrypt.iv, 'hex'),
        ephemPublicKey: Buffer.from(event.data.secp256k1Decrypt.ephemPublicKey, 'hex'),
        ciphertext: Buffer.from(event.data.secp256k1Decrypt.ciphertext, 'hex'),
        mac: Buffer.from(event.data.secp256k1Decrypt.mac, 'hex')
      }

      eccrypto.decrypt(ecpriv, response)
        .then(function(buf) {
          event.source.postMessage({'callback' : event.data.callback, 'result' : buf.toString('hex') }, event.origin);
        })
    })
  }

  respondsTo (event) {
    return ('init' in event.data) ||
           ('qrscan' in event.data) ||
           ('secp256k1KeyInfo' in event.data) ||
           ('secp256k1Sign' in event.data) ||
           ('secp256k1Encrypt' in event.data) ||
           ('secp256k1Decrypt' in event.data)
  }

  process (event) {
    if ('init' in event.data) {
      return this.init(event)
    }

    if ('qrscan' in event.data) {
      return this.qrscan(event)
    }

    if ('secp256k1KeyInfo' in event.data) {
      return this.secp256k1KeyInfo(event)
    }

    if ('secp256k1Sign' in event.data) {
      return this.secp256k1Sign(event)
    }

    if ('secp256k1Encrypt' in event.data) {
      return this.secp256k1Encrypt(event)
    }

    if ('secp256k1Decrypt' in event.data) {
      return this.secp256k1Decrypt(event)
    }
  }
}

