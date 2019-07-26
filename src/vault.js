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
 *
 */
import VERSION from '../version.js'

import FMS from './apis/fms.js'
import Permastore from './apis/permastore.js'
import Mailbox from './apis/mailbox.js'

import { Logger } from './logger'
import { MessageDispatcher } from './dispatch'

import shajs from 'sha.js'
import Crypto from 'crypto'
import secp256k1 from 'secp256k1'
import eccrypto from 'eccrypto'

import HDKey from 'hdkey'
import secrets from 'secrets.js-grempe'

import { hashToParams, detectDeviceName } from './utils'

// vault database contains:
// cache of app hash -> app-pubex
// device local private key
// device authentication private key
// seed piece 1 out of 2 (2of2) encrypted with device local private key
// forgetme server url if non-standard

//TODO:
//  - Local caching of pubex's

/**
 * Zippie Vault
 *
 *   The Zippie Vault stores and manages a users' digital identity and access to
 * it by 3rd party applications. A users' digital identity from the vaults
 * perspective is a master seed, which is used to derive a tree of encryption
 * and message signing keys for various purposes. As well as what devices are
 * allowed to have access to this master seed by the user to perform
 * authenticated operations.
 *
 *   Each of a users' device has two keys, an authentication key and a local
 * device key. The users' master seed is split into two slices, one of which is
 * stored remotely on a server but encrypted against the devices' local key.
 * The other slice is stored locally, and encrypted against the same device key.
 *
 *   When the vault is required to do an operation that requires the master seed
 * usually for private key deriviation for a cryptographic operation, like
 * ethereum transaction signing. The encrypted remote slice is retrieved from
 * the server, decrypted and combined with the local slice, it is then used and
 * dereferenced as soon as the operation is complete in order to reduce the time
 * that the master seed is stored in memory in it's unencrypted form.
 *
 */
export default class Vault {
  /**
   * Constructor
   */
  constructor (config) {
    // Local storage and configuration
    this._config = config
    this.store = window.localStorage

    // Create logger
    this.logger = new Logger('VAULT')
    // Create event dispatcher
    this.dispatcher = new MessageDispatcher(this, this.logger)

    // Install base message processors.
    this.dispatcher.addReceiver(this)

    // Vault plugins
    this._plugins = []

    // Vault execution mode (host|enclave)
    this.mode = undefined
    this.params = {}

    // Memcache for user application pubex cookies
    this._pubex = {}

    // Flag indicating whether user has a vault identity.
    this._isConfigured = false
    this._isSetup = null

    //   By using the masterseed transaction methods, we can ensure that any
    // nested uses of masterseed are handled correctly and only require a
    // single FMS request.
    this.__protected_masterseed = null
    this.__protected_masterseed_refs = 0

    // Import vault plugins
    this.install([
      new (require('./plugins/itp_support.js')).default(),
      new (require('./plugins/cookie_vault_injector.js')).default(),
      new (require('./plugins/root_mode.js')).default(),
      new (require('./plugins/user_mode.js')).default(),
      new (require('./plugins/secp256k1.js')).default(),
      new (require('./plugins/devices.js')).default(),
      new (require('./plugins/userdata.js')).default(),
      new (require('./plugins/passcode.js')).default(),
      new (require('./plugins/recovery.js')).default(),
      new (require('./plugins/misc.js')).default(),
      new (require('./plugins/ipc_router.js')).default(),
    ])
  }

  /**
   * Merge config data with that stored in localstorage and return.
   * XXX - Should probably cache it in memory on load.
   */
  get config () {
    let result = JSON.parse(JSON.stringify(this._config))
    for (let i = 0; i < localStorage.length; i++) {
      let key = localStorage.key(i)
      if (!key.startsWith('config.')) continue

      let parts = key.split('.').slice(1)
      let parent = result
      for (let i = 0; i < parts.length - 1; i++) {
        parent = parent[parts[i]]
      }
      parent[parts[parts.length-1]] = localStorage.getItem(key)
    }
    return result
  }

  /**
   * Install vault plugin/s
   */
  install (param) {
    if (param.constructor === Array) {
      this._plugins = this._plugins.concat(param)
      return
    }

    this._plugins.push(param)
    return
  }

  /**
   * Run through all registered plugins and execute a hook function if defined.
   */
  async plugin_exec(hook, params) {
    for (let i = 0; i < this._plugins.length; i++) {
      let plugin = this._plugins[i]
      if (typeof plugin[hook] === 'function') {
        await plugin[hook].apply(plugin, [].slice.call(arguments, 1))
      }
    }
  }

  /**
   * Configure vault and registered plugins
   */
  async configure () {
    console.info('VAULT: Configuring...')
    // Setup remote service APIs
    this.fms = new FMS(this.config.apis.fms)
    this.permastore = new Permastore(this.config.apis.permastore)
    this.mailbox = new Mailbox(this.config.apis.mailbox)

    // Check to see if we're running in root mode.
    if (window.top === window.self) {
      console.info('VAULT: Running in root mode.')
      this.mode = 'root'

    // Otherwise we're running in enclave mode.
    } else {
      console.info('VAULT: Running in enclave mode.')
      this.mode = 'enclave'
    }

    // Parse vault query parameters
    this.params = hashToParams(window.location)
    console.info('VAULT: Parsed vault parameters:', this.params)

    // Iterate vault plugins install phase.
    await this.plugin_exec('install', this)

    // Start listening for incoming message events
    self.addEventListener('message', ev => this.dispatcher.dispatch(ev))

    // Iterate vault plugins configure phase.
    await this.plugin_exec('configure')
    this._isConfigured = true
  }

  /**
   * Startup Zippie Vault
   */
  async startup () {
    if (!this._isConfigured) await this.configure()

    console.info('VAULT: Starting up...')

    // Iterate vault plugins startup phase and collect promises.
    let promises = []
    await this.plugin_exec('startup', promises)

    //   Wait for plugins that registered a future to complete before sending
    // ready message.
    Promise.all(promises)
      .then(async function() {
        if (this.mode !== 'enclave') return
        console.info('VAULT: Posting ready and waiting.')
        parent.postMessage({ready: await this.isSetup()}, '*')
      }.bind(this))
      .catch(e => {
        if (this.mode !== 'enclave') return
        console.warn('VAULT: Posting not-ready condition:', e)
        parent.postMessage(e, '*')
      })
  }

  /**
   * Launch a root or user application with options either in an iframe (for root)
   * level applications like signup, smartcard and pin apps. Or generate auth
   * token and pass them to user application for automatic signin.
   */
  async launch (uri, opts) {
    opts = opts || {}

    // Decompose URI for parameter injection
    let host = uri.split('#')[0]
    let hash = uri.split('#')[1]
    hash = (hash || '').split('?')[0]

    // Collect hash parameters into params object.
    let params = hashToParams(uri)

    // If we want to launch user app, we need to get pubex before we serialize
    // below parameters, so we can pass the cookie through to the dapp.
    if (!opts.root) {
      await this.plugin_exec('prelaunch', uri, opts)
    }

    // Inject specified parameters from provided opts into target params
    if (opts.params) params = Object.assign(params, opts.params)

    // Recombine params into paramstr for URI building
    let paramstr = ''
    Object.keys(params).forEach(k => {
      paramstr += (paramstr.length > 0 ? ';' : '') + k + '=' + params[k]
    })

    // Reconstitute full application URI
    hash = hash + (paramstr.length > 0 ? '?' + paramstr : '')
    uri = host + (hash.length > 0 ? '#' + hash : '')

    // Check to see if we're opening a root app.
    // XXX - Need to check, currently we can run multiple simultaneously!
    if (opts.root) {
      console.info('VAULT: Loading vault application:', uri)

      let iframe = document.createElement('iframe')
      iframe.style.cssText = 'border: none; position: absolute; width: 100%; height: 100%'

      iframe.src = uri

      document.body.innerHTML = ''
      document.body.appendChild(iframe)

      // For root apps, it's helpful to listen for a "finished" signal, so we
      // can use promises for handling things like, what to do after a new user
      // signs up
      return new Promise(function (resolve) {
        window.addEventListener('message', function (event) {
          if (event.source !== iframe.contentWindow) return
          if ('finished' in event.data) resolve(event.data.finished)
        })
      })

    // Otherwise we're loading a user app, and need to generate app cookie.
    } else {
      console.info('VAULT: Booting client application:', uri)
      window.location = uri
    }
  }

  /**
   * Check local store to see if vault is properly setup.
   */
  async isSetup () {
    if (!this._isSetup) {
      this._isSetup = (await this.store.getItem('isSetup')) ? true : false
      this._isSetup = this._isSetup || (await this.store.getItem('vaultSetup')) ? true : false
    }

    return this._isSetup
  }

  /**
   * Pull remote slice and combine with local slice to generate masterseed.
   */
  async __getMasterSeed () {
    if (!await this.isSetup()) {
      console.log('VAULT: Vault has no identity!')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    // Authkey used to index remote slice from FMS
    let authkey = this.store.getItem('authkey')
    if (!authkey) {
      console.error('VAULT: Failed to retrieve authkey from store.')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    // Translate hex encoded key to Buffer instance.
    //XXX: Fix in identity migration code.
    if (authkey[0] === '"') authkey = JSON.parse(authkey)
    authkey = Buffer.from(authkey, 'hex')

    // Retrieve encrypted remote slice from FMS
    let rcipher
    try {
      rcipher = await this.fms.fetch(authkey)
      if (!rcipher) {
        console.error('VAULT: Failed to retrieve remote slice')
        // XXX: Need a better way of invalidating after revokation.
        this.store.clear()
        return Promise.reject('VAULT_REMOTE_IDENTITY_ERROR')
      }
    } catch (e) {
      return Promise.reject('VAULT_FMS_OFFLINE')
    }

    // Retrieve localkey from store for decrypting remote slice from FMS
    let localkey = this.store.getItem('localkey')
    if (!localkey) {
      console.error('VAULT: Failed to retrieve localkey from store')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    // Translate hex encoded key to Buffer instance.
    //XXX: Fix in identity migration code.
    if (localkey[0] === '"') localkey = JSON.parse(localkey)
    localkey = Buffer.from(localkey, 'hex')

    // Translate hex encoded values to Buffer instances.
    Object.keys(rcipher)
      .map(k => { rcipher[k] = Buffer.from(rcipher[k], 'hex') })

    // Decrypt remote slice with localkey.
    let rslice_enc = await eccrypto.decrypt(localkey, rcipher)
    let rslice = rslice_enc.toString('utf8')

    // Retrieve encrypted localslice from store.
    let lcipher = await this.store.getItem('localslice_e')
    if (!lcipher) {
      console.error('VAULT: Failed to retrieve localslice from store')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    //XXX: Fix in identity migration code.
    if (lcipher[0] === '"') lcipher = JSON.parse(lcipher)

    try {
      lcipher = JSON.parse(lcipher)
    } catch (e) {
      console.error('VAULT: Failed to parse localslice JSON:', e)
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    // Translate hex encoded values to Buffer instances.
    Object.keys(lcipher)
      .map(k => { lcipher[k] = Buffer.from(lcipher[k], 'hex') })

    // Decrypt local slice with localkey.
    let lslice_enc = await eccrypto.decrypt(localkey, lcipher)
    let lslice = lslice_enc.toString('utf8')

    // Combine local and remote slices and return masterseed.
    return Buffer.from(secrets.combine([lslice, rslice]), 'hex')
  }

  /**
   * Used to reference count and combine nested requests for the master seed
   * into a single GET request.
   */
  async withMasterSeed (callback) {
    if(!this.__protected_masterseed) {
      console.info('VAULT: Generating local masterseed reference.')
      this.__protected_masterseed = await this.__getMasterSeed()
    }

    this.__protected_masterseed_refs++
    let result = await callback(this.__protected_masterseed)
    this.__protected_masterseed_refs--

    console.info('VAULT: Local masterseed refcount = ' +
      this.__protected_masterseed_refs)

    if (this.__protected_masterseed_refs === 0) {
      console.info('VAULT: Destroying local masterseed reference.')
      this.__protected_masterseed = null
    }

    return result
  }

  /**
   * Derive a hardened extended key from masterseed and provided hash.
   *
   * An app-pubex is calculated by taking private extended key of root + some
   * derivation, always hardened + [for every 32 bit of the 256-bit hash, take
   * the hardended child of index (value integer divided with 2^31) and then the
   * hardened child of index (value integer mod 2^31)
   *
   */
  async derive (hash, seed) {
    if (!seed && !await this.isSetup()) {
      console.info('VAULT: Vault has no identity!')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    function op (seed) {
      let hdkey = HDKey.fromMasterSeed(seed)

      for (let i = 0; i < 32; i += 4) {
        let v = hash.readUInt32LE(i)
        let u = Math.trunc(v / HDKey.HARDENED_OFFSET)
        let l = v - Math.trunc(v / HDKey.HARDENED_OFFSET) * HDKey.HARDENED_OFFSET
        hdkey = hdkey.deriveChild(u + HDKey.HARDENED_OFFSET)
        hdkey = hdkey.deriveChild(l + HDKey.HARDENED_OFFSET)
      }

      return hdkey
    }

    if (!seed) {
      return await this.withMasterSeed(seed => { return op(seed) })
    }

    return op(seed)
  }

  /**
   * Attempt to retrieve public extended key from memcache, local storage or
   * generate.
   */
  async pubex (key) {
    if (!await this.isSetup()) {
      console.info('VAULT: Vault has no identity!')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    let hash = (typeof key === 'string') ? shajs('sha256').update(key).digest() : key

    let pubex_hd = HDKey.fromExtendedKey((await this.derive(hash)).publicExtendedKey)
    return pubex_hd
  }

  /**
   * Derive private extended key
   */
  async privex (key) {
    if (!await this.isSetup()) {
      console.info('VAULT: Vault has no identity!')
      return Promise.reject('VAULT_LOCAL_IDENTITY_ERROR')
    }

    let hash = (typeof key === 'string') ? shajs('sha256').update(key).digest() : key

    let privex = HDKey.fromExtendedKey((await this.derive(hash)).privateExtendedKey)
    return privex
  }

  /**
   * Creates new vault identity.
   */
  // TODO: Move to devices plugin.
  async newidentity (ev) {
    console.info('VAULT: Creating new identity.')
    return await this.initidentity(Crypto.randomBytes(32), ev.data.newidentity)
  }
  
  /**
   * Creates vault identity data using provided masterseed.
   */
  async initidentity (masterseed, params) {
    params = params || {}

    console.info('VAULT: Initializing local device.')

    console.info('VAULT: Generating identity keys.')
    // Generate device local key
    let localkey = Crypto.randomBytes(32)
    let localpub = secp256k1.publicKeyCreate(localkey, false)

    // Generate device auth key for retrieving remote slice of masterseed
    let authkey = Crypto.randomBytes(32)
    let authpub = secp256k1.publicKeyCreate(authkey, false)

    // Generate predeterminate device revokation key
    let revokehash = shajs('sha256')
      .update('devices/' + localpub.toString('hex'))
      .digest()

    let revokekey = await (await this.derive(revokehash, masterseed)).derive("m/0")
    let revokepub = secp256k1.publicKeyConvert(
      revokekey.publicKey,
      false
    )

    console.info('VAULT: Splitting identity into local and remote components.')
    let parts = secrets.share(masterseed.toString('hex'), 2, 2)

    console.info('VAULT: Encrypting identity parts.')
    //XXX: Should both parts really be encrypted with the same key?
    let cipher1 = await eccrypto.encrypt(localpub, Buffer.from(parts[0], 'utf8'))
    let cipher2 = await eccrypto.encrypt(localpub, Buffer.from(parts[1], 'utf8'))

    // Convert eccrypto output buffers to hex encoded strings.
    Object.keys(cipher1).map(k => { cipher1[k] = cipher1[k].toString('hex')})
    Object.keys(cipher2).map(k => { cipher2[k] = cipher2[k].toString('hex')})

    console.info('VAULT: Sending remote identity part to FMS.')
    if (!await this.fms.store(authpub, revokepub, cipher2)) {
      console.error('VAULT: Store of identity part in FMS failed.')
      return false
    }

    console.info('VAULT: Storing local identity keys and data into.')
    this.store.setItem('authkey', authkey.toString('hex'))
    this.store.setItem('localkey', localkey.toString('hex'))
    this.store.setItem('localslice_e', JSON.stringify(cipher1))
    this.store.setItem('isSetup', true)

    // Auto-Generate device name/label
    let deviceName = detectDeviceName() || localpub.toString('hex').slice(-8)

    console.info('VAULT: Creating enrollment registry')
    await this.enroll('device', deviceName, localpub.toString('hex'), { userAgent: navigator.userAgent })

    let passport = {}

    if ('recover' in this.params) {
      console.info('VAULT: Attempting to get identity passport userdata.')
      try {
        passport = await this.userdata.get.bind(this)({data: {userdata: { get: {key: 'passport'}}}})
      } catch (e) {
        console.warn('VAULT: Failed to get passport userdata.')
      }
    }

    // XXX Still need a better, more robust way to do this.
    console.info('VAULT: Processing user parameters:', params)
    if (params['name']) passport.fullname = params['name']
    if (params['email']) passport.email = params['email']
    if (params['lang']) passport.language = params['lang']
    if (params['phone']) passport.phone = params['phone']

    console.info('VAULT: Uploading user passport data.')
    await this.userdata.set.bind(this)({data: {userdata: { set: {key: 'passport', value: passport}}}})

    console.info('VAULT: New identity created successfully!')
    this._isSetup = true
    return this._isSetup
  }

  /**
   * Registers a card or device to the users identity.
   */
  //XXX: Reimplement as a CRDT TwoPhaseSet
  async enroll (type, name, deviceKey, props) {
    let registryhash = shajs('sha256').update('devices').digest()
    let registryauth = await this.derive(registryhash)
    let registryauthpub = secp256k1.publicKeyConvert(registryauth.publicKey, false)

    let createdAt = Date.now()

    // Retrieve enrollment registry
    let enrollments = await this.enrollments()

    // Add new device to registry
    enrollments.push(
        Object.assign({
          type, name, deviceKey, createdAt
        }, props)
    )

    // Remove potential duplicates
    let keys = enrollments.map(i => i.deviceKey)
    enrollments = enrollments.filter((i, p) => {
      return keys.indexOf(i.deviceKey) === p
    })

    // Encrypt latest enrollments data
    let cipher = await eccrypto.encrypt(
      registryauthpub,
      Buffer.from(JSON.stringify(enrollments), 'utf8')
    )

    // Encode cipher data to hex strings
    Object.keys(cipher).map(k => {cipher[k] = cipher[k].toString('hex')})

    console.info('VAULT: Uploading identity enrollment registry to permastore.')
    return await this.permastore.store(registryauth.privateKey, cipher)
  }

  /**
   * Deregisters and revokes a card or device from a users identity.
   * @param {object} req - Revocation Request
   *    `{ revoke: { deviceKey: 'DEVICE_KEY' } }`
   */
  //XXX: Reimplement as a CRDT TwoPhaseSet
  async revoke (ev) {
    let req = ev.data
    let params = req.revoke

    // Retrieve enrollment registry
    let enrollments = await this.enrollments()

    let device = enrollments.filter(v => v.deviceKey === params.deviceKey)[0]
    if (!device) return Promise.reject('Unable to find device in enrollments.')

    // Derive revoke credentials for FMS device data.
    let revokekey = 'devices/' + params.deviceKey

    //   If enrollment is a recovery URI, we use a different revocation
    // key derivation method.
    if (device.type === 'uri') revokekey = 'recovery/' + device.name

    // Derive FMS revocation key
    let revokehash = shajs('sha256').update(revokekey).digest();
    let revokeauth = await (await this.derive(revokehash)).derive("m/0")

    // Revoke FMS device recovery/signin information.
    await this.fms.revoke(revokeauth.privateKey)

    // Derive access credentials for permastore device registry.
    let registryhash = shajs('sha256').update('devices').digest()
    let registryauth = await this.derive(registryhash)
    let registryauthpub = secp256k1.publicKeyConvert(registryauth.publicKey, false)

    // Remove requested device enrollment and any duplicates.
    let keys = enrollments.map(i => i.deviceKey)
    enrollments = enrollments.filter((i, p) => {
      return i.deviceKey !== params.deviceKey && keys.indexOf(i.deviceKey) === p
    })

    // Encrypt latest enrollments data
    let cipher = await eccrypto.encrypt(
      registryauthpub,
      Buffer.from(JSON.stringify(enrollments), 'utf8')
    )

    // Encode cipher data to hex strings
    Object.keys(cipher).map(k => {cipher[k] = cipher[k].toString('hex')})

    console.info('VAULT: Uploading identity enrollment registry to permastore.')
    return await this.permastore.store(registryauth.privateKey, cipher)    
  }

  /**
   * Return vault version information.
   */
  async getVersion (req) {
    return VERSION
  }

  /**
   * Return vault configuration information
   */
  async getConfig (req) {
    return this.config
  }

  /**
   * 
   */
  async setConfig (ev) {
    let req = ev.data.setConfig

    let parts = req.key.split('.')
    let parent = this._config
    for (var i = 0; i < parts.length - 1; i++) {
      parent = parent[parts[i]]
    }
    parent[parts[parts.length-1]] = req.value

    this.store.setItem('config.' + req.key, req.value)
    return true
  }

  async getDeviceInfo (ev) {
    let digest = shajs('sha256').update(ev.origin)
    let localkey = this.store.getItem('localkey')

    if (localkey[0] === '"') localkey = JSON.parse(localkey)
    localkey = Buffer.from(localkey, 'hex')

    return {
      deviceId: digest
          .update(secp256k1.publicKeyCreate(localkey, false))
          .digest().toString('hex')
    }
  }

  /**
   *
   */
  async reboot (req) {
    window.location.reload()
  }

  /**
   *
   */
  async isSignedInReq (req) {
    return await this.isSetup()
  }

  /**
   * Signin application to Zippie Vault
   */
  async signin (req) {
    return new Promise(function (resolve, reject) {
      this.plugin_exec('signin', req.origin, this.params.magiccookie, resolve, reject)
    }.bind(this))
  }

  /**
   * Return a list of enrolled smartcards and devices registered to users identity.
   */
  //XXX: Reimplement as a CRDT TwoPhaseSet
  async enrollments () {
    let registryhash = shajs('sha256').update('devices').digest()
    let registryauth = await this.derive(registryhash)
    let registryauthpub = secp256k1.publicKeyConvert(registryauth.publicKey, false)

    let result = await this.permastore.fetch(registryauthpub.toString('hex'))
    try {
      if (!result) return []

      // Convert cipher object from hex encoded to buffers for eccrypto
      result = JSON.parse(Buffer.from(result.data, 'hex').toString('utf8'))
      Object.keys(result).map(k => {result[k] = Buffer.from(result[k], 'hex')})

      // Decrypt data
      result = await eccrypto.decrypt(registryauth.privateKey, result)
      result = JSON.parse(result.toString('utf8'))
      return result
    } catch (e) {
      console.error('VAULT: Failed to process permastore response:', e)
      return []
    }

    return []
  }

  async setEnrollmentProperty (ev) {
    let req = ev.data.setEnrollmentProperty
    let prop = req.key

    let registryhash = shajs('sha256').update('devices').digest()
    let registryauth = await this.derive(registryhash)
    let registryauthpub = secp256k1.publicKeyConvert(registryauth.publicKey, false)

    // Retrieve enrollment registry
    let enrollments = await this.enrollments()

    let device = enrollments.filter(v => v.deviceKey === req.deviceKey)[0]
    if (!device) return Promise.reject('Unable to find device in enrollments.')

    // Remove potential duplicates
    let keys = enrollments.map(i => i.deviceKey)
    enrollments = enrollments.filter((i, p) => {
      return keys.indexOf(i.deviceKey) === p
    })

    enrollments = enrollments.map(i => {
      if (i.deviceKey === req.deviceKey) i[prop] = req.value
      return i
    })

    // Encrypt latest enrollments data
    let cipher = await eccrypto.encrypt(
      registryauthpub,
      Buffer.from(JSON.stringify(enrollments), 'utf8')
    )

    // Encode cipher data to hex strings
    Object.keys(cipher).map(k => {cipher[k] = cipher[k].toString('hex')})

    console.info('VAULT: Uploading identity enrollment registry to permastore.')
    return await this.permastore.store(registryauth.privateKey, cipher)
  }

  async setDeviceName (ev) {
    return this.setEnrollmentProperty({
      callback: ev.data.callback,
      data: {
        setEnrollmentProperty: {
          deviceKey: ev.data.setDeviceName.deviceKey,
          key: 'name',
          value: ev.data.setDeviceName.name
        }
      }
    })
  }

  async enrollmentsReq () {
    let result = await this.enrollments ()

    // Filter enrollments output.
    let localkey = this.store.getItem('localkey')

    // Translate hex encoded key to Buffer instance.
    //XXX: Fix in identity migration code.
    if (localkey[0] === '"') localkey = JSON.parse(localkey)
    localkey = Buffer.from(localkey, 'hex')

    let localpub = secp256k1.publicKeyCreate(localkey, false).toString('hex')

    let filtered = []
    for (let i = 0; i < result.length; i++) {
      let item = result[i]

      item.isLocal = item.deviceKey === localpub

      filtered.push(item)
    }

    return filtered
  }

  /**
   * MessageReceiver Interface
   */
  dispatchTo (context, event) {
    let req = event.data

    if (typeof req !== 'object') {
      console.warn('Unrecognised message format:', req)
      return
    }

    if (context.mode === 'root') { // ROOT-MODE ONLY RECEIVERS
      if ('launch' in req) return (function (req) { this.launch(req.launch.url, req.launch.opts) })
      if ('newidentity' in req) return this.newidentity
    }

    if ('version' in req) return this.getVersion
    if ('config' in req) return this.getConfig
    if ('setConfig' in req) return this.setConfig

    if ('getDeviceInfo' in req) return this.getDeviceInfo

    if ('reboot' in req) return this.reboot

    if ('isSignedIn' in req) return this.isSignedInReq

    if ('signin' in req) return this.signin

    if ('enrollments' in req) return this.enrollmentsReq
    if ('setEnrollmentProperty' in req) return this.setEnrollmentProperty

    if ('setDeviceName' in req) return this.setDeviceName

    // FIXME FIXME FIXME
    if ('revoke' in req) return this.revoke
  }

  /**
   * MessageDispatch Interface
   */
  addReceiver (receiver) {
    if (receiver.constructor === Array) {
      for (let i = 0; i < receiver.length; i++) {
        this.dispatcher.addReceiver(receiver[i])
      }
      return
    }

    if (typeof receiver.dispatchTo === 'function') {
      this.dispatcher.addReceiver(receiver)
      return
    }

    throw 'Invalid argument, expecting Array or MessageDispatch interface.'
  }
}

