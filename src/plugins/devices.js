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
import crypto from 'crypto'
import eccrypto from 'eccrypto'
import secp256k1 from 'secp256k1'
import secrets from 'secrets.js-grempe'
import shajs from 'sha.js'

/**
 * Multi-Device and Zippie Card Provider Plugin
 */
export default class {
  /**
   *
   */
  install (vault) {
    this.vault = vault
    vault.addReceiver(this)
  }

  /**
   *
   */
  async cardinfo (req) {
    let info = null
    let enrollments = await this.enrollments()

    for (let i = 0; i < enrollments.length; i++) {
      let r = enrollments[i]
      if (r.deviceKey === req.cardinfo.deviceKey) {
        info = r
        break
      }
    }

    return info
  }

  /**
   *
   */
  async enrollcard (req) {
    return await this.withMasterSeed(async function (masterseed) {
      let params = req.enrollcard

      // Decode recoveryKey parameter
      let recoverypub = secp256k1.publicKeyConvert(
        Buffer.from(params.recoveryKey, 'hex'),
        false
      )

      // Decode signingKey parameter
      let signingpub = secp256k1.publicKeyConvert(
        Buffer.from(params.signingKey, 'hex'),
        false
      )

      // Generate card recovery data revoke key
      console.info('VAULT: Deriving card revokation key.')
      let revokehash = shajs('sha256')
        .update('devices/' + recoverypub.toString('hex')).digest()

      let revokepub = secp256k1.publicKeyConvert(
        await (await this.derive(revokehash)).derive('m/0').publicKey,
        false
      )

      // Build card recovery data
      console.info('VAULT: Generate card recovery data.')
      let secret = shajs('sha256').update(params.passcode).digest()
      let maxtries = new Buffer(2)
      maxtries.writeUInt16BE(3)

      console.info('VAULT: Encrypting card recovery data.')
      let recovery = await eccrypto.encrypt(
        recoverypub,
        Buffer.concat([
          secret,
          maxtries,
          masterseed
        ])
      )

      // Convert buffers to hex.
      Object.keys(recovery).map(k => { recovery[k] = recovery[k].toString('hex')})

      console.info('VAULT: Attempting to store card recovery data to FMS')
      // Upload recovery data to FMS
      if (!await this.fms.store(signingpub, revokepub, recovery)) {
        console.error('VAULT: Failed to store card recovery data in FMS!')
        return false
      }
      console.info('VAULT: Recovery data upload success.')

      // Update device enrollments registry
      await this.enroll(
        'card',
        recoverypub.toString('hex').slice(-8),
        recoverypub.toString('hex'),
        signingpub.toString('hex')
      )

      return true
    }.bind(this))
  }

  /**
   *
   */
  async enroleeinfo (req) {
    // Generate local device and auth keys.
    let localkey = crypto.randomBytes(32)
    let localpub = secp256k1.publicKeyCreate(localkey, false)

    let authkey = crypto.randomBytes(32)
    let authpub = secp256k1.publicKeyCreate(authkey, false)

    // Store local device and auth keys in localstorage.
    //XXX: Move to session storage, until we're properly enrolled?
    this.store.setItem('localkey', localkey.toString('hex'))
    this.store.setItem('authkey', authkey.toString('hex'))

    //XXX: Should we sign a message to prove we are the key owner?
    return {
      localpubkey: localpub.toString('hex'),
      authpubkey: authpub.toString('hex')
    }
  }

  /**
   *
   */
  async enrolldevice (req) {
    let params = req.enrolldevice

    let devpub = Buffer.from(params.devicepubkey, 'hex')
    let devauthpub = Buffer.from(params.authpubkey, 'hex')

    let devhash = shajs('sha256').update('devices/' + devpub).digest()

    return await this.withMasterSeed(async function (masterseed) {
      // Generate device revokation key
      let revokekey = await (await this.derive(devhash)).derive('m/0')
      let revokepub = secp256k1.publicKeyConvert(revokekey.publicKey, false)

      // Split masterseed into device and remote components.
      let shares = secrets.share(masterseed.toString('hex'), 2, 2)
      let lcipher = await eccrypto.encrypt(devpub, Buffer.from(shares[0], 'utf8'))
      let rcipher = await eccrypto.encrypt(devpub, Buffer.from(shares[1], 'utf8'))

      // Convert ciphertext objects from buffers to hex strings.
      Object.keys(lcipher).map(k => {lcipher[k] = lcipher[k].toString('hex')})
      Object.keys(rcipher).map(k => {rcipher[k] = rcipher[k].toString('hex')})

      // Upload recovery data to FMS
      if (!await this.fms.store(devauthpub, revokepub, rcipher)) {
        console.error('VAULT: Failed to store device remote slice in FMS!')
        return false
      }

      return lcipher
    }.bind(this))
  }

  /**
   *
   */
  async finishenrollment (req) {
    let params = req.finishenrollment

    this.store.setItem('localslice_e',  JSON.stringify(params))
    this.store.setItem('isSetup', true)

    let localkey = Buffer.from(this.store.getItem('localkey'), 'hex')
    let localpub = secp256k1.publicKeyCreate(localkey, false)

    await this.enroll(
      'device',
      localpub.toString('hex').slice(-8),
      localpub.toString('hex')
    )

    return this.launch(this.config.apps.user.home)
  }

  /**
   * MessageReceiver Interface
   */
  dispatchTo (mode, req) {
    if ('cardinfo' in req) return this.cardinfo

    if (mode === 'root') { // ROOT-MODE ONLY RECEIVERS
      if ('enrollcard' in req) return this.enrollcard
      else if ('revokecard' in req) return this.revokecard
      else if ('enroleeinfo' in req) return this.enroleeinfo
      else if ('enrolldevice' in req) return this.enrolldevice
      else if ('revokedevice' in req) return this.revokedevice
      else if ('finishenrollment' in req) return this.finishenrollment
    } 
  }
}
