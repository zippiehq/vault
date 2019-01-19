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
import Crypto from 'crypto'
import shajs from 'sha.js'
import secp256k1 from 'secp256k1'
import eccrypto from 'eccrypto'

/**
 * Vault Recovery Actions Provider Plugin
 */
export default class {
  /**
   * Initialize plugin with vault instance.
   */
  install (vault) {
    this.vault = vault
    vault.addReceiver(this)
  }

  /**
   * Request:
   *   recovery: {
   *     create: {
   *        id: RECOVERY_ID,
   *       key: ENCKEY_AS_HEX
   *     }
   *   }
   */
  async create (event) {
    let req = event.data
    return await this.withMasterSeed(async function (masterseed) {
      let params = req.recovery.create

      let enckey = Buffer.from(params.key, 'hex').slice(0, 32)
      let encpub = secp256k1.publicKeyCreate(enckey, false)

      let authkey = Crypto.randomBytes(32)
      let authpub = secp256k1.publicKeyCreate(authkey, false)

      let revokehash = shajs('sha256').update('recovery/' + params.id).digest()
      let revokekey = await (await this.derive(revokehash)).derive('m/0')
      let revokepub = secp256k1.publicKeyConvert(revokekey.publicKey, false)

      // Encrypt masterseed against recovery generation key.
      let cipher = await eccrypto.encrypt(encpub, masterseed)

      // Encode cipher data buffers to hex strings.
      Object.keys(cipher).map(k => { cipher[k] = cipher[k].toString('hex') })

      console.info('VAULT: Uploading recovery data.')
      await this.fms.store(authpub, revokepub, cipher)

      return { authkey: authkey.toString('hex') }
    }.bind(this))
  }

  /**
   * Request:
   *   recovery: {
   *     restore: {
   *       key: RECOVERY_DATA_ENCKEY,
   *       recovery: RECOVERY_DATA_CIPHERTEXT
   *     }
   *   }
   */
  async restore (event) {
    let req = event.data
    let params = req.recovery.restore

    let enckey = Buffer.from(params.key, 'hex').slice(0, 32)
    let cipher = params.recovery
    Object.keys(cipher).map(k => { cipher[k] = Buffer.from(cipher[k], 'hex') })

    let masterseed = await eccrypto.decrypt(enckey, cipher)
    console.log(masterseed)

    return this.initidentity(masterseed)
      .then(function () {
        return this.launch(this.config.apps.user.home)
      }.bind(this))
  }

  /**
   * MessageDispatcher Interface
   */
  dispatchTo (context, event) {
    let req = event.data
    if (context.mode !== 'root' || !('recovery' in req)) return null

    if ('import' in req.recovery) return this.import
    if ('create' in req.recovery) return this.create
    if ('restore' in req.recovery) return this.restore

    return null
  }
}
