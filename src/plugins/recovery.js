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
 * Vault Miscellaneous Actions Provider Plugin
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
   *       key: ENCKEY_AS_HEX
   *     }
   *   }
   */
  async create (req) {
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
   * MessageDispatcher Interface
   */
  dispatchTo (mode, req) {
    if (mode !== 'root' || !('recovery' in req)) return

    if ('create' in req.recovery) return this.create

    return null
  }
}
