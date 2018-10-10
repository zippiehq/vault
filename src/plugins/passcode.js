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
import eccrypto from 'eccrypto'
import secp256k1 from 'secp256k1'
import shajs from 'sha.js'


/**
 * Vault Passcode Provider Plugin
 *
 * This plugin provides the ability to manage and verify user actions with a
 * passcode, passphrase, or PIN code. The API is only accessible to root
 * vault applications like the Zippie Signup, PIN and Card UXs.
 *
 */
export default class PasscodeProvider {
  /**
   * Request:
   *   passcode: {
   *     assign: {
   *       id: 'smartcard-recovery',
   *       passcode: 'passcode|passphrase|pincode'
   *     }
   *   }
   */
  async assign (req) {
    return await this.withMasterSeed(async function () {
      let params = req.passcode.assign
      let recordhash = shajs('sha256').update('passcodes/' + params.id).digest()

      let recordauth = await (await this.derive(recordhash)).derive('m/0')
      let recordrevoke = await (await this.derive(recordhash)).derive('m/1')

      let recordauthpub = secp256k1.publicKeyConvert(recordauth.publicKey, false)
      let recordrevokepub = secp256k1.publicKeyConvert(recordrevoke.publicKey, false)

      // Encrypt passcode record
      let cipher = await eccrypto.encrypt(
        recordauthpub,
        Buffer.from(JSON.stringify(params), 'utf8')
      )

      // Encode cipher data to hex strings
      Object.keys(cipher).map(k => { cipher[k] = cipher[k].toString('hex') })

      console.info('VAULT: Uploading passcode record to permastore.')
      return await this.fms.store(recordauthpub, recordrevokepub, cipher)
    }.bind(this))
  }

  /**
   * Request:
   *   passcode: {
   *     revoke: {
   *       id: 'smartcard-recovery'
   *     }
   *   }
   */
  async revoke (req) {
    return await this.withMasterSeed(async function () {
      let params = req.passcode.revoke
      let recordhash = shajs('sha256').update('passcodes/' + params.id).digest()
      let recordrevoke = await (await this.derive(recordhash)).derive('m/1')

      console.info('VAULT: Uploading passcode record to permastore.')
      return await this.fms.revoke(recordrevoke.privateKey)
    }.bind(this))
  }

  /**
   * Request:
   *   passcode: {
   *     verify: {
   *       id: 'smartcard-recovery',
   *       salt: 'some salt value',
   *       hash: 'passcode|passphrase|pincode'
   *     }
   *   }
   */
  async verify (req) {
    return await this.withMasterSeed(async function () {
      let params = req.passcode.verify

      let recordhash = shajs('sha256').update('passcodes/' + params.id).digest()
      let recordauth = await (await this.derive(recordhash)).derive('m/0')

      let cipher = await this.fms.fetch(recordauth.privateKey)
      if (!cipher) {
        console.warn('VAULT: Failed to retrieve passcode record.')
        return false
      }

      // Decode cipher data to hex strings
      Object.keys(cipher).map(k => { cipher[k] = Buffer.from(cipher[k], 'hex') })

      // Decrypt passcode record
      let record = await eccrypto.decrypt(recordauth.privateKey, cipher)
      record = JSON.parse(record.toString('utf8'))

      let hash = shajs('sha256').update(params.salt + record.passcode).digest()

      return params.hash === hash.toString('hex')
    }.bind(this))
  }

  /**
   * VaultPlugin Interface
   */
  install (vault) {
    vault.addReceiver(this)
  }

  /**
   * MessageReceiver Interface
   */
  dispatchTo (mode, req) {
    if (mode !== 'root' || !('passcode' in req)) return

    if ('assign' in req.passcode) return this.assign
    if ('revoke' in req.passcode) return this.revoke
    if ('verify' in req.passcode) return this.verify

    return null
  }
}
