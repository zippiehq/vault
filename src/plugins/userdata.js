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
import shajs from 'sha.js'
import secp256k1 from 'secp256k1'
import eccrypto from 'eccrypto'

/**
 * Remote Storage Plugin for User Data
 *
 * Currently uses FMS, authkey and revokekey generated from the hash of a
 * provided freeform "key". Serialises and deserialises JSON.
 *
 */
export default class {
  /**
   *
   */
  install (vault) {
    this.vault = vault
    this.vault.userdata = this
    vault.addReceiver(this)
  }

  /**
   *
   */
  async set (req) {
    req = req.userdata.set
    const keyhash = shajs('sha256').update(req.key).digest()
    const masterkey = await this.derive(keyhash)

    const authkey = await masterkey.derive('m/0')
    const revokekey = await masterkey.derive('m/1')

    const authpub = secp256k1.publicKeyConvert(authkey.publicKey, false)
    const revokepub = secp256k1.publicKeyConvert(revokekey.publicKey, false)

    let cipher = await eccrypto.encrypt(
      authpub,
      Buffer.from(JSON.stringify({value: req.value, version: 1}), 'utf8')
    )
    console.info(cipher)

    Object.keys(cipher).map(k => { cipher[k] = cipher[k].toString('hex') })

    console.info('VAULT: Uploading user data (' + req.key + ') to FMS.')
    return await this.fms.store(authpub, revokepub, cipher)
  }

  /**
   *
   */
  async get (req) {
    req = req.userdata.get
    const keyhash = shajs('sha256').update(req.key).digest()
    const masterkey = await this.derive(keyhash)

    const authkey = await masterkey.derive('m/0')
    const authpub = secp256k1.publicKeyConvert(authkey.publicKey, false)

    let cipher = await this.fms.fetch(authkey.privateKey)
    console.log(cipher)
    if (!cipher) {
      console.warn('VAULT: Failed to retrieve user data:', req.key)
      return null
    }

    Object.keys(cipher).map(k => { cipher[k] = Buffer.from(cipher[k], 'hex') })

    const plain = JSON.parse(await eccrypto.decrypt(authkey.privateKey, cipher))
    console.info('VAULT: Read user data', req.key, 'with version:', plain.version)

    return plain.value
  }

  /**
   *
   */
  async clear (req) {
    const keyhash = shajs('sha256').update(req.key).digest()
    const masterkey = await this.derive(keyhash)
    const revokekey = await masterkey.derive('m/1')

    return await this.fms.revoke(revokekey.privateKey)
  }

  /**
   * MessageReceiver Interface
   */
  dispatchTo (mode, req) {
    if (!('userdata' in req)) return

    if ('set' in req.userdata) return this.set
    if ('get' in req.userdata) return this.get
    if ('clear' in req.userdata) return this.clear

    return null
  }
}
