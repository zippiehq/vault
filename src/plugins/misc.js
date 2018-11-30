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
import HDKey from 'hdkey'
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
   *  In root mode replaces vault with some external URI.
   */
  async open (req) {
    console.info('VAULT: Opening external URI:', req.open.uri)
    window.location = req.open.uri
  }

  /**
   *  In root mode replaces vault with qrscan.io site.
   */
  async qrscan (req) {
    console.info('VAULT: Opening qrscan.io:', req.uri)
    window.location = 'https://qrscan.io'
    return true
  }

  /**
   *
   */
  async referral (req) {
    let hash = shajs('sha256').update('refs').digest()
    let pubex = await (await this.vault.derive(hash)).derive('m/0').publicExtendedKey
    return {name: this.vault.store.getItem('user.name'), key: pubex.toString('hex')}
  }

  /**
   *
   */
  async postTo (req) {
    const params = req.postTo

    let pubex = await HDKey.fromExtendedKey(params.key).derive('m/1')
    let pubkey = secp256k1.publicKeyConvert(pubex.publicKey, false)

    let cipher = await eccrypto.encrypt(pubkey, Buffer.from(JSON.stringify(params.data), 'utf8'))
    Object.keys(cipher).map(k => { cipher[k] = cipher[k].toString('hex') })

    return await this.vault.mailbox.store(
      pubkey.toString('hex'),
      cipher
    )
  }

  /**
   * MessageDispatcher Interface
   */
  dispatchTo (mode, req) {
    if (mode === 'root') { // ROOT-MODE ONLY RECEIVERS
      if ('open' in req) return this.open
      if ('qrscan' in req) return this.qrscan
    }

    if ('referral' in req) return this.referral.bind(this)
    if ('postTo' in req) return this.postTo.bind(this)

    return null
  }
}
