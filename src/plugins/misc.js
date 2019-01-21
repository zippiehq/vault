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
import crypto from 'crypto'
import HDKey from 'hdkey'
import secp256k1 from 'secp256k1'
import eccrypto from 'eccrypto'
import XMLHttpRequestPromise from 'xhr-promise'
import bs58 from 'bs58'

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
  async open (event) {
    let req = event.data
    console.info('VAULT: Opening external URI:', req.open.uri)
    window.location = req.open.uri
  }

  /**
   *  In root mode replaces vault with qrscan.io site.
   */
  async qrscan (event) {
    let req = event.data
    console.info('VAULT: Opening qrscan.io:', req.uri)
    window.location = 'https://qrscan.io'
    return true
  }

  /**
   *
   */
  async referral (event) {
    let req = event.data
    let hash = shajs('sha256').update('refs').digest()
    let pubex = await (await this.vault.derive(hash)).derive("m/0'/0").publicExtendedKey

    let key = crypto.randomBytes(16)
    let iv  = crypto.randomBytes(16)

    let plaintext = Buffer.from(JSON.stringify({
      name: this.vault.store.getItem('user.name'),
      key: pubex.toString('hex')
    }),'utf-8')

    let promise = new Promise(function (resolve, reject) {
      let cipher = crypto.createCipheriv('aes-128-cbc', key, iv)

      let ciphertext = new Buffer(0)
      cipher.on('readable', _ => {
        let data = cipher.read()
        if (data) ciphertext = Buffer.concat([ciphertext, data])
      })

      cipher.on('end', _ => {
        resolve(ciphertext)
      })

      cipher.write(plaintext)
      cipher.end()
    })

    return promise
      .then(async function (r) {
        r = r.toString('hex')
        let req = {
          url: 'https://api.contribution.zipperglobal.com/submit/store_incremental',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json; charset=UTF-8'
          },
          data: JSON.stringify({data: r})
        }

        let res = await (new XMLHttpRequestPromise()).send(req)

        if (res.status !== 200) {
          console.error('VAULT: Incremental store failed for request:', req)
          console.error('VAULT: Incremental store failed response:', res)
          return false
        }

        // Parse and process response data
        let result
        try {
          result = JSON.parse(res.responseText)
        } catch (e) {
          console.error('VAULT: Error parsing FMS fetch response:', e)
          return false
        }

        if (!('id' in result)) return false

        let id = new Buffer(4)
        id.writeUInt32BE(result.id, 0)

        return Promise.resolve({
          key: bs58.encode(Buffer.concat([id, key, iv])),
          pubex: pubex.toString('hex')
        })
      })
  }

  /**
   *
   */
  async postTo (event) {
    let req = event.data
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
  dispatchTo (context, event) {
    let req = event.data
    if (context.mode === 'root') { // ROOT-MODE ONLY RECEIVERS
      if ('open' in req) return this.open
      if ('qrscan' in req) return this.qrscan
    }

    if ('referral' in req) return this.referral.bind(this)
    if ('postTo' in req) return this.postTo.bind(this)

    return null
  }
}
