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

/**
 * Vault secp256k1 Provider Plugin
 */
export default class Secp256k1Provider {
  /**
   *
   */
  install (vault) {
    vault.addReceiver(this)
  }

  /**
   *
   */
  async keyinfo (event) {
    let req = event.data
    let params = req.secp256k1KeyInfo

    let ahdkey = await (await this.pubex(event.origin)).derive(params.key.derive)
    let pubkey = secp256k1.publicKeyConvert(ahdkey.publicKey, false)

    return {
      pubex: ahdkey.publicExtendedKey,
      pubkey: pubkey.toString('hex')
    }
  }

  /**
   *
   */
  async sign (event) {
    let req = event.data
    let params = req.secp256k1Sign
    let k = await (await this.privex(event.origin)).derive(params.key.derive).privateKey
    var s = secp256k1.sign(Buffer.from(params.hash, 'hex'), k)

    return {
      signature: s.signature.toString('hex'),
      recovery: s.recovery,
      hash: params.hash
    }
  }

  /**
   *
   */
  async encrypt (event) {
    let req = event.data
    let params = req.secp256k1Encrypt

    let ecpub = Buffer.from(params.pubkey, 'hex')
    let plaintext = Buffer.from(params.plaintext, 'hex')

    return eccrypto.encrypt(ecpub, plaintext)
      .then(cipher => {
        ['iv', 'ephemPublicKey', 'ciphertext', 'mac'].forEach(i => {
          cipher[i] = cipher[i].toString('hex')
        })

        return cipher
      })
  }

  /**
   *
   */
  async decrypt (event) {
    let req = event.data
    let params = req.secp256k1Decrypt

    let k = await (await this.privex(event.origin)).derive(params.key.derive).privateKey
    var cipher = {}

    let keys = ['iv', 'ephemPublicKey', 'ciphertext', 'mac']
    keys.forEach(i => {
      cipher[i] = Buffer.from(params[i], 'hex')
    })

    return (await eccrypto.decrypt(k, cipher)).toString('hex')
  }

  /**
   * MessageReceiver Interface
   */
  dispatchTo (context, event) {
    let req = event.data

    if ('secp256k1KeyInfo' in req) return this.keyinfo
    else if ('secp256k1Sign' in req) return this.sign
    else if ('secp256k1Encrypt' in req) return this.encrypt
    else if ('secp256k1Decrypt' in req) return this.decrypt

    return null
  }
}

