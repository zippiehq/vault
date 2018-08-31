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
import Cookie from 'js-cookie'


/**
 * == Cookie Vault Injector Plugin
 *
 *   A plugin that encrypts vault device/auth keys using a dapps pubex key. The
 * vault data is then set as a HTTP cookie on the client from vault domain.
 * Which makes it only accessible by vault, and when the correct dapp is
 * launching it.
 *
 *   This method was devised to as a work around for Apple/Webkit ITP-2.0 cookie
 * restrictions. It will be in use until, or if, Webkit ever includes support
 * for LocalStorage and IndexedDB data in their ITP implementation.
 *
 *
 * == A Note on Security
 *
 *   Even though our vault server can potentially read the cookie data, as it is
 * passed by the user-agent for every HTTP request. The data is encrypted
 * against the DAPPS pubex key. Which we do not have access to, as that is
 * passed in the URI fragment to the dapp. Meaning servers only ever see the
 * encrypted form of the vault data.
 *
 */
export default class {
  /**
   * Vault plugin 'install' hook
   */
  install (vault) {
    this.vault = vault
  }

  /**
   * Configuration hook run in user mode.
   */
  async signin (origin, magiccookie) {
    let parser = document.createElement('a')
    parser.href = origin

    let apphash = shajs('sha256').update(parser.host).digest().toString('hex')

    console.info('VAULT: Reading cookie data using origin:', apphash)

    let data = Cookie.get('v-data-' + apphash)

    // Check we have got cookie data, or prompt redirect.
    if (data === undefined) {
      console.info('No v-data cookie discovered, user needs to sign-in.')

      return {
        launch: window.location.href.split('#')[0],
        reason: 'Vault data cookie undefined.'
      }
    }

    // Decode & Extract iv and ciphertext from HTTP vault cookie.
    data = Buffer.from(data, 'hex')

    let iv = data.slice(0, 16)
    let text = data.slice(16)

    // We decrypt the vault data with apps magic cookie.
    let key = Buffer.from(magiccookie, 'hex')

    // Decrypt vault data parcel.
    console.info('VAULT: Decrypting vault data injection cookie.')
    let cipher = Crypto.createDecipheriv('aes-256-cbc', key, iv)
    let bs = cipher.update(text)
    let be = cipher.final()

    // Parse vault data JSON from decrypted plain text
    let vdata = JSON.parse(Buffer.concat([bs, be]).toString('utf8'))

    // Inject decrypted data to vault storage.
    for (let k in vdata) {
      console.info('VAULT: injecting key value: ' + k)
      this.vault.store.setItem(k, vdata[k])
    }
  }

  /**
   * Vault plugin 'prelaunch' hook
   */
  async prelaunch (uri, opts) {
    if (this.vault.mode !== 'root') return
    if (!await this.vault.isSetup()) return

    console.log('VAULT: cookie vault data plugin prelaunch.')
    let parser = document.createElement('a')
    parser.href = uri
    let apphash = shajs('sha256').update(parser.host).digest()

    let data = Cookie.get('v-data-' + apphash)
    if (data !== undefined) {
      console.info('VAULT: Vault data cookie for pubex exists, returning.')
      return
    }

    console.info('VAULT: Populating vault injection data.')
    let keys = [
      'localkey', 'authkey', 'localslice_e'
    ]

    data = {}
    for (let i = 0; i < keys.length; i++) {
      let k = keys[i]
      data[k] = this.vault.store.getItem(k)
    }
    data = Buffer.from(JSON.stringify(data), 'utf8')

    console.info('VAULT: Encrypting vault data injection cookie.')
    let iv = Crypto.randomBytes(16)
    let cookie = Crypto.randomBytes(32)
    let cipher = Crypto.createCipheriv('aes-256-cbc', cookie, iv)
    let bs = cipher.update(data)
    let be = cipher.final()

    this.vault.magiccookie = cookie.toString('hex')

    console.info('VAULT: Setting vault data injection cookie.')
    Cookie.set(
      'v-data-' + apphash.toString('hex'),
      Buffer.concat([iv, bs, be]).toString('hex'),
      {
        secure: true
      }
    )

    return
  }
}
