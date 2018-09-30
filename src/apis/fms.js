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
import XMLHttpRequestPromise from 'xhr-promise'

/**
 * FMS API
 */
//XXX: Refactor
export default class FMS {
  constructor (uri) {
    this.uri = uri || 'https://fms.zippie.org'
  }

  /**
   *
   */
  async store (authpub, revokepub, data) {
    authpub = (typeof authpub === 'string') ? authpub : authpub.toString('hex')
    revokepub = (typeof revokepub === 'string') ? revokepub : revokepub.toString('hex')

    let req = {
      url: this.uri + '/store',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8'
      },
      data: JSON.stringify({
        authpubkey: authpub,
        revokepubkey: revokepub,
        data: data
      })
    }

    let res = await (new XMLHttpRequestPromise()).send(req)

    if (res.status !== 200) {
      console.error('VAULT: FMS Failed store query for request:', req)
      console.error('VAULT: FMS Failed store query response:', res)
      return false
    }

    let result
    try {
      result = JSON.parse(res.responseText)
    } catch (e) {
      console.error('VAULT: Error parsing FMS store response:', e)
      return false
    }

    if ('error' in  result) {
      console.error('VAULT: FMS store returned error:', result)
      return false
    }

    return true
  }

  /**
   *
   */
  async fetch (authkey) {
    // Timestamp used to generate signature for device verification on FMS
    let tstamp = Date.now().toString()
    let tstamp_hash = shajs('sha256').update(tstamp).digest()

    // Generate timestamp signature
    let tstamp_sig = secp256k1.sign(tstamp_hash, authkey)

    // Perform XHR request to FMS to get remote slice.
    let req = {
      url: this.uri + '/fetch',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8'
      },
      data: JSON.stringify({
        timestamp: tstamp,
        sig: tstamp_sig.signature.toString('hex'),
        recovery: tstamp_sig.recovery
      })
    }
    let res = await (new XMLHttpRequestPromise()).send(req)

    // Check FMS response
    if (res.status !== 200) {
      console.error('VAULT: FMS Failed fetch query for request:', req)
      console.error('VAULT: FMS Failed fetch query response:', res)
      return null
    }

    // Parse and process response data
    let result
    try {
      result = JSON.parse(res.responseText)
    } catch (e) {
      console.error('VAULT: Error parsing FMS fetch response:', e)
      return null
    }

    if ('error' in result) {
      console.error('VAULT: FMS fetch returned error:', result)
      return null
    }

    return result.data
  }

  /**
   *
   */
  async revoke (revokekey) {
    // Timestamp used to generate signature for device verification on FMS
    let tstamp = Date.now().toString()
    let tstamp_hash = shajs('sha256').update(tstamp).digest()

    // Generate timestamp signature
    let tstamp_sig = secp256k1.sign(tstamp_hash, Buffer.from(authkey, 'hex'))

    // Perform XHR request to FMS to get remote slice.
    let req = {
      url: this.uri + '/revoke',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8'
      },
      data: JSON.stringify({
        timestamp: tstamp,
        sig: tstamp_sig.signature.toString('hex'),
        recovery: tstamp_sig.recovery
      })
    }
    let res = await (new XMLHttpRequestPromise()).send(req)

    // Check FMS response
    if (res.status !== 200) {
      console.error('VAULT: FMS Failed revoke for request:', req)
      console.error('VAULT: FMS Failed revoke response:', res)
      return null
    }

    // Parse and process response data
    let result
    try {
      result = JSON.parse(res.responseText)
    } catch (e) {
      console.error('VAULT: Error parsing FMS revoke response:', e)
      return null
    }

    if ('error' in result) {
      console.error('VAULT: FMS revoke returned error:', result)
      return null
    }

    return result.data    
  }
}

