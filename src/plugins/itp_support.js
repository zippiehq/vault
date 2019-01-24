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

/**
 * 
 */
export default class {
  install (vault) {
    this.vault = vault
  }

  startup (promises) {
    if (this.vault.mode !== 'enclave' || document.hasStorageAccess === undefined) return
    console.info('VAULT: ITP-2.0 support starting, checking storage status.')

    // Webkit ITP 2.0 Support
    promises.push(new Promise(function (resolve, reject) {
      document.hasStorageAccess()
        .then(
          async function (r) {
            if (r === false) {
              console.info('VAULT: ITP-2.0: Vault does not have storage access.')
              return reject({login: await this.isSetup()})
            }

            // Post vault ready.
            console.info('VAULT: ITP-2.0: Vault has storage access.')
            return resolve()
          }.bind(this),
          e => {
            console.error('VAULT: ITP-2.0: hasStorageAccess:', e)
            return reject({error: 'ITP-2.0'})
          }
        )
    }.bind(this.vault)))
  }

  requestStorage () {
    return new Promise (function (resolve, reject) {
      if (document.requestStorageAccess !== undefined) {
        return document.requestStorageAccess()
          .then(
            function () {
              console.log('ITP: Storage access granted!')
              return resolve(true)
            },
            function () {
              console.error('ITP: Storage access denied!')
              return reject()
            })
      }
  
      return resolve(true)
    })
  }  

  dispatchTo (context, ev) {
    if ('login' in ev.data) {
      return this.requestStorage()
        .then(function (r) {
          ev.source.postMessage({
            callback: ev.data.callback,
            result: r
          }, ev.origin)
        })
        .catch(e => {
          console.error('VAULT: ITP-2.0 REQUEST FAILURE.')
          ev.source.postMessage({
            callback: ev.data.callback,
            error: 'ITP_REQUEST_FAILURE'
          }, ev.origin)
        })
  
    }
  }
}