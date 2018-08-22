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
const api = require('./api.js')
const vault = require('./vault.js')
const version = require('../version.js')

/**
 * Global Vars
 */
var dispatcher
var worker

/**
 * Webkit ITP 2.0 Support
 */
function requestStorage () {
  return document.requestStorageAccess()
    .then(
      function () {
        console.log('ITP: Storage access granted!')
        // Post vault ready.
        console.log('Zippie Vault ready.')
        parent.postMessage({ready: true}, '*')
      },
      function () {
        console.error('ITP: Storage access denied!')
        parent.postMessage({error: 'ITP 2.0 Storage Access Denied'}, '*')
      })
}

/**
 * Vault Message Dispatcher
 */
class MessageDispatcher {
  constructor (processors) {
    this.processors = processors
    self.addEventListener('message', this.dispatch.bind(this))
  }

  dispatch (event) {
    console.log('CL: message received:', event.data)

    // Called by parent when the user presses the "Zippie Signin" button.
    //XXX: Not happy about this being here.
    if ('login' in event.data) {
      return requestStorage()
    }

    for (var i = 0; i < this.processors.length; i++) {
      var receiver = this.processors[i]
      if (!receiver.respondsTo(event)) continue
      if (receiver.process(event)) return
    }

    console.log('CL: message type unrecognized:', event)
  }
}

/**
 * Vault Entry-Point
 */
window.addEventListener('load', function () {
  console.info('VAULT: Loading...')

  if (window.top === window.self || window.location.hash.startsWith('#iframe=')) {
    console.info('VAULT: Configuring root mode...')
    dispatcher = new MessageDispatcher([
      new vault.RootMessageHandler()
    ])

    return vault.setup().then(() => {
      console.info('VAULT: Setup complete.')
    })
  }

  console.info('VAULT: Configuring enclave mode...')
  dispatcher = new MessageDispatcher([
    new vault.VaultMessageHandler()
  ])

  // Webkit ITP 2.0 Support
  //XXX: Not happy about this being here.
  if (document.hasStorageAccess !== undefined) {
    console.info('VAULT: ITP-2.0: browser support detected, checking storage status.')
    return document.hasStorageAccess()
      .then(
        r => {
          if (r === false) {
            console.info('VAULT: ITP-2.0: Vault does not have storage access, notifying client.')
            return parent.postMessage({login: null}, '*')
          }

          // Post vault ready.
          console.info('VAULT: ITP-2.0: Setup complete.')
          parent.postMessage({ready: true}, '*')
        },
        e => {
          console.error('VAULT: ITP-2.0: hasStorageAccess:', e)
          parent.postMessage({error: 'ITP-2.0'})
        }
      )
  }

  // Post vault ready.
  console.info('VAULT: Setup complete.')
  parent.postMessage({ready : true}, '*')
})

/**
 * Initialise Vault Service Worker
 *
function initSW () {
  if (!('serviceWorker' in navigator)) {
    console.error('SERVICE WORKERS NOT SUPPORTED IN THIS BROWSER!')
    return
  }

  // Register service worker
  navigator.serviceWorker.register('worker-bundle.js')
    .then(function (registration) {
      console.log('CL: Service worker registered:', registration)

      if (registration.installing) {
        console.log('CL: installing')
        worker = registration.installing
      } else if (registration.waiting) {
        console.log('CL: waiting')
        worker = registration.waiting
      } else if (registration.active) {
        console.log('CL: active')
        worker = registration.active
      }

      if (!worker) {
        console.log('CL: Failed to get a handle on worker!')
        return
      }

      worker.addEventListener('statechange', function (event) {
        console.log('CL: Service worker state changed:', worker.state)

        if (worker.state === 'redundant') {
          console.log('CL: Reloading...')
          window.location.reload()
        }
      })

      worker.addEventListener('error', function (event) {
        console.log('CL: Service worker error:', event)
      })

      worker.addEventListener('messageerror', function (event) {
        console.log('CL: Service worker message error:', event)
      })

      navigator.serviceWorker.addEventListener('message', function (event) {
        console.log('CL: Service worker message:', event)
      })

      // Create channel between iframe -> worker
      window.VaultChannel = new api.MessageChannel(worker, navigator.serviceWorker)
      window.VaultChannel.request({'version': {}})
        .then(r => {
          console.log("Service worker version:", r.result)
        })

      // Migrate from LocalStorage to ServiceWorker IndexedDB
      let doStoreMigration = store.get('vaultSetup')
      if (doStoreMigration) {
        let keys = [
          'authkey', 'localkey', 'localslice_e', 'vaultSetup'
        ]

        console.log("CL: Migrating identity from LocalStorage to IndexedDB")
        for (var i = 0; i < keys.length; i++) {
          let key = keys[i]

          VaultChannel.request({'store.set': {
            key: key,
            value: store.get(key)}
          })
        }
        //store.clearAll()
      }

      console.log('Zippie Vault Version:', version)
    })
    .catch(function (error) {
      console.error('Failed to register service worker:', error)
      return
    })
}
*/
