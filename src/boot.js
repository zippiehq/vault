const api = require('./api.js')
const vault = require('./vault.js')
const version = require('../version.js')

const store = require('store')

var worker

const VAULT_MESSAGE_HANDLERS = [
  new vault.RootMessageHandler(),
  new vault.VaultMessageHandler()
]

//
// Worker initialization
//
window.addEventListener('load', function () {
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
        store.clearAll()
      }

      if (window.top == window.self || window.location.hash.startsWith('#iframe=')) {
        vault.setup().then(() => {
          console.log('Setup done')
        })
      } else {
        // we're in an iframe, time to listen for commands
        console.log('Zippie Vault listening')
        parent.postMessage({'ready' : true}, '*')
      }
    })
    .catch(function (error) {
      console.error('Failed to register service worker:', error)
      return
    })
})

//
// Worker incoming message dispatcher
//
self.addEventListener('message', function (event) {
  console.log('CL: message received:', event.data)

  for (var i = 0; i < VAULT_MESSAGE_HANDLERS.length; i++) {
    var handler = VAULT_MESSAGE_HANDLERS[i]
    if (!handler.respondsTo(event)) continue
    if (handler.process(event)) return
  }

  console.log('CL: message type unrecognized:', event)
})

