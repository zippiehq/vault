// app resource cache
const CACHE_NAME = 'vault-v1'
const CACHE_URLS = [
  '/',
  '/style.css',
  '/boot-bundle.js',
]

class SystemHandler {
  respondsTo (event) {
    return ('version' in event.data)
  }

  process (event) {
    event.source.postMessage({
      response: 'version', requestId: event.data.requestId,
      success: true, result: require('../version.js').BUILD_VERSION
    })
  }
}

class StorageHandler {
  constructor (storeId, version) {
    this.storeId = storeId
    this.version = version
  }

  dbOpen () {
    return new Promise(function (resolve, reject) {
      var dbOpenReq = self.indexedDB.open(this.storeId, this.version);
      dbOpenReq.onerror = function (event) {
        console.log('SW: DB: error opening '+ this.storeId +':', event)
        reject(event)
      }.bind(this)

      dbOpenReq.onsuccess = function (event) {
        console.log('SW: DB: opened '+ this.storeId + ':', event)
        resolve(dbOpenReq.result)
      }.bind(this)

      dbOpenReq.onupgradeneeded = function (event) {
        console.log('SW: DB: upgrade required ' + this.storeId + ':', event)
        var db = event.target.result

        db.onerror = function (event) {
          console.log('SW: DB: error upgrading '+ this.storeId +':', event)
          reject(event)
        }.bind(this)

        var store = db.createObjectStore(this.storeId, { keyPath: 'key' })
        store.createIndex('value', 'value', { unique: false })
      }.bind(this)
    }.bind(this))
  }

  respondsTo (event) {
    return ('store.get' in event.data) ||
           ('store.set' in event.data) ||
           ('store.clearAll' in event.data)
  }

  process (event) {
    console.log('SW: DB: process', event)
    const source = event.source
    const requestId = event.data.requestId

    this.dbOpen()
      .then(function (db) {
        // SUBCOMMAND: store.get
        if ('store.get' in event.data) {
          console.log('SW: TRACE: store.get')
          var params = event.data['store.get']

          var tx = db.transaction([this.storeId], 'readonly')
          tx.onerror = function (event) {
            console.log('SW: DB: transaction error', event)

            source.postMessage({
              response: 'store.get', requestId: requestId,
              success: false
            })
          }

          tx.oncomplete = function (event) {
            console.log('SW: DB: transaction complete', event)
          }

          var req = tx.objectStore(this.storeId).get(params.key)
          req.onsuccess = function (event) {
            console.log('SW: DB: store get req success', event)
            console.log('SW: DB: store get:', req.result)

            console.log('SW: DB: ', source)
            source.postMessage({
              response: 'store.get', requestId: requestId,
              success: true, result: req.result
            })
          }
        // SUBCOMMAND: store.set
        } else if ('store.set' in event.data) {
          console.log('SW: TRACE: store.set')
          var params = event.data['store.set']

          var tx = db.transaction([this.storeId], 'readwrite')
          tx.onerror = function (event) {
            console.log('SW: DB: transaction error', event)
            source.postMessage({
              response: 'store.set', requestId: requestId,
              success: false
            })
          }

          tx.oncomplete = function (event) {
            console.log('SW: DB: transaction complete', event)
          }

          // FIXME: Should check params for required keys against object store.
          var req = tx.objectStore(this.storeId).put(params)
          req.onsuccess = function (event) {
            console.log('SW: DB: store add req success', event)
            source.postMessage({
              response: 'store.set', requestId: requestId,
              success: true
            })
          }
        // SUBCOMMAND: store.clearAll
        } else if ('store.clearAll' in event.data) { 
          console.log('SW: TRACE: store.clearAll')

          var tx = db.transaction([this.storeId], 'readwrite')
          tx.onerror = function (event) {
            console.log('SW: DB: transaction error', event)
            source.postMessage({
              response: 'store.clearAll', requestId: requestId,
              success: false
            })
          }

          tx.oncomplete = function (event) {
            console.log('SW: DB: transaction complete', event)
          }

          var req = tx.objectStore(this.storeId).clear()
          req.onsuccess = function (event) {
            console.log('SW: DB: store clear req success', event)
            source.postMessage({
              response: 'store.clearAll', requestId: requestId,
              success: true
            })
          }
       }

        db.close()
      }.bind(this))
      .catch(error => {
        console.log('SW: DB: Error processing request:', error)
      })

    return true
  }
}

// message handlers.
var ROOT_MESSAGE_HANDLERS = [
  new SystemHandler(),
  new StorageHandler('vault', 1)
]

// install
self.addEventListener('install', function (event) {
  console.log('SW: install event received:', event)

  /*
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('SW: cache open')
        return cache.addAll(CACHE_URLS)
      }))*/
})

// activate
self.addEventListener('activate', function (event) {
  console.log('SW: active event received:', event)
})

// fetch
self.addEventListener('fetch', function (event) {
  console.log('SW: fetch event received:', event.request)
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) return response
        
        return fetch(event.request)
      }))
})

// message
self.addEventListener('message', function (event) {
  console.log('SW: message received:', event.data)

  for (var i = 0; i < ROOT_MESSAGE_HANDLERS.length; i++) {
    var handler = ROOT_MESSAGE_HANDLERS[i]
    if (!handler.respondsTo(event)) continue
    if (handler.process(event)) return
  }

  console.log('SW: message type unrecognized:', event)
})

