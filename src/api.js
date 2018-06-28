export class MessageChannel {
  constructor (sender, receiver) {
    this.sender = sender
    this.receiver = receiver
    this.counterId = 0

    this.responders = {}

    receiver.addEventListener('message', this.onMessage.bind(this))
  }

  request (request) {
    return new Promise(function (resolve, reject) {
      var reqId = 'request-' + this.counterId++
      this.responders[reqId] = [resolve, reject]

      this.sender.postMessage(Object.assign({requestId: reqId}, request))

      //TODO: Add request timeout signaling.
    }.bind(this))
  }

  onMessage (event) {
    console.log('CL-API: Service worker message:', event)

    if (!event.data.requestId) {
      console.error('Unsolicited message received', event)
      return
    }

    var responder = this.responders[event.data.requestId]
    delete this.responders[event.data.requestId]

    if (!responder) {
      console.error('Unrecognised requestId:', event.data.requestId)
      return
    }

    responder[0](event.data)
  }
}

export class WindowMessageChannel {
  constructor (target, receiver) {
    this.target = target
    this.receiver = receiver
    this.counterId = 0

    this.responders = {}

    receiver.addEventListener('message', this.onMessage.bind(this))
  }

  postMessage (data) {
    this.target.postMessage(data, '*')
  }

  request (request) {
    return new Promise(function (resolve, reject) {
      var reqId = 'request-' + this.counterId++
      this.responders[reqId] = [resolve, reject]

      this.postMessage(Object.assign({requestId: reqId}, request))

      //TODO: Add request timeout signaling.
    }.bind(this))
  }

  onMessage (event) {
    console.log('CL-API: Client message:', event)

    if (!event.data.requestId) {
      console.error('Unsolicited message received', event)
      return
    }

    var responder = this.responders[event.data.requestId]
    delete this.responders[event.data.requestId]

    if (!responder) {
      console.error('Unrecognised requestId:', event.data.requestId)
      return
    }

    responder[0](event.data)
  }
}
