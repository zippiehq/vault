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
*/
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
