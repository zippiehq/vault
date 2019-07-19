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
import { Logger } from './logger'

/**
 * @module dispatch
 */

/**
 * Adds a requirement to the message that the receiver requires the request to
 * come from a vault root app. These methods are inaccessible to normal user
 * applications.
 *
 * @constructor
 * @param {MessageReceiver} receiver - The target message receiver
 *
 */
export const RootAuthFilter = function (receiver) {
  return function (context, event) {
    if (context.mode === 'root') return receiver(context, event)
  }
}


/**
 * Adds a requirement to the message receiver that requires the request provide
 * an authenticaton token for role.
 *
 * @constructor
 * @param {string} role - The permission role identifier.
 * @param {MessageReceiver} receiver - The target message receiver.
 *
 */
export const TokenAuthFilter = function (role, receiver) {
  return function (context, event) {
    
  }
}


/**
 * Implements a message handling framework for applications to process freeform
 * events and route them to application defined event handlers.
 *
 * @constructor
 * @param {Object} context - Context object to bind receivers to when calling.
 */
export class MessageDispatcher {
  constructor (context, logger) {
    this.__context = context
    this.__logger = new Logger('MessageDispatcher', logger)

    this.__receivers = []
  }

  /**
   * Adds an application event receiver to this dispatcher.
   * @param {MessageReceiver} receiver - Target receiver
   */
  addReceiver (receiver) {
    if (!('dispatchTo' in receiver) || typeof(receiver.dispatchTo) !== 'function') {
      throw 'Receiver does not implement MessageDispatcher interface!'
    }

    this.__receivers.push(receiver)
  }

  /**
   * Removes an application event receiver from this dispatcher.
   * @param {MessageReceiver} receiver - Target receiver
   */
  removeReceiver (receiver) {
    this.__receivers = this.__receivers.filter((v, i, a) => v === receiver)
  }

  /**
   * Dispatch event to appropriate message receiver. First receiver found is
   * the only one called.
   * @param {Event} event - Event to dispatch
   */
  async dispatch (event) {
    // Ignore empty messages.
    if (!event.data || event.data === '' || event.data === {}) {
      return
    }

    for (var i = 0; i < this.__receivers.length; i++) {
      let receiver = this.__receivers[i].dispatchTo(this.__context, event)
      if (!receiver) continue

      this.__logger.info('Processing event:', event)
      return receiver.bind(this.__context)(event)
        .then(r => {
          event.source.postMessage({
            callback: event.data.callback, result: r
          },
          event.origin)
        })
        .catch(e => {
          try { // Try to send error object, else stringify.
            event.source.postMessage({
              callback: event.data.callback, error: e
            },
            event.origin)
          } catch (_) {
            event.source.postMessage({
              callback: event.data.callback, error: e.toString()
            },
            event.origin)
          }
        })
    }

    this.__logger.warn('Unrecognised event:', event)
  }
}

