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
 * @module logger
 */

/**
 * Implements a stackable logging framework, for complex projects.
 *
 * @constructor
 * @param {string} tag - Module identifier prefix.
 * @param {Logger} logger - Optional parent logger for stacking.
 */
export class Logger {
  constructor (tag, logger) {
    this.__tag = tag
    this.__logger = logger || console
  }

  /** Output info logging message */
  info () {
    let params = Array.prototype.slice.call(arguments)
    if (this.__tag) params.unshift(this.__tag + ':')
    this.__logger.info.apply(this.__logger, params)
  }

  /** Output warn logging message */
  warn () {
    let params = Array.prototype.slice.call(arguments)
    if (this.__tag) params.unshift(this.__tag + ':')
    this.__logger.warn.apply(this.__logger, params)
  }

  /** Output error logging message */
  error () {
    let params = Array.prototype.slice.call(arguments)
    if (this.__tag) params.unshift(this.__tag + ':')
    this.__logger.error.apply(this.__logger, params)
  }
}
