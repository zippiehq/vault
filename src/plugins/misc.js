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
 * Vault Miscellaneous Actions Provider Plugin
 */
export default class {
  /**
   *
   */
  install (vault) {
    this.vault = vault
    vault.addReceiver(this)
  }

  /**
   *
   */
  async open (req) {
    console.info('VAULT: Opening external URI:', req.open.uri)
    window.location = req.open.uri
  }

  /**
   *
   */
  async qrscan (req) {
    console.info('VAULT: Opening qrscan.io:', req.uri)
    window.location = 'https://qrscan.io'
    return true
  }

  /**
   * MessageDispatcher Interface
   */
  dispatchTo (mode, req) {
    if (mode === 'root') { // ROOT-MODE ONLY RECEIVERS
      if ('open' in req) return this.open
      else if ('qrscan' in req) return this.qrscan
    }

    return null
  }
}
