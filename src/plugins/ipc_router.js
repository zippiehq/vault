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

export default class IPCRouter {

  constructor()
  {
    this._receivers = {}
  }

  install (vault) {
    this.vault = vault
    vault.addReceiver(this)
  }

  async handleMessage(req)
  {
    console.info("[IPCRouter]: Received Router Request")
    var params = req.IPCRouterRequest
    var receiver = this._receivers[params.target]

    if(receiver === undefined && params.payload.call == 'init')
    {
      console.info("[IPCRouter]: Creating iframe for " + params.target)
      var iframe = document.createElement('iframe')
      iframe.style.display = 'none'
  
      iframe.sandbox += ' allow-storage-access-by-user-activation'
      iframe.sandbox += ' allow-same-origin'
      iframe.sandbox += ' allow-scripts'
  
      iframe.src = params.target;
      document.body.appendChild(iframe)
  
      this._receivers[params.target] = iframe
      receiver = iframe
    }

    if(params.message == "ready")
    {
      console.info('[IPCRouter]: Iframe Ready!')
      receiver.contentWindow.postMessage({'payload': { 'call': 'getPassportInfo', 'args': ''}}, "*")
    }

    receiver.contentWindow.postMessage(params.payload, "*")

    return 
  }

  dispatchTo (node, req) {

    if('IPCRouterRequest' in req)
    {
      return this.handleMessage
    }

    return null;
  }
}
