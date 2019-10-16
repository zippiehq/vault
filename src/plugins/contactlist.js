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
import {fetchDataFromPermaStoreV2 } from '../utils';

/**
 * Remote Storage Plugin for Contact Data
 */
export default class {
  /**
   *
   */
  install(vault) {
    this.vault = vault;
    this.vault.contactList = this;
    vault.addReceiver(this);
  }

 
  /**
   *
   */
  async get(event) {
    const req = event.data.contactList.get
    const keyInfo = req.keyInfo
    let contactList = await fetchDataFromPermaStoreV2(keyInfo)
    if (!contactList) {
      contactList = []
    }
    return contactList
  }

  /**
   * MessageReceiver Interface
   */
  dispatchTo(context, event) {
    let req = event.data;
    if (!("contactList" in req)) return;
    if ("get" in req.contactList) return this.get;

    return null;
  }
}
