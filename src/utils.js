/*
 * Copyright (c) 2018-2019 Zippie Ltd.
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
export function detectDeviceName () {
  let deviceName = null

  if (navigator.userAgent.includes('Firefox')) {
    deviceName = 'Firefox'
  } else if (navigator.userAgent.includes('Chrome')) {
    deviceName = 'Chrome'
  } else if (navigator.userAgent.includes('Safari')) {
    deviceName = 'Safari'
  } else if (navigator.userAgent.includes('Opera') || navigator.userAgent.includes('OPR')) {
    deviceName = 'Opera'
  }

  // If we've not detected a supported browser, bail out.
  if (deviceName === null) return null

  if (navigator.userAgent.includes('iPhone')) {
    deviceName += ' iPhone'
  } else if (navigator.userAgent.includes('iPad')) {
    deviceName += ' iPad'
  } else if (navigator.userAgent.includes('iPod')) {
    deviceName += ' iPod'
  } else if (navigator.platform.toUpperCase().includes('MAC')) {
    deviceName += ' Mac'
  } else if (navigator.userAgent.includes('Mobi')) {
    deviceName += ' Mobile'
  } else if (navigator.userAgent.includes('Tablet')) {
    deviceName += ' Tablet'
  } else {
    deviceName += ' Desktop'
  }

  return deviceName
}