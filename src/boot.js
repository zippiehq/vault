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
import Vault from './vault.js'

/**
 * Detect Runtime Exection Mode
 */
var runtime_mode = 'release'

if (window.location.host.indexOf('localhost') !== -1) {
  runtime_mode = 'development'
} else if (window.location.host.indexOf('dev.zippie.org') !== -1) {
  runtime_mode = 'development'
} else if (window.location.host.indexOf('testing.zippie.org') !== -1) {
  runtime_mode = 'testing'
}

/**
 * Import Runtime Configuration
 */
var config = require('../zippie.config.js')[runtime_mode]
console.info('VAULT: Runtime Mode:', runtime_mode)

// Store vault URI in config, so applications can request it.
config.uri = window.location.origin

/**
 * Vault Entry-Point
 */
window.addEventListener('load', function () {
  let vault = new Vault(config)

  if (runtime_mode === 'development' || runtime_mode === 'testing') {
    window.vault = vault
  }

  vault.startup()
})

