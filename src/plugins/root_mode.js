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
import secp256k1 from 'secp256k1'
import bs58 from 'bs58'
import Cookie from 'js-cookie'
import { decrypt } from '../utils'

/**
 * Vault "Root" Mode Plugin
 *
 * In root mode, we accept fragment parameters to specify some vault launch
 * behaviors. This plugin defines these start up behaviours. Such as, wiping
 * vault data, launching signup UX, logging in to a dapp, launching card
 * registration / authentication UX, and PIN code entry UX.
 *
 *
 * TODO: Refactor to allow other plugins to register their root functions, so we
 *   can move out the functionality into their respective vault plugin source
 *   files.
 *
 */
export default class {
  /**
   * Initialize plugin with the vault instance.
   */
  install (vault) {
    this.vault = vault
  }

  /**
   * Plugin hook, invoked on vault startup to process URI fragment and act
   * accordingly.
   */
  async startup () {
    if (this.vault.mode !== 'root') return

    // https://vault.zippie.org/#?wipe
    if ('wipe' in this.vault.params && confirm('Do you really want to wipe Zippie Vault? This may cause data or money loss.') === true) {
      this.vault.store.clear()

      Object.keys(Cookie.get())
        .filter(k => k.startsWith('v-data-'))
        .forEach(k => Cookie.remove(k))

      return
    }

    // https://vault.zippie.org/#?signup=[uri-to-redirect-back-to]
    if ('signup' in this.vault.params) {
      // Process signup parameters.
      let params = { }
      Object.keys(this.vault.params).forEach(k => {
        if (k.startsWith('signup_')) params[k] = this.vault.params[k]
      })

      let path = ''
      if ('signup_page' in params) {
        path = '/#' + params['signup_page']
        delete params['signup_page']
      }

      this.vault.launch(this.vault.config.apps.root.signup + path, { root: true, params: params })
        .then(function () {
          let opts
          if (this.vault.params.itp) opts = { params: { itp: true } }
          this.vault.launch(this.vault.params.signup, opts)
        }.bind(this))
      return
    }

    // https://vault.zippie.org/#?launch=[user-app-to-launch]
    if ('launch' in this.vault.params) {
      // Check to see if user is signed up, if not, do signup process.
      if (!await this.vault.isSetup()) {
        if ('inhibit-signup' in this.vault.params) {
          return this.vault.launch(
            this.vault.params.launch,
            { params: {'inhibit-signup': true} }
          )
        }

        // Process signup parameters.
        let params = { }
        Object.keys(this.vault.params).forEach(k => {
          if (k.startsWith('signup_')) params[k] = this.vault.params[k]
        })

        let path = ''
        if ('signup_page' in params) {
          path = '/#' + params['signup_page']
          delete params['signup_page']
        }

        if (this.vault.params.launch) {
          params['signup_launch'] = this.vault.params.launch
        }

        this.vault.launch(this.vault.config.apps.root.signup + path, { root: true, params: params })
          .then(function () {
            let opts
            if (this.vault.params.itp) opts = { params: { itp: true } }
            this.vault.launch(this.vault.params.launch, opts)
          }.bind(this))
        return

      } else if (this.vault.params.itp &&
          confirm('Allow "' + this.vault.params.launch + '" access to vault?')) {
        let opts = { params: { itp: true } }
        return this.vault.launch(this.vault.params.launch, opts)
      }

      this.vault.launch(this.vault.params.launch)
      return
    }

    if ('diagnostics' in this.vault.params &&
        this.vault.config.apps.root.debug &&
        confirm('Here be dragons, proceed with caution!')) {
      return this.vault.launch(this.vault.config.apps.root.debug, { root: true })
    }

    // https://vault.zippie.org#?recover=v
    if ('recover' in this.vault.params) {
      let promise = Promise.resolve(true)

      // If we already have an identity, show the signup recovery confirmation
      // page and wait for response from user.
      if (await this.vault.isSetup()) {
        let params = {
          heading: 'You already have an identity!',
          message: 'Are you sure you want to overwrite by recovering new identity?' }

        promise = this.vault.launch(this.vault.config.apps.root.signup + '/#/confirm', { root: true, params: params })
      }

      // On successful resolution decode recovery data and load signup recovery
      return promise
        .then(async function (r) {
          if (!r) return

          let authkey, salt

          // Decode hex encoded ':' delimited recovery data.
          if (this.vault.params.recover.indexOf(':') > -1) {
            let parts = this.vault.params.recover.split(':')
            salt = parts[0]
            authkey = Buffer.from(parts[1], 'hex')

          // Decode base58 encoded recovery data
          } else if (this.vault.params.recover.length === 88) {
            let buff = bs58.decode(this.vault.params.recover)
            salt = buff.slice(0, 32).toString('hex')
            authkey = buff.slice(32)
          }

          let recovery = await this.vault.fms.fetch(authkey)

          if (recovery === null) {
            alert('Unable to download recovery data.')
            return
          }

          recovery = Buffer.from(JSON.stringify(recovery), 'ascii').toString('hex')

          // Process signup parameters.
          let params = { }
          Object.keys(this.vault.params).forEach(k => {
            if (k.startsWith('signup_')) params[k] = this.vault.params[k]
          })

          return this.vault.launch(this.vault.config.apps.root.signup + '/#/recover/auth/' + salt + '/' + recovery, { root: true, params: params })
        }.bind(this))
        .then(function () {
          let redirectTo = this.vault.config.apps.user.home

          if (this.vault.params.app) {
            redirectTo = this.vault.params.app
          }

          return this.vault.launch(redirectTo)
        }.bind(this))
        .catch(function (e) {
          return alert(e)
        })
    }

    // https://vault.zippie.org/#?card=v
    if ('card' in this.vault.params) {
      // Check to see if user is signed up, if not, do signup process, card enrollment
      // and then redirect to home.
      if (!await this.vault.isSetup()) {
        this.vault.launch(this.vault.config.apps.root.signup, { root: true })
        .then(function () {
          return this.vault.launch(this.vault.config.apps.root.card + '#/' + this.vault.params.card, { root: true })
        }.bind(this))
        .then(function () {
          return this.vault.launch(this.vault.config.apps.user.home)
        }.bind(this))
        return
      }

      //TODO: Decide what to do after card app does it's thing (close window?)
      this.vault.launch(this.vault.config.apps.root.card + '#/' + this.vault.params.card, {
        root: true
      })

      return
    }

    // https://vault.zippie.org/#?pinauth=v
    if ('pinauth' in this.vault.params) {
      this.vault.launch(this.vault.config.apps.root.pinauth, { root: true })
      .then(function () {
        alert('USER AUTHENTICATED, NOW WHAT?!')
      })
    }

    // https://vault.zippie.org/#?enroll=v
    if ('enroll' in this.vault.params) {
      this.vault.launch(this.vault.config.apps.root.signup + '/#/enroll/' + this.vault.params.enroll, { root: true })
      return
    }

    // https://vault.zippie.org/#?import=v
    if ('import' in this.vault.params) {
      let promise = Promise.resolve(true)

      // If we already have an identity, show the signup recovery confirmation
      // page and wait for response from user.
      if (await this.vault.isSetup()) {
        let params = {
          heading: 'You already have an identity!',
          message: 'Are you sure you want to overwrite by recovering new identity?' }

        promise = this.vault.launch(this.vault.config.apps.root.signup + '/#/confirm', { root: true, params: params })
      }

      // On successful resolution decode recovery data and load signup recovery
      return promise
        .then(async function (r) {

        // USE OTP TO GET MASTERSEED FROM FMS
        const key = this.vault.params['import'].length == 44 ?
            bs58.decode(this.vault.params['import']) :
            Buffer.from(this.vault.params['import'], 'hex')

        let ciphertext = await this.vault.fms.fetch(key)
        if (!ciphertext) {
          console.error('VAULT: Failed to retreive OTP masterseed from FMS.')
          return
        }

        // REVOKE OTP
        console.info('VAULT: Attempting to remove one-time recovery data.')
        const authpub = secp256k1.publicKeyCreate(key, false)
        const revokekey = secp256k1.ecdh(authpub, key)
        await this.vault.fms.revoke(revokekey)

        console.info('VAULT: Decrypting masterseed')
        ciphertext = Buffer.from(ciphertext, 'hex')
        return decrypt(ciphertext, key.slice(0, 16), key.slice(16,32))
          .then(function (masterseed) {
            return this.vault.initidentity(Buffer.from(masterseed, 'hex'))
          }.bind(this))
          .then(function () {
            // XXX - Handle specifying target application.
            this.vault.launch(this.vault.config.apps.user.home)
          }.bind(this))
      }.bind(this))
    }

    alert('VAULT: ' + JSON.stringify(await this.vault.getVersion()))
    return
  }
}
