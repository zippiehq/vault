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
 * Vault "Root" Mode Plugin
 */
export default class {
  /**
   *
   */
  install (vault) {
    this.vault = vault
  }

  /**
   *
   */
  async startup () {
    if (this.vault.mode !== 'root') return

    // https://vault.zippie.org/#?wipe
    if ('wipe' in this.vault.params && confirm('Do you really want to wipe Zippie Vault? This may cause data or money loss.') === true) {
      this.vault.store.clear()
      return
    }

    // https://vault.zippie.org/#?signup=[uri-to-redirect-back-to]
    if ('signup' in this.vault.params) {
      if (await this.vault.isSetup()) {
        alert('Already signed up.')
        return
      }

      this.vault.launch(this.vault.config.apps.root.signup, { root: true })
        .then(function () {
          this.vault.launch(this.vault.config.apps.user.home)
        }.bind(this))

      return
    }

    // https://vault.zippie.org/#?launch=[user-app-to-launch]
    if ('launch' in this.vault.params) {
      // Check to see if user is signed up, if not, do signup process.
      if (!await this.vault.isSetup()) {
        this.vault.launch(this.vault.config.apps.root.signup, { root: true })
          .then(function () {
            this.vault.launch(this.vault.params.launch)
          }.bind(this))
        return
      }

      this.vault.launch(this.vault.params.launch)
      return
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
  }
}
