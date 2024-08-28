import Plugin from 'src/plugin-system/plugin.class'
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';

import CidaasUtil from '../util/cidaas-util';

import * as $ from 'jquery'

export default class CidaasPassword extends Plugin {

    init() {
        $('#profilePasswordForm').on('submit', this.handleFormSubmit.bind(this))
        this.newPasswordInput = $('#newPassword')
        this.confirmPasswordInput = $('#passwordConfirmation')
        this.oldPasswordInput = $('#password')
        this.client = new HttpClient()
        this.client.get('/cidaas/url', (res) => {
            try {
                let result = JSON.parse(res)
                this.cidaasUrl = result.url
                this.cidaas = new CidaasUtil(result.url)
            } catch (err) {
                console.log(err, res)
            }
        })
        this.client.post('/cidaas/generate', JSON.stringify({
            _csrf_token: this.options.csrfGenerate
        }), (res) => {
            let result = JSON.parse(res)
            this.clientId = result.clientId
            this.url = result.url
            this.state = result.state
            this.scope = "openid offline_access email profile groups"
        })
    }

    async handleFormSubmit(evt) {
        evt.preventDefault()
        if (this.checkInputFields()) {
            this.client.post('/cidaas/changepassword', JSON.stringify({
                newPassword: this.newPasswordInput.val(),
                oldPassword: this.oldPasswordInput.val(),
                confirmPassword: this.confirmPasswordInput.val(),
                _csrf_token: this.options.csrf
            }), (res) => {
                try {
                    let result = JSON.parse(res)
                    if (result.success) {
                        this.performLogout();
                    }
                } catch (err) {

                }
            })
        }
    }
    performLogout() {
        const baseUrl = `${window.location.protocol}//${window.location.host}`;
        const path = window.location.pathname;
        const localeMatch = path.match(/^\/([a-z]{2})(\/|$)/i);
        const locale = localeMatch ? localeMatch[1] : '';

        const logoutUrl = locale ? `${baseUrl}/${locale}/account/logout` : `${baseUrl}/account/logout`;
        window.location.href = logoutUrl;
    }


    checkInputFields() {
        let newPassword = this.newPasswordInput.val()
        let oldPassword = this.oldPasswordInput.val()
        let confirmPassword = this.confirmPasswordInput.val()

        if (newPassword.length < 8)
            return false
        if (confirmPassword.length < 8)
            return false
        if (oldPassword.length < 1)
            return false
        if (newPassword !== confirmPassword)
            return false
        return true
    }
}