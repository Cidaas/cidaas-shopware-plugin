import Plugin from 'src/plugin-system/plugin.class'
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import Debouncer from 'src/helper/debouncer.helper';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';

import CidaasUtil from '../util/cidaas-util';

import * as $ from 'jquery'

export default class CidaasPassword extends Plugin {
    
    init() {
        $('#profilePasswordForm').on('submit', this.handleFormSubmit.bind(this))
        this.newPasswordInput = $('#newPassword')
        this.confirmPasswordInput = $('#passwordConfirmation')
        this.oldPasswordInput = $('#password')
        this.locale = DomAccess.getDataAttribute(document.querySelector('#emailForm'), 'locale')
        this.localeCode = this.locale.split('-')[0]
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
                        window.location.href = `/${this.localeCode}/account/logout`
                    }
                } catch (err) {
                    
                }
            })
        }
    }

    sendSuccessInfo() {
        this.client.post('/cidaas/changepassword', JSON.stringify({
            result: true,
            _csrf_token: this.options.csrf
        }) ,(res) => {
            window.location.href = `/${this.localeCode}/account`
        })
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