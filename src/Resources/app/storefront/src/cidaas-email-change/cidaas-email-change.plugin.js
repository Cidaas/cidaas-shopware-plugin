import Plugin from 'src/plugin-system/plugin.class'
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import Debouncer from 'src/helper/debouncer.helper';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';

import CidaasUtil from '../util/cidaas-util';

import * as $ from 'jquery'

export default class CidaasEmailChange extends Plugin {
    init() {
        this.client = new HttpClient()
        $('#emailForm').on('submit', this.handleSubmit.bind(this))
        this.locale = DomAccess.getDataAttribute(document.querySelector('#emailForm'), 'locale');
        this.mailContainer = DomAccess.querySelector(document, 'div#accountMailContainer')
    }
    sleep(ms) {
        return new Promise(resolve => {
            setTimeout(resolve, ms)
        })
    }
    handleSubmit(evt){
        evt.preventDefault()
        let email1 = $('#personalMail').val()
        let email2 = $('#personalMailConfirmation').val()
        if (email1 === email2) {
            $('#personalMailConfirmation').removeClass('is-invalid')
            $('#invalidFeedback').hide()
            
            this.changeEmail(email1, email2)

        } else {
            $('#invalidFeedback').show()
            $('#personalMailConfirmation').addClass('is-invalid')
        }
    }

    async changeEmail(email1, email2) {
        this.email = email1
        $('#emailForm').hide()
        $('#emailVerifySpan').text(email1)
        $('#verifyThing').show()
        $('#verifyButton').on('click', this.handleVerify.bind(this))
    }

    handleVerify() {
        ElementLoadingIndicatorUtil.create(this.mailContainer)
        this.client.post('/cidaas/emailform', JSON.stringify({
            _csrf_token: this.options.csrf,
            email: this.email
        }), (res) => {
            ElementLoadingIndicatorUtil.remove(this.mailContainer)
            $('#verifyThing').hide()

            const fullLocale = this.locale; // Example locale string
            const localeCode = fullLocale.split('-')[0];
            window.location.href=`/${localeCode}/account/profile`
        })
    }
}