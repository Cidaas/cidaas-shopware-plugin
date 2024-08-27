import Plugin from 'src/plugin-system/plugin.class'
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';

import * as $ from 'jquery'

export default class CidaasEmailChange extends Plugin {
    init() {
        this.client = new HttpClient()
        $('#emailForm').on('submit', this.handleSubmit.bind(this))
        this.mailContainer = DomAccess.querySelector(document, 'div#accountMailContainer')
    }
    sleep(ms) {
        return new Promise(resolve => {
            setTimeout(resolve, ms)
        })
    }
    handleSubmit(evt) {
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
            this.redirectProfilePath();
        })
    }


    redirectProfilePath() {
        // Determine the base URL
        const baseUrl = `${window.location.protocol}//${window.location.host}`;
        // Optional: Get the locale from the current URL if it's available
        const path = window.location.pathname;
        const localeMatch = path.match(/^\/([a-z]{2})(\/|$)/i);
        const locale = localeMatch ? localeMatch[1] : '';

        // Construct the profile URL, including locale if applicable
        const profileUrl = locale ? `${baseUrl}/${locale}/account/profile` : `${baseUrl}/account/profile`;

        // Redirect to the logout URL
        window.location.href = profileUrl;

    }
}