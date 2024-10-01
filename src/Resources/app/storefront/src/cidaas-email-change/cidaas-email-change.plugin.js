import Plugin from 'src/plugin-system/plugin.class'
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';

export default class CidaasEmailChange extends Plugin {
    init() {
        this.client = new HttpClient();
        const emailForm = document.getElementById('emailForm');
        emailForm.addEventListener('submit', this.handleSubmit.bind(this));
        this.mailContainer = DomAccess.querySelector(document, 'div#accountMailContainer');
    }

    sleep(ms) {
        return new Promise(resolve => {
            setTimeout(resolve, ms)
        })
    }

    handleSubmit(evt) {

        evt.preventDefault();

        let email1 = document.getElementById('personalMail').value;
        let email2 = document.getElementById('personalMailConfirmation').value;
        if (email1 === email2) {
            document.getElementById('personalMailConfirmation').classList.remove('is-invalid');
            document.getElementById('invalidFeedback').style.display = 'none';
            this.changeEmail(email1, email2);
        } else {
            document.getElementById('invalidFeedback').style.display = 'block';
            document.getElementById('personalMailConfirmation').classList.add('is-invalid');
        }
    }

    async changeEmail(email1, email2) {
        this.email = email1
        document.getElementById('emailForm').style.display = 'none';
        document.getElementById('emailVerifySpan').textContent = email1;
        document.getElementById('verifyThing').style.display = 'block';
        document.getElementById('verifyButton').addEventListener('click', this.handleVerify.bind(this));
    }

    handleVerify() {
        ElementLoadingIndicatorUtil.create(this.mailContainer);
        this.client.post('/cidaas/change/email', JSON.stringify({
            email: this.email
        }), (res) => {
            ElementLoadingIndicatorUtil.remove(this.mailContainer);
            document.getElementById('verifyThing').style.display = 'none';
            this.redirectProfilePath();
        });
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
