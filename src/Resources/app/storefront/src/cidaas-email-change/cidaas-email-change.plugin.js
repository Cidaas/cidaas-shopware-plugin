import Plugin from 'src/plugin-system/plugin.class';
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import Debouncer from 'src/helper/debouncer.helper';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';
import CidaasUtil from '../util/cidaas-util';

export default class CidaasEmailChange extends Plugin {

    init() {
        this.client = new HttpClient();
        const emailForm = document.getElementById('emailForm');
        console.log(emailForm)
        emailForm.addEventListener('submit', this.handleSubmit.bind(this));
        // ElementLoadingIndicatorUtil.create(this.mediaDiv);
        this.mailContainer = DomAccess.querySelector(document, 'div#accountMailContainer');
    }

    sleep(ms) {
        return new Promise(resolve => {
            setTimeout(resolve, ms);
        });
    }

    handleSubmit(evt) {
        evt.preventDefault();

        console.log(evt)
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
        this.email = email1;
        document.getElementById('emailForm').style.display = 'none';
        document.getElementById('emailVerifySpan').textContent = email1;
        document.getElementById('verifyThing').style.display = 'block';
        document.getElementById('verifyButton').addEventListener('click', this.handleVerify.bind(this));
    }

    handleVerify() {
        ElementLoadingIndicatorUtil.create(this.mailContainer);
        this.client.post(
            '/cidaas/emailform',
            JSON.stringify({
                email: this.email
            }),
            (res) => {
                ElementLoadingIndicatorUtil.remove(this.mailContainer);
                document.getElementById('verifyThing').style.display = 'none';
                window.location.href = '/account';
            }
        );
    }
}
