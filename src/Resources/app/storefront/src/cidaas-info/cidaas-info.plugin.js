import Plugin from 'src/plugin-system/plugin.class';
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import Debouncer from 'src/helper/debouncer.helper';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';
import CidaasUtil from '../util/cidaas-util';

export default class CidaasInfo extends Plugin {
    init() {
        this.infoShown = false;
        this.emailAuth = false;
        this.client = new HttpClient();
        this.cidaas = new CidaasUtil(this.options.cidaasUrl);
        this.clientId = this.options.clientId;
        this.nextButton = DomAccess.querySelector(document, '#weiterButton');
        this.requestId = '';
        this.redirectUrl = this.options.redirectUrl;

        this.nextLoadingThingy = new ButtonLoadingIndicatorUtil(this.nextButton);
        document.getElementById('devButton').addEventListener('click', async () => {
            let request = {
                client_id: this.clientId,
                redirect_uri: this.redirectUrl,
                response_type: 'code',
                scope: this.cidaas.getScope(),
                nonce: new Date().getTime(),
            };
            let ding = this.cidaas.checkRequestData(request);
            let response = await this.cidaas.getRequest(request);
            this.requestId = response.data.requestId;
        });

        document.getElementById('infoForm').addEventListener('submit', (evt) => {
            evt.preventDefault();
            this.nextLoadingThingy.create();
            this.email = document.getElementById('emailInput').value;
            let fixedEmail = this.email.replaceAll('+', '%2B');
            if (!this.infoShown) {
                this.client.post(
                    '/cidaas/exists',
                    JSON.stringify({
                        email: this.email,
                    }),
                    this.handleExistsData.bind(this)
                );
            } else if (this.emailAuth) {
                let redirectUrl = this.cidaas.getEmailAuthUri(
                    this.requestId,
                    this.email
                );
                window.location.href =
                    '/cidaas/login?redirect_login=email&email=' +
                    fixedEmail +
                    '&requestId=' +
                    this.requestId;
            } else {
                this.infoShown = false;
                document.getElementById('emailContainer').style.display = 'block';
                document.getElementById('infoContainer').style.display = 'none';
                this.nextLoadingThingy.remove();
            }
        });
    }

    async handleExistsData(data) {
        const userData = JSON.parse(data);
        let request = {
            client_id: this.clientId,
            redirect_uri: this.redirectUrl,
            response_type: 'code',
            scope: this.cidaas.getScope(),
            nonce: new Date().getTime(),
            state: this.options.state,
        };
        let response = await this.cidaas.getRequest(request);
        this.requestId = response.data.requestId;
        let fixedEmail = this.email.replaceAll('+', '%2B');
        if (!userData.exists) {
            let res = await this.cidaas.emailExists(this.email, this.requestId);
            if (res.success) {
                window.location.href =
                    '/cidaas/login?redirect_login=email&email=' +
                    fixedEmail +
                    '&requestId=' +
                    this.requestId;
            } else {
                window.location.href =
                    '/cidaas/register?userIdHint=' +
                    fixedEmail +
                    '&type=email';
            }
        } else if (userData.lastLogin === null) {
            this.nextLoadingThingy.remove();
            document.getElementById('emailContainer').style.display = 'none';
            document.getElementById('buttonContainer').style.display = 'none';
            document.getElementById('infoContainer').style.display = 'block';
            document.getElementById('notYet').addEventListener('click', (evt) => {
                window.location.href =
                    this.options.cidaasUrl +
                    '/identity/password_forgot_init?userIdHint=' +
                    fixedEmail +
                    '&requestId=' +
                    this.requestId +
                    '&type=email&redirect_to=' +
                    this.redirectUrl;
            });
            document.getElementById('already').addEventListener('click', (evt) => {
                window.location.href =
                    '/cidaas/login?redirect_login=email&email=' +
                    fixedEmail +
                    '&requestId=' +
                    this.requestId;
            });
        } else {
            window.location.href =
                '/cidaas/login?redirect_login=email&email=' +
                fixedEmail +
                '&requestId=' +
                this.requestId;
        }
    }
}
