import Plugin from 'src/plugin-system/plugin.class';
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import CidaasUtil from '../util/cidaas-util';
import * as $ from 'jquery';

export default class CidaasPassword extends Plugin {

    init() {
        $('#profilePasswordForm').on('submit', this.handleFormSubmit.bind(this));

        this.newPasswordInput = $('#newPassword');
        this.confirmPasswordInput = $('#passwordConfirmation');
        this.oldPasswordInput = $('#password');
        this.locale = DomAccess.getDataAttribute(document.querySelector('#emailForm'), 'locale');
        this.localeCode = this.locale.split('-')[0];
        
        this.client = new HttpClient();

        this.client.get('/cidaas/url', (res) => {
            try {
                const result = JSON.parse(res);
                this.cidaasUrl = result.url;
                this.cidaas = new CidaasUtil(result.url);
            } catch (err) {
                console.error('Error parsing Cidaas URL response:', err);
            }
        });

        this.client.post('/cidaas/generate', JSON.stringify({
            _csrf_token: this.options.csrfGenerate
        }), (res) => {
            try {
                const result = JSON.parse(res);
                this.clientId = result.clientId;
                this.url = result.url;
                this.state = result.state;
                this.scope = 'openid offline_access email profile groups';
            } catch (err) {
                console.error('Error parsing Cidaas generate response:', err);
            }
        });
    }

    async handleFormSubmit(evt) {
        evt.preventDefault();

        if (this.checkInputFields()) {
            try {
                const response = await this.client.post('/cidaas/changepassword', JSON.stringify({
                    newPassword: this.newPasswordInput.val(),
                    oldPassword: this.oldPasswordInput.val(),
                    confirmPassword: this.confirmPasswordInput.val(),
                    _csrf_token: this.options.csrf
                }));

                const result = JSON.parse(response);
                if (result.success) {
                    this.performLogout();
                }
            } catch (err) {
                console.error('Error changing password:', err);
            }
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
        const newPassword = this.newPasswordInput.val();
        const oldPassword = this.oldPasswordInput.val();
        const confirmPassword = this.confirmPasswordInput.val();

        return newPassword.length >= 8 &&
               confirmPassword.length >= 8 &&
               oldPassword.length > 0 &&
               newPassword === confirmPassword;
    }
}
