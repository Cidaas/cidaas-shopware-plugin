import Plugin from 'src/plugin-system/plugin.class';
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import Debouncer from 'src/helper/debouncer.helper';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';
import CidaasUtil from '../util/cidaas-util';

export default class CidaasPassword extends Plugin {
    init() {
        const profilePasswordForm = document.getElementById('profilePasswordForm');
        profilePasswordForm.addEventListener('submit', this.handleFormSubmit.bind(this));

        this.newPasswordInput = document.getElementById('newPassword');
        this.confirmPasswordInput = document.getElementById('passwordConfirmation');
        this.oldPasswordInput = document.getElementById('password');

        this.client = new HttpClient();
        this.client.get('/cidaas/url', (res) => {
            try {
                const result = JSON.parse(res);
                this.cidaasUrl = result.url;
                this.cidaas = new CidaasUtil(result.url);
            } catch (err) {
                console.log(err, res);
            }
        });

        this.client.post('/cidaas/generate', {}, (res) => {
            const result = JSON.parse(res);
            this.clientId = result.clientId;
            this.url = result.url;
            this.state = result.state;
            this.scope = "openid email profile";
        });
    }

    async handleFormSubmit(evt) {
        evt.preventDefault();
        if (this.checkInputFields()) {
            this.client.post('/cidaas/changepassword', JSON.stringify({
                newPassword: this.newPasswordInput.value,
                oldPassword: this.oldPasswordInput.value,
                confirmPassword: this.confirmPasswordInput.value,
            }), (res) => {
                try {
                    const result = JSON.parse(res);
                    if (result.success) {
                        window.location.href = "/account";
                    }
                } catch (err) {
                    // Handle error
                    console.log(err)
                }
            });
        }
    }

    sendSuccessInfo() {
        this.client.post('/cidaas/changepassword', JSON.stringify({
            result: true,
        }), (res) => {
            window.location.href = "/account";
        });
    }

    checkInputFields() {
        const newPassword = this.newPasswordInput.value;
        const oldPassword = this.oldPasswordInput.value;
        const confirmPassword = this.confirmPasswordInput.value;

        if (newPassword.length < 8) {
            return false;
        }
        if (confirmPassword.length < 8) {
            return false;
        }
        if (oldPassword.length < 1) {
            return false;
        }
        if (newPassword !== confirmPassword) {
            return false;
        }
        return true;
    }
}
