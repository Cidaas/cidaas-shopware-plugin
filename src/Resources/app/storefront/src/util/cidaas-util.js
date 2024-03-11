import HttpClient from 'src/service/http-client.service';

export default class CidaasUtil {
    constructor(url) {
        this.init(url);
    }

    init(url) {
        this.client = new HttpClient();
        this.url = url;
        this.scope = "openid email profile groups";
        this.cidaasUris = {
            generateRequest: '/authz-srv/authrequest/authz/generate',
            login: '/login-srv/login',
            changePassword: '/users-srv/changepassword',
            logout: '/session/end_session',
            token: '/token-srv/token',
            emailAuth: '/identity/login/initiate'
        };
    }

    getRequest(request) {
        return new Promise((resolve, reject) => {
            if (!this.checkRequestData(request)) {
                reject('invalid object');
            }
            this.client.post(this.url + this.cidaasUris.generateRequest, JSON.stringify(request), (res) => {
                resolve(JSON.parse(res));
            });
        });
    }

    getScope() {
        return this.scope;
    }

    checkRequestData(request) {
        let keys = Object.keys(request);
        let valid = true;
        const required = [
            'client_id',
            'redirect_uri',
            'response_type',
            'scope',
            'state'
        ];
        required.forEach(val => {
            if (keys.indexOf(val) < 0 || ("" + request[val].length) < 1) {
                valid = false;
            }
        });
        return valid;
    }

    getEmailAuthUri(requestId, email) {
        let result = '' + this.url + this.cidaasUris.emailAuth + '?userIdHint=' + email + '&requestId=' + requestId + '&type=email';
        return result;
    }

    emailExists(email, requestId) {
        return new Promise(resolve => {
            this.client.post(this.url + '/users-srv/user/checkexists/' + requestId, JSON.stringify({
                email,
                requestId
            }), (res) => {
                try {
                    let result = JSON.parse(res);
                    if (result) {
                        return resolve(result);
                    }
                } catch (err) {
                    return resolve({ exists: false });
                }
                return resolve({ exists: false });
            });
        });
    }

    changePassword(oldPassword, newPassword, confirmPassword, sub) {
        return new Promise((resolve, reject) => {
            this.client.post(this.url + '/users-srv/changepassword', JSON.stringify({
                new_password: newPassword,
                old_password: oldPassword,
                confirm_password: confirmPassword,
                identityId: sub
            }), (res) => {
                try {
                    let result = JSON.parse(res);
                    resolve(result);
                } catch (err) {
                    reject(err);
                }
            });
        });
    }
}
