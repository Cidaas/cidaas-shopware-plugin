import Plugin from 'src/plugin-system/plugin.class';
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';

export default class CidaasLogin extends Plugin {
    static options = {
        // Add your options here if needed
    };
    
    init() {
        this.client = new HttpClient();
        this.email = null;
        this.password = null;
        this.nextButton = DomAccess.querySelector(document, '#nextButton');
        this.nextLoadingThingy = new ButtonLoadingIndicatorUtil(this.nextButton);
        this.nextButton.addEventListener('click', (evt) => {
            if (this.email === null) {
                this.email = document.querySelector('#email').value;
                this.nextLoadingThingy.create();
                this.client.post(this.options.cidaas + '/users-srv/user/checkexists/' + this.options.requestId, JSON.stringify({
                    email: this.email,
                    requestId: this.options.requestId
                }), (res) => {
                    if (res) {
                        let result = JSON.parse(res);
                        if (result.success) {
                            this.client.post('/cidaas/exists', JSON.stringify({
                                email: this.email
                            }), (res2) => {
                                let result2 = JSON.parse(res2);
                                if (result2.exists) {
                                    this.client.get('/cidaas/lastlogin/' + result2.id, (res3) => {
                                        let result3 = JSON.parse(res3);
                                        if (result3.lastLogin !== null) {
                                            document.querySelector('#emailContainer').style.display = 'none';
                                            document.querySelector('#passwordContainer').style.display = 'block';
                                            document.querySelector('#nextButton').textContent = 'Login';
                                            this.nextLoadingThingy.remove();
                                            document.querySelector('#password').focus();
                                        } else {
                                            document.querySelector('#emailContainer').style.display = 'none';
                                            document.querySelector('#onetimePassword').style.display = 'block';
                                            this.nextLoadingThingy.remove();
                                            document.querySelector('#nextButton').style.display = 'none';
                                            document.querySelector('#toOtpLink').setAttribute('href', this.options.cidaas + '/identity/login/initiate?userIdHint=' + encodeURI(this.email) + '&requestId=' + this.options.requestId + '&type=email');
                                        }
                                    });
                                }
                            });
                        } else {
                            document.querySelector('#emailContainer').style.display = 'none';
                            document.querySelector('#nextButton').style.display = 'none';
                            this.nextLoadingThingy.remove();
                            document.querySelector('#complete').style.display = 'block';
                        }
                    } else {
                        window.location.href = '/cidaas/register?userIdHint=' + this.email + '&type=email';
                    }
                    
                });
            } else if (this.password === null) {
                this.password = document.querySelector('#password').value;
                document.querySelector('#loginForm').setAttribute('action', 'https://my-test.mainz05.de/login-srv/login');
                document.querySelector('#loginForm').dispatchEvent(new Event('submit'));
            }
        });
    }
    
    handleFormResponse(response) {
        // window.location.reload();
    }
}
