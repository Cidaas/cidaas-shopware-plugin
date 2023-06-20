import Plugin from 'src/plugin-system/plugin.class'
import DomAccess from 'src/helper/dom-access.helper';
import HttpClient from 'src/service/http-client.service';
import Debouncer from 'src/helper/debouncer.helper';
import ElementLoadingIndicatorUtil from 'src/utility/loading-indicator/element-loading-indicator.util';
import ButtonLoadingIndicatorUtil from 'src/utility/loading-indicator/button-loading-indicator.util';
import * as $ from 'jquery'

export default class CidaasLogin extends Plugin {
    static options = {

    }
    
    init() {
        this.client = new HttpClient()
        this.email = null
        this.password = null
        this.nextButton = DomAccess.querySelector(document, '#nextButton')
        this.nextLoadingThingy = new ButtonLoadingIndicatorUtil(this.nextButton)
        $('#nextButton').on('click', (evt) => {
            if (this.email === null) {
                this.email = $('#email').val()
                this.nextLoadingThingy.create()
                this.client.post(this.options.cidaas+'/users-srv/user/checkexists/'+this.options.requestId, JSON.stringify({
                    email: this.email,
                    requestId: this.options.requestId
                }), (res) => {
                    if (res) {
                        let result = JSON.parse(res)
                        if (result.success) {
                            this.client.post('/cidaas/exists', JSON.stringify({
                                email: this.email,
                                _csrf_token: this.options.csrfExists
                            }), (res2) => {
                                let result2 = JSON.parse(res2)
                                if (result2.exists) {
                                    this.client.get('/cidaas/lastlogin/'+result2.id, (res3) => {
                                        let result3 = JSON.parse(res3)
                                        if (result3.lastLogin !== null) {
                                            $('#emailContainer').hide()
                                            $('#passwordContainer').show()
                                            $('#nextButton').text('Login')
                                            this.nextLoadingThingy.remove()
                                            $('#password').focus()
                                        } else {
                                            $('#emailContainer').hide()
                                            $('#onetimePassword').show()
                                            this.nextLoadingThingy.remove()
                                            $('#nextButton').hide();
                                            $('#toOtpLink').attr('href', this.options.cidaas+'/identity/login/initiate?userIdHint='+encodeURI(this.email)+'&requestId='+this.options.requestId+'&type=email')
                                        }
                                    })
                                }
                            })
                        } else {
                            $('#emailContainer').hide()
                            $('#nextButton').hide()
                            this.nextLoadingThingy.remove()
                            $('#complete').show()
                        }
                    } else {
                        window.location.href='/cidaas/register?userIdHint='+this.email+'&type=email'
                    }
                    
                })
            } else if (this.password === null) {
                this.password = $('#password').val()
                $('#loginForm').attr('action', 'https://my-test.mainz05.de/login-srv/login')
                $('#loginForm').trigger('submit')
            }
        })
        // $('#loginForm').on('submit', evt => {
        //     evt.preventDefault()
        //     if (this.email === null) {
        //         this.email = $('#email').val()
        //         this.nextLoadingThingy.create()
        //         this.client.post('/cidaas/exists', JSON.stringify({
        //             email: this.email,
        //             _csrf_token: this.options.csrfExists
        //         }), (res) => {
        //             let result = JSON.parse(res)
        //             if (result.exists) {
        //                 $('#emailContainer').hide()
        //                 $('#passwordContainer').show()
        //                 $('#nextButton').text('Login')
        //                 this.nextLoadingThingy.remove()
        //                 $('#password').focus()
        //             } else {
        //                 $('#emailContainer').hide()
        //                 $('#nextButton').hide()
        //                 this.nextLoadingThingy.remove()
        //                 $('#complete').show()
        //             }
        //         })
        //     } else if (this.password === null) {
        //         this.password = $('#password').val()
        //         $('#loginForm').attr('action', 'http://shop-test.local:9998/cidaas/dev3')
        //     } else {
        //         Document.getElementById('loginForm').submit();
        //     }
        // })
    }
// ElementLoadingIndicatorUtil.create(this.mediaDiv)
    handleFormResponse(response) {
        // window.location.reload()

    }
}