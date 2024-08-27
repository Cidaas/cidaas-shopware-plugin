(window.webpackJsonp=window.webpackJsonp||[]).push([["cidaas-oauth-connect"],{"7VVN":function(e,t,n){"use strict";n.r(t);var i=n("FGIj"),o=n("gHbT"),r=n("k8s9"),a=(n("nhVY"),n("u0Tz")),s=n("477Q"),c=n("UoTJ");function u(e){return(u="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function l(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function f(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}function p(e,t){return!t||"object"!==u(t)&&"function"!=typeof t?function(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}(e):t}function d(e){return(d=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}function h(e,t){return(h=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}var y,m,w,v=function(e){function t(){return l(this,t),p(this,d(t).apply(this,arguments))}var n,i,a;return function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&h(e,t)}(t,e),n=t,(i=[{key:"init",value:function(){var e=this;this.client=new r.a,this.email=null,this.password=null,this.nextButton=o.a.querySelector(document,"#nextButton"),this.nextLoadingThingy=new s.a(this.nextButton),c("#nextButton").on("click",(function(t){null===e.email?(e.email=c("#email").val(),e.nextLoadingThingy.create(),e.client.post(e.options.cidaas+"/users-srv/user/checkexists/"+e.options.requestId,JSON.stringify({email:e.email,requestId:e.options.requestId}),(function(t){t?JSON.parse(t).success?e.client.post("/cidaas/exists",JSON.stringify({email:e.email,_csrf_token:e.options.csrfExists}),(function(t){var n=JSON.parse(t);n.exists&&e.client.get("/cidaas/lastlogin/"+n.id,(function(t){null!==JSON.parse(t).lastLogin?(c("#emailContainer").hide(),c("#passwordContainer").show(),c("#nextButton").text("Login"),e.nextLoadingThingy.remove(),c("#password").focus()):(c("#emailContainer").hide(),c("#onetimePassword").show(),e.nextLoadingThingy.remove(),c("#nextButton").hide(),c("#toOtpLink").attr("href",e.options.cidaas+"/identity/login/initiate?userIdHint="+encodeURI(e.email)+"&requestId="+e.options.requestId+"&type=email"))}))})):(c("#emailContainer").hide(),c("#nextButton").hide(),e.nextLoadingThingy.remove(),c("#complete").show()):window.location.href="/cidaas/register?userIdHint="+e.email+"&type=email"}))):null===e.password&&(e.password=c("#password").val(),c("#loginForm").attr("action","https://my-test.mainz05.de/login-srv/login"),c("#loginForm").trigger("submit"))}))}},{key:"handleFormResponse",value:function(e){}}])&&f(n.prototype,i),a&&f(n,a),t}(i.a);function g(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}w={},(m="options")in(y=v)?Object.defineProperty(y,m,{value:w,enumerable:!0,configurable:!0,writable:!0}):y[m]=w;var b=function(){function e(t){!function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,e),this.init(t)}var t,n,i;return t=e,(n=[{key:"init",value:function(e){this.client=new r.a,this.url=e,this.scope="openid offline_access email profile groups",this.cidaasUris={generateRequest:"/authz-srv/authrequest/authz/generate",login:"/login-srv/login",changePassword:"/users-srv/changepassword",logout:"/session/end_session",token:"/token-srv/token",emailAuth:"/identity/login/initiate"}}},{key:"getRequest",value:function(e){var t=this;return new Promise((function(n,i){t.checkRequestData(e)||i("invalid object"),t.client.post(t.url+t.cidaasUris.generateRequest,JSON.stringify(e),(function(e){n(JSON.parse(e))}))}))}},{key:"getScope",value:function(){return this.scope}},{key:"checkRequestData",value:function(e){var t=Object.keys(e),n=!0;return["client_id","redirect_uri","response_type","scope","state"].forEach((function(i){(t.indexOf(i)<0||""+e[i].length<1)&&(n=!1)})),n}},{key:"getEmailAuthUri",value:function(e,t){return""+this.url+this.cidaasUris.emailAuth+"?userIdHint="+t+"&requestId="+e+"&type=email"}},{key:"emailExists",value:function(e,t){var n=this;return new Promise((function(i){n.client.post(n.url+"/users-srv/user/checkexists/"+t,JSON.stringify({email:e,requestId:t}),(function(e){try{var t=JSON.parse(e);if(t)return i(t)}catch(e){return i({exists:!1})}return i({exists:!1})}))}))}},{key:"changePassword",value:function(e,t,n,i){var o=this;return new Promise((function(r,a){o.client.post(o.url+"/users-srv/changepassword",JSON.stringify({new_password:t,old_password:e,confirm_password:n,identityId:i}),(function(e){try{var t=JSON.parse(e);r(t)}catch(e){a(e)}}))}))}}])&&g(t.prototype,n),i&&g(t,i),e}();function O(e){return(O="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function _(e,t,n,i,o,r,a){try{var s=e[r](a),c=s.value}catch(e){return void n(e)}s.done?t(c):Promise.resolve(c).then(i,o)}function k(e){return function(){var t=this,n=arguments;return new Promise((function(i,o){var r=e.apply(t,n);function a(e){_(r,i,o,a,s,"next",e)}function s(e){_(r,i,o,a,s,"throw",e)}a(void 0)}))}}function P(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function S(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}function I(e,t){return!t||"object"!==O(t)&&"function"!=typeof t?function(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}(e):t}function x(e){return(x=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}function q(e,t){return(q=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}var j=function(e){function t(){return P(this,t),I(this,x(t).apply(this,arguments))}var n,i,a,u;return function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&q(e,t)}(t,e),n=t,(i=[{key:"init",value:function(){var e=this;this.infoShown=!1,this.emailAuth=!1,this.client=new r.a,this.cidaas=new b(this.options.cidaasUrl),this.clientId=this.options.clientId,this.nextButton=o.a.querySelector(document,"#weiterButton"),this.requestId="",this.redirectUrl=this.options.redirectUrl,this.nextLoadingThingy=new s.a(this.nextButton),c("#devButton").on("click",k(regeneratorRuntime.mark((function t(){var n,i;return regeneratorRuntime.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return n={client_id:e.clientId,redirect_uri:e.redirectUrl,response_type:"code",scope:e.cidaas.getScope(),nonce:(new Date).getTime()},e.cidaas.checkRequestData(n),t.next=4,e.cidaas.getRequest(n);case 4:i=t.sent,e.requestId=i.data.requestId;case 6:case"end":return t.stop()}}),t)})))),c("#infoForm").on("submit",(function(t){t.preventDefault(),e.nextLoadingThingy.create(),e.email=c("#emailInput").val();var n=e.email.replaceAll("+","%2B");e.infoShown?e.emailAuth?(e.cidaas.getEmailAuthUri(e.requestId,e.email),window.location.href="/cidaas/login?redirect_login=email&email="+n+"&requestId="+e.requestId):(e.infoShown=!1,c("#emailContainer").show(),c("#infoContainer").hide(),e.nextLoadingThingy.remove()):e.client.post("/cidaas/exists",JSON.stringify({email:e.email,_csrf_token:e.options.csrf}),e.handleExistsData.bind(e))}))}},{key:"handleExistsData",value:(u=k(regeneratorRuntime.mark((function e(t){var n,i,o,r,a=this;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n=JSON.parse(t),i={client_id:this.clientId,redirect_uri:this.redirectUrl,response_type:"code",scope:this.cidaas.getScope(),nonce:(new Date).getTime(),state:this.options.state},e.next=4,this.cidaas.getRequest(i);case 4:if(o=e.sent,this.requestId=o.data.requestId,r=this.email.replaceAll("+","%2B"),n.exists){e.next=14;break}return e.next=10,this.cidaas.emailExists(this.email,this.requestId);case 10:e.sent.success?window.location.href="/cidaas/login?redirect_login=email&email="+r+"&requestId="+this.requestId:window.location.href="/cidaas/register?userIdHint="+r+"&type=email",e.next=15;break;case 14:null===n.lastLogin?(this.nextLoadingThingy.remove(),c("#emailContainer").hide(),c("#buttonContainer").hide(),c("#infoContainer").show(),c("#notYet").on("click",(function(e){window.location.href=a.options.cidaasUrl+"/identity/password_forgot_init?userIdHint="+r+"&requestId="+a.requestId+"&type=email&redirect_to="+a.redirectUrl})),c("#already").on("click",(function(e){window.location.href="/cidaas/login?redirect_login=email&email="+r+"&requestId="+a.requestId}))):window.location.href="/cidaas/login?redirect_login=email&email="+r+"&requestId="+this.requestId;case 15:case"end":return e.stop()}}),e,this)}))),function(e){return u.apply(this,arguments)})}])&&S(n.prototype,i),a&&S(n,a),t}(i.a);function C(e){return(C="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function T(e,t,n,i,o,r,a){try{var s=e[r](a),c=s.value}catch(e){return void n(e)}s.done?t(c):Promise.resolve(c).then(i,o)}function E(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function J(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}function R(e,t){return!t||"object"!==C(t)&&"function"!=typeof t?function(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}(e):t}function N(e){return(N=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}function L(e,t){return(L=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}var U=function(e){function t(){return E(this,t),R(this,N(t).apply(this,arguments))}var n,i,s,u,l;return function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&L(e,t)}(t,e),n=t,(i=[{key:"init",value:function(){this.client=new r.a,c("#emailForm").on("submit",this.handleSubmit.bind(this)),this.mailContainer=o.a.querySelector(document,"div#accountMailContainer")}},{key:"sleep",value:function(e){return new Promise((function(t){setTimeout(t,e)}))}},{key:"handleSubmit",value:function(e){e.preventDefault();var t=c("#personalMail").val(),n=c("#personalMailConfirmation").val();t===n?(c("#personalMailConfirmation").removeClass("is-invalid"),c("#invalidFeedback").hide(),this.changeEmail(t,n)):(c("#invalidFeedback").show(),c("#personalMailConfirmation").addClass("is-invalid"))}},{key:"changeEmail",value:(u=regeneratorRuntime.mark((function e(t,n){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:this.email=t,c("#emailForm").hide(),c("#emailVerifySpan").text(t),c("#verifyThing").show(),c("#verifyButton").on("click",this.handleVerify.bind(this));case 5:case"end":return e.stop()}}),e,this)})),l=function(){var e=this,t=arguments;return new Promise((function(n,i){var o=u.apply(e,t);function r(e){T(o,n,i,r,a,"next",e)}function a(e){T(o,n,i,r,a,"throw",e)}r(void 0)}))},function(e,t){return l.apply(this,arguments)})},{key:"handleVerify",value:function(){var e=this;a.a.create(this.mailContainer),this.client.post("/cidaas/emailform",JSON.stringify({_csrf_token:this.options.csrf,email:this.email}),(function(t){a.a.remove(e.mailContainer),c("#verifyThing").hide(),e.redirectProfilePath()}))}},{key:"redirectProfilePath",value:function(){var e="".concat(window.location.protocol,"//").concat(window.location.host),t=window.location.pathname.match(/^\/([a-z]{2})(\/|$)/i),n=t?t[1]:"",i=n?"".concat(e,"/").concat(n,"/account/profile"):"".concat(e,"/account/profile");window.location.href=i}}])&&J(n.prototype,i),s&&J(n,s),t}(i.a);function B(e){return(B="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function F(e,t,n,i,o,r,a){try{var s=e[r](a),c=s.value}catch(e){return void n(e)}s.done?t(c):Promise.resolve(c).then(i,o)}function D(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}function M(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}function A(e,t){return!t||"object"!==B(t)&&"function"!=typeof t?function(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}(e):t}function V(e){return(V=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}function z(e,t){return(z=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}var H=function(e){function t(){return D(this,t),A(this,V(t).apply(this,arguments))}var n,i,o,a,s;return function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&z(e,t)}(t,e),n=t,(i=[{key:"init",value:function(){var e=this;c("#profilePasswordForm").on("submit",this.handleFormSubmit.bind(this)),this.newPasswordInput=c("#newPassword"),this.confirmPasswordInput=c("#passwordConfirmation"),this.oldPasswordInput=c("#password"),this.client=new r.a,this.client.get("/cidaas/url",(function(t){try{var n=JSON.parse(t);e.cidaasUrl=n.url,e.cidaas=new b(n.url)}catch(e){console.log(e,t)}})),this.client.post("/cidaas/generate",JSON.stringify({_csrf_token:this.options.csrfGenerate}),(function(t){var n=JSON.parse(t);e.clientId=n.clientId,e.url=n.url,e.state=n.state,e.scope="openid offline_access email profile groups"}))}},{key:"handleFormSubmit",value:(a=regeneratorRuntime.mark((function e(t){var n=this;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:t.preventDefault(),this.checkInputFields()&&this.client.post("/cidaas/changepassword",JSON.stringify({newPassword:this.newPasswordInput.val(),oldPassword:this.oldPasswordInput.val(),confirmPassword:this.confirmPasswordInput.val(),_csrf_token:this.options.csrf}),(function(e){try{JSON.parse(e).success&&n.performLogout()}catch(e){}}));case 2:case"end":return e.stop()}}),e,this)})),s=function(){var e=this,t=arguments;return new Promise((function(n,i){var o=a.apply(e,t);function r(e){F(o,n,i,r,s,"next",e)}function s(e){F(o,n,i,r,s,"throw",e)}r(void 0)}))},function(e){return s.apply(this,arguments)})},{key:"performLogout",value:function(){var e="".concat(window.location.protocol,"//").concat(window.location.host),t=window.location.pathname.match(/^\/([a-z]{2})(\/|$)/i),n=t?t[1]:"",i=n?"".concat(e,"/").concat(n,"/account/logout"):"".concat(e,"/account/logout");window.location.href=i}},{key:"checkInputFields",value:function(){var e=this.newPasswordInput.val(),t=this.oldPasswordInput.val(),n=this.confirmPasswordInput.val();return!(e.length<8||n.length<8||t.length<1||e!==n)}}])&&M(n.prototype,i),o&&M(n,o),t}(i.a);window.PluginManager.register("CidaasLogin",v,"[data-cidaas-login]"),window.PluginManager.register("CidaasInfo",j,"[data-cidaas-info]"),window.PluginManager.register("CidaasEmailChange",U,"[data-cidaas-email-change]"),window.PluginManager.register("CidaasPassword",H,"[data-cidaas-password]")}},[["7VVN","runtime","vendor-node","vendor-shared"]]]);