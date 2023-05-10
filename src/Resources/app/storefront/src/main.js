import CidaasLogin from "./cidaas-login/cidaas-login.plugin";
import CidaasInfo from "./cidaas-info/cidaas-info.plugin";
import CidaasEmailChange from './cidaas-email-change/cidaas-email-change.plugin'
import CidaasPassword from './cidaas-password/cidaas-password.plugin'

window.PluginManager.register(
    'CidaasLogin',
    CidaasLogin,
    '[data-cidaas-login]'
)

window.PluginManager.register(
    'CidaasInfo',
    CidaasInfo,
    '[data-cidaas-info]'
)

window.PluginManager.register(
    'CidaasEmailChange',
    CidaasEmailChange,
    '[data-cidaas-email-change]'
)

window.PluginManager.register(
    'CidaasPassword',
    CidaasPassword,
    '[data-cidaas-password]'
)

if (module.hot) {
    module.hot.accept();
}
