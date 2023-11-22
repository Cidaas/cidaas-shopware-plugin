# SETUP GUIDE

## Prerequisites

- Install docker in your system. Link to install docker [here](https://docs.docker.com/engine/install/)
- Install docker compose. Link to install docker composer [here](https://docs.docker.com/compose/install/standalone/)

### Follow the steps below to setup the plugin and test

1. clone the shopware plugin repository from remote. Link to the repository is [here](https://gitlab.widas.de/cidaas-public-devkits/cidaas-plugins/cidaas-shopware-plugin)
2. change the directory to the shopware-plugin folder or you can run the command `cd shopware-plugin`
3. run the command `docker compose up --build`. This may take a while to startup up container. Once done you will notice the log as shared below

```ssh
WOHOOO, dockware/dev:6.5.4.0 IS READY :) - let's get started
-----------------------------------------------------
DOCKWARE CHANGELOG: /var/www/CHANGELOG.md
PHP: PHP 7.4.33 (cli) (built: Feb 14 2023 18:30:50) ( NTS )
Apache DocRoot: /var/www/html/public
URLs (if you are using a custom domain, make sure its available using /etc/hosts or other approaches)
ADMINER URL: http://localhost/adminer.php
MAILCATCHER URL: http://localhost/mailcatcher
PIMPMYLOG URL: http://localhost/logs
SHOP URL: http://localhost
ADMIN URL: http://localhost/admin

What's new in this version? see the changelog for further details
https://www.shopware.com/de/changelog/
```

4. The shopware app is now ready to access. You can use the links shared in the log access the apps. To test the plugin we only need the **Admin** app and **Shop** app.

5. Access the admin app usting the `ADMIN URL` from the log. In our case, `http://localhost/admin` Use the credentials below to login to the app

```json
username: admin
password: shopware
```

6. Install the plugin `Cidaas SSO - OpenId Connect` from the section `My extensions`
7. Enable and configure the plugin by adding `client id`, `client secret` and `base url`. You can setup a client for shopware plugin in cidaas admin app following the [wiki](https://docs-old.cidaas.com/extension/shopware_plugin.html). Please read the README in the root folder for more details
8. Click on save
9. Now you are ready to access the shop app :). Access the `SHOP URL`. In our case, the link is `http://localhost`
10. Click on the profile icon and now you can start exploring `Cidaas shopware plugin` by clicking on `Login` or `Signup`

Happy Exploring :)
