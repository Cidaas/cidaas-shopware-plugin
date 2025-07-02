# SETUP GUIDE

## Prerequisites

- Install Docker on your system. You can find the installation guide [here](https://docs.docker.com/engine/install/).
- Install Docker Compose. The installation guide for Docker Compose is available [here](https://docs.docker.com/compose/install/standalone/).

### Follow the steps below to set up the plugin and test it

1. Clone the Shopware plugin repository from the remote repository. The repository link is [here](https://gitlab.widas.de/cidaas-public-devkits/cidaas-plugins/cidaas-shopware-plugin).
2. Change the directory to the `shopware-plugin` folder or run the command: `cd shopware-plugin`.
3. Run the command `docker compose up --build`. This may take a while to start up the container. Once done, you will see the following log:

```ssh
WOHOOO, dockware/dev:6.5.4.0 IS READY :) - let's get started
-----------------------------------------------------
DOCKWARE CHANGELOG: /var/www/CHANGELOG.md
PHP: PHP 7.4.33 (cli) (built: Feb 14 2023 18:30:50) ( NTS )
Apache DocRoot: /var/www/html/public
URLs (if you are using a custom domain, make sure it's available using /etc/hosts or other approaches)
ADMINER URL: http://localhost/adminer.php
MAILCATCHER URL: http://localhost/mailcatcher
PIMPMYLOG URL: http://localhost/logs
SHOP URL: http://localhost
ADMIN URL: http://localhost/admin

What's new in this version? See the changelog for further details:
https://www.shopware.com/de/changelog/
```

4. The Shopware app is now ready to access. You can use the links shared in the log to access the apps. To test the plugin, we only need the **Admin** app and the **Shop** app.

5. Access the Admin app using the `ADMIN URL` from the log. In this case, it would be `http://localhost/admin`. Use the following credentials to log in:

```json
username: admin
password: shopware
```

6. Install the plugin `Cidaas SSO - OpenID Connect` from the `My Extensions` section.
7. Enable and configure the plugin by adding the `Client ID`, `Client Secret`, and `Base URL`. You can set up a client for the Shopware plugin in the Cidaas Admin app by following this [wiki guide](https://docs.cidaas.com/docs/integration-doc/96y2q24sbw3jf-requirements-installation). Please refer to the README in the root folder for more details.
8. Click on **Save**.
9. Now you are ready to access the Shop app :). Go to the `SHOP URL`, which in this case is `http://localhost`.
10. Click on the profile icon and explore the `Cidaas Shopware Plugin` by clicking on **Login** or **Signup**.

Happy Exploring! :)