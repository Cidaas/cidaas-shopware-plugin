FROM dockware/dev:6.4.17.0
COPY . ./custom/plugins/cidaassso-main
COPY ./ssl etc/apache2/ssl
EXPOSE 443