![Logo](logo.jpg)

## About cidaas:
[cidaas](https://www.cidaas.com)
 is a fast and secure Cloud Identity & Access Management solution that standardises what’s important and simplifies what’s complex.

## Feature set includes:
* Single Sign On (SSO) based on OAuth 2.0, OpenID Connect, SAML 2.0 
* Multi-Factor-Authentication with more than 14 authentication methods, including TOTP and FIDO2 
* Passwordless Authentication 
* Social Login (e.g. Facebook, Google, LinkedIn and more) as well as Enterprise Identity Provider (e.g. SAML or AD) 
* Security in Machine-to-Machine (M2M) and IoT

# Cidaas SSO plugin

## Shopware extension to connect to [cidaas](https://www.cidaas.com) by Widas ID

## Author

[Joshua Kopp](mailto:me@joshuakopp.de?subject=Shopware-Plugin-Cidaas)

## Requirements / Installation

- Installation of the plugin via upload
- Activate and configure under 'My extension'
- Store Client-ID & Secret as well as Url of the IDP
- Select standard customer group and enter a field for the customer number
- Customer group assignment is coming in the next version

## Prerequisite CustomFields

The address must be mapped via the CustomFields:

Salutation
: field name `salutation`

country
: field name `country`

Street
: field name `billing_address_street`

City
: field name `billing_address_city`

Postcode
: field name `billing_address_zipcode`
