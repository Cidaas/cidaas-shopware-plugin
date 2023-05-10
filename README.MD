# Cidaas SSO plugin
Shopware extension to connect to [cidaas](https://www.cidaas.com) by Widas ID
----
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