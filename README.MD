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


# **Cidaas Plugin for Shopware**


The cidaas plugin for Shopware offers Shopware end-user/customer-user interface login using a passwordless or social login authorization method.

In this section,

- We will introduce you to the cidaas plugin for Shopware
- Demonstrate the steps to install the plugin and
- Login into the cidaas Shopware user interface.
- Customer group assignment with Cidaas 

If you are here, we assume you are already using Shopware and would like to add the cidaas extension to your e-commerce website for authentication.

# **Introduction**

cidaas Shopware plugin is an Open Authorization (OAuth) plugin. The primary focus of this plugin is to provide Shopware login via passwordless, classic, and social login cidaas authentication methods.

The overall process includes:

- Downloading the "cidaas plugin for Shopware"
- Installing and activating the plugin
- Configuring the cidaas Admin Dashboard
- Creating an OAuth2 application for Shopware 
- Selecting the required configurations in the cidaas OAuth2 Connect Configuration page.

# **Steps to Install the Plugin**

This installation will help you use cidaas login functionalities and authentication methods for user management on your website.

**1**. Download the cidaas plugin from the [ Shopware store](https://www.cidaas.com/shopware-plugin/) or the plugin manager on your Shopware admin site.

**2**. Click on Extension from the sidebar menu.

 - Select My Extensions from the drop-down list,
 - Upload the Shopware extension plugin.
 - Click on that Apps and install and activate the cidaas for the Shopware plugin.
 - Activate the plugin for the configuration 
    
  ![1](1.png)
  ![2](2.png)
  ![3](3.png)
  ![4](4.png)


 **Navigate to the cidaas admin dashboard and fill in the details of the cidaas Plugin Config.**

  ### Click here to get your [cidaas instance](https://www.cidaas.com/pricing-packages/)

Note: We required two cidass application configuration for shopware plugin 
- Cidaas Single page client application for Login, Register and get User profile functionality.
- Cidaas Non-interactive client application for updating profile and Change email functionality. 

**3**. Click on **App settings > Create a new app** to create an app (OAuth2 Client) in Shopware.

![cre_app](uploads/a2eda6c64616d2d1eceef829f60da24a/cre_app.png)
 
**4**. Fill in the app details and select Single page in App type and Click on Next.

   ![app_details](uploads/4856fd26adb4c611941a71460c156914/app_details.png)

**5**. Fill in the app settings with the following details:
 - The scopes to be added include openid, email,roles,cidaas:register, and profile.
 - Set the value for Hosted Page Group as "default".
 - Set your domain names for Redirect and Logout URLs.
 - Click on Next
 
 ![app_settings](uploads/86b1fb7277779cd6e162ee486c0ed9c3/app_settings.png)

**6**. Fill in company details and click on save
 
Note:- You have successfully created your app, the next step is to add the registration fields for the app.
For more cidaas Client Configuration please refer to our docs [link](https://cidaas.stoplight.io/docs/cidaas-iam/branches/master/288aa0f48e2fc-app-management)

**To add registration fields**

**7**. Navigate to App settings and click on the edit icon of the newly created application.

![edit_app](uploads/13da5aabc41dfc9ddb208a22738564f6/edit_app.png)

**8**. Scroll down to the company details section and click on Advance settings.

**9**. Go to the Registration field section and select the desired, allowed, and required registration fields.

  Also, select feasible communication medium verification to verify the users.

![registration_](uploads/fc40c0588c52fec2812200d6dcce246e/registration_.png)

 Kindly check [here](https://cidaas.stoplight.io/docs/cidaas-iam/branches/master/e8ce45afc47ba-user-field-settings) for more information on registration fields.

**10**. Create the Non-interactive app with the following details:
 - The scopes to be added include only cidaas:users_write.
 - Click on Next
 - Fill in company details and click on save
 
![non](uploads/4c10c0f249eda90e82f1ca9c8d00a3a4/non.png)
![scope](uploads/ab776ae3f2521e23525e1d377377232f/scope.png)
![Screenshot_2023-07-27_at_1.06.53_PM](uploads/75f8670348107413811bf01c60b5bf70/Screenshot_2023-07-27_at_1.06.53_PM.png)

**11**. Next, you need to copy the below details to configure the cidaas into shopware.

* Navigate to App settings.
* Copy the Client ID, Client Secret of both Single page and Non-interactive applications 
* Base URL endpoint will be your Domain URL example- https://your_domain.de
 
![data_copy](uploads/b543c99e8a75b500c9730047b6136ce6/data_copy.png)
![Screenshot_2023-07-27_at_1.16.53_PM](uploads/81821833fcf73c305ae7ddbaccc3df91/Screenshot_2023-07-27_at_1.16.53_PM.png)




**12**. Navigate to the Shopware dashboard > Extensions > My extensions > My plugin > click on configure.

 ![config](uploads/e6d1ed869e32b65d3ee07acc12bbf8df/config.png)

**13**. Enter the details on Cidaas OAuth2 Connect Configuration page. Select Sales Channel, provide values for the fields, and Save.
![j](uploads/fc593951efeff30ee9d7ba270712e5fe/j.png)

**14**. Once the plugin is active, the login with cidaas button will appear on your store end user login page. Your customer-user/end-user can now login with cidaas.

![pluggin_active](uploads/f2d6ab372d43f17da899823939f160e4/pluggin_active.png)

Note:- In a new user instance, a first-time customer-user/end-user has to create an account and register by filling in the details.

# **Customer group assignment with Cidaas**
- The customer groups allow you to define whether the prices in the store are displayed net or gross.
- These below  steps will help you use cidaas customer group functionalities setup with Shopware 


