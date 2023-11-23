![Logo](logo.jpg)

## About cidaas:
[cidaas](https://www.cidaas.com)
 is a fast and secure Cloud Identity & Access Management solution that standardizes what’s important and simplifies what’s complex.

## Feature set includes:
* Single Sign On (SSO) based on OAuth 2.0, OpenID Connect, SAML 2.0 
* Multi-Factor-Authentication with more than 14 authentication methods, including TOTP and FIDO2 
* Passwordless Authentication 
* Social Login (e.g. Facebook, Google, LinkedIn and more) as well as Enterprise Identity Provider (e.g. SAML or AD) 
* Security in Machine-to-Machine (M2M) and IoT
* Guest user Login 
* Address data Sync and update with Cidaas 
* Profile data Sync and update with Cidaas
* Change Email and Password functionalities

# Cidaas SSO plugin

This is a shopware 6 plugin that allows you to integrate your store into the cidaas platform for single sign on (SSO), multi factor

# Cidaas Shopware Plugin versions

   ## [Shopware Version 6.5](https://github.com/Cidaas/cidaas-shopware-plugin/tree/master) 
   ## [Shopware Version 6.4](https://github.com/Cidaas/cidaas-shopware-plugin/tree/version_6.4) 


## Author

[Cidaas](https://www.cidaas.com) by Widas ID in cooperation with [Joshua Kopp](mailto:me@joshuakopp.de?subject=Shopware-Plugin-Cidaas)

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
- Customer group assignment is coming in the next version

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

**1**. Click on Extension from the sidebar menu.

 - Select My Extensions from the drop-down list,
 - Upload the Shopware extension plugin.
 - Click on that Apps and install and activate the cidaas for the Shopware plugin.
 - Activate the plugin for the configuration 
   
  ![1](docs/docs-images/1.png)
  ![2](docs/docs-images/2.png)
  ![3](docs/docs-images/3.png)
  ![4](docs/docs-images/4.png)


 **Navigate to the cidaas admin dashboard and fill in the details of the cidaas Plugin Config.**

  ### Click here to get your [cidaas instance](https://www.cidaas.com/pricing-packages/)

Note: We required two cidass application configuration for shopware plugin 
- Cidaas Single page client application for Login, Register and get User profile functionality.
- Cidaas Non-interactive client application for updating profile and Change email functionality. 

**2**. Click on **App settings > Create a new app** to create an app (OAuth2 Client) in Shopware.

![cre_app](docs/docs-images/5.png)
 
**3**. Fill in the app details and select Single page in App type and Click on Next.

![app_details](docs/docs-images/6.png)

**4**. Fill in the app settings with the following details:
 - The scopes to be added include openid, email,roles,cidaas:register, and profile.
 - Set the value for Hosted Page Group as "default".
 - Set your domain names for Redirect and Logout URLs.
 - Click on Next
 
 ![app_settings](docs/docs-images/7.png)

**5**. Fill in company details and click on save
 
Note:- You have successfully created your app, the next step is to add the registration fields for the app.
For more cidaas Client Configuration please refer to our docs [link](https://cidaas.stoplight.io/docs/cidaas-iam/branches/master/288aa0f48e2fc-app-management)

**To add registration fields**

**6**. Navigate to App settings and click on the edit icon of the newly created application.

![edit_app](docs/docs-images/8.png)

**7**. Scroll down to the company details section and click on Advance settings.

**8**. Go to the Registration field section and select the desired, allowed, and required registration fields.

Also, select feasible communication medium verification to verify the users.


In Shopware, the specified fields are essential components for managing customer information and processing orders. Each field serves a specific purpose in capturing and organizing relevant data. Here's a brief explanation of each field:

**Email**: 
This field is essential for creating unique user accounts and establishing communication with customers. It serves as a primary identifier and contact point for order confirmations, password recovery, and other important notifications.

**Given Name (First Name)**: 
The given name field is used to store the customer's first name. This information personalizes the shopping experience and is often used in communications such as greetings and personalized messages.

**Family Name (Last Name)**: 
Similar to the given name, the family name field is crucial for personalization and proper identification of customers. It is often used in formal communications and is an integral part of the customer's profile.

**Password**: 
The password field is necessary for securing customer accounts and protecting sensitive information. It ensures that only authorized users can access their accounts and make purchases. It is crucial to enforce password policies to enhance security.

**Password Echo (Password Confirmation)**: 
This field is used to confirm the password entered by the user during the registration or password change process. It helps prevent errors and ensures that the customer has entered the correct password by requiring them to confirm it.

**billing_address_street**:
- Definition: This field captures the street address of the customer's billing information.
- Purpose: It is crucial for generating accurate invoices and ensuring the correct delivery of physical goods.

**billing_address_city**:
- Definition: This field captures the city of the customer's billing address.
- Purpose: Helps in identifying the customer's location for taxation purposes and provides essential information for shipping.

**salutation**:
- Definition: This field captures the salutation or title (e.g., Mr., Mrs., Dr.) associated with the customer.
- Purpose: Adds a personal touch to communications and is often used for formal addressing in documentation.

**country**:
- Definition: This field captures the customer's country information.
- Purpose: Necessary for determining applicable taxes, shipping costs, and complying with regional regulations.

**billing_address_zipcode**:
- Definition: This field captures the postal code or ZIP code of the customer's billing address.
- Purpose: Essential for precise location identification, shipping calculations, and compliance with postal regulations.

**company_name**:
- Definition: The "company_name" field in Shopware is a data container designated for storing the name of the company associated with a specific entity, such as a customer or business account.
- Purpose : The purpose of the "company_name" field is to accurately identify and associate the respective company information within the Shopware system

To guarantee a seamless customer experience and ensure accurate order processing in Shopware, it is essential to create these fields in the Cidass system and set them as mandatory.

![registration_](docs/docs-images/9.png)

 Kindly check [here](https://cidaas.stoplight.io/docs/cidaas-iam/branches/master/e8ce45afc47ba-user-field-settings) for more information on registration fields.

**9**. Create the Non-interactive app with the following details:
 - The scopes to be added include only cidaas:users_write.
 - Click on Next
 - Fill in company details and click on save
 
![non](docs/docs-images/10.png)
![scope](docs/docs-images/11.png)
![submit](docs/docs-images/12.png)

**10**. Next, you need to copy the below details to configure the cidaas into shopware.

* Navigate to App settings.
* Copy the Client ID, Client Secret of both Single page and Non-interactive applications 
* Base URL endpoint will be your Domain URL example- https://your_domain.de
 
![data_copy](docs/docs-images/13.png)
![data_copy-0](docs/docs-images/14.png)

**11**. Navigate to the Shopware dashboard > Extensions > My extensions > My plugin > click on configure.

![config](uploads/e6d1ed869e32b65d3ee07acc12bbf8df/config.png)

**12**. Enter the details on Cidaas OAuth2 Connect Configuration page. Select Sales Channel, provide values for the fields, and Save.

![j](docs/docs-images/15.png)

**13**. Once the plugin is active, the login with cidaas button will appear on your store end user login page. Your customer-user/end-user can now login with cidaas.

![plugin_active](docs/docs-images/16.png)

Note:- In a new user instance, a first-time customer-user/end-user has to create an account and register by filling in the details.

# How does Shopware synchronize data with Cidaas?

The process begins with the application initiating an OAuth flow, prompting the user to authorize a request. Within this process, the client includes the OpenID Connect scope along with scopes for any additional user information needed.

Upon processing the request, the client receives both an access token and an ID token issued by Cidaas (the authorization server). This ID token contains claims with user information, facilitating a seamless Single Sign-On (SSO) experience by delivering the ID token from Cidaas to the client. Subsequently, the client can contact a specific endpoint on Cidaas, known as the UserInfo endpoint, to obtain the remaining claims about the user.

During login, if any of the aforementioned fields are missing for a user, the system redirects to the "register_additional_info" page to add those missing details.

The user info includes data such as sub, given_name, family_name, salutation, company, email, billing_address_street, billing_address_zipcode, and billing_address_city.

To determine whether the Cidaas user exists in Shopware, we store the "sub" parameter in the Shopware database under the customfields object.

After login, the system retrieves the user data and checks if the user exists in the Shopware database using the unique Sub parameter. If the user exists, the user info data is updated with the corresponding Shopware data, such as address and customer details. If the user doesn't exist, the system performs an upsert and maps the Cidaas user data to Shopware with the specified format.

In the Shopware storefront, when the user updates their profile and address, the system concurrently updates the same data in Cidaas using the Cidaas update user API endpoint.

- **Profile data update from Shopware to Cidaas**
  - Email
  - Password
  - First Name
  - Last Name
  - Salutation

- **Address data update from Shopware to Cidaas (only Billing address is stored in Cidaas)**
  - billing_address_street
  - billing_address_zipcode
  - billing_address_city
  - company
  - billing_address_country

  We don't send empty values. If I send a new billing address with no company, the company does not get removed.

# **Customer group assignment with Cidaas**
- upcoming in next version


