# DSSP SDK for PHP

This project contains the PHP client library for the e-Contact.be Digital Signature Service.

Tested PHP version: 8.2.11

## Requirements

You need the following PHP modules:
* `soap`

You can check the available PHP modules via:
```
php -m
```

Install the required dependencies via:
```
composer install
```

## Example

The PDF upload and initial Browser POST call is demonstrated in `index.php`.

The verification of the DSS Browser POST and subsequent PDF downloading is demonstrated in `landing.php`.

A document signature validation is demonstrated in `verify.php`.