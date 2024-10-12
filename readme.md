# OAuth2 client for LARAVEL

This package is used to consume OAuth2 API´s from Laravel

## Installation

Run the following command from you terminal:

 ```bash
 composer require "douglasresendemaciel/oauth2-client:@dev"
 ```

or add this to require section in your composer.json file:

 ```
 "douglasresendemaciel/oauth2-client"
 ```

then run ```composer update```

Once it is installed, you need to register the service provider. 
Open up config/app.php and add the following to the providers key.

```php
'providers' => [
...
DouglasResende\OAuth2Client\OAuth2ClientServiceProvider::class
...
```

Publishing config file

``` bash
php artisan vendor:publish
```

## Usage

``` php
$oauth2Client = new \DouglasResende\OAuth2Client\OAuth2Client();

# METHODS TO GET TOKEN // https://laravel.com/docs/5.7/passport

// authorization_code
$oauth2 = $oauth2Client->withOAuthTokenTypeAuthorizationCode('client-id', 'client-secret', 'redirect-url', 'code');

// client_credentials
$oauth2 = $oauth2Client->withOAuthTokenTypeClientCredentials('client-id', 'client-secret','scope');

// password
$oauth2 = $oauth2Client->withOAuthTokenTypePassword('client-id', 'client-secret', 'username', 'password', 'scope');

// GET RESPONSE
$response = $oauth2Client->get("user")->getResponseAsArray();

```

## Author

Douglas Resende: [http://www.douglasresende.com/](http://www.douglasresende.com/)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.


## References

For more information read the official documentation at [https://laravel.com/docs/5.7/](https://laravel.com/docs/5.7/)
