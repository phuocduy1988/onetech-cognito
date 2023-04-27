## Installation

You can install the package via composer.

```bash
composer require onetech/cognito
```

Next you can publish the config

```bash
    php artisan vendor:publish --provider="Onetech\Cognito\Providers\CognitoServiceProvider"
```

Add config to environment file .env
```dotenv
# AWS Cognito configurations
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
AWS_COGNITO_CLIENT_ID=""
AWS_COGNITO_CLIENT_SECRET=""
AWS_COGNITO_USER_POOL_ID=""
AWS_COGNITO_REGION="us-east-1"
AWS_COGNITO_VERSION="latest"

```

Last but not least you want to change the auth driver. To do so got to your config\auth.php file and change it
to look the following:

```php
    'guards' => [
        'cognito-token' => [
            'driver' => 'cognito-token', // This line is important for using AWS Cognito as API Driver
            'provider' => 'users',
        ],
    ],
```

## Usage

Our package is providing you these traits you can just add to your Auth Controllers to get our package running.

-   Onetech\Cognito\Auth\AuthenticatesUsers
-   Onetech\Cognito\Auth\RegistersUsers
