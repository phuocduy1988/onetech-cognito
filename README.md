## Installation

You can install the package via composer.

```bash
composer require onetechasia/cognito
```

Next you can publish the config

```bash
    php artisan vendor:publish --provider="Onetech\Cognito\Providers\CognitoServiceProvider"
```

## Configure

Add config to environment file:
.env

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

Last but not least you want to change the auth driver:
config/auth.php

```php
    'guards' => [
        'cognito-token' => [
            'driver' => 'cognito-token', // This line is important for using AWS Cognito as API Driver
            'provider' => 'users',
        ],
    ],
```

Add to middleware for authentication:
app/Http/Kernel.php

```php
    protected $routeMiddleware = [
        'onetech.cognito' => \Onetech\Cognito\Http\Middleware\CognitoAuthenticate::class,
    ];
```

## Usage

Our package is providing you these traits you can just add to your Auth Controllers to get our package running.

- Onetech\Cognito\Auth\AuthenticatesUsers
- Onetech\Cognito\Auth\RegistersUsers
- Onetech\Cognito\Auth\RefreshToken

```php
    use Onetech\Cognito\Auth\RegistersUsers;
    use Onetech\Cognito\Auth\AuthenticatesUsers;
    use Onetech\Cognito\Auth\RefreshToken;
    class UserController
    {
        use CognitoAuthenticatesUsers, RegistersUsers, RefreshToken;
    }
```

Using in code.
1. Registering to cognito:

Payload: username = email or custom username,
password belong to policy of cognito need validation
```json
    {
        "name": "Le Duy",
        "username": "duy@onetech.vn",
        "email": "duy@onetech.vn",
        "password": "123456",
        "any attributes": "add more if needed"
    }
```
```php
    //Registering user
    $bool = $this->createCognitoUser($request);
    //return boolean
```
2. Login cognito

Payload: username and password is required
```json
    {
      "username": "duy@onetech.vn",
      "password": "password",
      "remember": true
    }
```
```php
    //Login user
    $check = $this->attemptLogin($request);
    //Response using AccessToken for call API
    //Response using RefreshToken to fetch new AccessToken
    //Response using IdToken to get user information
```
3. Fetch new token

Payload: username and refresh_token is required
```json
    {
      "username": "duy@onetech.vn",
      "refresh_token": "refresh token"
    }
```
```php
    //Fetch new AccessToken and IdToken
    $response = $this->refreshCoginitoToken($request);
    //Same API login
```

4. Set user password use for reset password

Payload: username and refresh_token is required
```json
    {
      "username": "duy@onetech.vn",
      "password": "password"
    }
```
```php
    $check = $this->setUserPassword($request);
```
4. Change user password

API call need add header.
Authorization: Bearer AccessToken

Payload: old_password and new_password is required
```json
    {
      "old_password": "old password",
      "new_password": "new password"
    }
```
```php
    $accessToken = Auth::guard('cognito-token')->getTokenForRequest();
    $oldPassword = $request->old_password;
    $newPassword = $request->new_password;
    $check = $this->changeUserPassword($accessToken, $oldPassword, $newPassword);
```

5. Get User Info

You can using IdToken parse user info or call api to get information

API call need add header.
Authorization: Bearer AccessToken

```php
    $userInfo = Auth::guard('cognito-token')->user();
```
6. Sign out user

API call need add header.
Authorization: Bearer AccessToken

```php
    $accessToken = Auth::guard('cognito-token')->getTokenForRequest();
    $check = $this->signOut($accessToken);
```



