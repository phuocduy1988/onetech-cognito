<?php

return [
    /*
    |--------------------------------------------------------------------------
    | AWS configurations
    |--------------------------------------------------------------------------
    |
    | If you have created the aws iam users, you should set the details from
    | the aws console within your environment file. These values will
    | get used while connecting with the aws using the official sdk.
    |
    */
    'credentials' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | AWS Cognito configurations
    |--------------------------------------------------------------------------
    |
    | If you have created the aws cognito , you should set the details from
    | the aws console within your environment file. These values will
    | get used while issuing fresh personal access tokens to your users.
    |
    */
    'app_client_id' => env('AWS_COGNITO_CLIENT_ID'),
    'app_client_secret' => env('AWS_COGNITO_CLIENT_SECRET'),
    'user_pool_id' => env('AWS_COGNITO_USER_POOL_ID'),
    'region' => env('AWS_COGNITO_REGION', 'us-east-1'),
    'version' => env('AWS_COGNITO_VERSION', 'latest'),

    // Package configurations
    'sso_user_model' => env('AWS_COGNITO_USER_MODEL', 'App\Model\User'),
    'force_new_user_email_verified' => env('AWS_COGNITO_FORCE_NEW_USER_EMAIL_VERIFIED', true),

    'cognito_jwk_key' => 'https://cognito-idp.' . env('AWS_COGNITO_REGION', 'us-east-1') . '.amazonaws.com/' . env('AWS_COGNITO_USER_POOL_ID') . '/.well-known/jwks.json',
];
