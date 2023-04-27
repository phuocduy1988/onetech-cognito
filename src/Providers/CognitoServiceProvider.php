<?php

/*
 * This file is part of AWS Cognito Auth solution.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito\Providers;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Onetech\Cognito\AwsCognito;
use Onetech\Cognito\Guards\CognitoGuard;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Onetech\Cognito\Services\CognitoService;

/**
 * Class AwsCognitoServiceProvider.
 */
class CognitoServiceProvider extends ServiceProvider
{
    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        //Register Alias
        $this->registerAliases();
    }

    public function boot()
    {
        //Configuration path
        $path = realpath(__DIR__ . '/../../config/cognito.php');

        //Publish config
        $this->publishes(
            [
                $path => config_path('cognito.php'),
            ],
            'config'
        );

        //Register configuration
        $this->mergeConfigFrom($path, 'cognito');

        $this->registerPolicies();

        //Set Singleton Class
        $this->registerCognitoProvider();

        //Set Guards
        $this->extendApiAuthGuard();
    } //Function ends

    /**
     * Register Cognito Provider
     *
     * @return void
     */
    protected function registerCognitoProvider()
    {
        $this->app->singleton(CognitoService::class, function (Application $app) {
            $awsConfig = [
                'region' => config('cognito.region'),
                'version' => config('cognito.version'),
            ];

            //Set AWS Credentials
            $credentials = config('cognito.credentials');
            if (!empty($credentials['key']) && !empty($credentials['secret'])) {
                $awsConfig['credentials'] = Arr::only($credentials, ['key', 'secret', 'token']);
            } //End if

            return new CognitoService(
                new CognitoIdentityProviderClient($awsConfig),
                config('cognito.app_client_id'),
                config('cognito.app_client_secret'),
                config('cognito.user_pool_id'),
                config('cognito.app_client_secret_allow', true)
            );
        });
    } //Function ends

    /**
     * Extend Cognito Api Auth.
     *
     * @return void
     */
    protected function extendApiAuthGuard()
    {
        Auth::extend('cognito-token', function (Application $app, $name, array $config) {
            $client = $app->make(CognitoService::class);
            $guard = new CognitoGuard($app['onetech.aws.cognito'], $client, $app['request'], Auth::createUserProvider($config['provider']));

            $guard->setRequest($app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    } //Function ends

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->bind('onetech.aws.cognito', AwsCognito::class);
    } //Class ends
}
