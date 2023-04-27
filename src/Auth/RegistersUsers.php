<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Onetech <dev@onetech.vn>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

use Onetech\Cognito\Exceptions\ChangePasswordException;
use Onetech\Cognito\Exceptions\ResetPasswordException;
use Onetech\Cognito\Services\CognitoService;

use Onetech\Cognito\Exceptions\InvalidUserFieldException;

trait RegistersUsers
{
    /**
     * Adds the newly created user to the default group (if one exists) in the config file.
     *
     * @param $username
     * @return array
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function setDefaultGroup($username)
    {
        if (!empty(config('cognito.default_user_group', null))) {
            return app()
                ->make(CognitoService::class)
                ->adminAddUserToGroup($username, config('cognito.default_user_group', null));
        } //End if
        return [];
    } //Function ends

    /**
     * Handle a registration request for the application.
     *
     * @param \Illuminate\Support\Collection $request
     * @return \Illuminate\Http\Response
     * @throws InvalidUserFieldException
     */
    public function createCognitoUser(Request $request, array $clientMetadata = null, string $groupname = null)
    {
        $request = collect($request->all());

        //Initialize Cognito Attribute array
        $attributes = [];

        //Get the configuration for new user invitation message action.
        $messageAction = config('cognito.new_user_message_action', 'SUPPRESS');

        //Get the configuration for the forced verification of new user
        $isUserEmailForcedVerified = config('cognito.force_new_user_email_verified', false);

        $forceSetUserPassword = config('cognito.force_set_user_password', false);

        //Get the registeration fields
        $userFields = config('cognito.cognito_user_fields');

        //Iterate the fields
        foreach ($userFields as $key => $userField) {
            if ($request->has($userField)) {
                $attributes[$key] = $request->get($userField);
            } else {
                Log::error('RegistersUsers:createCognitoUser:InvalidUserFieldException');
                Log::error("The configured user field {$userField} is not provided in the request.");
                throw new InvalidUserFieldException("The configured user field {$userField} is not provided in the request.");
            } //End if
        } //Loop ends

        //Register the user in Cognito
        $userKey = $request->has('username') ? 'username' : 'email';

        //Temporary Password paramter
        $password = $request->has('password') ? $request['password'] : null;

        return app()
            ->make(CognitoService::class)
            ->adminRegister($request[$userKey], $password, $attributes, $clientMetadata, $messageAction, $isUserEmailForcedVerified, $forceSetUserPassword, $groupname);
    } //Function ends

    /**
     * Handle a set password for user.
     *
     * @param \Illuminate\Support\Collection $request
     * @return \Illuminate\Http\Response
     * @throws InvalidUserFieldException
     */
    public function setUserPassword(Request $request)
    {
        //setUserPassword the user in Cognito
        $userKey = $request->has('username') ? 'username' : 'email';
        $userName = $request[$userKey];
        //Password paramter
        $password = $request->get('password');

        if (!$userName || !$password) {
            throw new ResetPasswordException("Invalid data provided for set password.");
        }

        return app()
            ->make(CognitoService::class)
            ->adminSetUserPassword($userName, $password);
    } //Function ends

    /**
     * Handle a change password for user.
     *
     * @param \Illuminate\Support\Collection $request
     * @return \Illuminate\Http\Response
     * @throws InvalidUserFieldException
     */
    public function changeUserPassword($accessToken, $passwordOld, $passwordNew)
    {

        if (!$accessToken || !$passwordOld || !$passwordNew) {
            throw new ChangePasswordException("Invalid data provided for change password.");
        }

        $cognitoService = app()->make(CognitoService::class);

        return $cognitoService->changePassword($accessToken, $passwordOld, $passwordNew);
    } //Function ends


} //Trait ends
