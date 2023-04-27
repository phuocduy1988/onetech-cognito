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
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

use Onetech\Cognito\Services\CognitoService;

use Exception;
use Illuminate\Validation\ValidationException;
use Onetech\Cognito\Exceptions\NoLocalUserException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

trait AuthenticatesUsers
{
    /**
     * Attempt to log the user into the application.
     *
     * @param Request $request
     * @param \string $paramUsername  (optional)
     * @param \string $paramPassword  (optional)
     *
     * @return mixed
     */
    protected function attemptLogin(Request $request, $guard = 'cognito-token', string $paramUsername = 'username', string $paramPassword = 'password')
    {
        try {
            //Get key fields
            $keyUsername = 'username';
            $keyPassword = 'password';
            $rememberMe = $request->has('remember') ? $request['remember'] : false;

            //Generate credentials array
            $credentials = [
                $keyUsername => $request->get($paramUsername),
                $keyPassword => $request->get($paramPassword),
            ];

            //Authenticate User
            return Auth::guard($guard)->attempt($credentials, $rememberMe);
        } catch (CognitoIdentityProviderException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:CognitoIdentityProviderException');
            return $this->sendFailedCognitoResponse($e, $paramUsername);
        } catch (Exception $e) {
            Log::error('AuthenticatesUsers:attemptLogin:Exception');
            return $this->sendFailedLoginResponse($e, $paramUsername);
        } //Try-catch ends
    } //Function ends

    /**
     * Handle Failed Cognito Exception
     *
     * @param CognitoIdentityProviderException $exception
     */
    private function sendFailedCognitoResponse(CognitoIdentityProviderException $exception, string $paramUsername = 'email')
    {
        throw ValidationException::withMessages([
            $paramUsername => $exception->getAwsErrorMessage(),
        ]);
    } //Function ends

    /**
     * Handle Generic Exception
     *
     * @param Collection $request
     * @param \Exception $exception
     */
    private function sendFailedLoginResponse(Exception $exception = null, string $paramUsername = 'email')
    {
        $message = 'FailedLoginResponse';
        throw ValidationException::withMessages([
            $paramUsername => $message,
        ]);
    } //Function ends

    /**
     * Handle a change password for user.
     *
     * @param \Illuminate\Support\Collection $request
     * @return \Illuminate\Http\Response
     */
    public function signOut($accessToken)
    {
        return app()
            ->make(CognitoService::class)
            ->signOut($accessToken);
    } //Function ends

} //Trait ends
