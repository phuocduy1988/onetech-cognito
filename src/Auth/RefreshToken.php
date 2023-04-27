<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Onetech <support@Onetech.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

use Onetech\Cognito\AwsCognito;
use Onetech\Cognito\Services\CognitoService;

use Exception;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

trait RefreshToken
{
    /**
     * The AwsCognito instance.
     *
     * @var \Onetech\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * RespondsMFAChallenge constructor.
     *
     * @param AwsCognito $cognito
     */
    public function __construct(AwsCognito $cognito)
    {
        $this->cognito = $cognito;
    }

    /**
     * Generate a new token.
     *
     * @param \Illuminate\Http\Request $request
     * @param string                   $paramUsername     (optional)
     * @param string                   $paramRefreshToken (optional)
     *
     * @return mixed
     */
    public function refreshCoginitoToken(Request $request)
    {
        try {
            if ($request instanceof Request) {
                //Validate request
                $validator = Validator::make($request->all(), [
                    'username' => 'required',
                    'refresh_token' => 'required',
                ]);

                if ($validator->fails()) {
                    throw new ValidationException($validator);
                } //End if
            } //End if

            //Create AWS Cognito Client
            $client = app()->make(CognitoService::class);

            $response = $client->refreshToken($request);
            if (empty($response) || empty($response->get('AuthenticationResult'))) {
                throw new HttpException(400);
            } //End if

            return $response->get('AuthenticationResult');
        } catch (Exception $e) {
            if ($e instanceof CognitoIdentityProviderException) {
                return response()->json(['error' => $e->getAwsErrorCode()], 400);
            } //End if
            throw $e;
        } //Try-catch ends
    } //Function ends
} //Trait ends
