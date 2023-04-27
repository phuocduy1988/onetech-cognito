<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Onetech <dev@onetech.vn>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito\Guards;

use Illuminate\Http\Request;
use Illuminate\Auth\TokenGuard;
use Illuminate\Support\Facades\Log;
use Illuminate\Contracts\Auth\UserProvider;

use Exception;
use Onetech\Cognito\AwsCognito;
use Onetech\Cognito\Exceptions\NoLocalUserException;
use Onetech\Cognito\Services\CognitoService;

class CognitoGuard extends TokenGuard
{
    /**
     * Username key
     *
     * @var  \string
     */
    protected $keyUsername;

    /**
     * @var  \Onetech\Cognito\Services\CognitoService
     */
    protected $client;

    /**
     * The AwsCognito instance.
     *
     * @var \Onetech\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * The AwsCognito Claim token
     *
     * @var \Onetech\Cognito\AwsCognitoClaim|null
     */
    protected $claim;

    /**
     * CognitoTokenGuard constructor.
     *
     * @param $callback
     * @param CognitoService $client
     * @param Request $request
     * @param UserProvider $provider
     */
    public function __construct(AwsCognito $cognito, CognitoService $client, Request $request, UserProvider $provider = null, string $keyUsername = 'username')
    {
        $this->cognito = $cognito;
        $this->client = $client;
        $this->keyUsername = $keyUsername;

        parent::__construct($provider, $request);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $remember
     * @return \Onetech\Cognito\AwsCognitoClaim|bool|\Illuminate\Http\JsonResponse
     * @throws
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        try {
            return $this->client->authenticate($credentials, $remember);
        } catch (Exception $e) {
            Log::error('CognitoTokenGuard:attempt:NoLocalUserException:' . $e->getMessage());
            throw $e;
        }
    } //Function ends

    /**
     * Logout the user, thus invalidating the token.
     *
     * @param  bool  $forceForever
     *
     * @return void
     */
    public function logout(bool $forceForever = false)
    {
        $this->user = null;
    } //Function ends

    /**
     * Get the authenticated user.
     *
     * @return string
     */
    public function user()
    {
        //Check if the user exists
        if (!is_null($this->user)) {
            return $this->user;
        } //End if

        //Retrieve token from request and authenticate
        return $this->getUserByAccessToken();
    } //Function ends

    /**
     * Get the token for the current request.
     * @return string
     */
    public function getUserByAccessToken()
    {
        //Check for request having token
        if (
            !$this->cognito
                ->parser()
                ->setRequest($this->request)
                ->hasToken()
        ) {
            return null;
        } //End if

        $accessToken = (string)$this->cognito->getToken();
        return $this->client->getUserByAccessToken($accessToken);

    } //Function ends

    /**
     * Get the token for the current request.
     * @return string
     */
    public function getTokenForRequest()
    {
        //Check for request having token
        if (
            !$this->cognito
                ->parser()
                ->setRequest($this->request)
                ->hasToken()
        ) {
            return null;
        } //End if

        if (!$this->cognito->parseToken()->authenticate()) {
            throw new NoLocalUserException();
        } //End if

        //Get claim
        $claim = $this->cognito->getClaim();
        if (empty($claim)) {
            return null;
        } //End if

        //Get user and return
        return $this->user = $claim;
    } //Function ends
} //Class ends
