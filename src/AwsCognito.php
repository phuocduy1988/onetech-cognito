<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Onetech <dev@onetech.vn>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito;

use Illuminate\Http\Request;
use Onetech\Cognito\Auth\Parser;
use Onetech\Cognito\Exceptions\AwsCognitoException;
use Onetech\Cognito\Exceptions\InvalidTokenException;

class AwsCognito
{
    /**
     * The authentication provider.
     *
     */
    protected $auth;

    /**
     * Aws Cognito Manager
     *
     * @var \Onetech\Cognito\AwsCognitoManager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \Onetech\Cognito\Auth\Parser
     */
    protected $parser;

    /**
     * The AwsCognito Claim token
     *
     * @var \Onetech\Cognito\AwsCognitoClaim|null
     */
    protected $claim;

    /**
     * The AWS Cognito token.
     *
     * @var \Onetech\Cognito\AwsCognitoToken|string|null
     */
    protected $token;

    /**
     * JWT constructor.
     *
     * @param  \Onetech\Cognito\AwsCognitoManager  $manager
     * @param  \Onetech\Cognito\Auth\Parser  $parser
     *
     * @return void
     */
    public function __construct(AwsCognitoManager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Get the token.
     *
     * @return \Onetech\Cognito\AwsCognitoToken|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (AwsCognitoException $e) {
                $this->token = null;
            } //try-catch ends
        } //End if

        return $this->token;
    } //Function ends

    /**
     * Parse the token from the request.
     *
     * @throws \Onetech\Cognito\Exceptions\AwsCognitoException
     *
     * @return \Onetech\Cognito\AwsCognito
     */
    public function parseToken()
    {
        //Parse the token
        $token = $this->parser->parseToken();

        if (empty($token)) {
            throw new AwsCognitoException('The token could not be parsed from the request');
        } //End if

        return $this->setToken($token);
    } //Function ends

    /**
     * Set the token.
     *
     * @param  \string  $token
     *
     * @return \Onetech\Cognito\AwsCognito
     */
    public function setToken(string $token)
    {
        $this->token = new AwsCognitoToken($token);
        if (empty($this->token)) {
            throw new AwsCognitoException('The token could not be validated.');
        } //End if

        return $this;
    } //Function ends

    /**
     * Get the token.
     *
     * @return \Onetech\Cognito\AwsCognitoClaim|null
     */
    public function getClaim()
    {
        return !empty($this->claim) ? $this->claim : null;
    } //Function ends

    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Onetech\Cognito\AwsCognito
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    } //Function ends

    /**
     * Get the Parser instance.
     *
     * @return \Onetech\Cognito\Auth\Parser
     */
    public function parser()
    {
        return $this->parser;
    } //Function ends

    /**
     * Authenticate a user via a token.
     *
     * @return \Onetech\Cognito\AwsCognito|false
     */
    public function authenticate()
    {
        try {
            $claim = $this->manager->fetchUserFromIdToken($this->token->get());
            $this->claim = $claim;
            if (empty($this->claim)) {
                throw new InvalidTokenException();
            } //End if

            return $this;
        } catch (\Exception $e) {
            throw $e;
        }
    } //Function ends

    /**
     * Get the authenticated user.
     *
     * @throws InvalidTokenException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function user()
    {
        //Get Claim
        if (empty($this->claim)) {
            throw new InvalidTokenException();
        } //End if

        return $this->claim->getUser();
    } //Function ends
} //Class ends
