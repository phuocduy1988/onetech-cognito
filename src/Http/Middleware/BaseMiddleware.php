<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Onetech <dev@onetech.vn>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito\Http\Middleware;

use Illuminate\Http\Request;

use Illuminate\Support\Facades\Log;
use Onetech\Cognito\AwsCognito;

use Exception;
use Onetech\Cognito\Exceptions\InvalidTokenException;
use Onetech\Cognito\Exceptions\NoTokenException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

abstract class BaseMiddleware //extends Middleware
{
    /**
     * The Cognito Authenticator.
     *
     * @var \Onetech\Cognito\AwsCognito
     */
    protected $cognito;

    /**
     * Create a new BaseMiddleware instance.
     *
     * @param  \Onetech\Cognito\AwsCognito  $cognito
     *
     * @return void
     */
    public function __construct(AwsCognito $cognito)
    {
        $this->cognito = $cognito;
    }

    /**
     * Check the request for the presence of a token.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     *
     * @return void
     */
    public function checkForToken(Request $request)
    {
        if (
            !$this->cognito
                ->parser()
                ->setRequest($request)
                ->hasToken()
        ) {
            throw new NoTokenException();
        } //End if
    } //Function ends

    /**
     * Attempt to authenticate a user via the token in the request.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @throws \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     *
     * @return void
     */
    public function authenticate(Request $request)
    {
        try {
            $this->checkForToken($request);
            if (!$this->cognito->parseToken()->authenticate()) {
                throw new UnauthorizedHttpException('aws-cognito', 'User not found');
            } //End if
        } catch (Exception $e) {
            throw new InvalidTokenException();
        } //Try-catch ends
    } //Function ends
} //Class ends
