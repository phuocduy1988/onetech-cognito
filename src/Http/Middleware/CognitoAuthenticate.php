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

use Closure;
use Illuminate\Http\Request;

use Exception;
use Onetech\Cognito\Exceptions\NoTokenException;
use Onetech\Cognito\Exceptions\InvalidTokenException;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class CognitoAuthenticate extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $routeMiddleware = $request->route()->middleware();
            if (!count($routeMiddleware)) {
                return $this->failedResponse('UnknownMiddleware');
            }

            //Authenticate the request
            $this->authenticate($request);

            return $next($request);
        } catch (Exception $e) {
            if ($e instanceof NoTokenException) {
                return $this->failedResponse('NoTokenException');
            } //End if

            if ($e instanceof InvalidTokenException) {
                return $this->failedResponse('InvalidTokenException');
            } //End if

            //Raise error in case of generic error
            return $this->failedResponse();
        } //Try-catch ends
    } //Function ends

    private function failedResponse($exception = null): \Illuminate\Http\JsonResponse
    {
        return response()->json(
            [
                'success' => false,
                'message' => 'UNAUTHORIZED',
                'exception' => $exception,
            ],
            ResponseAlias::HTTP_UNAUTHORIZED
        );
    }
} //Class ends
