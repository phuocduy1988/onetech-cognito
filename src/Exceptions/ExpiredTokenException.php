<?php

namespace Onetech\Cognito\Exceptions;

use Throwable;

use Exception;
use Illuminate\Auth\AuthenticationException;

class ExpiredTokenException extends Exception
{
    /**
     * Report the exception.
     *
     * @return void
     */
    public function report($message = 'Expired Token')
    {
        throw new AuthenticationException($message);
    }

    /**
     * Render the exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Throwable  $exception
     * @return \Illuminate\Http\Response
     */
    public function render($request, Throwable $exception)
    {
        return parent::render($request, $exception);
    }
} //Class ends
