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
use Illuminate\Support\Str;

class Parser
{
    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array  $chain
     *
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    } //Function ends

    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     *
     * @return string|null
     */
    public function parseToken()
    {
        $header = $this->request->header('Authorization', '');
        if (Str::startsWith($header, 'Bearer ')) {
            return Str::substr($header, 7);
        }
    } //Function ends

    /**
     * Check whether a token exists in the chain.
     *
     * @return bool
     */
    public function hasToken()
    {
        return $this->parseToken() !== null;
    } //Function ends

    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    } //Function ends
} //Class ends
