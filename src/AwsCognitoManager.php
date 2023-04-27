<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) Onetech <support@oOnetech.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Onetech\Cognito;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use Onetech\Cognito\Providers\StorageProvider;

class AwsCognitoManager
{
    /**
     * The provider.
     *
     * @var \Onetech\Cognito\Providers\StorageProvider
     */
    protected $provider;

    /**
     * The blacklist.
     *
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * The AWS Cognito token.
     *
     * @var string|null
     */
    protected $token;

    /**
     * The AwsCognito Claim token
     *
     * @var \Onetech\Cognito\AwsCognitoClaim|null
     */
    protected $claim;

    /**
     * Constructor.
     *
     * @param \Onetech\Cognito\Providers\StorageProvider $provider
     * @param \Tymon\JWTAuth\Blacklist                   $blacklist
     * @param \Tymon\JWTAuth\Factory                     $payloadFactory
     *
     * @return void
     */
    public function __construct(StorageProvider $provider, $blacklist = null)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
    }

    /**
     * Encode the claim.
     *
     * @return AwsCognitoManager
     */
    public function encode(AwsCognitoClaim $claim)
    {
        $this->claim = $claim;
        $this->token = $claim->getToken();

        return $this;
    } //Function ends

    /**
     * Decode token.
     *
     * @return \Onetech\Cognito\AwsCognitoClaim
     */
    public function decode()
    {
        return $this->claim ?: null;
    } //Function ends

    /**
     * Persist token.
     *
     * @return \boolean
     */
    public function store()
    {
        $data = $this->claim->getData();
        $durationInSecs = $data ? (int) $data['ExpiresIn'] : 3600;
        $this->provider->add($this->token, json_encode($this->claim), $durationInSecs);

        return true;
    } //Function ends

    /**
     * Get Token from store.
     *
     * @return AwsCognitoManager
     */
    public function fetch(string $token)
    {
        $this->token = $token;
        $claim = $this->provider->get($token);
        $this->claim = $claim ? json_decode($claim, true) : null;

        return $this;
    } //Function ends

    /**
     * Get Token from store.
     *
     * @return \stdClass
     */
    public function fetchUserFromIdToken(string $token)
    {
        $jwkCacheKey = 'cognito_jwk_key';
        if ($this->provider->has($jwkCacheKey)) {
            $jsonWebKeys = $this->provider->get($jwkCacheKey);
        } else {
            $jsonWebKeyUrl = config('cognito.cognito_jwk_key');
            $jsonWebKeys = Http::get($jsonWebKeyUrl)->json();
            $this->provider->add($jwkCacheKey, $jsonWebKeys);
        }
        //Cache lai cai key
        $firebaseKeys = JWK::parseKeySet($jsonWebKeys);
        return JWT::decode($token, $firebaseKeys);
    } //Function ends

    /**
     * Release token.
     *
     * @return AwsCognitoManager
     */
    public function release(string $token)
    {
        $this->provider->destroy($token);

        return $this;
    } //Function ends
} //Class ends
