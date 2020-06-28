<?php

namespace DataHiveDevelopment\PassportIntrospectionClient\Guards;

use DateInterval;
use Firebase\JWT\JWT;
use RuntimeException;
use BadMethodCallException;
use Laravel\Passport\Token;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\TransientToken;
use Illuminate\Support\Facades\Cache;
use Laravel\Passport\Guards\TokenGuard;
use Illuminate\Http\Client\RequestException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Cookie\Middleware\EncryptCookies;
use DataHiveDevelopment\PassportIntrospectionClient\Introspection;

class IntrospectionGuard
{
    /**
     * The encrypter implementation.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;

    /**
     * Create a new token guard instance.
     *
     * @param  \Illuminate\Contracts\Encryption\Encrypter  $encrypter
     * @return void
     */
    public function __construct(
        Encrypter $encrypter
    ) {
        $this->encrypter = $encrypter;
    }

    /**
     * Retrieve an OAuth access token from the cache, or fetch a new one from the authorization server.
     * TODO: Make use of the refresh_token?
     *
     * @return string
     */
    protected function getAccessToken()
    {
        Log::debug('IntrospectionGuard\getAccessToken(): Checking cache for token...');
        return Cache::remember('introspection.access_token', config('introspection.access_token_ttl', new DateInterval('P1Y')), function () {
            Log::debug('IntrospectionGuard\getAccessToken(): Token not available from cache.');
            return $this->retrieveAccessToken();
        });
    }

    /**
     * Make an HTTP request for an access token.
     *
     * @return string
     *
     * @throws RequestException
     */
    protected function retrieveAccessToken()
    {
        Log::debug('IntrospectionGuard\retrieveAccessToken(): Fetching fresh token...');
        $response = Http::asForm()->post(config('introspection.token_url'), [
            'grant_type' => 'client_credentials',
            'client_id' => config('introspection.client_id'),
            'client_secret' => config('introspection.client_secret'),
            'scope' => config('introspection.token_scopes')
        ]);

        // If a client or server error occurs, throw a RequestException
        // Otherwise, return the access token
        return $response->throw()->json()['access_token'];
    }

    /**
     * Pass the bearer token to the authorization server for introspection and return the details.
     *
     * @param  \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Request|void
     *
     * @throws RequestException
     */
    protected function introspect(Request $request)
    {
        Log::debug('IntrospectionGuard\introspect(): Making request to introspection endpoint...');
        $response = Http::asForm()->withToken($this->getAccessToken())->post(config('introspection.introspect_url'), [
            'token_type_hint' => 'access_token',
            'token' => $request->bearerToken()
        ]);

        if ($response->failed()) {
            Log::debug('IntrospectionGuard\introspect(): Request failed with status code: '.$response->status());
            if ($response->status() === 401) {
                // Try and get a new access token
                $response = Http::asForm()->withToken($this->retrieveAccessToken())->post(config('introspection.introspect_url'), [
                    'token_type_hint' => 'access_token',
                    'token' => $request->bearerToken()
                ]);

                if ($response->failed()) {
                    $this->logError('Introspection request experienced a server or client error while trying to fetch an access token.');
                    throw new RequestException($response);
                }
            } else {
                $this->logError('Introspection request experienced an error while trying to fetch an access token.');
                throw new RequestException($response);
            }
        }

        $token = $response->json();
        Log::debug('IntrospectionGuard\introspect(): Introspection response: '.$response->body());

        // If we have an active response...
        if (isset($token['active']) && $token['active']) {
            // Add the attributes to the request
            $request->attributes->add([
                'oauth_access_token_id' => $token['jti'],
                'oauth_client_id' => $token['aud'],
                'oauth_user_id' => $token['id'] ?? null,
                'oauth_expires_at' => $token['exp'],
                'oauth_scopes' => $token['scope'],
                'oauth_token' => $token,
            ]);
        
            return $request;
        }
    }

    /**
     * Get the user for the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    public function user(Request $request)
    {
        Log::debug('IntrospectionGuard\user(): Checking for bearer token...');
        if ($request->bearerToken()) {
            Log::debug('IntrospectionGuard\user(): Token found via Authorization header: '.$request->bearerToken());
            return $this->authenticateViaBearerToken($request);
        } elseif ($request->cookie(Introspection::cookie())) {
            Log::debug('IntrospectionGuard\user(): Token found via cookie.');
            return $this->authenticateViaCookie($request);
        }

        // Maybe not
        return; // Returns unauthenticated, we failed to locate a user
    }

    /**
     * Authenticate the incoming request via the Bearer token.
     *
     * @param  Request $request
     * @return mixed
     */
    protected function authenticateViaBearerToken(Request $request)
    {
        if (! $request = $this->introspect($request)) {
            Log::debug('IntrospectionGuard\authenticateViaBearerToken(): Introspection failed!');
            return; // Returns unauthenticated error
        }

        if ($request->attributes->get('oauth_user_id')) {
            if ($user = $this->getUserModel($request->attributes->get('oauth_user_id'))) {
                $token = new Token([
                    'client' => $request->attributes->get('oauth_client_id'),
                    'scopes' => explode(' ', $request->attributes->get('oauth_scopes')),
                    'expires_at' => $request->attributes->get('oauth_expires_at'),
                ]);
            }
        }

        return $token ? $user->withAccessToken($token) : null;
    }

    /**
     * Authenticate the incoming request via the token cookie.
     *
     * @param  Request $request
     * @return mixed
     */
    public function authenticateViaCookie(Request $request)
    {
        $token = (array) JWT::decode(
            $this->encrypter->decrypt($request->cookie(Introspection::cookie()), false),
            $this->encrypter->getKey(),
            ['HS256']
        );

        if (! $this->validCsrf($token, $request) || time() >= $token['expiry']) {
            return;
        }

        if ($user = $this->getUserModel($token['sub'], true)) {
            return $user->withAccessToken(new TransientToken);
        }
    }

    /**
     * Attempts to locate the User model from the configured provider.
     *
     * @param  string  $id
     * @param  bool $useId Determines if we should use the findForIntrospection() method or not to locate the user
     * @return mixed
     *
     * @throws BadMethodCallException|RuntimeException
     */
    protected function getUserModel(string $id, bool $useId = false)
    {
        // Get the model used for the current API provider, typically App\User
        $provider = config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        if (!$useId) {
            if (method_exists($model, 'findForIntrospection')) {
                return $user = (new $model)->findForIntrospection($id);
            }
            throw new BadMethodCallException('Method not defined "findForIntrospection()"');
        }

        return (new $model)->find($id);
    }

    /**
     * Log an error and return a correlation ID.
     *
     * @param  string  $message
     * @return string
     */
    protected function logError(String $message)
    {
        $correlationId = \Str::uuid();
        Log::error('CID: ' . $correlationId . ' - ' . $message);

        return $correlationId;
    }

    /*
    |--------------------------------------------------------------------------
    | CSRF Handling
    |--------------------------------------------------------------------------
    |
    | These methods have been taken directly from Passports TokenGuard
    |
    */

    /**
     * Determine if the CSRF / header are valid and match.
     *
     * @param  array  $token
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function validCsrf($token, $request)
    {
        return isset($token['csrf']) && hash_equals(
            $token['csrf'],
            (string) $this->getTokenFromRequest($request)
        );
    }
    
    /**
     * Get the CSRF token from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function getTokenFromRequest($request)
    {
        $token = $request->header('X-CSRF-TOKEN');

        if (! $token && $header = $request->header('X-XSRF-TOKEN')) {
            $token = $this->encrypter->decrypt($header, static::serialized());
        }

        return $token;
    }

    /**
     * Determine if the cookie contents should be serialized.
     *
     * @return bool
     */
    public static function serialized()
    {
        return EncryptCookies::serialized('XSRF-TOKEN');
    }
}
