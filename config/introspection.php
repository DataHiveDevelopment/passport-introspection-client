<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Authorization Server
    |--------------------------------------------------------------------------
    |
    | URLs for the introspect and token endpoints on the authorization server.
    | In addition, any scopes that my be required by the /introspect endpoint.
    |
    | A default Introspection Server install does not check for a scope so
    | all scopes are requested by default.
    |
    | With a standard Passport setup, these are:
    | - https://myapp.test/oauth/introspect
    | - https://myapp.test/oauth/token
    |
    */

    'introspect_url' => env('INTROSPECTION_INTROSPECT_URL'),

    'token_url' => env('INTROSPECTION_TOKEN_URL'),

    'token_scopes' => env('INTROSPECTION_TOKEN_SCOPES', '*'),

    /*
    |--------------------------------------------------------------------------
    | Client Credentials
    |--------------------------------------------------------------------------
    |
    | These credentials will be used to connect to the introspection endpoint
    | on the authorization server.
    |
    | By default, these should be the details of a Client Credentials client.
    |
    */

    'client_id' => env('INTROSPECTION_CLIENT_ID'),

    'client_secret' => env('INTROSPECTION_CLIENT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | Performance
    |--------------------------------------------------------------------------
    |
    | To reduce network traffic and load on your authorization server, this
    | package will cache the introspection response for a configurable amount
    | of time. Use the options below to change this behavior.
    |
    */

    // Time in seconds, 15 minutes by default - Set to 0 to disable caching
    'introspection_cache_ttl' => 900,
];
