<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Authorization Server
    |--------------------------------------------------------------------------
    |
    | URLs for the introspect and token endpoints on the authorization server.
    | In addition, any scopes that my be required by the /introspect
    | endpoint. A default Introspection Server does not check for a scope so
    | all scopes are requested.
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

];
