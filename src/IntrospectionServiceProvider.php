<?php

namespace DataHiveDevelopment\PassportIntrospectionClient;

use Illuminate\Auth\RequestGuard;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\ServiceProvider;
use Illuminate\Config\Repository as Config;
use DataHiveDevelopment\PassportIntrospectionClient\Guards\IntrospectionGuard;
use Laravel\Passport\Guards\TokenGuard;

class IntrospectionServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/introspection.php' => config_path('introspection.php'),
        ], 'introspection-client-config');
    }

    /**
    * Register the service provider.
    *
    * @return void
    */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/introspection.php', 'introspection');

        $this->registerGuard();
    }

    /**
     * Register the custom token guard.
     *
     * @return void
     */
    protected function registerGuard()
    {
        Auth::resolved(function ($auth) {
            $auth->extend('introspection', function ($app, $name, array $config) {
                return tap($this->makeGuard($config), function ($guard) {
                    $this->app->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }

    /**
     * Make an instance of the token guard.
     *
     * @param  array  $config
     * @return \Illuminate\Auth\RequestGuard
     */
    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new IntrospectionGuard(
                $this->app->make('encrypter')
            ))->user($request);
        }, $this->app['request']);
    }
}
