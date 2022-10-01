<?php

namespace App\AuthSignal\Providers;

use App\AuthSignal\Controllers\AuthSignalController;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;

class AuthSignalServiceProvider extends BaseServiceProvider
{
    public function boot()
    {
        $this
            ->app['router']
            ->prefix('auth-signal')
            ->name('auth-signal.')
            ->middleware('web')
            ->group(function() {
                Route::get('/enrol-mfa' , [AuthSignalController::class, 'enrolMfa'])
                    ->middleware('auth')
                    ->name('enrol-mfa');

                Route::get('/challenge-callback' , [AuthSignalController::class, 'challengeCallback'])
                    ->name('challenge-callback');
            });
    }

    public function register()
    {
        \Authsignal::setApiKey(env('AUTH_SIGNAL_API_KEY'));
    }
}
