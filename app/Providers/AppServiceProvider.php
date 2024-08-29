<?php

namespace App\Providers;

use App\Http\Controllers\AuthsignalController;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Route;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        \Authsignal::setApiKey(env('AUTH_SIGNAL_API_KEY'));
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this
            ->app['router']
            ->prefix('auth')
            ->name('auth.')
            ->middleware('web')
            ->group(function() {
                Route::get('/settings' , [AuthsignalController::class, 'settingsPage'])
                    ->middleware('auth')
                    ->name('settings');

                Route::post('/enroll/authenticator-app' , [AuthsignalController::class, 'enrolWithAuthenticatorApp'])
                    ->middleware('auth')
                    ->name('enroll-authenticator-app');

                Route::get('/enroll/validate/authenticator-app' , [AuthsignalController::class, 'validateAuthenticatorApp'])
                    ->name('validate-authenticator-app');

                Route::get('/challenge/validate' , [AuthsignalController::class, 'validateChallenge'])
                    ->name('validate-challenge');

                Route::post('/enroll/validate/passkey' , [AuthSignalController::class, 'validatePasskeyEnrollment'])
                    ->middleware('auth')
                    ->name('validate-passkey-enrollment');

                Route::post('/enroll/passkey' , [AuthSignalController::class, 'enrollWithPasskey'])
                    ->middleware('auth')
                    ->name('api.enroll-passkey');
            });
    }
}
