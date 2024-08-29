<?php

namespace App\Actions;

use App\Models\User;
use Illuminate\Auth\SessionGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use Ramsey\Uuid\Uuid;

class AuthsignalLoginAction
{
    public static function handle(User $user, SessionGuard $guard): bool
    {
        /** @var Request $request */
        $request = $guard->getRequest();

        $idempotencyKey = Uuid::uuid4()->toString();

        $redirectUrl =  URL::temporarySignedRoute(
            'auth.validate-challenge', now()->addMinutes(3), [
                'userId' => $user->id,
                'remember' => $request->boolean('remember')
            ]
        );

        $payload = [
            "redirectUrl" => $redirectUrl,
            "email" => $user->email,
            "deviceId" => $request->cookie('__as_aid'),
            "userAgent" => $_SERVER["HTTP_USER_AGENT"],
            "ipAddress" => $request->ip(),
            'idempotencyKey' => $idempotencyKey,
        ];

        $response = \Authsignal::track($user->id, 'signIn', $payload);

        switch ($response["state"]) {
            case "ALLOW":
                return true;
            case "BLOCK":
                return false;
            case "CHALLENGE_REQUIRED":
                abort(redirect($response["challengeUrl"]));
        }

        return false;
    }
}
