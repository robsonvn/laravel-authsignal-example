<?php

namespace App\AuthSignal\Services;

use App\Models\User;
use Illuminate\Auth\SessionGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use Ramsey\Uuid\Uuid;

class AuthSignalService
{
    const SIGN_IN_ACTION = 'signIn';

    public function trackSignIn(User $user, SessionGuard $guard): bool
    {
        /** @var Request $request */
        $request = $guard->getRequest();

        $idempotencyKey = Uuid::uuid4()->toString();

        // Generate a temporary url signed valid for three minutes containing the userid, so we know who to authenticate after passing the challenge
        $redirectUrl =  URL::temporarySignedRoute(
            'auth-signal.challenge-callback', now()->addMinutes(3), [
                'userId' => $user->id,
                'idempotencyKey' => $idempotencyKey,
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

        $response = \Authsignal::trackAction($user->id, self::SIGN_IN_ACTION, $payload);

        switch ($response["state"]) {
            case "ALLOW":
               return true;
            case "BLOCK":
                return false;
            case "CHALLENGE_REQUIRED":
                $this->handleChallengeRequired($request, $response["challengeUrl"]);
        }

        return false;
    }

    private function handleChallengeRequired(Request $request, string $challengeUrl): void
    {
        if ($request->wantsJson()) {
            // If the requests wants JSON, return an object containing the challenge url
            abort(response()->json([
                'challenge_url' => $challengeUrl,
            ]));

        } else {
            // Abort the request and redirect to the challenge
            abort(redirect($challengeUrl));
        }
    }
}
