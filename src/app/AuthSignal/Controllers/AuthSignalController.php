<?php

namespace App\AuthSignal\Controllers;

use App\AuthSignal\Services\AuthSignalService;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthSignalController extends Controller
{
    public function enrolMfa(Request $request)
    {
        /** @var User $user */
        $user = Auth::user();

        // Update the redirect url to a page saying that the setup was successful or not
        $payload = ["redirectUrl" => route('dashboard')];

        $result = \Authsignal::trackAction($user->id, "enroll", $payload);

        if ($result['isEnrolled'] === false && $result['state'] === 'ALLOW') {
            if ($request->wantsJson()) {
                return response()->json(['enrol_url' => $result['url']]);
            }
            return redirect($result['url']);
        } else {
            // Abort request if can't enrol
            abort(401);
        }
    }

    public function challengeCallback(Request $request)
    {
        // Validate the request signature but ignore the token sent by AuthSignal
        if (! $request->hasValidSignatureWhileIgnoring(['token'])) {
            abort(401);
        }

        // As the URL is signed, we can trust the id present. Alternatively, we can use sessions or in memory db to fetch the user id
        $userId = $request->get('userId');
        $idempotencyKey = $request->get('idempotencyKey');

        $response = \Authsignal::getAction($userId, AuthSignalService::SIGN_IN_ACTION , $idempotencyKey);

        if ($response["state"] === 'CHALLENGE_SUCCEEDED') {
            // Authenticate the user using only the id
            Auth::loginUsingId($userId);
            return redirect()->route('dashboard');
        } else {
            return redirect()->route('login');
        }
    }
}
