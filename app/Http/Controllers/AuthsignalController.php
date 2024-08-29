<?php

namespace App\Http\Controllers;

use App\Models\User;
use Authsignal;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthsignalController extends Controller
{
    public function settingsPage()
    {
        $result = Authsignal::getUser(
            Auth::id()
        );

        return view('auth.settings', [
            'enrolledVerificationMethods' => $result['enrolledVerificationMethods'] ?? []
        ]);
    }

    public function enrolWithAuthenticatorApp(Request $request) {
        /** @var User $user */
        $user = Auth::user();

        $result = Authsignal::getUser(
            Auth::id()
        );

        $isEnrolled = $result['isEnrolled'];

        $result = Authsignal::track($user->id, 'enroll', [
            'redirectToSettings' => $isEnrolled,
            'redirectUrl' =>  route('auth.validate-authenticator-app', ['remember' => $request->boolean('remember')]),
            'email' => $user->email,
            'deviceId' => $request->cookie('__as_aid'),
            'userAgent' => $_SERVER["HTTP_USER_AGENT"],
            'ipAddress' => $request->ip(),
        ]);

        if ($result['state'] === 'ALLOW') {
            return redirect($result['url']);
        } else {
            return redirect()->route('auth.settings')
                ->with('status', 'Unable to enroll authenticator app. Please try again later.');
        }
    }

    public function validateAuthenticatorApp(Request $request)
    {
        $token = $request->input('token');

        if (!$token) {
            abort(400, 'Token is required');
        }

        /** @var User $user */
        $user = Auth::user();

        $response = Authsignal::validateChallenge($token, $user->id);

        $isValid = $response['isValid'];

        return redirect()->route('auth.settings')
            ->with('status', $isValid ? 'Authenticator app enrolled successfully' : 'Failed to enroll authenticator app');
    }


    public function validateChallenge(Request $request)
    {
        if (!$request->hasValidSignatureWhileIgnoring(['token'])) {
            abort(401);
        }

        $token = $request->get('token');
        $userId = $request->get('userId');

        if (!$token || !$userId) {
            abort(400, 'token and userId are required');
        }

        $response = Authsignal::validateChallenge($token, $userId);

        if ($response['isValid'] && $response["state"] === 'CHALLENGE_SUCCEEDED') {
            // Authenticate the user using only the id
            Auth::loginUsingId($response['userId'], $request->boolean('remember'));
            return redirect()->route('dashboard');
        } else {
            return redirect()->route('login');
        }
    }

    public function enrollWithPasskey(Request $request)
    {
        /** @var User $user */
        $user = Auth::user();

        $result = Authsignal::track($user->id, 'enroll-passkey', [
            'scope' => 'add:authenticators',
            'redirectUrl' =>  route('dashboard'),
            'email' => $user->email,
            'deviceId' => $request->cookie('__as_aid'),
            'userAgent' => $_SERVER["HTTP_USER_AGENT"],
            'ipAddress' => $request->ip(),
        ]);

        if (!in_array('PASSKEY', $result['allowedVerificationMethods'])) {
            abort(403);
        }

        return response()->json(['token' => $result['token']]);
    }

    public function validatePasskeyEnrollment(Request $request)
    {
        $token = $request->input('token');

        if (!$token) {
            return response()->json(['error' => 'Token is required'], 400);
        }
        /** @var User $user */
        $user = Auth::user();

        $response = Authsignal::validateChallenge($token, $user->id);

        $isValid = $response['isValid'];

        return redirect()->route('auth.settings')
            ->with('status', $isValid ? 'Passkey enrolled successfully' : 'Failed to enroll passkey');
    }
}
