# Laravel Authentication with Authsignal Integration
This documentation assumes you have a Laravel application set up with [Laravel Sanctum](https://laravel.com/docs/11.x/sanctum) and Blade. The examples are based on a standard Laravel project scaffolded with [Laravel Breeze](https://laravel.com/docs/11.x/starter-kits#laravel-breeze) for simplicity. However, the steps can be easily adapted to other frontend frameworks or authentication mechanisms within your stack.

For a complete reference implementation, you can find the project used in this example in the following repository: [authsignal/laravel-authsignal-example](https://github.com/authsignal/laravel-authsignal-example.git).

## Summary

indexes go here.

## Installing Authsignal

1. Install the Authsignal PHP package:

```bash
composer require authsignal/authsignal-php
```

2. Create an account on [Authsignal](https://portal.authsignal.com/users/sign_up) if you haven't already.

3. Retrieve your secret API key from the Authsignal portal under **Settings > API Keys**.

4. Add the API key to your `.env` file:

```bash
AUTH_SIGNAL_API_KEY=<your secret key>
```

### Creating a Service Provider for Authsignal

Create a service provider to configure Authsignal:

```bash
php artisan make:provider AuthsignalServiceProvider
```

In the `register` method of the `AuthsignalServiceProvider`, add the following code:

```php
public function register(): void
{
    \Authsignal::setApiKey(env('AUTH_SIGNAL_API_KEY'));
}
```

## Settings Page for MFA Enrollment

For simplicity, we'll create a settings page where users can enroll in MFA and check their status.

### Creating the Settings Page

Create the `AuthsignalController`
```bash
php artisan make:controller AuthsignalController
```

1. Add a `settingsPage` method in the `AuthsignalController`:

```php
use App\Models\User;
use Authsignal;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

public function settingsPage()
{
    $result = Authsignal::getUser(Auth::id());

    return view('auth.settings', [
        'enrolledVerificationMethods' => $result['enrolledVerificationMethods'] ?? []
    ]);
}
```

For JavaScript frameworks like React, you can return the response as JSON:

```php
public function settingsPage()
{
    $result = Authsignal::getUser(Auth::id());

    return response()->json([
        'enrolledVerificationMethods' => $result['enrolledVerificationMethods'] ?? []
    ]);
}
```

2. Create a `settings.blade.php` file in `resources/views/auth` with the following content:

```html
<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 leading-tight">
            Authentication Settings
        </h2>
    </x-slot>
    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8">
            @if (session('status'))
                <div class="p-4 bg-amber-200 rounded mb-4">
                    {{ session('status') }}
                </div>
            @endif
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                <div class="p-6"></div>
            </div>
        </div>
    </div>
</x-app-layout>
```

3. Add a navigation link to the settings page in `resources/view/layouts/navigation.blade.php`:

```diff
<x-dropdown-link :href="route('profile.edit')">
    {{ __('Profile') }}
</x-dropdown-link>
+<x-dropdown-link
+    :href="route('auth.settings')">
+    {{ __('Authentication Settings') }}
+</x-dropdown-link>
```

4. Add a route for the settings page in the `AuthsignalServiceProvider`:

```php
use App\Http\Controllers\AuthsignalController;
use Illuminate\Support\Facades\Route;

public function boot()
{
    $this->app['router']
        ->prefix('auth')
        ->name('auth.')
        ->middleware('web')
        ->group(function() {
            Route::get('/settings', [AuthsignalController::class, 'settingsPage'])
                ->middleware('auth')
                ->name('settings');
        });
}
```

Now you can navigate to `http://localhost/auth/settings`.

### Enabling Multi-Factor Authentication (MFA)

1. Add UI components for enrolling in MFA to your `settings.blade.php` in between `<div class="p-6"></div>`:

```html
                   <div class="grid gap-4">
    <div class="flex items-center justify-between rounded-md border border-muted bg-background p-4">
        <div class="flex items-center gap-3">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-6 w-6 text-muted-foreground">
                <rect width="14" height="20" x="5" y="2" rx="2" ry="2"></rect>
                <path d="M12 18h.01"></path>
            </svg>
            <div>
                <div class="font-medium">MFA</div>
                <div class="text-sm text-muted-foreground">Secure your account with MFA</div>
            </div>
        </div>
        <div class="flex items-center gap-2">
            @if (!empty($enrolledVerificationMethods))
            <div>
                <div class="text-sm text-muted-foreground">
                    @foreach ($enrolledVerificationMethods as $method)
                    <span class="rounded-full bg-green-500 px-2 py-1 text-xs font-medium text-green-50">{{ Str::title(str_replace('_', ' ',$method)) }}</span>
                    @endforeach
                </div>
            </div>
            @else
            <div class="rounded-full bg-red-500 px-2 py-1 text-xs font-medium text-green-50">Not enrolled</div>
            @endif
            <form method="POST" action="{{route('auth.enroll-mfa')}}">
                @csrf
                <button class="inline-flex items-center justify-center whitespace-nowrap text-sm font-medium h-9 rounded-md px-3 border border-input">
                    @if (empty($enrolledVerificationMethods))
                    Enroll
                    @else
                    Manage
                    @endif
                </button>
            </form>
        </div>
    </div>
</div>
```

2. Create a method to enroll users in MFA in the `AuthsignalController`:

```php
public function enrollMFA(Request $request) {
    $user = Auth::user();
    $result = Authsignal::getUser(Auth::id());

    $isEnrolled = $result['isEnrolled'];

    $result = Authsignal::track($user->id, 'enroll', [
        'redirectToSettings' => $isEnrolled,
        'redirectUrl' => route('auth.validate-mfa-challenge', ['remember' => $request->boolean('remember')]),
        'email' => $user->email,
        'deviceId' => $request->cookie('__as_aid'),
        'userAgent' => $_SERVER["HTTP_USER_AGENT"],
        'ipAddress' => $request->ip(),
    ]);

    if ($result['state'] === 'ALLOW') {
        return redirect($result['url']);
    } else {
        return redirect()->route('auth.settings')
            ->with('status', 'Unable to enroll MFA. Please try again later.');
    }
}
```

3. Register the route for enrolling in MFA:

```php
Route::post('/enroll/mfa', [AuthsignalController::class, 'enrollMFA'])
    ->middleware('auth')
    ->name('enroll-mfa');
```

4. Add a method to handle MFA validation in `AuthsignalController`:

```php
public function validateMfaChallenge(Request $request)
{
    $token = $request->input('token');
    if (!$token) {
        abort(400, 'Token is required');
    }

    $user = Auth::user();
    $response = Authsignal::validateChallenge($token, $user->id);

    return redirect()->route('auth.settings')
        ->with('status', $response['isValid'] ? 'Enrolled MFA successfully' : 'Failed to enroll MFA');
}
```

5. Register the validation route in `AuthsignalServiceProvider`:

```php
Route::get('/enroll/validate/mfa', [AuthsignalController::class, 'validateMfaChallenge'])
    ->name('validate-mfa-challenge');
```

Now, you can enroll and validate MFA using your preferred authentication app.

## Challenging the User When Authenticating

This step assumes that your application uses Laravel Fortify, but you can adapt the following instructions to any part of your application that handles user login. The goal is to track the login action and redirect the user if a second method of authentication is required.

### Step 1: Create a New Action for Authsignal Login

Create a new file `app/Actions/AuthsignalLoginAction.php` and add the following content:

```php
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

        $redirectUrl = URL::temporarySignedRoute(
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
```

### Step 2: Modify the `authenticate` Method

To integrate this login action, modify the `authenticate` method in the `LoginRequest` class located in `app/Http/Requests/Auth/LoginRequest.php`:

```diff
- if (! Auth::attempt($this->only('email', 'password'), $this->boolean('remember'))) {
+ if (! Auth::attemptWhen($this->only('email', 'password'), [[\App\Actions\AuthsignalLoginAction::class, 'handle']], $this->boolean('remember'))) {
```

This modification ensures that the Authsignal login action is called during the login attempt.

### Step 3: Create a Challenge Validation Endpoint

Next, create the endpoint to validate the MFA challenge. In the `AuthsignalController`, add the following method:

```php
public function validateAuthenticationChallenge(Request $request)
{
    if (! $request->hasValidSignatureWhileIgnoring(['token'])) {
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
```

### Step 4: Register the Challenge Validation Route

Finally, register the route for the challenge validation in the `AuthsignalServiceProvider`:

```php
Route::get('/challenge/validate', [AuthsignalController::class, 'validateAuthenticationChallenge'])
    ->name('validate-challenge');
```

### Final Step: Test the Integration

Congratulations! Your application is now integrated with Authsignal MFA. To test it, log out and log back in. If you are not prompted to provide an MFA code, ensure that the action `signIn` rule in the Authsignal portal is set to challenge. You can configure this in the Authsignal portal under **Actions > signIn > Settings > Outcome**.


# Setting up Passkey Authentication with Authsignal

In this section, we will guide you through setting up Passkey authentication using the Authsignal. This example uses Laravel with plain JavaScript for the frontend, but it can easily be adapted to other stacks, such as React.

For more details on configuring Passkeys with Authsignal, refer to the official documentation: [Authsignal Passkeys](https://docs.authsignal.com/scenarios/passkeys-prebuilt-ui).

## Step 1: Setup Enrollment and Validation Endpoints

To begin, we need to create endpoints that handle the enrollment and validation of Passkey authentication. In the `AuthsignalController`, add the following methods:

### 1. Enroll User with Passkey

This method triggers the Passkey enrollment process and generates a token to be used by the Authsignal SDK.

```php
public function enrollWithPasskey(Request $request)
{
    /** @var User $user */
    $user = Auth::user();

    $result = Authsignal::track($user->id, 'enroll-passkey', [
        'scope' => 'add:authenticators',
        'redirectUrl' => route('dashboard'),
        'email' => $user->email,
        'deviceId' => $request->cookie('__as_aid'),
        'userAgent' => $_SERVER["HTTP_USER_AGENT"],
        'ipAddress' => $request->ip(),
    ]);

    if (!in_array('PASSKEY', $result['allowedVerificationMethods'])) {
        abort(403, 'Passkey enrollment is not allowed.');
    }

    return response()->json(['token' => $result['token']]);
}
```

### 2. Validate Passkey Enrollment

This method validates the Passkey enrollment after the user completes the process on the frontend.

```php
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
```

### 3. Register the Routes

Next, register these routes in your `AuthsignalServiceProvider`:

```php
Route::post('/enroll/validate/passkey', [AuthsignalController::class, 'validatePasskeyEnrollment'])
    ->middleware('auth')
    ->name('validate-passkey-enrollment');

Route::post('/enroll/passkey', [AuthsignalController::class, 'enrollWithPasskey'])
    ->middleware('auth')
    ->name('api.enroll-passkey');
```

## Step 2: Setting up the Frontend

In this example, we will use plain JavaScript and HTML, but the same principles apply to frameworks like React or Vue. We will trigger a challenge by calling our backend API to issue a new enrollment token and then use the `Authsignal JavaScript SDK` to handle Passkey enrollment in the browser.

### 1. Install the Authsignal JavaScript SDK

First, install the Authsignal SDK:

```bash
npm install @authsignal/browser
```

### 2. Configure the SDK

We need to configure the SDK on the frontend. If you're using Laravel Vite for asset management, follow these steps:

1. Add the Authsignal tenant ID to your `.env` file:

    ```env
    VITE_AUTH_SIGNAL_TENANT_ID=<your tenant id>
    ```

2. Initialize the SDK in your `resources/js/app.js`:

    ```js
    import { Authsignal } from "@authsignal/browser";

    const authsignal = new Authsignal({
        tenantId: import.meta.env.VITE_AUTH_SIGNAL_TENANT_ID,
    });

    window.authsignal = authsignal;
    ```

### 3. Add the Passkey UI Component

Add a UI component to the settings page for enrolling in Passkey:

```html
@if (!in_array('PASSKEY', $enrolledVerificationMethods))
    <div class="flex items-center justify-between rounded-md border border-muted bg-background p-4">
        <div class="flex items-center gap-3">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-6 w-6 text-muted-foreground">
                <path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"></path>
                <path d="m21 2-9.6 9.6"></path>
                <circle cx="7.5" cy="15.5" r="5.5"></circle>
            </svg>
            <div>
                <div class="font-medium">Passkey</div>
                <div class="text-sm text-muted-foreground">Secure your account with a passkey</div>
            </div>
        </div>
        <div class="flex items-center gap-2">
            <div class="rounded-full bg-red-500 px-2 py-1 text-xs font-medium text-green-50">Not enrolled</div>
            <form method="POST" id="passkey-form" action="{{route('auth.validate-passkey-enrollment')}}">
                @csrf
                <input type="hidden" name="token">
                <button type="submit" class="inline-flex items-center justify-center whitespace-nowrap text-sm font-medium h-9 rounded-md px-3 border border-input">
                    Enroll
                </button>
            </form>
        </div>
    </div>
@endif
```

### 4. Handle Passkey Enrollment with JavaScript

Add the following JavaScript code to trigger the Passkey enrollment when the user clicks the enroll button. Place this script just before `</x-app-layout>` in your Blade template:

```html
<script type="text/javascript">
    document.addEventListener('DOMContentLoaded', function() {
        const passkeyForm = document.getElementById("passkey-form");

        passkeyForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            // Fetch the enrollment token from the backend
            const enrollPasskeyResponse = await fetch('{{ route('auth.api.enroll-passkey') }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                },
            });

            const { token } = await enrollPasskeyResponse.json();

            // Use Authsignal SDK to enroll with Passkey
            const resultToken = await window.authsignal.passkey.signUp({
                token,
                userName: "{{ Auth::user()->email }}",
            });

            // Submit the token to the backend for validation
            document.querySelector('form#passkey-form input[name="token"]').value = resultToken.token;
            passkeyForm.submit();
        });
    });
</script>
```

## Final Step: Testing the Passkey Enrollment

After setting up the backend and frontend, you can test the Passkey enrollment:

1. Go to your account's settings page.
2. Enroll with a Passkey using the UI component.
3. Once enrolled, the status will be updated on the settings page.

That's it! You've successfully integrated Passkey authentication with Authsignal in your Laravel application.


# Logging in with Passkey

In this section, we will configure the UI and backend to allow users to log in with a Passkey. We will modify the login page to trigger Passkey authentication, handle the challenge on the frontend, and validate the Passkey token in the backend.

This example will modify the existing login endpoint to accept either a Passkey token or the standard username and password. You can choose to split the endpoints if you prefer separate routes.

## Step 1: Configuring the UI

### 1. Update the Login Page

We need to modify the `resources/views/auth/login.blade.php` file to add support for Passkey authentication.

1. **Add `autocomplete` to the Email Input Field**

   This allows the browser to autocomplete the email field using WebAuthn.

   ```diff
   - <x-text-input id="email" class="block mt-1 w-full" type="email" name="email" :value="old('email')" required autofocus />
   + <x-text-input id="email" class="block mt-1 w-full" type="email" name="email" :value="old('email')" required autofocus autocomplete="username webauthn"/>
   ```

2. **Add a Hidden Input for the Passkey Token**

   We need to add a hidden input field to store the Passkey token that will be generated by the JavaScript challenge.

   ```diff
   <form method="POST" action="{{ route('login') }}">
       @csrf
   +   <input type="hidden" name="passkey" id="passkey" />
   ```

3. **Add JavaScript to Handle Passkey Challenge**

   At the beginning of the file, include the following script to initiate the Passkey challenge when the page loads. If a Passkey is successfully retrieved, it will automatically submit the form.

   ```html
   <script>
       document.addEventListener('DOMContentLoaded', async function() {
           const passkeyResponse = await authsignal.passkey.signIn({
               autofill: true,
           });

           if (passkeyResponse.token) {
               document.getElementById('passkey').value = passkeyResponse.token;
               document.querySelector('form').submit();
           }
       });
   </script>
   ```

## Step 2: Validating the Passkey Token and Authenticating the User

Now, we need to modify the backend to handle Passkey authentication. The goal is to validate the Passkey token and authenticate the user accordingly.

### 1. Modify Validation Rules

In `app/Http/Requests/Auth/LoginRequest.php`, adjust the validation rules to accept either the Passkey token or the traditional email and password.

```diff
public function rules(): array
{
    return [
-        'email' => ['required', 'string', 'email'],
-        'password' => ['required', 'string'],
+        'passkey' => ['required_without_all:email,password', 'nullable', 'string'],
+        'email' => ['required_without:passkey', 'nullable', 'string', 'email'],
+        'password' => ['required_without:passkey', 'nullable', 'string'],
    ];
}
```

### 2. Modify the `authenticate` Method

Update the `authenticate` method to check if a Passkey token is present in the request. If a Passkey token is provided, validate it using Authsignal. Otherwise, fall back to the traditional email and password authentication.

```diff
public function authenticate(): void
{
    $this->ensureIsNotRateLimited();

+   if ($passkey = $this->input('passkey')) {
+       $response = \Authsignal::validateChallenge($passkey);
+
+       if ($response['state'] === 'CHALLENGE_SUCCEEDED' && $response['isValid']) {
+           Auth::loginUsingId($response['userId']);
+       } else {
+           RateLimiter::hit($this->throttleKey());
+           throw ValidationException::withMessages([
+               'passkey' => 'Unable to authenticate with Passkey. Please try again.',
+           ]);
+       }
+   } else {
       if (! Auth::attempt($this->only('email', 'password'), $this->boolean('remember'))) {
           RateLimiter::hit($this->throttleKey());

           throw ValidationException::withMessages([
               'email' => trans('auth.failed'),
           ]);
       }
+   }

    RateLimiter::clear($this->throttleKey());
}
```

## Final Step: Testing the Passkey Login

With the integration complete, you can now test the login functionality:

1. Visit the login page.
2. If a Passkey is configured for your account, the page will automatically trigger the Passkey challenge.
3. If the challenge is successful, the form will be submitted, and you will be logged in.

If Passkey authentication fails, the system will prompt you to try again, or you can log in using your email and password.

This concludes the Passkey login integration!
