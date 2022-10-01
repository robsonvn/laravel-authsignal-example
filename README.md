

# Auth Signal + Laravel

This project demonstrates who to integrate AuthSignal with [Laravel Breeze Start Kit](https://laravel.com/docs/9.x/starter-kits) with Session Guard but the concept can be used with all sort of authentication methods.

It includes:

* An endpoint to enrol the authenticated user with a new MFA Authenticator (`GET /auth-signal/enrol-mfa`)
* A callback endpoint to validate the MFA challenge

The content of the integration is present in the folder `/src/app/AuthSignal` containing

## Installing AuthSignal PHP Library

```
composer require authsignal/authsignal-php
```

## Register the AuthSignal Service Provider

Add the AuthSignal Service provider in the `config/app.php` 

```php
'providers' => [
        ...
        \App\AuthSignal\Providers\AuthSignalServiceProvider::class,
]
```

## Register the MFA Challenge to the Login Endpoint

In the `authenticate` method of the `src/app/Http/Requests/Auth/LoginRequest.php`, introduce the MFA Challenge by replacing the lines

```php
    if (! Auth::attempt($this->only('email', 'password'), $this->boolean('remember'))) {
```

by

```php
    /** @var AuthSignalService $authSignalService */
    $authSignalService = app(AuthSignalService::class);
    $trackLogin = [$authSignalService, 'trackSignIn'];

    if (! Auth::attemptWhen($this->only('email', 'password'), [$trackLogin], $this->boolean('remember'))) {
```

### Bootstrapping example project

```bash
cp src/.env.example src/.env
# Update the AUTH_SIGNAL_API_KEY with your key

docker-compose up
docker-compose exec php composer install
docker-compose exec php artisan migrate
cd src 
yarn dev
```