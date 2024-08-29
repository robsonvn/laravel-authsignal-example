# Laravel Authsignal Integration Example

This project is a demonstration of how to integrate **Laravel** with [Authsignal](https://www.authsignal.com/) to implement Multi-Factor Authentication (MFA) and Passkey enrollment and authentication. This project was bootstrapped using **Laravel Breeze** and utilizes **Blade** and **Laravel Fortify**. However, it can be adapted to any Laravel stack.

Step by step instructions on how to integrate Authsignal with your Laravel application can be found in the [Authsignal Documentation](HOWTO.md).

## Project Overview

- **Laravel Version:** 11.x
- **Bootstrap Starter Kit:** Laravel Breeze
- **Authentication:** Laravel Fortify
- **Frontend:** Blade Templates
- **Containerization:** Laravel Sail (Docker)

## Features

- **Multi-Factor Authentication (MFA):** Enhance your application’s security by adding a second layer of authentication.
- **Passkey Enrollment and Authentication:** Allow users to register and authenticate using passkeys for a passwordless and more secure login experience.

## Getting Started

### Prerequisites

Before you begin, ensure you have met the following requirements:

- **Docker** installed on your local machine (required for Laravel Sail).

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/authsignal/laravel-authsignal-example.git
   cd laravel-authsignal-example
   ```

2. **Set up environment variables:**

   Copy the `.env.example` to `.env`:

   ```bash
   cp .env.example .env
   ```

   Then, open the `.env` file and configure the following:

    ```env
    AUTH_SIGNAL_API_KEY=
    VITE_AUTH_SIGNAL_TENANT_ID=
    ```

3. **Start the development environment:**

   Laravel Sail makes it easy to start your development environment using Docker:

   ```bash
   ./vendor/bin/sail up -d
   ```

   This will start the application in a Docker container. Once it's running, you can access the application at [http://localhost](http://localhost).

4. **Install dependencies:**

   ```bash
   ./vendor/bin/sail composer install
   ./vendor/bin/sail npm install
   ```

5. **Run database migrations:**

   Run the migrations to set up the database tables:

   ```bash
   ./vendor/bin/sail artisan migrate
   ```

6. **Install frontend assets:**

   Compile the frontend assets using Laravel Mix:

   ```bash
   npm run dev
   ```

## Usage

Once the setup is complete, you can:

- **Register a new user:** Create a new account via the registration form.
- **Enable MFA:** After logging in, navigate to the settings page to enable MFA.
- **Enroll Passkey:** Follow the instructions to enroll a passkey for passwordless login.
- **Test Authentication:** Log out and test logging in using both MFA and passkey authentication.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open-source and available under the MIT License.

## Acknowledgments

- [Laravel](https://laravel.com/)
- [Authsignal](https://www.authsignal.com/)

## Contact

For any questions or suggestions, feel free to reach out at [hello@authsignal.com](mailto:hello@authsignal.com).
