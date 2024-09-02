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
                <div class="p-6">
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
                </div>
            </div>
        </div>
    </div>

    <script type="text/javascript">

        document.addEventListener('DOMContentLoaded', function() {
            const passkeyForm = document.getElementById("passkey-form")
            passkeyForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                const enrollPasskeyResponse = await fetch('{{ route('auth.api.enroll-passkey') }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                    },
                });

                const { token } = await enrollPasskeyResponse.json();

                const resultToken = await window.authsignal.passkey.signUp({
                    token,
                    userName: "{{ Auth::user()->email }}",
                });

                document.querySelector('form#passkey-form input[name="token"]').value = resultToken.token;

                passkeyForm.submit();
            });
        });

    </script>
</x-app-layout>
