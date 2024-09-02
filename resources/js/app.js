import './bootstrap';

import Alpine from 'alpinejs';
import {Authsignal} from "@authsignal/browser";

window.Alpine = Alpine;

Alpine.start();

const authsignal = new Authsignal({
    tenantId: import.meta.env.VITE_AUTH_SIGNAL_TENANT_ID,
});

window.authsignal = authsignal;
