/**
 * Firebase UI — JWT Authenticator Plugin
 * MIT License — Copyright (c) 2024 JWT Authenticator Contributors
 */
( function () {
    'use strict';

    const cfg = window.jwtAuthFirebase || {};

    // ── Helpers ──────────────────────────────────────────────────────────────

    function setLoading( form, loading ) {
        const btn      = form.querySelector( '.jwt-auth-btn' );
        const btnText  = form.querySelector( '.jwt-auth-btn-text' );
        const btnLoad  = form.querySelector( '.jwt-auth-btn-loading' );
        if ( ! btn ) return;
        btn.disabled = loading;
        if ( btnText ) btnText.style.display = loading ? 'none'   : '';
        if ( btnLoad ) btnLoad.style.display = loading ? 'inline' : 'none';
    }

    function showError( form, message ) {
        const el = form.querySelector( '.jwt-auth-error' );
        if ( ! el ) return;
        el.textContent  = message;
        el.style.display = 'block';
    }

    function hideError( form ) {
        const el = form.querySelector( '.jwt-auth-error' );
        if ( el ) el.style.display = 'none';
    }

    function showSocialError( container, message ) {
        const el = container.querySelector( '.jwt-auth-error' );
        if ( ! el ) return;
        el.textContent  = message;
        el.style.display = 'block';
    }

    async function exchangeFirebaseToken( idToken, redirectUrl ) {
        const res = await fetch( cfg.apiKeyEndpoint, {
            method  : 'POST',
            headers : {
                'Content-Type' : 'application/json',
                'X-WP-Nonce'   : cfg.nonce,
            },
            body : JSON.stringify( { firebase_token: idToken } ),
        } );

        const data = await res.json();

        if ( ! res.ok ) {
            throw new Error( data.message || 'Authentication failed.' );
        }

        // Store JWT for SPA use
        if ( data.token ) {
            localStorage.setItem( 'jwt_auth_token', data.token );
        }
        if ( data.refresh_token ) {
            localStorage.setItem( 'jwt_auth_refresh_token', data.refresh_token );
        }

        window.location.href = redirectUrl || cfg.redirectUrl || '/';
    }

    // ── Firebase initialisation (lazy, via config endpoint) ──────────────────

    let firebaseApp  = null;
    let firebaseAuth = null;

    async function getFirebase() {
        if ( firebaseAuth ) return firebaseAuth;

        // Fetch public config from WP
        const cfgRes  = await fetch( cfg.configEndpoint );
        const cfgData = await cfgRes.json();

        if ( ! cfgData.web_api_key || ! cfgData.project_id ) {
            throw new Error( 'Firebase is not configured. Please contact the site administrator.' );
        }

        // Dynamically import Firebase SDK modules
        const { initializeApp }                                              = await import( 'https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js' );
        const { getAuth, signInWithEmailAndPassword,
                createUserWithEmailAndPassword, signInWithPopup,
                GoogleAuthProvider, FacebookAuthProvider, TwitterAuthProvider,
                GithubAuthProvider, OAuthProvider,
                signInWithPhoneNumber, RecaptchaVerifier }                   = await import( 'https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js' );

        firebaseApp  = initializeApp( {
            apiKey    : cfgData.web_api_key,
            authDomain: cfgData.auth_domain || `${ cfgData.project_id }.firebaseapp.com`,
            projectId : cfgData.project_id,
        } );
        firebaseAuth = getAuth( firebaseApp );

        // Expose individual providers for use below
        window._jwtAuthProviders = {
            GoogleAuthProvider, FacebookAuthProvider, TwitterAuthProvider,
            GithubAuthProvider, OAuthProvider,
            signInWithEmailAndPassword, createUserWithEmailAndPassword,
            signInWithPopup, signInWithPhoneNumber, RecaptchaVerifier,
            getAuth,
        };

        return firebaseAuth;
    }

    function getProvider( providerName ) {
        const p = window._jwtAuthProviders;
        if ( ! p ) return null;
        switch ( providerName ) {
            case 'google'    : return new p.GoogleAuthProvider();
            case 'facebook'  : return new p.FacebookAuthProvider();
            case 'twitter'   : return new p.TwitterAuthProvider();
            case 'github'    : return new p.GithubAuthProvider();
            case 'apple'     : return new p.OAuthProvider( 'apple.com' );
            case 'yahoo'     : return new p.OAuthProvider( 'yahoo.com' );
            case 'microsoft' : return new p.OAuthProvider( 'microsoft.com' );
            default          : return null;
        }
    }

    // ── Login Form ────────────────────────────────────────────────────────────

    function initLoginForms() {
        document.querySelectorAll( '.jwt-auth-firebase-login-form' ).forEach( form => {
            form.addEventListener( 'submit', async e => {
                e.preventDefault();
                hideError( form );
                setLoading( form, true );

                const email    = form.querySelector( '[name="firebase_email"]' ).value.trim();
                const password = form.querySelector( '[name="firebase_password"]' ).value;
                const redirect = form.closest( '[data-redirect]' )?.dataset.redirect || cfg.redirectUrl;

                try {
                    const auth        = await getFirebase();
                    const p           = window._jwtAuthProviders;
                    const userCred    = await p.signInWithEmailAndPassword( auth, email, password );
                    const idToken     = await userCred.user.getIdToken();
                    await exchangeFirebaseToken( idToken, redirect );
                } catch ( err ) {
                    showError( form, err.message || 'Login failed.' );
                    setLoading( form, false );
                }
            } );
        } );
    }

    // ── Register Form ─────────────────────────────────────────────────────────

    function initRegisterForms() {
        document.querySelectorAll( '.jwt-auth-firebase-register-form' ).forEach( form => {
            form.addEventListener( 'submit', async e => {
                e.preventDefault();
                hideError( form );

                const email    = form.querySelector( '[name="firebase_email"]' ).value.trim();
                const password = form.querySelector( '[name="firebase_password"]' ).value;
                const confirm  = form.querySelector( '[name="firebase_confirm"]' )?.value;
                const redirect = form.closest( '[data-redirect]' )?.dataset.redirect || cfg.redirectUrl;

                if ( confirm !== undefined && password !== confirm ) {
                    showError( form, 'Passwords do not match.' );
                    return;
                }

                setLoading( form, true );

                try {
                    const auth     = await getFirebase();
                    const p        = window._jwtAuthProviders;
                    const userCred = await p.createUserWithEmailAndPassword( auth, email, password );
                    const idToken  = await userCred.user.getIdToken();
                    await exchangeFirebaseToken( idToken, redirect );
                } catch ( err ) {
                    showError( form, err.message || 'Registration failed.' );
                    setLoading( form, false );
                }
            } );
        } );
    }

    // ── Social Login ──────────────────────────────────────────────────────────

    function initSocialButtons() {
        document.querySelectorAll( '.jwt-auth-social-btn' ).forEach( btn => {
            btn.addEventListener( 'click', async () => {
                const providerName = btn.dataset.provider;
                const container    = btn.closest( '.jwt-auth-social-login' );
                const redirect     = container?.dataset.redirect || cfg.redirectUrl;
                const origText     = btn.innerHTML;

                btn.disabled  = true;
                btn.innerHTML = '<span>Connecting…</span>';

                try {
                    const auth     = await getFirebase();
                    const provider = getProvider( providerName );
                    if ( ! provider ) throw new Error( `Provider "${ providerName }" not supported.` );

                    const p        = window._jwtAuthProviders;
                    const userCred = await p.signInWithPopup( auth, provider );
                    const idToken  = await userCred.user.getIdToken();
                    await exchangeFirebaseToken( idToken, redirect );
                } catch ( err ) {
                    if ( container ) showSocialError( container, err.message || 'Social login failed.' );
                    btn.disabled  = false;
                    btn.innerHTML = origText;
                }
            } );
        } );
    }

    // ── Phone / OTP ───────────────────────────────────────────────────────────

    function initPhoneAuth() {
        document.querySelectorAll( '.jwt-auth-phone-form' ).forEach( form => {
            let confirmationResult = null;

            const phoneInput = form.querySelector( '[name="firebase_phone"]' );
            const otpSection = form.querySelector( '.jwt-auth-otp-section' );
            const otpInput   = form.querySelector( '[name="firebase_otp"]' );
            const sendBtn    = form.querySelector( '.jwt-auth-send-otp' );
            const verifyBtn  = form.querySelector( '.jwt-auth-verify-otp' );
            const redirect   = form.closest( '[data-redirect]' )?.dataset.redirect || cfg.redirectUrl;

            if ( sendBtn ) {
                sendBtn.addEventListener( 'click', async () => {
                    hideError( form );
                    sendBtn.disabled = true;
                    sendBtn.textContent = 'Sending…';

                    try {
                        const auth = await getFirebase();
                        const p    = window._jwtAuthProviders;

                        if ( ! window._jwtRecaptchaVerifier ) {
                            window._jwtRecaptchaVerifier = new p.RecaptchaVerifier(
                                auth, 'jwt-auth-recaptcha-container', { size: 'invisible' }
                            );
                        }

                        confirmationResult = await p.signInWithPhoneNumber(
                            auth, phoneInput.value, window._jwtRecaptchaVerifier
                        );

                        if ( otpSection ) otpSection.style.display = 'block';
                        sendBtn.textContent = 'Resend OTP';
                        sendBtn.disabled    = false;
                    } catch ( err ) {
                        showError( form, err.message || 'Failed to send OTP.' );
                        sendBtn.disabled    = false;
                        sendBtn.textContent = 'Send OTP';
                    }
                } );
            }

            if ( verifyBtn ) {
                verifyBtn.addEventListener( 'click', async () => {
                    if ( ! confirmationResult ) { showError( form, 'Please request an OTP first.' ); return; }
                    hideError( form );
                    verifyBtn.disabled = true;

                    try {
                        const userCred = await confirmationResult.confirm( otpInput.value );
                        const idToken  = await userCred.user.getIdToken();
                        await exchangeFirebaseToken( idToken, redirect );
                    } catch ( err ) {
                        showError( form, err.message || 'Invalid OTP.' );
                        verifyBtn.disabled = false;
                    }
                } );
            }
        } );
    }

    // ── Boot ──────────────────────────────────────────────────────────────────

    document.addEventListener( 'DOMContentLoaded', () => {
        initLoginForms();
        initRegisterForms();
        initSocialButtons();
        initPhoneAuth();
    } );

} )();
