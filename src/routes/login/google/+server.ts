import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { createGoogleAuth } from '$lib/auth-google';
import { generateState, generateCodeVerifier } from 'arctic';

export const GET: RequestHandler = async (event) => {
	const state = generateState();
	const codeVerifier = generateCodeVerifier();
	const googleAuth = createGoogleAuth(event.url);
	
	const scopes = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'];
	
	const url = googleAuth.createAuthorizationURL(
		state,
		codeVerifier,
		scopes
	);

	event.cookies.set('google_oauth_state', state, {
		path: '/',
		secure: import.meta.env.PROD,
		httpOnly: true,
		maxAge: 60 * 10,
		sameSite: 'lax'
	});

	event.cookies.set('google_oauth_code_verifier', codeVerifier, {
		path: '/',
		secure: import.meta.env.PROD,
		httpOnly: true,
		maxAge: 60 * 10,
		sameSite: 'lax'
	});

	throw redirect(302, url.toString());
};
