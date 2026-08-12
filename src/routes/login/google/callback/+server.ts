import { redirect, isRedirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { createGoogleAuth } from '$lib/auth-google';
import { lucia } from '$lib/lucia';
import db from '$lib/db';
import { generateId } from 'lucia';

export const GET: RequestHandler = async (event) => {
	const code = event.url.searchParams.get('code');
	const state = event.url.searchParams.get('state');
	const storedState = event.cookies.get('google_oauth_state') ?? null;
	const storedCodeVerifier = event.cookies.get('google_oauth_code_verifier') ?? null;

	if (!code || !state || !storedState || state !== storedState || !storedCodeVerifier) {
		throw redirect(302, '/login?error=invalid_request');
	}

	try {
		const googleAuth = createGoogleAuth(event.url);
		const tokens = await googleAuth.validateAuthorizationCode(code, storedCodeVerifier);
		
		// Get user info from Google
		const googleUserResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
			headers: {
				Authorization: `Bearer ${tokens.accessToken()}`
			}
		});
		
		if (!googleUserResponse.ok) {
			throw new Error('Failed to fetch user info from Google');
		}
		
		const googleUser = await googleUserResponse.json() as {
			sub: string;
			name: string;
			email: string;
			picture?: string;
		};

		// Check if user exists by Google ID
		const existingUser = db
			.prepare('SELECT * FROM users WHERE google_id = ?')
			.get(googleUser.sub) as
			| {
					id: string;
					name: string;
					email: string;
					sport: string;
					google_id: string | null;
			  }
			| undefined;

		let userId: string;

		if (existingUser) {
			userId = existingUser.id;
		} else {
			// Check if user exists by email
			const existingByEmail = db
				.prepare('SELECT * FROM users WHERE email = ?')
				.get(googleUser.email) as
				| {
						id: string;
						name: string;
						email: string;
						sport: string;
						google_id: string | null;
				  }
				| undefined;

			if (existingByEmail) {
				// Update existing user with Google ID
				db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(googleUser.sub, existingByEmail.id);
				userId = existingByEmail.id;
			} else {
				// Create new user - redirect to profile completion to select sport
				userId = generateId(15);
				db.prepare(
					'INSERT INTO users (id, name, email, sport, google_id) VALUES (?, ?, ?, ?, ?)'
				).run(userId, googleUser.name, googleUser.email, 'Other', googleUser.sub);
			}
		}

		const session = await lucia.createSession(userId, {});
		const sessionCookie = lucia.createSessionCookie(session.id);

		event.cookies.set(sessionCookie.name, sessionCookie.value, {
			path: '.',
			...sessionCookie.attributes
		});

		event.cookies.delete('google_oauth_state', {
			path: '/'
		});
		event.cookies.delete('google_oauth_code_verifier', {
			path: '/'
		});

		// Check if user needs to complete profile (new user or sport is 'Other')
		const user = db.prepare('SELECT sport FROM users WHERE id = ?').get(userId) as { sport: string } | undefined;
		if (!user || user.sport === 'Other') {
			throw redirect(302, '/profile/complete');
		}

		throw redirect(302, '/progress');
	} catch (e) {
		// Re-throw redirects (they're thrown as errors in SvelteKit)
		if (isRedirect(e)) {
			throw e;
		}
		console.error('Google OAuth error:', e);
		throw redirect(302, '/login?error=server_error');
	}
};
