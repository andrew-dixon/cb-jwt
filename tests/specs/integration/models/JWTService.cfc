component extends="testbox.system.BaseSpec" {

	/*********************************** LIFE CYCLE Methods ***********************************/

	function beforeAll() {

		jwt = new models.JWTService();

		payload = {
					'ts' = '2016-07-01 12:30:00',
					'userid' = 'jdoe',
					'anythingIlike' = 'somevalue'
				};

		key = 'my-secret-key';
		keyAsBase64 = 'Zm9vLWJhci1ib28tYmF6LXNlY3JldA';

		JWTs = {
			'HS256' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.7j1hXffzImfU9ahv-JeTf35zc6Us3r-2IIBVb_tYpMs',
			'HS384' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.GoQQ2pLda1GzqODp8oaVQmMyhVbBBsgP9hEqErqRzFH0pq2nHwKn4ViK5LIo2W26',
			'HS512' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.sbeVB6v73IPtd8YhUL3b1I3kYYP9gIUYgrTSs6P2YcNH95LJVTN0ihfvyQDm329WP1CjHNyGtSVVIDfHPWW2YA'
		};
		JWTsUsingSecretInBase64 = {
			'HS256' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9._iMCD0BjJjUwTm-9ViaOGiJ3WT9Sww2Cn30_vRrZYJE',
			'HS384' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.k9IcOykSN9bzeJGzfM7b3Cqk6cpoJ89volAcSOxq_AfNYUaprdomhaElKpVeepvc',
			'HS512' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.TPNFA59ToYTCABKcx6J23bLgm9NHjKJhlOCdt0mQXSIPqwvsV-c5t6MD3pOyK76ICvWRKGDKXQ-UhL_-Q6eUOg'
		};

	}

	/*********************************** BDD SUITES ***********************************/

	function run() {

		describe( "JSON Web Token Tests", function() {

			story( "I need to be able to create a new JSON Web Token", function() {
				given( "a payload, key and algorithm", function() {
					then( "a JSON Web Token should be returned", function() {

						loop struct=JWTs item="algorithm" {
							actual = jwt.encode( payload , key , algorithm );
							expect( actual ).toBe( JWTs[algorithm] );
						}

						loop struct=JWTsUsingSecretInBase64 item="algorithm" {
							actual = jwt.encode( payload, keyAsBase64, algorithm, true );
							expect( actual ).toBe( JWTsUsingSecretInBase64[algorithm] );
						}

					});
				});
			});

			story( "I need to be able to decode a JSON Web Token", function() {
				given( "an encoded token", function() {
					then( "a payload structure should be returned", function() {

						loop struct=JWTs item="algorithm" {
							actual = jwt.decode( JWTs[algorithm] , key , algorithm );

							expect( actual ).toBeTypeOf( 'struct' );

							expect( actual ).toHaveKey( 'ts' );
							expect( actual ).toHaveKey( 'userid' );
							expect( actual ).toHaveKey( 'anythingIlike' );

							expect( actual.ts ).toBe( payload.ts );
							expect( actual.userid ).toBe( payload.userid );
							expect( actual.anythingIlike ).toBe( payload.anythingIlike );
						}

						loop struct=JWTsUsingSecretInBase64 item="algorithm" {
							actual = jwt.decode( JWTsUsingSecretInBase64[algorithm], keyAsBase64, algorithm, true );

							expect( actual ).toBeTypeOf( 'struct' );

							expect( actual ).toHaveKey( 'ts' );
							expect( actual ).toHaveKey( 'userid' );
							expect( actual ).toHaveKey( 'anythingIlike' );

							expect( actual.ts ).toBe( payload.ts );
							expect( actual.userid ).toBe( payload.userid );
							expect( actual.anythingIlike ).toBe( payload.anythingIlike );
						}

					});
				});
			});

			story( "I need to be able to verify a JSON Web Token", function() {
				given( "a valid token", function() {
					then( "a true boolean should be returned", function() {

						loop struct=JWTs item="algorithm" {
							actual = jwt.verify( JWTs[algorithm] , key , algorithm );

							expect( actual ).toBeTypeOf( 'boolean' );
							expect( actual ).toBe( true );
						}

						loop struct=JWTsUsingSecretInBase64 item="algorithm" {
							actual = jwt.verify( JWTsUsingSecretInBase64[algorithm], keyAsBase64, algorithm, true );

							expect( actual ).toBeTypeOf( 'boolean' );
							expect( actual ).toBe( true );
						}

					});
				});

				given( "a invalid token", function() {
					then( "a false boolean should be returned", function() {

						loop struct=JWTs item="algorithm" {
							actual = jwt.verify( JWTs[algorithm] & "make-token-invalid" , key , algorithm );

							expect( actual ).toBeTypeOf( 'boolean' );
							expect( actual ).toBe( false );
						}

						loop struct=JWTsUsingSecretInBase64 item="algorithm" {
							actual = jwt.verify( JWTsUsingSecretInBase64[algorithm] & "make-token-invalid", keyAsBase64, algorithm, true );

							expect( actual ).toBeTypeOf( 'boolean' );
							expect( actual ).toBe( false );
						}
					});
				});

			});

		});

	}

}