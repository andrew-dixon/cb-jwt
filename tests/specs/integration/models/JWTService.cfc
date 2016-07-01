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

		JWTs = {
			'HmacSHA256' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIbWFjU0hBMjU2In0.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.lKWBhDp82eKHsT6U59B45jZel8UlIyhOpeXjy77NaVg',
			'HmacSHA384' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIbWFjU0hBMzg0In0.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.nP68Cgs8xRlIPHcCHMXhuB4RTdT8Mz7ci_RE_11tNb_y4nGTLcwuHaB_Rq4T9eQr',
			'HmacSHA512' = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIbWFjU0hBNTEyIn0.eyJ1c2VyaWQiOiJqZG9lIiwiYW55dGhpbmdJbGlrZSI6InNvbWV2YWx1ZSIsInRzIjoiMjAxNi0wNy0wMSAxMjozMDowMCJ9.TUKr6u5Ud803kgogt_aSiaZRCVX7EKdHyXXej1hbj4f4IsiIIiGGDKB170BVMRZuSv83r85n-6NmPh3VEVXNQg'
		}

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
					});
				});

				given( "a invalid token", function() {
					then( "a false boolean should be returned", function() {

						loop struct=JWTs item="algorithm" {

							actual = jwt.verify( JWTs[algorithm] & "make-token-invalid" , key , algorithm );
							
							expect( actual ).toBeTypeOf( 'boolean' );
							expect( actual ).toBe( false );
						
						}
					});
				});

			});

		});

	}

}