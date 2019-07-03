component singleton {

	/*
		Available algorithms:

			* HmacSHA256
			* HmacSHA384
			* HmacSHA512
	*/

	variables.instance.algorithmMap = {
		"HS256": "HmacSHA256",
		"HS384": "HmacSHA384",
		"HS512": "HmacSHA512"
	};

	/**
	* @token A valid JWT, having three segments separated by dots
	* @key The secret used to verify the signature which may be a string of characters or a collection of bytes expressed in Base64
	* @algorithm One of three supported algorithms: HS256, HS384, HS512
	* @secretIsBase64 When true, the secret is the collection of bytes represented in Base64, not the literal characters passed as @key
	*/
	function decode( required string token, required string key, string algorithm="HS512", boolean secretIsBase64=false ) {

		if ( ListLen( arguments.token , "." ) != 3 ) {
			throw( type="Invalid Token", message="Token should contain 3 segments" );
		}

		var header 		= DeserializeJSON( _base64UrlDecode( listGetAt( arguments.token , 1 , "." )));
		var payload 	= DeserializeJSON( _base64UrlDecode( listGetAt( arguments.token , 2 , "." )));
		var signiture 	= ListGetAt( arguments.token , 3 , "." );

		var signInput = ListGetAt( arguments.token , 1 , "." ) & "." & ListGetAt( arguments.token , 2 , "." );
		if ( signiture != _sign( signInput, arguments.key, arguments.algorithm, arguments.secretIsBase64 )) {
			throw( type="Invalid Token" , message="Signiture verification failed");
		}

		return payload;
	}

	/**
	* @payload A CFML structure to be serialized as the token payload
	* @key The secret used to sign the JWT, which may be a string of characters or a collection of bytes expressed in Base64
	* @algorithm One of three supported algorithms: HS256, HS384, HS512
	* @secretIsBase64 When true, the secret is the collection of bytes represented in Base64, not the literal characters passed as @key
	*/
	function encode( required struct payload, required string key, string algorithm="HS512", boolean secretIsBase64=false ) {

		var segments = "";

		segments = ListAppend( segments , _base64UrlEscape( toBase64( serializeJSON( { "typ" =  "JWT", "alg" = arguments.algorithm } ))) , "." );
		segments = ListAppend( segments , _base64UrlEscape( toBase64( serializeJSON( arguments.payload ))) , "." );
		segments = ListAppend( segments , _sign( segments, arguments.key, arguments.algorithm, arguments.secretIsBase64 ) , "." );

		return segments;
	}

	/**
	* @token A valid JWT, having three segments separated by dots
	* @key The secret used to sign the JWT, which may be a string of characters or a collection of bytes expressed in Base64
	* @algorithm One of three supported algorithms: HS256, HS384, HS512
	* @secretIsBase64 When true, the secret is the collection of bytes represented in Base64, not the literal characters passed as @key
	*/
	function verify( required string token, required string key, string algorithm="HS512", boolean secretIsBase64=false ) {
		var isValid = true;
		try {
			decode( arguments.token, arguments.key, arguments.algorithm, arguments.secretIsBase64 );
		}
		catch(any e) {
			isValid = false;
		}

		return isValid;
	}

	private function _sign( required string msg, required string key, string algorithm="HS512", boolean secretIsBase64=false ) {
		var keySpec = CreateObject( "java" , "javax.crypto.spec.SecretKeySpec" ).init( arguments.secretIsBase64 ? binaryDecode(_base64UrlUnescape(arguments.key), "base64") : arguments.key.getBytes(), arguments.algorithm );
		var mac = CreateObject( "java" , "javax.crypto.Mac" ).getInstance( variables.instance.algorithmMap[arguments.algorithm] );
		mac.init( keySpec );
		return _base64URLEscape( toBase64( mac.doFinal( msg.getBytes() )));
	}

	private function _base64UrlEscape( required str ) {
		return REReplace( REReplace( REReplace( str , "\+" , "-" , "ALL") , "\/" , "_" , "ALL" ) , "=" , "" , "ALL" );
	}

	private function _base64UrlUnescape( required str ) {
		var base64String = REReplace( REReplace( arguments.str , "\-" , "+" , "ALL" ) , "\_" , "/" , "ALL" );
		var padding = RepeatString("=",4 - len(base64String) mod 4);
		return base64String & padding;
	}

	private function _base64UrlDecode( required str ) {
		return ToString( ToBinary( _base64UrlUnescape( arguments.str )));
	}

}
