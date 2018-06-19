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

	function decode( required string token, required string key , string algorithm = "HS512" ) {
	
		if ( ListLen( arguments.token , "." ) != 3 ) {
			throw( type="Invalid Token", message="Token should contain 3 segments" );
		}

		var header 		= DeserializeJSON( _base64UrlDecode( listGetAt( arguments.token , 1 , "." )));
		var payload 	= DeserializeJSON( _base64UrlDecode( listGetAt( arguments.token , 2 , "." )));
		var signiture 	= ListGetAt( arguments.token , 3 , "." );

		var signInput = ListGetAt( arguments.token , 1 , "." ) & "." & ListGetAt( arguments.token , 2 , "." );
		if ( signiture != _sign( signInput , arguments.key , variables.instance.algorithmMap[arguments.algorithm] )) {
			throw( type="Invalid Token" , message="Signiture verification failed");
		}

		return payload;
	}

	function encode( required struct payload , required string key , string algorithm="HS512" ) {

		var segments = "";

		segments = ListAppend( segments , _base64UrlEscape( toBase64( serializeJSON( { "typ" =  "JWT", "alg" = arguments.algorithm } ))) , "." );
		segments = ListAppend( segments , _base64UrlEscape( toBase64( serializeJSON( arguments.payload ))) , "." );
		segments = ListAppend( segments , _sign( segments , arguments.key , arguments.algorithm ) , "." );

		return segments;
	}

	function verify( required string token, required string key , string algorithm="HS512" ) {
		var isValid = true;
		try {
			decode( arguments.token, arguments.key , variables.instance.algorithmMap[arguments.algorithm] );
		}
		catch(any e) {
			isValid = false;
		}

		return isValid;
	}

	private function _sign( required string msg , required string key , string algorithm="HS512" ) {
		var keySpec = CreateObject( "java" , "javax.crypto.spec.SecretKeySpec" ).init( arguments.key.getBytes() , arguments.algorithm );
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
