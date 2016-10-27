component {

	this.title 				= "ColdBox JSON Web Tokens (JWT)";
	this.author 			= "Andrew Dixon";
	this.description 		= "ColdBox Module for encoding and decoding JSON Web Tokens (JWT). This is a port of the CF-JWT-Simple project which itself is a port of the node.js project node-jwt-simple to CFML. It currently supports HS256, HS384, and HS512 signing algorithms.";
	this.version			= "1.0.1";
	this.cfmapping 			= "jwt";
    this.entryPoint 		= "/jwt";

	function configure() {
	}

}