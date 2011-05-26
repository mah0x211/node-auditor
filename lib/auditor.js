/*
	auditor.js
	author: masatoshi teruya
	email: mah0x211@gmail.com
	copyright (C) 2011, masatoshi teruya. all rights reserved.
	
	errno:
		204		// NO_CONTENT
		406		// HTTP_NOT_ACCEPTABLE
		412		// PRECONDITION_FAILED

	[prefix|method]: {
		field_name: {
			type: [text | email | email_loose | url | signed | unsigned]
			required: [any]
			fix = [number]
			min = [number]
			max = [number]
			match = [regexp]
		}
	}
*/

var TypeRule = /^(text|email(_loose)?|url|date|(un)?signed)$/,
	NumberRule = /^(fix|min|max)$/,
	// REGEXP
	REGEXP_EMAIL = undefined,
	REGEXP_EMAIL_LOOSE = undefined,
	REGEXP_URL = undefined,
	// Status
	STATUS = {
		NO_CONTENT: 204,
		BAD_REQUEST: 400,
		NOT_ACCEPTABLE: 406,
		PRECONDITION_FAILED: 412
	};

function Init()
{
	// EMAIL REGEXP
	// ATOM: a-z A-Z 0-9 ! # $ % & ' * + - / = ? ^ _ ` { | } ~
	var ATEXT = "[-a-zA-Z0-9!#$%&'*+/=?^_`{|}~]",
		DOT_ATOM = "(?:" + ATEXT + "+(?:\\." + ATEXT + "+)*)",
		DOT_ATOM_LOOSE = "(?:" + ATEXT + "+(?:\\.|" + ATEXT + ")*)",
		QTEXT = "(?:\"(?:\\[^\\r\\n]|[^\\\"])*\")",
		LOCAL_PART = "(?:" + DOT_ATOM + "|" + QTEXT + ")",
		LOCAL_PART_LOOSE = "(?:" + DOT_ATOM_LOOSE + "|" + QTEXT + ")",
		/*
		[\x21-\x5a\x5e-\x7e]
		\x21-\x2f = [!"#$%&'()*+,=./]
		\x30-\x39 = [0-9]
		\x3a-\x40 = [:;<=>?@]
		\x41-\x5a = [A-Z]
		\x5e-\x60 = [^_`]
		\x61-\x7a = [a-z]
		\x7b-\x7e = [{|}~]
		*/
		DOMAIN_LIT = "\\[(?:\\S|[\x21-\x5a\x5e-\x7e])*\\]",
		DOMAIN_PART = "(?:" + DOT_ATOM + "|" + DOMAIN_LIT + ")",
		VALID = "^(?:" + LOCAL_PART + "@" + DOMAIN_PART + ")$",
		LOOSE = "^(?:" + LOCAL_PART_LOOSE + "@" + DOMAIN_PART + ")$";
		
	REGEXP_EMAIL = new RegExp( VALID );
	REGEXP_EMAIL_LOOSE = new RegExp( LOOSE );

	// URL REGEXP
		// scheme
	var SCHEME = "(https?|shttp)://",
		// userinfo
		USERINFO = "(?:((?:[-_.!~*'()a-zA-Z0-9;:&=+$,]|%[0-9A-Fa-f][0-9A-Fa-f])*)@)?",
		// host name
		DOMAIN_LABEL = "[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?",
		TOP_LABEL = "[a-zA-Z](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?",
		HOSTNAME = "(?:" + DOMAIN_LABEL + "\\.)*" + TOP_LABEL + "\\.?",
		// IPv4
		IPv4Address = "(?:[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)",
		// host
		HOST = "(" + HOSTNAME + "|" + IPv4Address + ")",
		// port
		PORT = "(?::([0-9]*))?"
		// path_segments
		PARAM = "(?:[-_.!~*'()a-zA-Z0-9:@&=+$,]|%[0-9A-Fa-f][0-9A-Fa-f])",
		SEGMENT = PARAM + "*(?:;" + PARAM + ")*",
		PATH_SEGMENTS = "(/" + SEGMENT + "(?:/" + SEGMENT + ")*)?",
		// [ reserved[;:@&=+$,]| unreserved[a-zA-Z0-9] | mark[\/-_.!~*'()]] | escaped
		uric = "(?:[;:@&=+$,?a-zA-Z0-9/\\_.!~*'()-]|%[0-9A-Fa-f][0-9A-Fa-f])*",
		uris = "(?:(?:[;:@&=+$,?a-zA-Z0-9/\\_.!~*'()-]+|%[0-9A-Fa-f][0-9A-Fa-f])*)",
		// query
		QUERY = "(\\?" + uris + ")?",
		// fragment
		FRAGMENT = "(#" + uris + ")?",
		// absolute uri
		ABSOLUTE_URI = SCHEME + USERINFO + HOST + PORT + PATH_SEGMENTS + QUERY,
		// uri reference
		URI_REFERENCE = ABSOLUTE_URI + FRAGMENT;

	REGEXP_URL = new RegExp( "\\b" + URI_REFERENCE );
}
Init();

// MARK: type check
function isBool( arg ){
	return ( typeof arg === 'boolean' );
};
function isNumber( arg ){
	return ( typeof arg === 'number' );
};
function isString( arg ){
	return ( typeof arg === 'string' );
};
function isArray( arg ){
	return ( arg && arg.constructor === Array );
};
function isObject( arg ){
	return ( arg && arg.constructor === Object );
};
function isFunction( arg ){
	return ( arg && typeof arg === 'function' );
};
function isRegExp( arg ){
	return ( arg && arg.constructor === RegExp );
};
function isDate( arg ){
	return ( arg && arg.constructor === Date );
}
function isEmail( arg ){
	return ( isString( arg ) && REGEXP_EMAIL.test( arg ) );
}
function isEmailLoose( arg ){
	return ( isString( arg ) && REGEXP_EMAIL_LOOSE.test( arg ) );
}
function isURL( arg ){
	return ( isString( arg ) && REGEXP_URL.test( arg ) );
}

function auditor()
{
	this.RuleSet = {};
	this.isBool = isBool;
	this.isNumber = isNumber;
	this.isString = isString;
	this.isArray = isArray;
	this.isObject = isObject;
	this.isFunction = isFunction;
	this.isRegExp = isRegExp;
	this.isDate = isDate;
	this.isEmail = isEmail;
	this.isEmailLoose = isEmailLoose;
	this.isURL = isURL;
}

// MARK: defined status
// add options
for( var ename in STATUS ){
	auditor.prototype[ename] = STATUS[ename];
}

auditor.prototype.addField = function( label, field, rule )
{
	if( !isString( label ) ){
		throw new Error( 'label must be type of String' );
	}
	else if( !isString( field ) ){
		throw new Error( 'field must be type of String' );
	}
	else if( !isObject( rule ) ){
		throw new Error( 'rule must be type of Object' );
	}
	else if( !rule.hasOwnProperty( 'type' ) || 
			 !isString( rule.type ) || 
			 !TypeRule.test( rule.type ) ){
		throw new Error( 'invalid rule type' );
	}
	else
	{
		var newRule = {};
		
		if( !isObject( this.RuleSet[label] ) ){
			this.RuleSet[label] = {};
		}
		
		for( var p in rule )
		{
			val = rule[p];
			if( p === 'type' )
			{
				if( !TypeRule.test( val ) ){
					throw new Error( 'invalid rule: ' + p );
				}
				else {
					newRule[p] = val;
				}
			}
			else if( p === 'required' ){
				newRule[p] = true;
			}
			else if( p === 'match' )
			{
				if( !isObject( val ) || !val.hasOwnProperty( 'pattern' ) ){
					throw new Error( 'invalid rule: ' + p );
				}
				else
				{
					if( val.hasOwnProperty( 'flag' ) ){
						newRule[p] = new RegExp( val.pattern, val.flag );
					}
					else {
						newRule[p] = new RegExp( val );
					}
				}
			}
			else if( NumberRule.test( p ) )
			{
				if( isString( val ) ){
					val = +val;
				}
				if( !isNumber( val ) || isNaN( val ) ){
					throw new Error( 'invalid rule: ' + p );
				}
				else {
					newRule[p] = val;
				}
			}
			else {
				throw new Error( 'unknown rule: ' + p );
			}
		}
		
		this.RuleSet[label][field] = newRule;
	}
};
auditor.prototype.removeField = function( label, field )
{
	if( isObject( this.RuleSet[label] ) ){
		delete this.RuleSet[label][field];
	}
}

auditor.prototype.add = function( label, rule )
{
	if( !isObject( rule ) ){
		throw new Error( 'rule must be type of Object' );
	}
	else
	{
		for( var field in rule ){
			this.addField( label, field, rule[field] );
		}
	}
};

auditor.prototype.remove = function( label )
{
	if( isObject( this.RuleSet[label] ) ){
		delete this.RuleSet[label];
	}
};

auditor.prototype.getFields = function( label )
{
	var fields = [],
		obj = this.RuleSet[label];
	
	if( isObject( obj ) )
	{
		for( var p in obj ){
			fields.push( p );
		}
	}
	return fields;
};

auditor.prototype.check = function( label, field, val )
{
	if( !isObject( this.RuleSet[label] ) || !isObject( this.RuleSet[label][field] ) ){
		return undefined;
	}
	else
	{
		var rule = this.RuleSet[label][field],
			result = {
				type: rule.type,
				required: ( rule.required ) ? true : false,
				val: val,
				errno: 0
			},
			tmp = val;
		
		// unknown field type
		// PRECONDITION_FAILED
		if( !TypeRule.test( rule.type ) ){
			result.errno = STATUS.PRECONDITION_FAILED;
			result.errstr = 'unknown field type';
		}
		// check defined
		// 204 NO_CONTENT
		else if( tmp === undefined || tmp === null || ( isString( tmp ) && tmp.length === 0 ) ){
			result.errno = STATUS.NO_CONTENT;
			result.errstr = 'field val undefined';
		}
		// check text
		else if( result.type === 'text' )
		{
			if( isNumber( tmp ) ){
				tmp += '';
			}
			// 400 BAD_REQUEST
			if( !isString( tmp ) ){
				result.errno = STATUS.BAD_REQUEST;
				result.errstr = 'invalid field type';
			}
			// check length
			else if( !tmp.length ){
				// 204 NO_CONTENT
				result.errno = STATUS.NO_CONTENT;
				result.errstr = 'field val undefined';
			}
			// check fix/min/max/match
			else if( ( isNumber( rule.fix ) && tmp.length !== rule.fix ) || 
					 ( isNumber( rule.min ) && tmp.length < rule.min ) ||
					 ( isNumber( rule.max ) && tmp.length > rule.max ) ||
					 ( isRegExp( rule.match ) && !rule.test( tmp ) ) ){
				// 406 NOT_ACCEPTABLE
				result.errno = STATUS.NOT_ACCEPTABLE;
				result.errstr = 'invalid field val';
			}
			else {
				result.val = tmp;
			}
			// convert only japanese half to full width
		}
		// check email
		else if( result.type === 'email' )
		{
			// 406 NOT_ACCEPTABLE
			if( !isEmail( tmp ) ){
				result.errno = STATUS.NOT_ACCEPTABLE;
				result.errstr = 'invalid field val';
			}
		}
		// check email_loose
		else if( result.type === 'email_loose' )
		{
			// 406 NOT_ACCEPTABLE
			if( !isEmailLoose( tmp ) ){
				result.errno = STATUS.NOT_ACCEPTABLE;
				result.errstr = 'invalid field val';
			}
		}
		// check url
		else if( result.type === 'url' )
		{
			// 406 NOT_ACCEPTABLE
			if( !isURL( tmp ) ){
				result.errno = STATUS.NOT_ACCEPTABLE;
				result.errstr = 'invalid field val';
			}
		}
		// check number
		else if( result.type === 'signed' || result.type === 'unsigned' )
		{
			if( isString( tmp ) ){
				tmp = +tmp;
			}
			
			// 400 BAD_REQUEST
			if( !isNumber( tmp ) || isNaN( tmp ) ){
				result.errno = STATUS.BAD_REQUEST;
				result.errstr = 'invalid field type';
			}
			// check fix/min/max/match
			else if( ( result.type === 'unsigned' && tmp < 0 ) ||
					 ( isNumber( rule.fix ) && tmp !== rule.fix ) || 
					 ( isNumber( rule.min ) && tmp < rule.min ) ||
					 ( isNumber( rule.max ) && tmp > rule.max ) ||
					 ( isRegExp( rule.match ) && !rule.match.test( tmp ) ) ){
				// 406 NOT_ACCEPTABLE
				result.errno = STATUS.NOT_ACCEPTABLE;
				result.errstr = 'invalid field val';
			}
			else {
				result.val = tmp;
			}
		}
		// check date
		else if( result.type === 'date' )
		{
			if( !isString( tmp ) ){
				result.errno = STATUS.BAD_REQUEST;
				result.errstr = 'invalid field type';
			}
			else
			{
				tmp = Date.parse( tmp );
				// 400 BAD_REQUEST
				if( !isNumber( tmp ) || isNaN( tmp ) ){
					result.errno = STATUS.BAD_REQUEST;
					result.errstr = 'invalid field type';
				}
			}
		}
		
		if( !result.required && result.errno === STATUS.NO_CONTENT ){
			delete result;
			result = undefined;
		}
		
		return result;
	}
};


module.exports = auditor;

