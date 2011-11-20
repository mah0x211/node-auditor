/*
    auditor.js
    author: masatoshi teruya
    email: mah0x211@gmail.com
    copyright (C) 2011, masatoshi teruya. all rights reserved.
    
    errno:
        204        // NO_CONTENT
        406        // HTTP_NOT_ACCEPTABLE
        412        // PRECONDITION_FAILED

    [prefix|method]: {
        field_name: {
            type: [text | email | email_loose | url | date | signed | unsigned]
            required: [any]
            fix = [number]
            min = [number]
            max = [number]
            match = [regexp]
        }
    }
*/

var pkg = {
        url: require('url')
    },
    self = this,
    TypeRule = /^(text|email(_loose)?|url|date|(un)?signed)$/,
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

this.setStatus = function( obj, status )
{
    switch( status )
    {
        case STATUS.NO_CONTENT:
            obj.errno = status;
            obj.ename = 'NO_CONTENT';
            obj.errstr = 'field val undefined';
        break;
        case STATUS.BAD_REQUEST:
            obj.errno = status;
            obj.ename = 'BAD_REQUEST';
            obj.errstr = 'invalid field type';
        break;
        case STATUS.NOT_ACCEPTABLE:
            obj.errno = status;
            obj.ename = 'NOT_ACCEPTABLE';
            obj.errstr = 'invalid field val';
        break;
        case STATUS.PRECONDITION_FAILED:
            obj.errno = status;
            obj.ename = 'PRECONDITION_FAILED';
            obj.errstr = 'unknown field type';
        break;
    }
}

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
this.isBool = function( arg ){
    return ( typeof arg === 'boolean' );
};
this.isNumber = function( arg ){
    return ( typeof arg === 'number' );
};
this.isString = function( arg ){
    return ( typeof arg === 'string' );
};
this.isArray = function( arg ){
    return ( arg && arg.constructor === Array );
};
this.isObject = function( arg ){
    return ( arg && arg.constructor === Object );
};
this.isFunction = function( arg ){
    return ( typeof arg === 'function' );
};
this.isRegExp = function( arg ){
    return ( arg && arg.constructor === RegExp );
};
this.isDate = function( arg ){
    return ( arg && arg.constructor === Date );
};
this.isEmail = function( arg ){
    return ( self.isString( arg ) && REGEXP_EMAIL.test( arg ) );
};
this.isEmailLoose = function( arg ){
    return ( self.isString( arg ) && REGEXP_EMAIL_LOOSE.test( arg ) );
};
this.isURL = function( arg )
{
    var valid = false;
    
    if( self.isString( arg ) )
    {
        var url = pkg.url.parse( arg );
        
        if( url.slashes && !url.auth &&
            url.protocol && url.protocol.match( /^https?:$/ ) &&
            url.hostname && url.hostname.match( /\.[a-zA-Z]{2,}$/ ) )
        {
            if( url.port )
            {
                var port = +url.port;
                
                if( port >= 0 && port <= 65535){
                    valid = url.href;
                }
            }
            else {
                valid = url.href;
            }
        }
    }
    
    return valid;
};

this.audit = function()
{
    this.RuleSet = {};
    this.setStatus = self.setStatus;
    this.isBool = self.isBool;
    this.isNumber = self.isNumber;
    this.isString = self.isString;
    this.isArray = self.isArray;
    this.isObject = self.isObject;
    this.isFunction = self.isFunction;
    this.isRegExp = self.isRegExp;
    this.isDate = self.isDate;
    this.isEmail = self.isEmail;
    this.isEmailLoose = self.isEmailLoose;
    this.isURL = self.isURL;
};

// MARK: defined status
// add options
for( var ename in STATUS ){
    this.audit.prototype[ename] = STATUS[ename];
}

this.audit.prototype.addField = function( label, field, rule )
{
    if( !self.isString( label ) ){
        throw new Error( 'label must be type of String' );
    }
    else if( !self.isString( field ) ){
        throw new Error( 'field must be type of String' );
    }
    else if( !self.isObject( rule ) ){
        throw new Error( 'rule must be type of Object' );
    }
    else if( !rule.hasOwnProperty( 'type' ) || 
             !self.isString( rule.type ) || 
             !TypeRule.test( rule.type ) ){
        throw new Error( 'invalid rule type' );
    }
    else
    {
        var newRule = {};
        
        if( !self.isObject( this.RuleSet[label] ) ){
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
                newRule[p] = val;
            }
            else if( p === 'multiline' ){
                newRule[p] = val;
            }
            else if( p === 'match' )
            {
                if( !self.isObject( val ) || !val.hasOwnProperty( 'pattern' ) ){
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
                if( self.isString( val ) ){
                    val = +val;
                }
                if( !self.isNumber( val ) || isNaN( val ) ){
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
this.audit.prototype.removeField = function( label, field )
{
    if( self.isObject( this.RuleSet[label] ) ){
        delete this.RuleSet[label][field];
    }
};

this.audit.prototype.add = function( label, rule )
{
    if( !self.isObject( rule ) ){
        throw new Error( 'rule must be type of Object' );
    }
    else
    {
        for( var field in rule ){
            this.addField( label, field, rule[field] );
        }
    }
};

this.audit.prototype.remove = function( label )
{
    if( self.isObject( this.RuleSet[label] ) ){
        delete this.RuleSet[label];
    }
};

this.audit.prototype.getFields = function( label )
{
    var fields = [],
        obj = this.RuleSet[label];
    
    if( self.isObject( obj ) )
    {
        for( var p in obj ){
            fields.push( p );
        }
    }
    return fields;
};

this.audit.prototype.check = function( label, field, val )
{
    if( !self.isObject( this.RuleSet[label] ) || !self.isObject( this.RuleSet[label][field] ) ){
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
            self.setStatus( result, STATUS.PRECONDITION_FAILED );
        }
        // check defined
        // 204 NO_CONTENT
        else if( tmp === undefined || tmp === null || ( self.isString( tmp ) && tmp.length === 0 ) ){
            self.setStatus( result, STATUS.NO_CONTENT );
        }
        // check text
        else if( result.type === 'text' )
        {
            if( self.isNumber( tmp ) ){
                tmp += '';
            }
            // 400 BAD_REQUEST
            if( !self.isString( tmp ) ){
                self.setStatus( result, STATUS.BAD_REQUEST );
            }
            else
            {
                if( rule.multiline ){
                    tmp = tmp.replace( /\r\n?/g, "\n" );
                }
                else {
                    tmp = tmp.replace( /[\r\n]/g, '' );
                }
                
                // check length
                if( !tmp.length ){
                    // 204 NO_CONTENT
                    self.setStatus( result, STATUS.NO_CONTENT );
                }
                // check fix/min/max/match
                else if( ( self.isNumber( rule.fix ) && tmp.length !== rule.fix ) || 
                         ( self.isNumber( rule.min ) && tmp.length < rule.min ) ||
                         ( self.isNumber( rule.max ) && tmp.length > rule.max ) ||
                         ( self.isRegExp( rule.match ) && !rule.test( tmp ) ) ){
                    // 406 NOT_ACCEPTABLE
                    self.setStatus( result, STATUS.NOT_ACCEPTABLE );
                }
                else {
                    result.val = tmp;
                }
            }
            // convert only japanese half to full width
        }
        // check email
        else if( result.type === 'email' )
        {
            // 406 NOT_ACCEPTABLE
            if( !self.isEmail( tmp ) ){
                self.setStatus( result, STATUS.NOT_ACCEPTABLE );
            }
        }
        // check email_loose
        else if( result.type === 'email_loose' )
        {
            // 406 NOT_ACCEPTABLE
            if( !self.isEmailLoose( tmp ) ){
                self.setStatus( result, STATUS.NOT_ACCEPTABLE );
            }
        }
        // check url
        else if( result.type === 'url' )
        {
            // 406 NOT_ACCEPTABLE
            if( !( tmp = self.isURL( tmp ) ) ){
                self.setStatus( result, STATUS.NOT_ACCEPTABLE );
            }
            else {
                result.val = tmp;
            }
        }
        // check number
        else if( result.type === 'signed' || result.type === 'unsigned' )
        {
            if( self.isString( tmp ) ){
                tmp = +tmp;
            }
            
            // 400 BAD_REQUEST
            if( !self.isNumber( tmp ) || isNaN( tmp ) ){
                self.setStatus( result, STATUS.BAD_REQUEST );
            }
            // check fix/min/max/match
            else if( ( result.type === 'unsigned' && tmp < 0 ) ||
                     ( self.isNumber( rule.fix ) && tmp !== rule.fix ) || 
                     ( self.isNumber( rule.min ) && tmp < rule.min ) ||
                     ( self.isNumber( rule.max ) && tmp > rule.max ) ||
                     ( self.isRegExp( rule.match ) && !rule.match.test( tmp ) ) ){
                // 406 NOT_ACCEPTABLE
                self.setStatus( result, STATUS.NOT_ACCEPTABLE );
            }
            else {
                result.val = tmp;
            }
        }
        // check date
        else if( result.type === 'date' )
        {
            if( !self.isString( tmp ) ){
                self.setStatus( result, STATUS.BAD_REQUEST );
            }
            else
            {
                tmp = Date.parse( tmp );
                // 400 BAD_REQUEST
                if( !self.isNumber( tmp ) || isNaN( tmp ) ){
                    self.setStatus( result, STATUS.BAD_REQUEST );
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


module.exports = this;

