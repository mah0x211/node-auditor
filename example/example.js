var pkg = {
        auditor: require('../'),
        formidable: require('formidable'),
        http: require('http'),
        log: require('util').log
    },
    RULES = {
        txt: {
            type: 'text',
            required: true,
            max: 40
        },
        txt_multi: {
            type: 'text',
            required: false,
            multiline: true,
            min: 1,
            max: 40
        },
        signed: {
            type: 'signed',
            required: true,
            min: -10,
            max: 100
        },
        unsigned: {
            type: 'unsigned',
            required: true,
            min: 1,
            max: 100
        },
        email: {
            type: 'email',
            required: true
        },
        email_loose: {
            type: 'email_loose',
            required: true
        },
        url: {
            type: 'url',
            required: true
        },
        date: {
            type: 'date',
            required: true,
            func: function(val){
                return new Date(val);
            }
        }
    };
    
function Inspect( obj, level ){
    return require('util').inspect( obj, true, level );
}

function App()
{
    var label = 'test',
        auditor = new pkg.auditor.audit(),
        finish = function( res )
        {
            res.writeHead( 200, {
                'Content-Type': 'text/plain'
            });
            res.end( Inspect( data ) );
        },
        data = {
            errno:0,
            fields: {}
        };
    
    auditor.add( label, RULES );
    pkg.http.createServer(function(req,res)
    {
        if( req.method === 'POST' )
        {
            var form = new pkg.formidable.IncomingForm(),
                fields = auditor.getFields( label, true );
            
            form.on( 'field', function( field, val )
            {
                delete fields[field];
                if( ( val = auditor.check( label, field, val ) ) ){
                    data.fields[field] = val;
                    data.errno += val.errno;
                }
            })
            .on( 'file', function( field, val ){
                data.files[field] = val;
            })
            .on( 'error', function( err ){
                console.log( err );
                finish(res);
            })
            .on( 'end', function()
            {
                var val = undefined;
                
                for( var p in fields )
                {
                    if( ( val = auditor.check( label, p, undefined ) ) ){
                        data.fields[p] = val;
                        data.errno += val.errno;
                    }
                }
                finish(res);
            });
            form.parse(req);
        }
        else {
            finish(res);
        }
        
    }).listen( 1080, "127.0.0.1", function(){
        pkg.log('Server running at http://127.0.0.1:1080/');
    });
}


new App();

