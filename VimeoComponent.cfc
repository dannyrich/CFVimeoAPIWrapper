<cfcomponent>
	<cfset db = application.db>

	<cfset this.API_REST_URL = 'http://vimeo.com/api/rest/v2'>
	<cfset this.API_AUTH_URL = 'http://vimeo.com/oauth/authorize'>
	<cfset this.API_ACCESS_TOKEN_URL = 'http://vimeo.com/oauth/access_token'>
	<cfset this.API_REQUEST_TOKEN_URL = 'http://vimeo.com/oauth/request_token'>

    <cfset this.CACHE_FILE = 'file'>

    <cfset this._consumer_key = false>
    <cfset this._consumer_secret = false>
    <cfset this._cache_enabled = false>
    <cfset this._cache_dir = false>
    <cfset this._token = false>
    <cfset this._token_secret = false>
    <cfset this._upload_md5s = false>

    <cffunction name="init" access="public" returntype="void">
        <cfargument name="consumer_key" default="">
        <cfargument name="consumer_secret" default="">
        <cfargument name="token" default=false>
        <cfargument name="token_secret" default=false>

        <cfset this._consumer_key = arguments.consumer_key>
        <cfset this._consumer_secret = arguments.consumer_secret>

        <cfif (arguments.token AND arguments.token_secret)>
            <cfset setToken(token=arguments.token, token_secret=arguments.token_secret)>
        </cfif>
    </cffunction>

    <!--- Utility function to URL encode a string as rfc3986 --->
    <cffunction name="__encode_rfc3986" access="public" returntype="string">
        <cfargument name="string">
        <cfset local.s = replacelist(urlencodedformat(arguments.string), "%2D,%2E,%5F,%7E", "-,.,_,~")>
        <cfreturn local.s>
    </cffunction>

    <!--- Utility function to HMAC hash a string --->
    <cffunction name="__hash_hmac" access="private" returntype="string">
        <cfargument name="algorithm" default="HmacSHA1">
        <cfargument name="string">
        <cfargument name="key">

        <cfset local.jMsg = JavaCast("string",arguments.string).getBytes("iso-8859-1") />
        <cfset local.jKey = JavaCast("string",arguments.key).getBytes("iso-8859-1") />

        <cfset local.key = createObject("java","javax.crypto.spec.SecretKeySpec") />
        <cfset local.mac = createObject("java","javax.crypto.Mac") />

        <cfset local.key = local.key.init(local.jKey,arguments.algorithm) />

        <cfset local.mac = local.mac.getInstance(local.key.getAlgorithm()) />
        <cfset local.mac.init(local.key) />
        <cfset local.mac.update(local.jMsg) />

        <cfreturn toBase64(local.mac.doFinal())>
    </cffunction>

    <!--- Utility function create url query --->
    <cffunction name="__url_query" access="private" returntype="string">
        <cfargument name="struct" default="#StructNew()#">
        <cfargument name="sortarray" default="#ArrayNew(1)#">
        <cfargument name="encode" default=false>

        <cfset local.return = "">

        <cfloop array="#arguments.sortarray#" index="local.k">
            <cfif StructKeyExists(arguments.struct, local.k)>
                <cfif arguments.encode>
                    <cfset local.return = ListAppend(local.return, __encode_rfc3986(string=local.k) & "=" & __encode_rfc3986(string=arguments.struct[local.k]), "&")>
                <cfelse>
                    <cfset local.return = ListAppend(local.return, local.k & "=" & arguments.struct[local.k], "&")>
                </cfif>
                <cfset StructDelete(arguments.struct, local.k)>
            </cfif>
        </cfloop>

        <cfloop list="#StructKeyList(arguments.struct)#" index="local.i">
            <cfif arguments.encode>
                <cfset local.return = ListAppend(local.return, __encode_rfc3986(string=local.i) & "=" & __encode_rfc3986(string=arguments.struct[local.i]), "&")>
            <cfelse>
                <cfset local.return = ListAppend(local.return, local.i & "=" & arguments.struct[local.i], "&")>
            </cfif>
        </cfloop>

        <cfreturn local.return>
    </cffunction>

    <!--- Utility function to parse a URL string into a struct --->
    <cffunction name="__parse_string" access="private" returntype="struct">
        <cfargument name="string" default="">

        <cfset local.return = {}>

        <cfloop array="#ListToArray(arguments.string, "&")#" index="local.p">
            <cfset local.temp = ListToArray(local.p, "=")>
            <cfif ArrayLen(local.temp) GT 1>
                <cfset local.return[local.temp[1]] = local.temp[2]>
            </cfif>
        </cfloop>

        <cfreturn local.return>
    </cffunction>

    <!--- Utility function for generating base string --->
    <cffunction name="__generate_base_string" access="private" returntype="string">
        <cfargument name="request_method" default="GET">
        <cfargument name="base_uri" default="#this.API_REST_URL#">
        <cfargument name="params" default="#StructNew()#">

        <cfset local.return = arguments.request_method & "&" & __encode_rfc3986(arguments.base_uri)>
        <cfset local.keys = StructKeyArray(arguments.params)>

        <cfset ArraySort(local.keys, "textNoCase")>

        <cfloop array="#local.keys#" index="local.key">
            <cfset local.return &= __encode_rfc3986("&#local.key#=#arguments.params[local.key]#")>
        </cfloop>

        <cfreturn local.return>
    </cffunction>

    <!--- Cache a response
            @param struct params The parameters for the response.
            @param string response The serialized response data.
    --->
    <cffunction name="_cache" access="private" returntype="boolean">
        <cfargument name="params" default=false>
        <cfargument name="response" default="">

        <cfif IsStruct(arguments.params)>
            <cfset StructDelete(arguments.params, "oauth_nonce")>
            <cfset StructDelete(arguments.params, "oauth_signature")>
            <cfset StructDelete(arguments.params, "oauth_timestamp")>

            <cfset local.hash = hash(SerializeJSON(arguments.params))>

            <cfif this._cache_enabled EQ this.CACHE_FILE>
                <cfset local.file = this._cache_dir & '/' & local.hash & '.cache'>
                <cfif FileExists(local.file)>
                    <cfset FileDelete(local.file)>
                </cfif>
                <cftry>
                    <cffile action="write" file=local.file output="#SerializeJSON(arguments.params)#" />

                    <cfreturn true>

                    <cfcatch type="any">
                        <cfreturn false>
                    </cfcatch>
                </cftry>
            </cfif>
        </cfif>
    </cffunction>

    <!--- Create the authorization header for a set of params.
            @param struct oauth_params The OAuth parameters for the call.
            @return string The OAuth Authroization header.
    --->

    <cffunction name="_generateAuthHeader" access="private" returntype="string">
        <cfargument name="request_url" default="">
        <cfargument name="request_method" default="GET">
        <cfargument name="oauth_params" default="#StructNew()#">
        <cfargument name="oauth_params_sortorder" default="#ArrayNew(1)#">

        <cfset local.url = ReReplace(arguments.request_url, "^(https?|ftp):\/\/", "")>
        <cfset local.base = ListGetAt(local.url, 1, "/")>
        <cfset local.request = Replace(local.url, local.base, "")>

        <!--- <cfset local.auth_header = UCase(arguments.request_method) & " " & local.request & " HTTP/1.1 Host: " & local.base & ' Accept: */* Authorization: OAuth realm=""'> --->
        <cfset local.auth_header = 'Authorization: OAuth realm=""'>

        <!--- First loop through the sorted params --->
        <cfloop array="#arguments.oauth_params_sortorder#" index="local.k">
            <cfif StructKeyExists(arguments.oauth_params, local.k)>
                <cfset local.key = __encode_rfc3986(string=local.k)>
                <cfset local.value = __encode_rfc3986(string=arguments.oauth_params[local.k])>
                <cfset local.auth_header = ListAppend(local.auth_header, local.key & '="' & local.value & '"')>
                <cfset StructDelete(arguments.oauth_params, local.k)>
            </cfif>
        </cfloop>

        <!--- Add the rest --->
        <cfloop list="#StructKeyList(arguments.oauth_params)#" index="local.v">
            <cfset local.key = __encode_rfc3986(string=local.v)>
            <cfset local.value = __encode_rfc3986(string=arguments.oauth_params[local.v])>
            <cfset local.auth_header = ListAppend(local.auth_header, local.key & '="' & local.value & '"')>
        </cfloop>

        <cfreturn local.auth_header>
    </cffunction>

    <!--- Generate a nonce for the call.
            @return string The nonce
    --->

    <cffunction name="_generateNonce" access="private" returntype="string">
        <cfset var iMin = 0>
        <cfset var iMax = CreateObject("java","java.lang.Integer").MAX_VALUE>
        <cfset var sToEncode = (DateDiff("s", CreateDate(1970,1,1), DateConvert("Local2UTC", Now()))) & RandRange(iMin, iMax)>

        <cfreturn hash(sToEncode)>
    </cffunction>

    <!--- Generate the OAuth signature.
            @param struct args The full list of args to generate the signature for.
            @param string request_method The request method, either POST or GET.
            @param string url The base URL to use.
            @return string The OAuth signature.
    --->

    <cffunction name="_generateSignature" access="private" returntype="string">
        <cfargument name="args" default=StructNew()>
        <cfargument name="request_method" default="GET">
        <cfargument name="url" default=this.API_REST_URL>

        <cfif IsStruct(arguments.args)>
            <cfset local.keys = ListToArray(ListSort(StructKeyList(arguments.args), "textnocase"))>

            <!--- Make the base string --->
            <cfset local.base_parts = []>
            <cfset ArrayAppend(local.base_parts, UCase(arguments.request_method))>
            <cfset ArrayAppend(local.base_parts, arguments.url)>
            <!--- build http query --->
            <cfset local.query = __url_query(struct=local.arguments.args, sortarray=local.keys)>
            <cfset ArrayAppend(local.base_parts, local.query)>

            <cfloop from="1" to="#ArrayLen(local.base_parts)#" index="local.i">
                <cfset local.base_parts[local.i] = __encode_rfc3986(string=local.base_parts[local.i])>
            </cfloop>

            <cfset local.base_string = ArrayToList(local.base_parts, "&")>

            <!--- Make the key --->
            <cfset local.key_parts = []>
            <cfset ArrayAppend(local.key_parts, this._consumer_secret)>
            <cfif len(this._token_secret)>
                <cfset ArrayAppend(local.key_parts, this._token_secret)>
            <cfelse>
                <cfset ArrayAppend(local.key_parts, "")>
            </cfif>

            <cfloop from="1" to="#ArrayLen(local.key_parts)#" index="local.i">
                <cfset local.key_parts[local.i] = __encode_rfc3986(string=local.key_parts[local.i])>
            </cfloop>

            <cfset local.key = ArrayToList(local.key_parts, "&")>
            <!--- Generate signature --->
            <cfreturn __hash_hmac(string=local.base_string, key=local.key)>
        </cfif>

    </cffunction>

    <!--- Get the unserialized contents of the cached request.
            @param struct params The full list of api parameters for the request.
    --->
    <cffunction name="_getCached" access="private" returntype="string">
        <cfargument name="params" default="">

        <cfif IsStruct(arguments.params)>
            <cfset StructDelete(arguments.params, "oauth_nonce")>
            <cfset StructDelete(arguments.params, "oauth_signature")>
            <cfset StructDelete(arguments.params, "oauth_timestamp")>

            <cfset local.hash = hash(SerializeJSON(arguments.params))>

            <cfif (this._cache_enabled EQ this.CACHE_FILE)>
                <cfset local.file = this._cache_dir & '/' & local.hash & '.cache'>
                <cfif FileExists(local.file)>
                    <cffile action="read" file=local.file variable="local.fileContents" />
                    <cfreturn DeserializeJSON(local.fileContents)>
                </cfif>
            </cfif>
        </cfif>
    </cffunction>

    <!--- Call an API method
            @param string method The method to call.
            @param struct call_params The parameters to pass to the method.
            @param string request_method The HTTP request method to use.
            @param string url The base URL to use.
            @param boolean cache Whether or not to cache the response.
            @param boolean use_auth_header Use the OAuth Authorization header to pass the OAuth params.
            @return string The response from the method call.
    --->
    <cffunction name="_request" access="private" returntype="any">
        <cfargument name="method">
        <cfargument name="call_params" default="">
        <cfargument name="request_method" default="GET">
        <cfargument name="url" default=this.API_REST_URL>
        <cfargument name="cache" default=true>
        <cfargument name="use_auth_header" default=true>

        <cfif !IsStruct(arguments.call_params)>
            <cfset arguments.call_params = StructNew()>
        </cfif>

        <!--- Prepare oauth arguments --->
        <cfset local.oauth_params = {}>
        <cfset local.oauth_params_sortorder = []>
        <cfset local.oauth_params['oauth_consumer_key'] = this._consumer_key>
        <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_consumer_key")>
        <cfset local.oauth_params['oauth_version'] = "1.0">
        <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_version")>
        <cfset local.oauth_params['oauth_signature_method'] = "HMAC-SHA1">
        <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_signature_method")>
        <cfset local.oauth_params['oauth_timestamp'] = DateDiff("s", CreateDate(1970,1,1), DateConvert("Local2UTC", Now()))>
        <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_timestamp")>
        <cfset local.oauth_params['oauth_nonce'] = _generateNonce()>
        <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_nonce")>

        <!--- If we have a token, include it --->
        <cfif Len(this._token)>
            <cfset local.oauth_params['oauth_token'] = this._token>
            <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_token")>
        </cfif>

        <!--- Regular args --->
        <cfset local.api_params = {}>
        <cfset local.api_params['format'] = 'json'>
        <cfif Len(arguments.method)>
            <cfset local.api_params['method'] = arguments.method>
        </cfif>

        <!--- Merge args --->
        <cfloop list="#StructKeyList(arguments.call_params)#" index="local.i">
            <cfif Find("oauth_", local.i)>
                <cfset local.oauth_params[local.i] = arguments.call_params[local.i]>
                <cfif !ArrayFind(local.oauth_params_sortorder, local.i)>
                    <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_consumer_key")>
                </cfif>
            <cfelseif Len(arguments.call_params[local.i])>
                <cfset local.api_params[local.i] = arguments.call_params[local.i]>
            </cfif>
        </cfloop>

        <!--- Generate the signature --->
        <cfset local.mergeStruct = StructCopy(local.oauth_params)>
        <cfset StructAppend(local.mergeStruct, local.api_params)>

        <cfset local.oauth_params['oauth_signature'] = _generateSignature(args=local.mergeStruct, request_method=arguments.request_method, url=arguments.url)>
        <cfset ArrayAppend(local.oauth_params_sortorder, "oauth_signature")>

        <!--- Merge all args --->
        <cfset local.all_params = StructCopy(local.oauth_params)>
        <cfset StructAppend(local.all_params, local.api_params)>

        <!--- Returned cached value --->
        <cfset local.response = _getCached(local.all_params)>
        <cfif this._cache_enabled AND (arguments.cache AND local.response)>
            <cfreturn local.response>
        </cfif>

        <!--- CFHTTP options --->
        <cfif arguments.use_auth_header>
            <cfset local.params = local.api_params>
        <cfelse>
            <cfset local.params = local.all_params>
        </cfif>

        <cfif UCase(arguments.request_method) EQ "GET">
            <cfset local.cfhttp_method = "GET">
            <cfset local.cfhttp_url = arguments.url & "?" & __url_query(struct=local.params) & "&" & __url_query(struct=oauth_params, sortarray=local.oauth_params_sortorder, encode=true)>
            <cfset local.cfhttp_fieldForms = {}>
        <cfelse>
            <cfset local.cfhttp_method = "POST">
            <cfset local.cfhttp_url = arguments.url>
            <cfset local.cfhttp_fieldForms = local.params>
        </cfif>

        <!--- Authorization header --->
        <cfif arguments.use_auth_header>
            <cfset local.cfhttp_header = _generateAuthHeader(request_url=local.cfhttp_url, request_method=local.cfhttp_method, oauth_params=local.oauth_params, oauth_params_sortorder=local.oauth_params_sortorder)>
        <cfelse>
            <cfset local.cfhttp_header = "">
        </cfif>

        <!--- Call the api --->
        <cfhttp url="#local.cfhttp_url#" method="#local.cfhttp_method#" result="local.response">
            <cfif ListLen(StructKeyList(local.cfhttp_fieldForms))>
                <cfloop list="#StructKeyList(local.cfhttp_fieldForms)#" index="local.f">
                    <cfhttpparam type="formField" encoded="false" value="#local.cfhttp_fieldForms[local.f]#" name="#local.f#" />
                </cfloop>
            </cfif>
            <cfhttpparam type="body" encoded="false" value="#local.cfhttp_header#" />
        </cfhttp>

        <!--- Cache the response --->
        <cfif this._cache_enabled AND arguments.cache>
            <cfset _cache(params=local.all_params, response=local.response.fileContent)>
        </cfif>

        <!--- Return --->
        <cfif Len(arguments.method)>
            <cfif IsJSON(local.response.fileContent)>
                <cfset local.response = deserializeJSON(local.response.fileContent)>
            <cfelse>
                <cfset local.response = {}>
                <cfset local.response.err = {}>
                <cfset local.response.err.code = '-2'>
                <cfset local.response.err.msg = "Unknown error occurred.">
                <cfset local.response.err.html = local.response.fileContent>
            </cfif>

            <cfif local.response['stat'] EQ 'ok'>
                <cfreturn local.response>
            <cfelseif local.response.err.code EQ -1>
                <!--- internal error -- try again --->
                <cfset _request(arguments)>
            <cfelse>
                <cfthrow type="any" message="#local.response.err.msg#" errorCode="#local.response.err.code#">
            </cfif>

            <cfreturn ''>
        </cfif>

        <cfreturn local.response.fileContent>

    </cffunction>

    <!--- Send the user to Vimeo to authorize your app.
            http://www.vimeo.com/api/docs/oauth
            @param string perms The level of permissions to request: read, write, or delete.
    --->
    <cffunction name="auth" access="public">
        <cfargument name="permission" default="read">
        <cfargument name="callback_url" default="oob">

        <cfset local.t = getRequestToken(callback_url=arguments.callback_url)>
        <cfset setToken(token=local.t['oauth_token'], token_secret=local.t['oauth_token_secret'], type="request", session_store=true)>
        <cfset local.url = getAuthorizeURL(token=this._token, permission=arguments.permission)>

        <cflocation url="#local.url#" addtoken="false" />
    </cffunction>

    <!--- Call a method.
            @param string method The name of the method to call.
            @param struct params The parameters to pass to the method.
            @param string request_method The HTTP request method to use.
            @param string url The base URL to use.
            @param boolean cache Whether or not to cache the response.
            @return struct The response from the API method
    --->
    <cffunction name="call" access="public" returntype="any">
        <cfargument name="method" default="">
        <cfargument name="params" default=StructNew()>
        <cfargument name="request_method" default="GET">
        <cfargument name="url" default="#this.API_REST_URL#">
        <cfargument name="cache" default=true>

        <cfset local.method = arguments.method>
        <cfif Left(arguments.method, 6) NEQ "vimeo.">
            <cfset local.method = "vimeo." & arguments.method>
        </cfif>

        <cfreturn _request(local.method, arguments.params, arguments.request_method, arguments.url, arguments.cache)>
    </cffunction>

    <!--- Enable the cache.
            @param string type The type of cache to use
            @param string path The path to the cache
            @param numeric expire The amount of time in seconds to cache responses
    --->
    <cffunction name="enableCache" access="public" returntype="boolean">
        <cfargument name="type" default="">
        <cfargument name="path" default="">
        <cfargument name="expire" default="600">

        <cfset this._cache_enabled = arguments.type>
        <cfif (this._cache_enabled EQ this.CACHE_FILE)>
            <cfset this._cache_dir = arguments.path>
            <cfif DirectoryExists(this._cache_dir)>
                <cfdirectory name="local.files" directory="#this._cache_dir#" filter="*.cache" />
                <cfoutput query="local.files">
                    <cfif Abs(DateDiff('s', local.files.DateLastModified, Now())) GT arguments.expire>
                        <cfset DeleteFile(local.files.name)>
                    </cfif>
                </cfoutput>
            </cfif>
        </cfif>

        <cfreturn false>
    </cffunction>

    <!--- Get an access token. Make sure to call setToken() with the request token before calling this function
            @param string verifier The OAuth verifier returned from the authorization page or the user.
            @return struct The returned request
    --->
    <cffunction name="getAccessToken" access="public" returntype="struct">
        <cfargument name="verifier" default="">

        <cfset local.access_token = _request(method="", call_params={ "oauth_verifier"=arguments.verifier }, request_method="GET", url=this.API_ACCESS_TOKEN_URL, cache=false, use_auth_header=true)>

        <cfreturn __parse_string(string=local.access_token)>

    </cffunction>

    <!--- Get the URL of the authorization page.
            @param string token The request token.
            @param string permission The level of permissions to request: read, write, or delete.
            @return string The Authorization URL.
    --->
    <cffunction name="getAuthroizeURL" access="public" returntype="string">
        <cfargument name="token" default="">
        <cfargument name="permission" default="read">

        <cfreturn this.API_AUTH_URL & "?oauth_token=" & arguments.token & "&permission=" & arguments.permission>
    </cffunction>

    <!--- Get a request token.
    --->
    <cffunction name="getRequestToken" access="public" returntype="struct">
        <cfargument name="callback_url" default="oob">

        <cfset local.request_token = _request(method="", call_params={ "oauth_callback"=arguments.callback_url }, request_method="GET", url=this.API_REQUEST_TOKEN_URL, cache=false, use_auth_header=false)>

        <cfreturn __parse_string(string=local.request_token)>
    </cffunction>

    <!--- Get the stored auth token.
            @return array Token and token secret.
    --->
    <cffunction name="getToken" access="public" returntype="array">
        <cfreturn [this._token, this._token_secret]>
    </cffunction>

    <!--- Set the OAuth token.
            @param string token The OAuth token
            @param string token_secret The OAuth token secret
            @param boolean session_store Store the token in a session variable
            @return boolean true
    --->
    <cffunction name="setToken" access="public" returntype="boolean">
        <cfargument name="token" default="">
        <cfargument name="token_secret" default="">
        <cfargument name="type" default="access">
        <cfargument name="session_store" default=false>

        <cfset this._token = arguments.token>
        <cfset this._token_secret = arguments.token_secret>

        <cfif arguments.session_store>
            <cfset session[arguments.type & "_token"] = this._token>
            <cfset session[arguments.type & "_token_secret"] = this._token_secret>
        </cfif>

        <cfreturn true>
    </cffunction>

    <!--- Upload a video in one piece.
            @param string file_path The full path to the file
            @param boolean use_multiple_chunks Whether or not to split the file up into smaller chunks
            @param string chunk_temp_dir The directory to store the chunks in
            @param numeric size The size of each chunk in bytes (defaults to 2MB)
            @param numeric replace_id The video id if this is a replacement upload
            @return int The video ID
    --->
    <cffunction name="upload" access="public" returntype="numeric">
        <cfargument name="file_path" default="">
        <cfargument name="use_multiple_chunks" default=false>
        <cfargument name="chunk_temp_dir" default=".">
        <cfargument name="size" default="2097152">
        <cfargument name="replace_id" default="0">

        <cfif !FileExists(arguments.file_path)>
            <cfreturn 0>
        </cfif>

        <!--- Figure out the filename and full size --->
        <cfset local.path_parts = GetFileInfo(arguments.file_path)>
        <cfset local.file_name = local.path_parts.name>
        <cfset local.file_size = local.path_parts.size>

        <!--- Make sure we have enough room left in the user's quota --->
        <cfset local.quota = call('vimeo.videos.upload.getQuota')>
        <cfif local.quota.user.upload_space.free LT local.file_size>
            <cfthrow type="VimeoAPIException" message="The file is larger than the user's remaining quota." errorCode="707" />
        </cfif>

        <!--- Get an upload ticket --->
        <cfset local.params = {}>

        <cfif arguments.replace_id>
            <cfset local.params['video_id'] = arguments.replace_id>
        </cfif>

        <cfset local.rsp = call("vimeo.videos.upload.getTicket", local.params, "GET", this.API_REST_URL, false)>

        <cfset local.ticket = local.rsp.ticket.id>
        <cfset local.endpoint = local.rsp.ticket.endpoint>

        <!--- Make sure we're allowed to upload this size file --->
        <cfif local.file_size GT local.rsp.ticket.max_file_size>
            <cfthrow type="VimeoAPIException" message="File exceeds maximum allowed size." errorCode="710" />
        </cfif>

        <!--- Split up the file if using multiple pieces --->
        <cfset local.chunks = []>
        <cfif arguments.use_multiple_chunks>

            <cfif DirectoryExists(arguments.chunk_temp_dir)>

                <cfset local.dir_info = GetFileInfo(arguments.chunk_temp_dir)>
                <cfif !local.dir_info.canWrite>
                    <cfthrow type="any" message="Could not write chunks. Make sure the specified folder has write access.">
                </cfif>

                <!--- create pieces --->
                <cfset local.number_of_chunks = Ceiling(local.file_size / arguments.size)>
                <cfset local.input = CreateObject("java", "java.io.FileInputStream").Init(JavaCast("string", arguments.file_path)) />
                <cfset local.buffer = RepeatString( " ", arguments.size).GetBytes() />
                <cfloop from="1" to="#local.number_of_chunks#" index="local.i">

                    <cfset local.chunk_file_name = arguments.chunk_temp_dir & "/" & local.file_name & "." & local.i>

                    <!--- Break it up --->
                    <cfset local.read = local.input.Read(local.buffer, JavaCast("int", 0), JavaCast( "int", ArrayLen(local.buffer))) />

                    <cfif val(local.read)>
                        <cfset local.out = CreateObject("java", "java.io.FileOutputStream").Init(JavaCast("string", local.chunk_file_name)) />
                        <cfset local.out.Write(local.buffer, JavaCast( "int", 0 ), JavaCast("int", local.read)) />

                        <cfset local.tmp = {}>
                        <cfset local.tmp['file'] = local.chunk_file_name>
                        <cfset local.temp = GetFileInfo(local.chunk_file_name)>
                        <cfset local.tmp['size'] = local.temp.size>
                        <cfset ArrayAppend(local.chunks, local.tmp)>

                        <cfset local.out.Close() />
                    <cfelse>
                        <cfset local.input.Close() />
                        <cfbreak />
                    </cfif>
                </cfloop>
            </cfif>
        <cfelse>
            <cfset ArrayAppend(local.chunks, { "file"=arguments.file_path, "size"=local.file_size })>
        </cfif>

        <!--- Upload each piece --->
        <cfloop from="1" to="#ArrayLen(local.chunks)#" index="local.f">

            <cfset local.params = {}>
            <cfset local.params['oauth_consumer_key'] = this._consumer_key>
            <cfset local.params['oauth_token'] = this._token>
            <cfset local.params['oauth_signature_method'] = "HMAC-SHA1">
            <cfset local.params['oauth_timestamp'] = DateDiff("s", CreateDate(1970,1,1), DateConvert("Local2UTC", Now()))>
            <cfset local.params['oauth_nonce'] = _generateNonce()>
            <cfset local.params['oauth_version'] = "1.0">
            <cfset local.params['ticket_id'] = local.ticket>
            <cfset local.params['chunk_id'] = local.f>

            <!--- Generate the OAuth signature --->
            <cfset local.params2 = {}>
            <cfset local.params2['oauth_signature'] = _generateSignature(StructCopy(local.params), "POST", this.API_REST_URL)>

            <cfset StructAppend(local.params, local.params2)>

            <cfset local.file_data = local.chunks[local.f]['file']>

            <!--- Post the file --->
            <cfset local.cfhttp_url = local.endpoint & "&" & __url_query(struct=local.params, encode=true)>

            <cfhttp url="#local.cfhttp_url#" method="POST" result="local.response" timeout="#(24 * 60 * 60)#">
                <cfhttpparam type="file" name="file_data" file="#local.file_data#" mimetype="video/mp4" />
            </cfhttp>
        </cfloop>

        <!--- Verify --->
<!---         <cfset local.verify = call("vimeo.videos.upload.verifyChunks", { "ticket_id"=local.ticket, "oauth_token"=this._token })>
        Make sure our file sizes match up
        <cfinvoke component="usercomponent" method="senddebugemail" data="#local.verify#" email="danny@kaganonline.com"> --->
        <!--- <cfset local.chunk = local.chunks[local.f]>

        <cfif local.chunk['size'] NEQ local.verify.ticket.chunks.chunk.size>
            <cfthrow message="Chunk #local.verify.ticket.chunks.chunk.id# is actually #local.chunk['size']# but uploaded as #local.verify.ticket.chunks.chunk.size#">
        </cfif> --->
        <!--- Complete the upload --->
        <cfset local.complete = call("vimeo.videos.upload.complete", { "ticket_id"=local.ticket, "oauth_token"=this._token })>

        <!--- Clean up --->
        <cfif ArrayLen(local.chunks) GT 1>
            <cfloop array="#local.chunks#" index="local.a">
                <cfif FileExists(local.a)>
                    <cfset FileDelete(local.a)>
                </cfif>
            </cfloop>
        </cfif>

        <!--- Confirmation successful, return video id --->
        <cfif local.complete.stat EQ 'ok'>
            <cfreturn local.complete.ticket.video_id>
        <cfelseif Len(local.complete.err)>
            <cfthrow type="VimeoAPIException" message="#local.complete.err.msg#" errorCode="#local.complete.err.code#">
        </cfif>

    </cffunction>

    <!--- Upload a video in multiple pieces
            @deprecated
    --->
    <cffunction name="uploadMulti" access="public" returntype="string">
        <cfargument name="file_name" default="">
        <cfargument name="size" defualt="1048576">

        <cfreturn upload(arguments.file_name, true, '.', arguments.size)>
    </cffunction>

</cfcomponent>