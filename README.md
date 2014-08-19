CFVimeoAPIWrapper
=================

A Coldfusion wrapper to upload videos to Vimeo using the Vimeo API.

##To Use:

```
<cfset local.CLIENT_ID = "Client ID provided by Vimeo">
<cfset local.CLIENT_SECRET = "Client secret provided by Vimeo">
<cfset local.ACCESS_TOKEN = "Access token provided by Vimeo">
<cfset local.ACCESS_TOKEN_SECRET = "Access token secret provided by Vimeo">

<cfset local.vimeo = createObject("component", "VimeoComponent")>
<cfset local.vimeo.init(this.CLIENT_ID, this.CLIENT_SECRET)>
<cfset local.vimeo.setToken(this.ACCESS_TOKEN, this.ACCESS_TOKEN_SECRET)>

<cfset new_id = vimeo.upload(
  file_path=[Local video file path], 
  use_multiple_chunks=[true/false], 
  chunk_temp_dir=[Local video chuck directory], 
  replace_id=[If replacing a video, provide its id here]
) />
```

In the above example, `new_id` will be the ID of the uploaded video.
