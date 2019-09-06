This project has been abandoned. I have not used it since 2014 and do not know if it still works with Vimeo's API. But feel free to use it or make a fork of it if you want to keep it going. 


CFVimeoAPIWrapper
=================

A Coldfusion wrapper to upload videos to Vimeo using the Vimeo API.

All examples assume
```
<cfset CLIENT_ID = "Client ID provided by Vimeo">
<cfset CLIENT_SECRET = "Client secret provided by Vimeo">
<cfset ACCESS_TOKEN = "Access token provided by Vimeo">
<cfset ACCESS_TOKEN_SECRET = "Access token secret provided by Vimeo">
```

## API
All of Vimeo's API calls can be made in a similar way to this example:

```
<cfset vimeo = createObject("component", "VimeoComponent")>
<cfset vimeo.init(CLIENT_ID, CLIENT_SECRET)>
<cfset vimeo.setToken(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)>
<cfset data = vimeo.call(
  "vimeo.videos.getUploaded", 
  { 
    "user_id"=ACCESS_TOKEN, 
    "sort"="newest", 
    "page"="1", 
    "per_page"=PER_PAGE 
  }
) />
```

A list of available API calls are available at http://developer.vimeo.com/api/endpoints

## Upload Videos:

```
<cfset local.vimeo = createObject("component", "VimeoComponent")>
<cfset local.vimeo.init(CLIENT_ID, CLIENT_SECRET)>
<cfset local.vimeo.setToken(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)>

<cfset new_id = vimeo.upload(
  file_path=[Local video file path], 
  use_multiple_chunks=[true/false], 
  chunk_temp_dir=[Local video chuck directory], 
  replace_id=[If replacing a video, provide its id here]
) />
```

In the above example, `new_id` will be the ID of the uploaded video.
