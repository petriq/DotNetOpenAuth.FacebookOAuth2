DotNetOpenAuth OAuth2 Client for Facebook
======================================

This is a slightly improved implementation over the default Facebook client that ships with DNOA as used in MVC4 (VS2012).
It keeps the provider and sid off of the redirect uri, and puts them in the state parameter where they belong.

It also lets you customize the scopes, in case you want access to other Facebook data.  And it doesn't manipulate
the response fields - so you get back exactly what facebook provided.

**IMPORTANT** - If you are using ASP.Net MVC 5, this package is not applicable.  You should use [Microsoft.Owin.Security.Facebook](https://www.nuget.org/packages/Microsoft.Owin.Security.Google) instead.  (It also ships with the MVC 5 starter templates in VS 2013.)  See also [the tutorial here](http://www.asp.net/mvc/tutorials/mvc-5/create-an-aspnet-mvc-5-app-with-facebook-and-google-oauth2-and-openid-sign-on).


## Setup

 1. Setup your Facebook App using the [Facebook developer apps site](https://developers.facebook.com/apps).
    Detailed instructions [here](http://ben.onfabrik.com/posts/oauth-providers#facebook)

 2. Install this library from [NuGet](https://nuget.org/packages/DotNetOpenAuth.FacebookOAuth2), or compile from source and reference.

 3. Register the client instead of the existing Facebook OpenId client.

        var client = new FacebookOAuth2Client("yourAppId", "yourAppSecret");
        var extraData = new Dictionary<string, object>();
        OAuthWebSecurity.RegisterClient(client, "Facebook", extraData);

## Usage

Just like any other `OAuthWebSecurity` client, except you need one extra hook:

        // add this line
        FacebookOAuth2Client.RewriteRequest();

        // it belongs right before your existing call to
        OAuthWebSecurity.VerifyAuthentication(....)

This is needed because Facebook requires that any extra querystring parameters for the
redirect be packed into a single parameter called `state`.  Since `OAuthWebSecurity` needs
two parameters, `__provider__` and `__sid__` - we have to rewrite the url.

**Note:** The `RewriteRequest` method will unpack the `state` parameter and place its contents back into the regular querystring.
So if you are looking for a state value such as `ReturnUrl`, you will find it has been moved to `Request.QueryString["ReturnUrl"]`.


## Disclaimer

I don't work for Facebook, Microsoft, or DNOA.  This is released under the [MIT](LICENCE.txt) licence.  Do what you want with it.
