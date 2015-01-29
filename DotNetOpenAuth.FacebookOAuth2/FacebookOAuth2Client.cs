using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using DotNetOpenAuth.AspNet.Clients;
using Newtonsoft.Json;

namespace DotNetOpenAuth.FacebookOAuth2
{
    /// <summary>
    /// A DotNetOpenAuth client for logging in to Facebook using OAuth2.
    /// Reference: http://developers.facebook.com/docs/howtos/login/server-side-login/
    /// </summary>
    public class FacebookOAuth2Client : OAuth2Client
    {
        #region Constants

        /// <summary>
        /// The authorization endpoint.
        /// </summary>
        private const string AuthorizationEndpoint = "https://www.facebook.com/{0}dialog/oauth";

        /// <summary>
        /// The token endpoint.
        /// </summary>
        private const string TokenEndpoint = "https://graph.facebook.com/{0}oauth/access_token";

        /// <summary>
        /// The user info endpoint.
        /// </summary>
        private const string UserInfoEndpoint = "https://graph.facebook.com/{0}me";

        /// <summary>
        /// The debug access token endpoint.
        /// </summary>
        private const string DEBUG_ACCESS_TOKEN_ENDPOINT = "https://graph.facebook.com/{0}debug_token";

        #endregion

        #region Fields and properties

        /// <summary>
        /// The app id.
        /// </summary>
        private readonly string _appId;

        /// <summary>
        /// The app secret.
        /// </summary>
        private readonly string _appSecret;

        /// <summary>
        /// Facebook graph API version.
        /// </summary>
        private string _apiVersion = "v2.2";

        /// <summary>
        /// Gets or setts current API version.
        /// </summary>
        public string ApiVersion
        {
            get { return _apiVersion; }
            set { _apiVersion = value; }
        } 


        /// <summary>
        /// The requested scopes.
        /// </summary>
        private readonly string[] _requestedScopes;

        #endregion



        #region Constuctors

        /// <summary>
        /// Creates a new Facebook OAuth2 client, requesting the default "email" scope.
        /// </summary>
        /// <param name="appId">The Facebook App Id</param>
        /// <param name="appSecret">The Facebook App Secret</param>
        public FacebookOAuth2Client(string appId, string appSecret)
            : this(appId, appSecret, "email") { }

        /// <summary>
        /// Creates a new Facebook OAuth2 client.
        /// </summary>
        /// <param name="appId">The Facebook App Id</param>
        /// <param name="appSecret">The Facebook App Secret</param>
        /// <param name="requestedScopes">One or more requested scopes, passed without the base URI.</param>
        public FacebookOAuth2Client(string appId, string appSecret, params string[] requestedScopes)
            : base("facebook")
        {
            if (string.IsNullOrWhiteSpace(appId))
                throw new ArgumentNullException("appId");

            if (string.IsNullOrWhiteSpace(appSecret))
                throw new ArgumentNullException("appSecret");

            if (requestedScopes == null)
                throw new ArgumentNullException("requestedScopes");

            if (requestedScopes.Length == 0)
                throw new ArgumentException("One or more scopes must be requested.", "requestedScopes");

            _appId = appId;
            _appSecret = appSecret;
            _requestedScopes = requestedScopes;
        }

        #endregion


        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var state = string.IsNullOrEmpty(returnUrl.Query) ? string.Empty : returnUrl.Query.Substring(1);

            string baseUrl = string.Format(AuthorizationEndpoint, string.IsNullOrWhiteSpace(_apiVersion) ? string.Empty : _apiVersion + "/");

            return BuildUri(baseUrl, new NameValueCollection
                {
                    { "client_id", _appId },
                    { "scope", string.Join(" ", _requestedScopes) },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
                    { "state", state },
                });
        }

        protected override IDictionary<string, string> GetUserData(string accessToken)
        {
            var uri = BuildUri(UserInfoEndpoint);
            var webRequest = (HttpWebRequest) WebRequest.Create(uri);
            webRequest.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + accessToken);

            using (var webResponse = webRequest.GetResponse())
            {
                using (var stream = webResponse.GetResponseStream())
                {
                    if (stream == null)
                        return null;

                    using (var textReader = new StreamReader(stream))
                    {
                        var json = textReader.ReadToEnd();
                        var extraData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                        var data = extraData.ToDictionary(x => x.Key, x => x.Value.ToString());

                        data.Add("picture", string.Format("https://graph.facebook.com/{0}/picture", data["id"]));

                        return data;
                    }
                }
            }
        }

        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            var uri = BuildUri(TokenEndpoint, new NameValueCollection
                {
                    { "code", authorizationCode },
                    { "client_id", _appId },
                    { "client_secret", _appSecret },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
                });

            var webRequest = (HttpWebRequest) WebRequest.Create(uri);

            using (var webResponse = webRequest.GetResponse())
            {
                var responseStream = webResponse.GetResponseStream();
                if (responseStream == null)
                    return null;

                using (var reader = new StreamReader(responseStream))
                {
                    var response = reader.ReadToEnd();

                    var results = HttpUtility.ParseQueryString(response);
                    return results["access_token"];
                }
            }
        }

        private Uri BuildUri(string baseUri, NameValueCollection queryParameters = null)
        {
            UriBuilder builder;

            baseUri = string.Format(baseUri, string.IsNullOrWhiteSpace(_apiVersion) ? string.Empty : _apiVersion + "/");

            if (queryParameters != null)
            {
                var keyValuePairs = queryParameters.AllKeys.Select(k => HttpUtility.UrlEncode(k) + "=" + HttpUtility.UrlEncode(queryParameters[k]));
                var qs = String.Join("&", keyValuePairs);

                builder = new UriBuilder(baseUri) { Query = qs };
            }
            else {
                builder = new UriBuilder(baseUri);
            }
            return builder.Uri;
        }

        /// <summary>
        /// Facebook works best when return data be packed into a "state" parameter.
        /// This should be called before verifying the request, so that the url is rewritten to support this.
        /// </summary>
        public static void RewriteRequest()
        {
            var ctx = HttpContext.Current;

            var stateString = HttpUtility.UrlDecode(ctx.Request.QueryString["state"]);
            if (stateString == null || !stateString.Contains("__provider__=facebook"))
                return;

            var q = HttpUtility.ParseQueryString(stateString);
            q.Add(ctx.Request.QueryString);
            q.Remove("state");

            ctx.RewritePath(ctx.Request.Path + "?" + q);
        }

        /// <summary>
        /// Verifies whether provided access token is really issued for specified application.
        /// </summary>
        /// <param name="accessToken">Access token.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">Throws exception when dynamic data object does not contain app_id or is_valid attributes.</exception>
        public bool VerifyAccessToken(string accessToken) {
            bool ret = false;

            var uri = BuildUri(DEBUG_ACCESS_TOKEN_ENDPOINT, new NameValueCollection
                {
                    { "input_token", accessToken },
                });

            var webRequest = (HttpWebRequest)WebRequest.Create(uri);
            webRequest.Headers.Add(HttpRequestHeader.Authorization, string.Format("Bearer {0}|{1}", _appId, _appSecret));

            try
            {
                using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
                {
                    var responseStream = webResponse.GetResponseStream();
                    if (responseStream != null)
                    {
                        using (var reader = new StreamReader(responseStream))
                        {
                            var json = reader.ReadToEnd();
                            dynamic responseData = JsonConvert.DeserializeObject<dynamic>(json);

                            try
                            {
                                if (responseData.data.app_id == _appId && responseData.data.is_valid == true)
                                {
                                    ret = true;
                                }
                            }
                            catch (Exception ex)
                            {
                                throw new Exception("Cannot verify access token. See inner exception.", ex);
                            }
                        }
                    }
                }
            }
            catch (Exception ex) 
            {
                throw new Exception("Cannot verify access token. See inner exception.", ex);
            }

            return ret;
        }

        /// <summary>
        /// Verifies whether provided access token was really issued for specified application and checks it againts provided e-mail.
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        /// <exception cref="System.Exception">Throws exception when dynamic data object does not contain app_id or is_valid attributes OR when downloaded user data does not contain email.</exception>
        public bool VerifyAccessToken(string accessToken, string email) {
            bool ret = false;

            try
            {
                if (VerifyAccessToken(accessToken))
                {
                    IDictionary<string, string> data = GetUserData(accessToken);
                    if (data != null)
                    {
                        ret = (data["email"] == email);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Cannot verify access token and e-mail. See inner exception.", ex);
            }
            
            return ret;
        }
    }
}
