// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs.Host.Bindings;
using Microsoft.Azure.WebJobs.Host.Protocols;
using Newtonsoft.Json.Linq;

namespace Microsoft.Azure.WebJobs.Extensions.Http
{
    /// <summary>
    /// This provider provides a binding to Type <see cref="ClaimsIdentity"/>.
    /// </summary>
    /// <remarks>
    /// Attempts to bind to an identity in precedence order based on <see cref="AuthorizationLevel"/> levels.
    /// I.e. if the request is key authenticated (Function/System/Admin) that identity is returned, if the
    /// request is user authenticated (User) that identity is returned.
    /// </remarks>
    internal class ClaimsIdentityBindingProvider : IBindingProvider
    {
        public Task<IBinding> TryCreateAsync(BindingProviderContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (context.Parameter.ParameterType != typeof(ClaimsIdentity))
            {
                return Task.FromResult<IBinding>(null);
            }

            return Task.FromResult<IBinding>(new ClaimsIdentityBinding(context.Parameter));
        }

        private class ClaimsIdentityBinding : IBinding, IDisposable
        {
            private readonly ParameterInfo _parameter;
            private readonly HttpClient _httpClient = new HttpClient();
            private bool disposedValue = false;

            public ClaimsIdentityBinding(ParameterInfo parameter)
            {
                _parameter = parameter;
            }

            public bool FromAttribute
            {
                get { return false; }
            }

            public async Task<IValueProvider> BindAsync(BindingContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }

                // if the request is EasyAuth authenticated, get the identity provider type
                object value = null;
                string identityProvider = null;
                string authToken = null;
                if (context.BindingData.TryGetValue(HttpTriggerAttributeBindingProvider.HttpHeadersKey, out value))
                {
                    IDictionary<string, string> headers = (IDictionary<string, string>)value;
                    if (headers != null)
                    {
                        headers.TryGetValue("X-MS-CLIENT-PRINCIPAL-IDP", out identityProvider);
                        headers.TryGetValue("X-ZUMO-AUTH", out authToken);
                    }  
                }

                var identity = GetPrimaryIdentity(ClaimsPrincipal.Current, identityProvider);

                if (identity != null && !string.IsNullOrEmpty(authToken))
                {
                    await ApplyUserInfo(identity, authToken);
                }

                return await BindInternalAsync(identity);
            }

            public Task<IValueProvider> BindAsync(object value, ValueBindingContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }

                var identity = GetPrimaryIdentity(ClaimsPrincipal.Current);

                return BindInternalAsync(identity);
            }

            private static Task<IValueProvider> BindInternalAsync(ClaimsIdentity identity)
            {
                return Task.FromResult<IValueProvider>(new ClaimsIdentityValueProvider(identity));
            }

            public ParameterDescriptor ToParameterDescriptor()
            {
                return new ParameterDescriptor
                {
                    Name = _parameter.Name,
                    DisplayHints = new ParameterDisplayHints
                    {
                        Description = "Identity"
                    }
                };
            }

            private static ClaimsIdentity GetPrimaryIdentity(ClaimsPrincipal claimsPrincipal, string identityProvider = null)
            {
                var identity = claimsPrincipal.Identities.LastOrDefault(p => p.IsAuthenticated && string.Compare(p.AuthenticationType, "key", StringComparison.OrdinalIgnoreCase) == 0);
                if (identity != null)
                {
                    return identity;
                }

                if (identityProvider != null)
                {
                    foreach (var currIdentity in claimsPrincipal.Identities.Where(p => p.IsAuthenticated))
                    {
                        if (string.Compare(currIdentity.AuthenticationType, identityProvider, StringComparison.OrdinalIgnoreCase) == 0)
                        {
                            return currIdentity;
                        }

                        var identityProviderClaim = currIdentity.FindFirst("http://schemas.microsoft.com/identity/claims/identityprovider");
                        if (identityProviderClaim != null && string.Compare(identityProviderClaim.Value, identityProvider, StringComparison.OrdinalIgnoreCase) == 0)
                        {
                            return currIdentity;
                        }
                    }
                }

                return (ClaimsIdentity)claimsPrincipal.Identity;
            }

            private async Task ApplyUserInfo(ClaimsIdentity identity, string authToken)
            {
                var host = Environment.GetEnvironmentVariable("WEBSITE_HOSTNAME");
                string uri = $"https://{host}/.auth/me";
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Add("X-ZUMO-AUTH", authToken);

                var response = await _httpClient.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();

                    // get the detailed user claims
                    JArray results = JArray.Parse(json);
                    JObject firstResult = (JObject)results[0];
                    JArray userClaims = (JArray)firstResult["user_claims"];

                    // apply all the claims to the specified identity
                    foreach (JObject claim in userClaims)
                    {
                        string claimType = (string)claim["typ"];
                        string claimValue = (string)claim["val"];
                        identity.AddClaim(new Claim(claimType, claimValue));
                    }
                }
            }

            private class ClaimsIdentityValueProvider : IValueProvider
            {
                private ClaimsIdentity _identity;

                public ClaimsIdentityValueProvider(ClaimsIdentity identity)
                {
                    _identity = identity;
                }

                public Type Type
                {
                    get { return typeof(ClaimsIdentity); }
                }

                public Task<object> GetValueAsync()
                {
                    return Task.FromResult<object>(_identity);
                }

                public string ToInvokeString()
                {
                    // TODO: figure out right value here
                    return ClaimsPrincipal.Current.ToString();
                }
            }

            protected virtual void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    if (disposing)
                    {
                        _httpClient?.Dispose();
                    }

                    disposedValue = true;
                }
            }

            // This code added to correctly implement the disposable pattern.
            public void Dispose()
            {
                Dispose(true);
            }
        }
    }
}
