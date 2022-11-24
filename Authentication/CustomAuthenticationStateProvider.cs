using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorServerAuthenticationAndAuthorzation.Authentication
{
    /// <summary>
    /// https://youtu.be/iq2btD9WufI?t=370
    /// </summary>
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            throw new NotImplementedException();
        }
    }
}
