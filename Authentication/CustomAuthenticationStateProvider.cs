using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;

namespace BlazorServerAuth.Authentication
{
    /// <summary>
    /// 實作教學
    /// https://youtu.be/iq2btD9WufI?t=370
    /// authorization-blazor原理
    /// https://www.pragimtech.com/blog/blazor/authorization-in-blazor/
    /// 名詞解釋
    /// https://iter01.com/549156.html
    /// </summary>
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        //ProtectedSessionStorage
        //提供在瀏覽器的 'sessionStorage' 集合中儲存和擷取資料的機制。
        private readonly ProtectedSessionStorage _sessionStorage;
        private ClaimsPrincipal _annonymous = new ClaimsPrincipal(new ClaimsIdentity());

        public CustomAuthenticationStateProvider(ProtectedSessionStorage sessionStorage)
        {
            _sessionStorage = sessionStorage;
        }

        /// <summary>
        /// 取得使用者Session狀態資訊
        /// </summary>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var userSessionStorageResult = await _sessionStorage.GetAsync<UserSession>("UserSession");
                var userSession = userSessionStorageResult.Success ? userSessionStorageResult.Value : null;

                if (userSession == null)
                    return await Task.FromResult(new AuthenticationState(_annonymous));

                var clamisPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>           
                {
                    new Claim(ClaimTypes.Name,userSession.UserName),
                    new Claim(ClaimTypes.Role,userSession.Role) 
                }, "CustomAuth"));

                return await Task.FromResult(new AuthenticationState(clamisPrincipal));
            }
            catch
            {
                return await Task.FromResult(new AuthenticationState(_annonymous));
            }
        }

        /// <summary>
        /// 更新user授權登入狀態
        /// </summary>
        /// <param name="userSession"></param>
        /// <returns></returns>
        public async Task UpdateAuthenticationState(UserSession userSession) 
        {
            ClaimsPrincipal claimsPrincipal;

            if (userSession != null)
            {       
                await _sessionStorage.SetAsync("UserSession",userSession);
                var clamisPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.Name,userSession.UserName),
                    new Claim(ClaimTypes.Role,userSession.Role)
                }));
            }
            else
            {
                await _sessionStorage.DeleteAsync("UserSession");
                claimsPrincipal = _annonymous;
            }

        }
    }
}
