using Microsoft.Extensions.Caching.Memory;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;
using Jose;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Collections.Generic;
using System.Net;

namespace BlazorServerAuth.Authentication
{
    public class UserAccountService : IDisposable
    {
        private List<UserAccount> _users;

        //## resource
        internal record Ticket
        {
            public Guid ticketId;
            public string userId;
            public string returnUrl;
            public DateTime expires;
        }

        //# Injection Member
        readonly IMemoryCache _cache;
        readonly IHttpContextAccessor _http;

        /// <summary>
        /// 門票緩衝池
        /// </summary>
        readonly Dictionary<Guid, Ticket> _ticketPool = new();
        readonly object _lockObj = new object();

        //public UserAccountService()
        //{
        //    _users = new List<UserAccount>()
        //    {
        //        new UserAccount() { UserName = "admin", Password = "admin", Role = "Administrator" },
        //        new UserAccount() { UserName = "user", Password = "user", Role = "User" }
        //    };
        //}

        public UserAccountService(IMemoryCache cache, IHttpContextAccessor http)
        {
            _cache = cache;
            _http = http;

        }

        public void Dispose()
        {
        }

        /// <summary>
        /// 依據用戶ID取得用戶資訊
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public UserAccount? GetByUserName(string username)
        {
            return _users.FirstOrDefault(x => x.UserName == username);
        }

        internal UserAccount GetAuthDataFromPool(string userIdentityName)
        {
            lock (_lockObj)
            {
                var UserAccount = _cache.Get<UserAccount>($"AuthData:{userIdentityName}");

                // 若已過時，則清除
                if (UserAccount != null && DateTime.UtcNow > UserAccount.ExpiresUtc)
                {
                    _cache.Remove($"AuthData:{userIdentityName}");
                    return null;
                }

                return UserAccount;
            }
        }

        /// <summary>
        /// 清除主機端登入狀態
        /// </summary>
        public void SignoutUser(string userId)
        {
            lock (_lockObj)
            {
                _cache.Remove($"AuthData:{userId}");
            }
        }

        internal UserAccount GetCurrentUser()
        {
            var user = _http.HttpContext.User; // 現在使用者
            if (!user.Identity.IsAuthenticated)
                return null;

            return GetAuthDataFromPool(user.Identity.Name);
        }

        /// <summary>
        /// 取出（登入認證）門票
        /// </summary>
        internal Ticket TakeOutTicket(string ticketToken)
        {
            Guid ticketId = JwtHostingDecode<Guid>(ticketToken);
            lock (_lockObj)
            {
                _ticketPool.Remove(ticketId, out Ticket ticket);
                return ticket;
            }
        }

        /// <summary>
        /// 解開 ClaimsIdentity，解開使用者的識別聲明資訊。
        /// </summary>
        internal UserAccount UnpackUserClaimsData(System.Security.Principal.IIdentity identity)
        {
            if (!identity.IsAuthenticated)
                return null;

            var claimsIdentity = (System.Security.Claims.ClaimsIdentity)identity;
            var UserAccountJson = claimsIdentity.FindFirst(System.Security.Claims.ClaimTypes.UserData)?.Value;
            if (UserAccountJson == null)
                throw new UnauthorizedAccessException("授權資料不完整！請重新登入。");

            return JsonSerializer.Deserialize<UserAccount>(UserAccountJson);
        }

        /// <summary>
        /// 封裝 ClaimsIdentity: 將使用者的登入資訊包裝成 ClaimsIdentity 以用於 Cookie-Base Auth.。
        /// </summary>
        internal ClaimsIdentity PackUserClaimsData(UserAccount auth)
        {
            // 使用者聲明
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, auth.UserName),
                //new Claim(ClaimTypes.Role, auth.Role)
                //new Claim(ClaimTypes.Sid, auth.AuthGuid.ToString()), // 登入識別序號
                //new Claim(ClaimTypes.GivenName, auth.UserName) // 顯示名稱
            };

            // 『角色』可能有多個
            foreach (string role in auth.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            return claimsIdentity;
        }

        //=====================================
        /// <summary>
        /// Authenticate & Authorize
        /// </summary>
        /*
        public string ValidateUser(LoginArgs ln)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(ln.clientIp))
                    throw new ApplicationException("登入認證失敗！");

                if (String.IsNullOrWhiteSpace(ln.hostName))
                    throw new ApplicationException("登入認證失敗！");

                //## verify vcode;
                if (!"123456".Equals(ln.vcode))
                    throw new ApplicationException("登入認證失敗！");

                //## 驗證帳號與密碼 並 取得角色
                AuthUser authUser = AuthModule.GetUserAuthz(ln.clientIp.Trim(), ln.hostName.Trim());
                if (authUser == null)
                    throw new ApplicationException("登入認證失敗！");

                // 補充登入來源資訊
                var (clientIp, hostName) = GetClientHostInfo();
                authUser.ClientIp = clientIp;
                authUser.ClientHostName = hostName;

                // 補充時效
                double expiresMinutes = _config.GetValue<double>("ExpiresMinutes");
                authUser.AuthGuid = Guid.NewGuid();
                authUser.IssuedUtc = DateTimeOffset.UtcNow;
                authUser.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(expiresMinutes);

                lock (_lockObj)
                {
                    ///
                    ///※ 授權資料建議存入Database，可用 MemoryCache 加速。
                    ///
                    _cache.Set<AuthUser>($"AuthData:{authUser.UserId}", authUser, TimeSpan.FromMinutes(expiresMinutes));
                }

                //## 製作 ticket
                var ticket = new Ticket
                {
                    ticketId = Guid.NewGuid(),
                    userId = authUser.UserId,
                    returnUrl = "/mainpage",
                    expires = DateTime.Now.AddSeconds(5)
                };

                lock (_lockObj)
                {
                    try
                    {
                        _ticketPool.Add(ticket.ticketId, ticket);
                    }
                    catch (Exception ex)
                    {
                        throw new ApplicationException("AuthTicket新增失敗！", ex);
                    }
                }

                //# success
                string ticketToken = Utils.JwtHostingEncode<Guid>(ticket.ticketId);
                _logger.DebugEx($"ValidateUser SUCCESS, userId:{ticket.userId}.");
                return ticketToken;
            }
            catch (Exception ex)
            {
                _logger.ErrorEx($"ValidateUser FAIL, clientIp:{ln.clientIp}, hostName:{ln.hostName}", ex);
                return null;
            }
        }
        */

        /// <summary>
        /// JwtHelper:只能用於短期且同APP內的交換訊息。
        /// </summary>
        public TObject JwtHostingDecode<TObject>(string token)
        {
            using var sha = new HMACSHA256(Encoding.ASCII.GetBytes(Environment.ProcessPath));
            string envprops = $"{Environment.ProcessId}{Environment.MachineName}{Environment.Version}{Environment.UserName}{Environment.OSVersion}{Environment.UserDomainName}{Environment.ProcessorCount}{DateTime.Today.DayOfYear}0okmNJIx.y(8uhbVGY&";
            byte[] key256 = sha.ComputeHash(Encoding.ASCII.GetBytes(envprops));
            string tokenR = String.Join('.', token.Split('.').Reverse());
            byte[] blobR = JWT.DecodeBytes(tokenR, key256, JweAlgorithm.A256GCMKW, JweEncryption.A256GCM);
            byte[] blob = blobR.Select(b => (byte)~b).ToArray();
            string json = Encoding.UTF8.GetString(blob, 0, blob.Length);
            TObject payload = JsonSerializer.Deserialize<TObject>(json);
            return payload;
        }

        /// <summary>        
        /// JwtHelper:只能用於短期且同APP內的交換訊息。
        /// </summary>
        public static string JwtHostingEncode<TObject>(TObject payload)
        {
            using var sha = new HMACSHA256(Encoding.ASCII.GetBytes(Environment.ProcessPath));
            string envprops = $"{Environment.ProcessId}{Environment.MachineName}{Environment.Version}{Environment.UserName}{Environment.OSVersion}{Environment.UserDomainName}{Environment.ProcessorCount}{DateTime.Today.DayOfYear}0okmNJIx.y(8uhbVGY&";
            byte[] key256 = sha.ComputeHash(Encoding.ASCII.GetBytes(envprops));
            string json = JsonSerializer.Serialize<TObject>(payload);
            byte[] blob = Encoding.UTF8.GetBytes(json);
            byte[] blobR = blob.Select(b => (byte)~b).ToArray();
            string token = JWT.EncodeBytes(blobR, key256, JweAlgorithm.A256GCMKW, JweEncryption.A256GCM);
            string tokenR = String.Join('.', token.Split('.').Reverse());
            return tokenR;
        }

        public class Model
        {
            public string UserName { get; set; }
            public string Password { get; set; }
        }

    }
}
