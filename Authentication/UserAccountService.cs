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
using BlazorServerAuth.Pages;
using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace BlazorServerAuth.Authentication
{
    public class UserAccountService : IDisposable
    {
        private List<AuthUser> _users;

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
        public AuthUser? GetByUserName(string username)
        {
            return _users.FirstOrDefault(x => x.UserName == username);
        }

        internal AuthUser GetAuthDataFromPool(string userIdentityName)
        {
            lock (_lockObj)
            {
                var UserAccount = _cache.Get<AuthUser>($"AuthData:{userIdentityName}");

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

        internal AuthUser GetCurrentUser()
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
        internal AuthUser UnpackUserClaimsData(System.Security.Principal.IIdentity identity)
        {
            if (!identity.IsAuthenticated)
                return null;

            var claimsIdentity = (System.Security.Claims.ClaimsIdentity)identity;
            var UserAccountJson = claimsIdentity.FindFirst(ClaimTypes.UserData)?.Value;
            if (UserAccountJson == null)
                throw new UnauthorizedAccessException("授權資料不完整！請重新登入。");

            return JsonSerializer.Deserialize<AuthUser>(UserAccountJson);
        }

        /// <summary>
        /// 封裝 ClaimsIdentity: 將使用者的登入資訊包裝成 ClaimsIdentity 以用於 Cookie-Base Auth.。
        /// </summary>
        internal ClaimsIdentity PackUserClaimsData(AuthUser auth)
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
        public string ValidateUser(LoginArgs login)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(login.UserName))
                    throw new ApplicationException("登入認證失敗！");

                if (String.IsNullOrWhiteSpace(login.HostName))
                    throw new ApplicationException("登入認證失敗！");

                ////## verify vcode;
                //if (!"123456".Equals(login.Vcode))
                //    throw new ApplicationException("登入認證失敗！");

                ////## 驗證帳號與密碼 並 取得角色
                //AuthUser authUser = AuthModule.GetUserAuthz(login.UserName.Trim(), HostName.Trim());
                //if (authUser == null)
                //    throw new ApplicationException("登入認證失敗！");

                AuthUser authUser = new AuthUser
                {
                    UserId = "TEST001",
                    UserName = "泰斯特",
                    Roles = new[] { "Admin" }
                };

                // 補充登入來源資訊
                var (userName, hostName) = GetClientHostInfo();
                authUser.ClientIp = userName;
                authUser.ClientHostName = hostName;

                // 補充時效
                double expiresMinutes = 20d;
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
                    returnUrl = "/",
                    expires = DateTime.Now.AddSeconds(20)
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
                string ticketToken = this.JwtHostingEncode<Guid>(ticket.ticketId);
                return ticketToken;
            }
            catch (Exception ex)
            {
                return null;
            }

        }

        public (string clientIp, string hostName) GetClientHostInfo()
        {
            //## 取登入者來源IP
            string clientIp = "無法取得來源IP";
            string hostName = "無法識別或失敗";
            try
            {
                IPAddress remoteIp = _http.HttpContext?.Connection.RemoteIpAddress;
                if (remoteIp != null)
                {
                    clientIp = remoteIp.ToString();
                    IPHostEntry host = Dns.GetHostEntry(remoteIp);
                    hostName = host.HostName;

                    ////※ 模擬跑數秒，因為在真實網路環境有時真的跑的有點久。
                    //System.Threading.SpinWait.SpinUntil(() => false, 5 * 1000); // 等三秒

                    //# 若有多餘的字尾".local" 則移除它。
                    const string suffix = ".local";
                    if (hostName.EndsWith(suffix))
                        hostName = hostName.Substring(0, hostName.Length - suffix.Length);
                }
            }
            catch (Exception ex)
            {
                // 預防取不到IP/HostName當掉。
            }

            return (clientIp, hostName);
        }

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
        public string JwtHostingEncode<TObject>(TObject payload)
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

        public class LoginArgs
        {
            /// <summary>
            /// 帳號
            /// </summary>
            public string UserName { get; set; }

            /// <summary>
            /// 密碼
            /// </summary>
            public string HostName { get; set; }
            
            /// <summary>
            /// 驗證碼
            /// </summary>
            public string Vcode { get; set; }
        }
    }
}

