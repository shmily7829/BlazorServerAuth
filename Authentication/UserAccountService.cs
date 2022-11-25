using System.Security.Cryptography.X509Certificates;

namespace BlazorServerAuthenticationAndAuthorzation.Authentication
{
    public class UserAccountService
    {
        private List<UserAccount> _users;
        public UserAccountService()
        {
            _users = new List<UserAccount>()
            {
                new UserAccount() { UserName = "admin", Password = "admin", Role = "Administrator" },
                new UserAccount() { UserName = "user", Password = "user", Role = "User" }
            };
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
    }
}
