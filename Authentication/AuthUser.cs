namespace BlazorServerAuth.Authentication
{
    public class AuthUser
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string[] Roles { get; init; }
        public string ClientIp { get; set; }
        public Guid AuthGuid { get; set; }
        public DateTimeOffset IssuedUtc { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
    }
}
