namespace BlazorServerAuth.Authentication
{
    public class AuthUser
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string[] Roles { get; init; }
        public string ClientIp { get; set; }
        public string ClientHostName { get; set; }
        public Guid AuthGuid { get; set; }
        public DateTimeOffset IssuedUtc { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
    }
}
