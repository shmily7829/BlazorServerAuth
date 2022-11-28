namespace BlazorServerAuthenticationAndAuthorzation.Authentication
{
    public class UserAccount
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string[] Roles { get; init; }
        public DateTimeOffset IssuedUtc { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
    }
}
