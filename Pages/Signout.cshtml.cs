using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BlazorServerAuthenticationAndAuthorzation.Authentication
{
    [Authorize]
  public class SignoutModel : PageModel
  {
    readonly ILogger<SignoutModel> _logger;
    readonly UserAccountService _accSvc;

    public SignoutModel(ILogger<SignoutModel> logger, UserAccountService accSvc)
    {
      _logger = logger;
      _accSvc = accSvc;
    }

    /// 用 HTTP GET 登出
    public async Task<IActionResult> OnGetAsync()
    {
      string? loginUserId = (this.HttpContext.User.Identity.IsAuthenticated)
          ? this.HttpContext.User.Identity.Name
          : null;

      // 清除主機端登入狀態
      _accSvc.SignoutUser(loginUserId);

      // Clear the existing external cookie
      await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
      //_logger.InfoEx($"登出帳號：{loginUserId}。");

      return LocalRedirect("~/"); // 轉址回首頁
    }
  }
}
