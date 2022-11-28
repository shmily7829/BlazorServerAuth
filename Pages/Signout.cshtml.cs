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

    /// �� HTTP GET �n�X
    public async Task<IActionResult> OnGetAsync()
    {
      string? loginUserId = (this.HttpContext.User.Identity.IsAuthenticated)
          ? this.HttpContext.User.Identity.Name
          : null;

      // �M���D���ݵn�J���A
      _accSvc.SignoutUser(loginUserId);

      // Clear the existing external cookie
      await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
      //_logger.InfoEx($"�n�X�b���G{loginUserId}�C");

      return LocalRedirect("~/"); // ��}�^����
    }
  }
}
