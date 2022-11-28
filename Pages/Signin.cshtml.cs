using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace BlazorServerAuth.Authentication;

[AllowAnonymous]
public class SigninModel : PageModel
{
  readonly UserAccountService _accSvc;
  readonly ILogger<SigninModel> _logger;
  readonly IConfiguration _config;

  public SigninModel(ILogger<SigninModel> logger, IConfiguration config, UserAccountService accSvc)
  {
    _accSvc = accSvc;
    _config = config;
    _logger = logger;
  }

  /// ��HTTP GET �n�J: ���U Auth-Cookie
  public async Task<IActionResult> OnGetAsync(string tid)
  {
    UserAccount? UserAccount = null;
    try
    {
      if (String.IsNullOrWhiteSpace(tid))
        return BadRequest();

      //## ���X�]�n�J�{�ҡ^����
      var ticket = _accSvc.TakeOutTicket(decode(tid));
      if (ticket == null)
        return BadRequest();

      if (DateTime.Now >= ticket.expires)
        return StatusCode(408, "[ticket]�w�L�ɡC");

      // �ǳưѼ�
      string returnUrl = String.IsNullOrWhiteSpace(ticket.returnUrl) ? Url.Content("~/Main") : ticket.returnUrl;

      //## �����v��� -----------------------

      UserAccount = _accSvc.GetAuthDataFromPool(ticket.userId);
      if (UserAccount == null)
        return Unauthorized();

      //## ���U Cookie-Base Auth  -----------------------

      //# ���M�� Cookie-Base Auth
      try
      {
        // Clear the existing external cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
      }
      catch { }

      //# �ǳ� Cookie-Base Auth 

      // �ϥΪ��n��
      var claimsIdentity = _accSvc.PackUserClaimsData(UserAccount);

      var authProperties = new AuthenticationProperties
      {
        IsPersistent = false,
        IssuedUtc = UserAccount.IssuedUtc,
        ExpiresUtc = UserAccount.ExpiresUtc,
        RedirectUri = this.Request.Host.Value
        //AllowRefresh = <bool>,
        // Refreshing the authentication session should be allowed.
      };

      //# ���� Cookie-Base Auth ���U
      await HttpContext.SignInAsync(
          CookieAuthenticationDefaults.AuthenticationScheme,
          new ClaimsPrincipal(claimsIdentity),
          authProperties);

      // success
      //_logger.InfoEx($"�n�J�{�Ҧ��\�A�b���G{ticket.userId}�C");
      return LocalRedirect(returnUrl);
    }
    catch (Exception ex)
    {
      //�� �޿�W�S���|�i��o�̨ӡA���D�Q�b�ȧ����I
      return Unauthorized();
    }
  }

  string decode(string param)
  {
    return System.Web.HttpUtility.UrlDecode(param);
  }
}

