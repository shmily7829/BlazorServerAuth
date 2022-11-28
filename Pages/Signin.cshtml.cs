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

  /// 用HTTP GET 登入: 註冊 Auth-Cookie
  public async Task<IActionResult> OnGetAsync(string tid)
  {
    UserAccount? UserAccount = null;
    try
    {
      if (String.IsNullOrWhiteSpace(tid))
        return BadRequest();

      //## 拿出（登入認證）門票
      var ticket = _accSvc.TakeOutTicket(decode(tid));
      if (ticket == null)
        return BadRequest();

      if (DateTime.Now >= ticket.expires)
        return StatusCode(408, "[ticket]已過時。");

      // 準備參數
      string returnUrl = String.IsNullOrWhiteSpace(ticket.returnUrl) ? Url.Content("~/Main") : ticket.returnUrl;

      //## 取授權資料 -----------------------

      UserAccount = _accSvc.GetAuthDataFromPool(ticket.userId);
      if (UserAccount == null)
        return Unauthorized();

      //## 註冊 Cookie-Base Auth  -----------------------

      //# 先清除 Cookie-Base Auth
      try
      {
        // Clear the existing external cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
      }
      catch { }

      //# 準備 Cookie-Base Auth 

      // 使用者聲明
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

      //# 執行 Cookie-Base Auth 註冊
      await HttpContext.SignInAsync(
          CookieAuthenticationDefaults.AuthenticationScheme,
          new ClaimsPrincipal(claimsIdentity),
          authProperties);

      // success
      //_logger.InfoEx($"登入認證成功，帳號：{ticket.userId}。");
      return LocalRedirect(returnUrl);
    }
    catch (Exception ex)
    {
      //※ 邏輯上沒機會進到這裡來，除非被駭客攻擊！
      return Unauthorized();
    }
  }

  string decode(string param)
  {
    return System.Web.HttpUtility.UrlDecode(param);
  }
}

