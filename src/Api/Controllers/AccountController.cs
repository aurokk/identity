using System.Net;
using System.Security.Claims;
using IdentityModel;
using JetBrains.Annotations;
using Kochnev.Auth.Private.Client.Api;
using Kochnev.Auth.Private.Client.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

[PublicAPI]
public sealed record CallbackResponse(string LoginResponseId);

[PublicAPI]
public sealed record LoginRequest(string Username, string Password, string LoginRequestId);

[PublicAPI]
public sealed record LoginGoogleRequest(string ReturnUrl, string LoginRequestId);

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILoginCallbackApi _loginCallbackApi;

    public AccountController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILoginCallbackApi loginCallbackApi)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _loginCallbackApi = loginCallbackApi;
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user == null)
        {
            user = new ApplicationUser
            {
                Id = Random.Shared.Next(1, 100000).ToString(),
                UserName = request.Username,
            };
            var createResult = await _userManager.CreateAsync(user, request.Password);
            if (!createResult.Succeeded)
            {
                return BadRequest(string.Join(" ", createResult.Errors.Select(x => x.Description)));
            }
        }

        var result = await _signInManager.PasswordSignInAsync(
            user: user,
            password: request.Password,
            isPersistent: true,
            lockoutOnFailure: false
        );

        if (!result.Succeeded)
        {
            await NotifySignInFailure(request.LoginRequestId, ct);
            return BadRequest(result.ToString());
        }

        {
            var loginResponseId = await NotifySignInSuccess(request.LoginRequestId, user.Id, ct);
            return Ok(new { LoginResponseId = loginResponseId, });
        }
    }

    [HttpGet]
    [Route("login/google")]
    public IActionResult LoginGoogle([FromQuery] LoginGoogleRequest request, CancellationToken ct)
    {
        var hostUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}";
        var props = new AuthenticationProperties
        {
            RedirectUri = $"{hostUrl}/account/login/google/callback",
            Items =
            {
                { "LoginRequestId", request.LoginRequestId },
                { "LoginProvider", "Google" }, // used to enable await _signInManager.GetExternalLoginInfoAsync()
                { "ReturnUrl", request.ReturnUrl },
            },
        };

        return Challenge(props, "Google");
    }

    [Authorize(AuthenticationSchemes = "Google")]
    [HttpGet]
    [Route("login/google/callback")]
    public async Task<IActionResult> LoginGoogleCallback(CancellationToken ct)
    {
        // var internalAuthResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        // if (internalAuthResult.Succeeded != true)
        // {
        //     throw new Exception("Internal authentication error");
        // }

        var externalAuthResult = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
        if (externalAuthResult.Succeeded != true)
        {
            throw new Exception("External authentication error");
        }

        var externalUser = externalAuthResult.Principal;

        var userIdClaim =
            externalUser.FindFirst(JwtClaimTypes.Subject) ??
            externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
            throw new Exception("Unknown userid");

        var otherClaims = externalUser.Claims.ToList();
        otherClaims.Remove(userIdClaim);

        var provider = "Google";
        var providerUserId = userIdClaim.Value;

        // var internalUser = await _userManager.GetUserAsync(internalAuthResult.Principal);
        // if (internalUser == null)
        // {
        //     throw new NotImplementedException();
        // }

        // var providerUser = await _userManager.FindByLoginAsync(provider, providerUserId);
        // if (providerUser == null)
        // {
        //     await _userManager.AddLoginAsync(internalUser, new UserLoginInfo(provider, providerUserId, provider));
        // }

        var internalUser = new ApplicationUser { UserName = Guid.NewGuid().ToString(), };
        var internalUserResult = await _userManager.CreateAsync(internalUser);
        if (!internalUserResult.Succeeded)
        {
            throw new Exception(internalUserResult.Errors.First().Description);
        }

        var addLoginResult = await _userManager.AddLoginAsync(
            internalUser,
            new UserLoginInfo(provider, providerUserId, provider)
        );
        if (!addLoginResult.Succeeded)
        {
            throw new Exception(addLoginResult.Errors.First().Description);
        }

        var internalUserPrincipal = await _signInManager.CreateUserPrincipalAsync(internalUser);
        var internalUserLocalSignInProps = new AuthenticationProperties();
        await HttpContext.SignInAsync(
            IdentityConstants.ApplicationScheme,
            internalUserPrincipal,
            internalUserLocalSignInProps
        );

        // delete external cookie
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        var loginRequestId = externalAuthResult.Properties.Items["LoginRequestId"];
        var loginResponseId = await NotifySignInSuccess(loginRequestId, internalUser.Id, ct);

        var returnUrl = externalAuthResult.Properties.Items["ReturnUrl"] + $"&LoginResponseId={loginResponseId}";
        return Redirect(returnUrl);
    }

    [HttpPost]
    [Route("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        await _signInManager.SignOutAsync();
        return Ok();
    }

    [HttpGet]
    [Route("me")]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        await Task.CompletedTask;
        return Ok(new
        {
            IsSignedIn = _signInManager.IsSignedIn(User),
        });
    }

    private async Task<string> NotifySignInSuccess(string loginRequestId, string subjectId, CancellationToken ct)
    {
        var request = new ApiApiPrivateLoginCallbackAcceptRequest
        {
            LoginRequestId = loginRequestId,
            SubjectId = subjectId,
        };
        var response = await _loginCallbackApi.ApiPrivateLoginCallbackAcceptPostWithHttpInfoAsync(
            apiApiPrivateLoginCallbackAcceptRequest: request,
            cancellationToken: ct
        );
        return response.StatusCode == HttpStatusCode.OK
            ? response.Data.LoginResponseId
            : throw new Exception();
    }

    private async Task NotifySignInFailure(string loginRequestId, CancellationToken ct)
    {
        var request = new ApiApiPrivateLoginCallbackRejectRequest
        {
            LoginRequestId = loginRequestId,
        };
        var response = await _loginCallbackApi.ApiPrivateLoginCallbackRejectPostWithHttpInfoAsync(
            apiApiPrivateLoginCallbackRejectRequest: request,
            cancellationToken: ct
        );
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new Exception();
        }
    }
}