using System.Security.Claims;
using System.Text;
using System.Web;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Api.Controllers;

public sealed record CallbackResponse(string LoginResponseId);

public sealed record LoginRequest(string Username, string Password, string LoginRequestId);

public sealed record LoginGoogleRequest(string ReturnUrl, string LoginRequestId);

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AccountController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    private async Task<string> NotifySignInSuccess(string loginRequestId, string subjectId, CancellationToken ct)
    {
        // todo: refactor, pass login request id, make it optional
        using var client = new HttpClient();
        var responseMessage = await client.PostAsync(
            requestUri: $"https://localhost:20000/api/private/login/callback/accept",
            content: new StringContent(
                content: JsonConvert.SerializeObject(new
                {
                    LoginRequestId = loginRequestId,
                    SubjectId = subjectId,
                }),
                encoding: Encoding.UTF8,
                mediaType: "application/json"
            ),
            cancellationToken: ct
        );
        var rawResponse = await responseMessage.Content.ReadAsStringAsync(ct);
        var response = JsonConvert.DeserializeObject<CallbackResponse>(rawResponse);
        return response.LoginResponseId;
    }

    private async Task NotifySignInFailure(string loginRequestId, CancellationToken ct)
    {
        // todo: refactor, pass login request id, make it optional
        using var client = new HttpClient();
        var responseMessage = await client.PostAsync(
            requestUri: $"https://localhost:20000/api/private/login/callback/reject",
            content: new StringContent(
                content: JsonConvert.SerializeObject(new
                {
                    LoginRequestId = loginRequestId,
                }),
                encoding: Encoding.UTF8,
                mediaType: "application/json"
            ),
            cancellationToken: ct
        );
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var user = await _signInManager.UserManager.FindByNameAsync(request.Username);
        if (user == null)
        {
            // todo register a set of users at startup
            user = new ApplicationUser
            {
                Id = Random.Shared.Next(1, 100000).ToString(),
                UserName = request.Username,
            };
            var createResult = await _signInManager.UserManager.CreateAsync(user, request.Password);
            if (!createResult.Succeeded)
            {
                return BadRequest(string.Join(" ", createResult.Errors.Select(x => x.Description)));
            }

            // return BadRequest("User not found");
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
        var props = new AuthenticationProperties
        {
            RedirectUri = "https://localhost:20010/account/login/google/callback",
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
}