using System.Security.Claims;
using System.Text;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Api.Controllers;

public sealed record CallbackResponse(string LoginResponseId);

public sealed record LoginRequest(string Username, string Password, string LoginRequestId);

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
            // todo: refactor, pass login request id, make it optional
            using var client = new HttpClient();
            var responseMessage = await client.PostAsync(
                requestUri: $"https://localhost:20000/api/private/login/callback/reject",
                content: new StringContent(
                    content: JsonConvert.SerializeObject(new
                    {
                        LoginRequestId = request.LoginRequestId,
                    }),
                    encoding: Encoding.UTF8,
                    mediaType: "application/json"
                ),
                cancellationToken: ct
            );
            return BadRequest(result.ToString());
        }

        {
            // todo: refactor, pass login request id, make it optional
            using var client = new HttpClient();
            var responseMessage = await client.PostAsync(
                requestUri: $"https://localhost:20000/api/private/login/callback/accept",
                content: new StringContent(
                    content: JsonConvert.SerializeObject(new
                    {
                        LoginRequestId = request.LoginRequestId,
                        SubjectId = user.Id,
                    }),
                    encoding: Encoding.UTF8,
                    mediaType: "application/json"
                ),
                cancellationToken: ct
            );
            var rawResponse = await responseMessage.Content.ReadAsStringAsync(ct);
            var response = JsonConvert.DeserializeObject<CallbackResponse>(rawResponse);
            return Ok(new { LoginResponseId = response.LoginResponseId, });
        }
    }

    [HttpGet]
    [Route("login/google")]
    public async Task<IActionResult> LoginGoogle(CancellationToken ct)
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = "https://localhost:20010/account/login/google/callback",
            Items =
            {
                //     { "returnUrl", "https://localhost:20010/account/login/google/callback" },
                //     { "scheme", "google" },
                { "LoginProvider", "Google" }, // used to enable await _signInManager.GetExternalLoginInfoAsync()
            },
        };

        return Challenge(props, "Google");
    }

    [Authorize(AuthenticationSchemes = "Google")]
    [HttpGet]
    [Route("login/google/callback")]
    public async Task<IActionResult> LoginGoogleCallback(CancellationToken ct)
    {
        var internalAuthResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (internalAuthResult.Succeeded != true)
        {
            throw new Exception("Internal authentication error");
        }

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
        
        var internalUser = await _userManager.GetUserAsync(internalAuthResult.Principal);
        if (internalUser == null)
        {
            throw new NotImplementedException();
        }

        var providerUser = await _userManager.FindByLoginAsync(provider, providerUserId);
        if (providerUser == null)
        {
            await _userManager.AddLoginAsync(internalUser, new UserLoginInfo(provider, providerUserId, provider));
        }

        // delete external cookie
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        return Ok();
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

    // private async Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)>
    //     FindUserFromExternalProviderAsync(AuthenticateResult result)
    // {
    //     var externalUser = result.Principal;
    //
    //     // try to determine the unique id of the external user (issued by the provider)
    //     // the most common claim type for that are the sub claim and the NameIdentifier
    //     // depending on the external provider, some other claim type might be used
    //     var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
    //                       externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
    //                       throw new Exception("Unknown userid");
    //
    //     // remove the user id claim so we don't include it as an extra claim if/when we provision the user
    //     var claims = externalUser.Claims.ToList();
    //     claims.Remove(userIdClaim);
    //
    //     var provider = result.Properties.Items["scheme"];
    //     var providerUserId = userIdClaim.Value;
    //
    //     // find external user
    //     var user = await _userManager.FindByLoginAsync(provider, providerUserId);
    //
    //     return (user, provider, providerUserId, claims);
    // }
}