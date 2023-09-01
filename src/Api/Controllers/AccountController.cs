using System.Text;
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

    public AccountController(SignInManager<ApplicationUser> signInManager)
    {
        _signInManager = signInManager;
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