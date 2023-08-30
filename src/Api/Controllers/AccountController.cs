using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

public sealed record LoginRequest(string Username, string Password);

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
            return BadRequest(result.ToString());
        }

        // todo notify ids4 with login_challenge

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
}