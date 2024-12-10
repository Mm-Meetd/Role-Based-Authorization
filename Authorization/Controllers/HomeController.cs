using Authorization.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Authorization.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly RoleManager<IdentityRole> _roleManager;

        public HomeController(ILogger<HomeController> logger, RoleManager<IdentityRole> roleManager)
        {
            _logger = logger;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }
        [Authorize(Roles = "User")]
        public IActionResult UserRoleCheck()
        {
            return View();
        }
        [Authorize(Roles = "admin")]
        public IActionResult AdminRoleCheck()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Admin()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Admin(Role role)
        {
            var result = _roleManager.RoleExistsAsync(role.RoleName).Result;
            if (!result)
            {
                await _roleManager.CreateAsync(new IdentityRole(role.RoleName));
            }

            return RedirectToAction("Admin");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}