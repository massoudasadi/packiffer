using System;
using System.Collections.Generic;
using System.Text;

namespace packiffer.Models.Auth
{
    public class LoginResult
    {
        public string? Message { get; set; }
        public string? Email { get; set; }
        public string? JwtBearer { get; set; }
        public bool Success { get; set; }
    }
}
