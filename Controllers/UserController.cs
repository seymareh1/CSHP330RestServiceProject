using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CSHP330RestServiceProject.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserRepository _repository = new UserRepository();

        public UserController(UserRepository repository)
        {
            _repository = repository;
        }


        [HttpGet]
        public IActionResult GetAllUsers()
         {
            return Ok(_repository.GetAll());
        }

        [HttpGet("{id}")]
        public IActionResult GetUser(Guid id)
        {
            var user = _repository.GetById(id);
            if (user == null) return NotFound();
            return Ok(user);
        }

        [HttpPost]
        public IActionResult AddUser(UserInput input)
        {
            if (string.IsNullOrWhiteSpace(input.UserEmail) || string.IsNullOrWhiteSpace(input.UserPassword))
                return BadRequest("Required fields are missing");
            var user = new User()
            {
                UserId = Guid.NewGuid()
                , UserEmail = input.UserEmail
                , UserPassword = input.UserPassword
                , CreatedDate = DateTime.UtcNow
            };

            return CreatedAtAction(nameof(GetUser), new { id = user.UserId }, _repository.Add(user));
        }

        [HttpPut("{id}")]
        public IActionResult UpdateUser(Guid id, UserInput input)
        {
            if (string.IsNullOrWhiteSpace(input.UserEmail) || string.IsNullOrWhiteSpace(input.UserPassword))
                return BadRequest("Required fields are missing");

            var updatedUser = _repository.Update(id, input);
            if (updatedUser == null) return NotFound();
            return Ok(updatedUser);
        }

        [HttpDelete("{id}")]
        public IActionResult DeleteUser(Guid id)
        {
            var user = _repository.GetById(id);
            if (user == null) return NotFound();

            _repository.Delete(id);
            return Ok();
        }

        [HttpGet("login/{email}/{password}")]
        public IActionResult Login(string email, string password)
        {
            var user = _repository.GetByEmailAndPassword(email, password);
            if (user == null) return NotFound();

            var token = GetToken(user);
            return Ok(new { Token = token });
        }

        private string GetToken(User user)
        {
            Token newToken = new Token()
            {
                UserEmail = user.UserEmail
                , Expires = DateTime.UtcNow.AddMinutes(1)
            };


            // Encrypt the JSON Token 
            var jsonToken = JsonSerializer.Serialize(newToken);
            string encryptedToken = EncryptString(jsonToken);

            return encryptedToken;
        }

        private string EncryptString(string plainText)
        {
            byte[] salt = Encoding.ASCII.GetBytes("B78A07A7-14D8-4890-BC99-9145A14713C1");
            string pass = "commonpass";

            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("plainText");
            }

            string outStr;                   // Encrypted string to return
            RijndaelManaged aesAlg = null;   // Used to encrypt the data
            try
            {
                var key = new Rfc2898DeriveBytes(pass, salt);
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                // Create a decryptor to perform the stream transform.
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                {
                    aesAlg.Clear();
                }
            }
            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        public static string DecryptStringAES(string cipherText)
        {
            byte[] salt = Encoding.ASCII.GetBytes("B78A07A7-14D8-4890-BC99-9145A14713C1");
            string pass = "commonpass";

            if (string.IsNullOrEmpty(cipherText))
            {
                throw new ArgumentNullException("cipherText");
            }

            RijndaelManaged aesAlg = null;
            string plaintext;
            try
            {
                // generate the key from the shared secret and the salt
                var key = new Rfc2898DeriveBytes(pass, salt);

                // Create the streams used for decryption.
                var bytes = Convert.FromBase64String(cipherText);
                using (var msDecrypt = new MemoryStream(bytes))
                {
                    // Create a RijndaelManaged object with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);

                    // Create a decrytor to perform the stream transform.
                    var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                {
                    aesAlg.Clear();
                }
            }
            return plaintext;
        }

        private static byte[] ReadByteArray(Stream s)
        {
            var rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }
            var buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }
            return buffer;
        }



        public class Token
        {
            public string UserEmail { get; set;}
            public DateTime Expires { get; set;}
        }
    }
}
