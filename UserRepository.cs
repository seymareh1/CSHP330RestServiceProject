namespace CSHP330RestServiceProject
{
    public class UserRepository
    {
        private readonly List<User> _users = new List<User>();

        public IEnumerable<User> GetAll() => _users;

        public User GetById(Guid id) => _users.FirstOrDefault(u => u.UserId == id);

        public User Add(User user)
        {
            _users.Add(user);
            return user;
        }

        public void Delete(Guid id) => _users.RemoveAll(u => u.UserId == id);

        public User Update(Guid id, UserInput input)
        {
            var existingUser = _users.FirstOrDefault(u => u.UserId == id);
            if (existingUser != null)
            {
                existingUser.UserEmail = input.UserEmail;
                existingUser.UserPassword = input.UserPassword;
            }
            return existingUser;
        }

        public User GetByEmailAndPassword(string email, string password) =>
            _users.FirstOrDefault(u => u.UserEmail == email && u.UserPassword == password);
    }
}
