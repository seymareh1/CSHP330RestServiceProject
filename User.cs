namespace CSHP330RestServiceProject
{
    public class User
    {
        public Guid UserId { get; set; } = Guid.NewGuid();
        public string UserEmail { get; set; }
        public string UserPassword { get; set; } // You can hash this later.
        public DateTime CreatedDate { get; set; } = DateTime.Now;
    }
}
