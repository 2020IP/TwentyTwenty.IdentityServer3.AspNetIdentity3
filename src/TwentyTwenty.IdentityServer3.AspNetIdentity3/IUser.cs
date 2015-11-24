namespace TwentyTwenty.IdentityServer3.AspNetIdentity3
{
    public interface IUser
    {
        string Id { get; set; }

        string UserName { get; set; }
    }
}