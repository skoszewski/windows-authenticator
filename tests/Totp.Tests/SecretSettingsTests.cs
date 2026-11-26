namespace Totp.Tests;

[TestClass]
public sealed class SecretSettingsTests
{
    [TestMethod]
    public void TheDefaultsAskEveryTimeAndHideAfterThirtySeconds()
    {
        var settings = new SecretSettings();
        Assert.IsTrue(settings.RequiresAuthentication);
        Assert.AreEqual(0, settings.AuthenticationSeconds);
        Assert.AreEqual(30, settings.HideSeconds);
    }

    [TestMethod]
    public void TheStoredTextRoundTrips()
    {
        var settings = new SecretSettings(requiresAuthentication: false, authenticationSeconds: 90, hideSeconds: 0);
        Assert.AreEqual("authenticate=0&seconds=90&hide=0", settings.Text);
        Assert.AreEqual(settings, SecretSettings.FromText(settings.Text));
    }

    [TestMethod]
    [DataRow("", true, 0, 30)]
    [DataRow("authenticate=0", false, 0, 30)]
    [DataRow("authenticate=1", true, 0, 30)]
    [DataRow("authenticate=1&seconds=60", true, 60, 30)]
    [DataRow("authenticate=1&seconds=60&hide=5", true, 60, 5)]
    [DataRow("hide=0", true, 0, 0)]
    public void TheFormsOfEarlierBuildsAndMissingKeysTakeDefaults(string text, bool requires, int seconds, int hide) =>
        Assert.AreEqual(new SecretSettings(requires, seconds, hide), SecretSettings.FromText(text));

    [TestMethod]
    [DataRow("garbage")]
    [DataRow("authenticate=2")]
    [DataRow("seconds=-1")]
    [DataRow("hide=-5")]
    [DataRow("seconds=ten")]
    [DataRow("authenticate=1&hide")]
    public void ATextThatIsNotValidIsNull(string text) => Assert.IsNull(SecretSettings.FromText(text));

    [TestMethod]
    public void NegativeNumbersAreRaisedToZero()
    {
        var settings = new SecretSettings(authenticationSeconds: -3, hideSeconds: -1);
        Assert.AreEqual(0, settings.AuthenticationSeconds);
        Assert.AreEqual(0, settings.HideSeconds);
    }
}
