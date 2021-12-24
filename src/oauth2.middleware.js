const oauthBoot = () => {
  const boot = {};

  boot.addEndPoints = (expressApp) => {
    expressApp.get("/auth", (req, res) => {
      res.json({ x: false });
    });
  };

  boot.guard = (req, res, next) => {
    console.log("hi");
    next();
  };

  return boot;
};

module.exports = oauthBoot;
