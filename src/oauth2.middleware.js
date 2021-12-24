const oauthBoot = () => {
  const boot = {};

  boot.bootExpress = (expressApp) => {
    expressApp.post = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.post(path, ...handler);
    };

    expressApp.get = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.post(path, ...handler);
    };

    expressApp.put = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.post(path, ...handler);
    };

    expressApp.delete = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.post(path, ...handler);
    };

    console.log("xx");
    return expressApp;
  };

  boot.addEndPoints = (expressBootApp) => {
    expressBootApp.get("/auth", (req, res) => {
      res.json({ x: false });
    });
  };

  boot.guard = (req, res, next) => {
    console.log(req.path);
    next();
  };

  return boot;
};

module.exports = oauthBoot;
