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

    return expressApp;
  };

  boot.addEndPoints = (expressBootApp) => {
    expressApp.get("/auth", (req, res) => {
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
