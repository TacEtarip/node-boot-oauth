const oauthBoot = {
  bootOauthExpress: (expressApp) => {
    // expressApp.post = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressApp.obGet = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.get(path, ...handler);
    };

    // expressApp.put = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressApp.obDelete = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.delete(path, ...handler);
    };

    // console.log("xx");
    return expressApp;
  },

  bootOauthExpressRouter: (expressRouter) => {
    // expressApp.post = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressRouter.obGet = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.get(path, ...handler);
    };

    // expressApp.put = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressRouter.obDelete = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.delete(path, ...handler);
    };

    // console.log("xx");
    return expressRouter;
  },

  addEndPoints: (expressBootApp) => {
    expressBootApp.get("/auth", (req, res) => {
      res.json({ x: false });
    });
  },

  guard: (req, res, next) => {
    console.log(req.path);
    next();
  },
};

module.exports = oauthBoot;
