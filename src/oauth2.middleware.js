class OauthBoot {
  constructor(expressApp, knex) {
    this.expressApp = expressApp;
    this.knex = knex;
    this.expressSecured = this.bootOauthExpress(expressApp);
  }

  async init() {
    try {
      await this.auditDataBase();
      this.addEndPoints();
    } catch (error) {
      console.log(error);
    }
  }

  async auditDataBase() {
    try {
      const hasTableSubject = await this.knex.hasTable("OAUTH2_Subjects");
      console.log(hasTableSubject);
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  }

  bootOauthExpress(expressApp) {
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
  }

  static bootOauthExpressRouter(expressRouter) {
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
  }

  addEndPoints() {
    this.expressSecured.get("/auth", (req, res) => {
      res.json({ x: false });
    });
  }

  guard() {
    return (req, res, next) => {
      console.log(req.path);
      console.log(this.expressApp.get(req.path));
      next();
    };
  }
}

module.exports = OauthBoot;
