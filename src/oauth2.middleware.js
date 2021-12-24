const oauthMiddleware = (req, res, next) => {
  console.log("xxxx");
  next();
};

module.exports = oauthMiddleware;
